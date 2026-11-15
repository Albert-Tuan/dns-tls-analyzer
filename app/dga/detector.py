"""Explainable rule-based DGA scoring. Score 0..100 is a heuristic risk score, NOT a probability.

Labels: ``suspicious_dga`` (rules met), ``benign`` (not flagged by the rules; not a verdict that
the domain is safe) and ``unknown`` (cannot be scored, see ``reasons``).
Only ``suspicious_dga`` records count as DGA alerts.
"""
from collections import defaultdict
from dataclasses import asdict, dataclass, fields
import json
from math import isfinite
from pathlib import Path

from app.dga.features import extract_dga_features

SUSPICIOUS, BENIGN, UNKNOWN = 'suspicious_dga', 'benign', 'unknown'

# rule name -> (feature, direction, signal group). Correlated rules share a group and
# together count as one independent signal.
RULES = {
    'unusual_ngrams': ('ngram_score', 'high', 'ngram'),
    'high_entropy': ('entropy', 'high', 'randomness'),
    'high_digit_ratio': ('digit_ratio', 'high', 'composition'),
    'low_vowel_ratio': ('vowel_ratio', 'low', 'composition'),
    'long_label': ('length', 'high', 'length'),
}

# Declared before tuning. Each set sums to 100.
WEIGHT_SETS = {
    'equal': {'unusual_ngrams': 20, 'high_entropy': 20, 'high_digit_ratio': 20,
              'low_vowel_ratio': 20, 'long_label': 20},
    'ngram_weighted': {'unusual_ngrams': 35, 'high_entropy': 20, 'high_digit_ratio': 15,
                       'low_vowel_ratio': 15, 'long_label': 15},
}

TOO_SHORT = 'label_too_short_for_scoring'
IDN = 'idn_label_outside_reference_corpus'


@dataclass(frozen=True)
class DgaConfig:
    """Defaults are the frozen values selected on the dev split (configs/dga_frozen.json)."""
    min_label_length: int = 5
    min_signal_groups: int = 2
    weight_set: str = 'equal'
    calibration_percentile: int = 90
    ngram_score_threshold: float = 0.779542
    entropy_threshold: float = 3.189898
    digit_ratio_threshold: float = 0.0
    vowel_ratio_threshold: float = 0.230769
    length_threshold: float = 13.0
    alert_score: int = 40

    def __post_init__(self):
        for name in ('min_label_length', 'min_signal_groups', 'calibration_percentile', 'alert_score'):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f'{name} must be a positive integer')
        for name in ('ngram_score_threshold', 'entropy_threshold', 'digit_ratio_threshold',
                     'vowel_ratio_threshold', 'length_threshold'):
            value = getattr(self, name)
            if type(value) not in (int, float) or not isfinite(value) or value < 0:
                raise ValueError(f'{name} must be finite and >= 0')
        if self.weight_set not in WEIGHT_SETS:
            raise ValueError(f'weight_set must be one of {sorted(WEIGHT_SETS)}')
        if self.alert_score > 100 or self.calibration_percentile >= 100:
            raise ValueError('alert_score must be <= 100 and calibration_percentile < 100')
        if self.min_signal_groups > len({group for *_, group in RULES.values()}):
            raise ValueError('min_signal_groups exceeds the number of signal groups')

    @classmethod
    def from_file(cls, path):
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(data, dict) or set(data) - {f.name for f in fields(cls)}:
            raise ValueError('Config must be an object with known DgaConfig keys')
        return cls(**data)

    def to_dict(self):
        return asdict(self)

    def threshold(self, feature):
        return getattr(self, f'{feature}_threshold')


def _round(value):
    return round(value, 4) if isinstance(value, float) else value


def evaluate_rules(features: dict, config: DgaConfig) -> tuple[list[str], list[str], int]:
    """Return (fired rule names, distinct signal groups, score) for one label's features."""
    weights = WEIGHT_SETS[config.weight_set]
    fired = []
    for name, (feature, direction, _) in RULES.items():
        value = features.get(feature)
        if value is None:
            continue
        limit = config.threshold(feature)
        # Strict comparisons: a rule fires only beyond the dev-benign percentile.
        if (value > limit) if direction == 'high' else (value < limit):
            fired.append(name)
    groups = sorted({RULES[name][2] for name in fired})
    return fired, groups, sum(weights[name] for name in fired)


def score_domain(qname: str, config: DgaConfig | None = None) -> dict:
    """Score one name on its registered-domain label; deterministic and offline."""
    cfg = config or DgaConfig()
    info = extract_dga_features(qname)
    base = {'detector': 'dga', 'target': info['registered_domain'] or info['qname'] or info['input'],
            'registered_domain': info['registered_domain'], 'dga_label': info['dga_label']}
    if info['status'] != 'ok':
        return {**base, 'classification': UNKNOWN, 'score': None, 'features': None,
                'reasons': [info['reason']], 'signal_groups': [], 'eligible': False}
    features = info['features']
    fired, groups, score = evaluate_rules(features, cfg)
    reasons = list(fired)
    eligible = features['length'] >= cfg.min_label_length
    if not eligible:
        reasons.append(TOO_SHORT)
    if info['is_idn']:
        reasons.append(IDN)
        classification = UNKNOWN
    elif eligible and len(groups) >= cfg.min_signal_groups and score >= cfg.alert_score:
        classification = SUSPICIOUS
    else:
        classification = BENIGN
    return {**base, 'classification': classification, 'score': score,
            'features': {k: _round(v) for k, v in features.items()},
            'reasons': reasons, 'signal_groups': groups, 'eligible': eligible and not info['is_idn']}


_ORDER = {SUSPICIOUS: 0, BENIGN: 1, UNKNOWN: 2}


def analyze_dns_domains(dns_events: list[dict], config: DgaConfig | None = None) -> list[dict]:
    """One result per registered domain seen in DNS *queries*; responses are ignored.

    Query events without a registered domain (unknown suffix, reverse/internal names) are
    grouped by QNAME and returned as ``unknown`` with a reason. Every result carries
    ``observations`` (query count, distinct QNAMEs, clients, first frame/time).
    Sorted: suspicious first, then by score (high to low), then by target.
    """
    if not isinstance(dns_events, list):
        raise TypeError('dns_events must be a list of DNS event dicts')
    cfg = config or DgaConfig()
    groups = defaultdict(list)
    for event in dns_events:
        if not isinstance(event, dict):
            raise TypeError('each DNS event must be a dict')
        if event.get('is_query') is not True:
            continue
        domain = event.get('registered_domain')
        if 'registered_domain' not in event:  # contract-less fixture: derive from the QNAME
            domain = extract_dga_features(event.get('qname'))['registered_domain']
        groups[('domain', domain) if domain else ('name', str(event.get('qname')))].append(event)
    results = []
    for (kind, key), events in groups.items():
        if kind == 'domain':
            result = score_domain(key, cfg)
        else:
            result = {**score_domain(key, cfg), 'target': key}
            if result['classification'] != UNKNOWN or result['registered_domain'] is not None:
                # Parser had no registered domain for this name: keep TV2's verdict.
                result.update(classification=UNKNOWN, score=None, features=None, signal_groups=[],
                              eligible=False, reasons=['no_registered_domain_in_event'],
                              registered_domain=None, dga_label=None)
        frames = [e['frame_number'] for e in events if isinstance(e.get('frame_number'), int)]
        stamps = [float(e['timestamp']) for e in events
                  if isinstance(e.get('timestamp'), (int, float)) and isfinite(e['timestamp'])]
        result['observations'] = {
            'query_count': len(events),
            'unique_qnames': len({e.get('qname') for e in events}),
            'sample_qnames': sorted({str(e.get('qname')) for e in events})[:3],
            'src_ips': sorted({str(e['src_ip']) for e in events if e.get('src_ip')}),
            'first_timestamp': min(stamps) if stamps else None,
            'first_frame': min(frames) if frames else None,
        }
        results.append(result)
    results.sort(key=lambda r: (_ORDER[r['classification']], -(r['score'] or 0), str(r['target'])))
    return results
