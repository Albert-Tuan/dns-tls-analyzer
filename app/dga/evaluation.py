"""Domain-level evaluation for TV1. One row = one registered domain (not a window, not a packet)."""
import csv
from dataclasses import replace
from pathlib import Path

from app.dga.detector import SUSPICIOUS, UNKNOWN, WEIGHT_SETS, DgaConfig, score_domain
from app.dga.features import extract_dga_features

THRESHOLD_FEATURES = {'ngram_score': 'high', 'entropy': 'high', 'digit_ratio': 'high',
                      'vowel_ratio': 'low', 'length': 'high'}
PERCENTILES = (90, 95, 99)
ALERT_SCORES = (40, 50, 60, 70, 80)


def load_dataset(path, split):
    """Rows of samples/dga/dga_dataset.csv for one split; labels are benign/dga."""
    if split not in ('dev', 'test'):
        raise ValueError('split must be dev or test')
    with Path(path).open(encoding='utf-8', newline='') as f:
        rows = [r for r in csv.DictReader(f) if r['split'] == split]
    if not rows or any(r['label'] not in ('benign', 'dga') for r in rows):
        raise ValueError(f'No valid labelled rows for split {split}')
    return rows


def nearest_rank(values, percentile):
    """Nearest-rank percentile, deterministic, no interpolation."""
    ordered = sorted(values)
    rank = max(1, -(-percentile * len(ordered) // 100))
    return ordered[rank - 1]


def calibrate(dev_rows, percentile, base=None):
    """Feature thresholds = p-th (or (100-p)-th for 'low') percentile of DEV benign labels."""
    cfg = base or DgaConfig()
    benign = [extract_dga_features(r['domain'])['features'] for r in dev_rows if r['label'] == 'benign']
    benign = [f for f in benign if f is not None and f['length'] >= cfg.min_label_length]
    if not benign:
        raise ValueError('No eligible benign dev rows for calibration')
    thresholds = {}
    for feature, direction in THRESHOLD_FEATURES.items():
        values = [f[feature] for f in benign if f[feature] is not None]
        p = percentile if direction == 'high' else 100 - percentile
        thresholds[f'{feature}_threshold'] = round(float(nearest_rank(values, p)), 6)
    return replace(cfg, calibration_percentile=percentile, **thresholds)


def predict(rows, config):
    out = []
    for r in rows:
        result = score_domain(r['domain'], config)
        out.append({'domain': r['domain'], 'dga_label': r['dga_label'], 'family': r['family'],
                    'split': r['split'], 'true_label': r['label'], 'classification': result['classification'],
                    'predicted_label': 'dga' if result['classification'] == SUSPICIOUS else 'benign',
                    'score': result['score'], 'reasons': ';'.join(result['reasons']),
                    'signal_groups': ';'.join(result['signal_groups']), **(result['features'] or {})})
    for row in out:
        truth, pred = row['true_label'] == 'dga', row['predicted_label'] == 'dga'
        row['outcome'] = ('TP' if pred else 'FN') if truth else ('FP' if pred else 'TN')
    return out


def metrics(rows):
    count = {k: sum(r['outcome'] == k for r in rows) for k in ('TP', 'FP', 'TN', 'FN')}
    tp, fp, tn, fn = count['TP'], count['FP'], count['TN'], count['FN']
    ratio = lambda a, b: a / b if b else None
    return {'unit': 'registered domain', 'n': len(rows),
            'n_benign': fp + tn, 'n_dga': tp + fn,
            'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'unknown': sum(r['classification'] == UNKNOWN for r in rows),
            'precision': ratio(tp, tp + fp), 'recall': ratio(tp, tp + fn),
            'f1': ratio(2 * tp, 2 * tp + fp + fn), 'false_positive_rate': ratio(fp, fp + tn),
            'accuracy': ratio(tp + tn, len(rows))}


def candidate_grid(dev_rows):
    """Declared grid: percentile x weight set x alert score. Thresholds come from dev only."""
    for percentile in PERCENTILES:
        calibrated = calibrate(dev_rows, percentile)
        for weight_set in WEIGHT_SETS:
            for alert in ALERT_SCORES:
                yield replace(calibrated, weight_set=weight_set, alert_score=alert)
