"""Deterministic string features of the registered-domain label. Pure rules, no model.

All features are computed on the ASCII (IDNA/Punycode) form of the DGA label, i.e. the
label in front of the public suffix (``example`` for ``www.example.co.uk``).
Raw precision is kept; rounding belongs to presentation.
"""
from collections import Counter
from math import log, log2

from app.dga.ngram_reference import BIGRAM_COUNTS, TRIGRAM_COUNTS
from app.dga.normalizer import normalize_domain

VOWELS = frozenset('aeiou')
_MAX_COUNT = {2: max(BIGRAM_COUNTS.values()), 3: max(TRIGRAM_COUNTS.values())}
_TABLES = {2: BIGRAM_COUNTS, 3: TRIGRAM_COUNTS}


def shannon_entropy(value: str) -> float:
    """H = -sum(p_i * log2(p_i)) in bits per character; 0.0 for '' and 1-char strings."""
    if not value:
        return 0.0
    n = len(value)
    return sum(-(c / n) * log2(c / n) for c in Counter(value).values())


def ngrams(label: str, n: int) -> list[str]:
    """Consecutive n-grams inside each '-'/'_' separated segment (separators never inside a gram)."""
    grams = []
    for segment in label.replace('_', '-').split('-'):
        grams.extend(segment[i:i + n] for i in range(len(segment) - n + 1))
    return grams


def ngram_rarity(gram: str) -> float:
    """r(g) = 1 - ln(1 + count(g)) / ln(1 + max_count) in [0, 1]; 1 = never seen.

    The +1 is the fixed add-one smoothing: an n-gram absent from the reference table
    (count 0) gets r = 1 instead of an undefined log(0); the most frequent n-gram gets 0.
    """
    n = len(gram)
    return 1.0 - log(1 + _TABLES[n].get(gram, 0)) / log(1 + _MAX_COUNT[n])


def _mean(values):
    return sum(values) / len(values) if values else None


def label_features(label: str) -> dict:
    """Features of an already normalized ASCII label."""
    chars = [c for c in label if c not in '-_']
    n = len(chars)
    digits = sum(c.isdigit() for c in chars)
    letters = n - digits
    bigrams, trigrams = ngrams(label, 2), ngrams(label, 3)
    bigram_rarity = _mean([ngram_rarity(g) for g in bigrams])
    trigram_rarity = _mean([ngram_rarity(g) for g in trigrams])
    grams = trigrams or bigrams
    return {
        'length': len(label),
        'entropy': shannon_entropy(''.join(chars)),
        'digit_ratio': digits / n if n else 0.0,
        # Over letters only, so a digit-heavy label does not look vowel-poor twice.
        'vowel_ratio': sum(c in VOWELS for c in chars) / letters if letters else None,
        'unique_character_ratio': len(set(chars)) / n if n else 0.0,
        'hyphen_count': label.count('-'),
        'bigram_rarity': bigram_rarity,
        'trigram_rarity': trigram_rarity,
        # Headline n-gram feature: trigram rarity, falling back to bigrams for 2-char segments.
        'ngram_score': trigram_rarity if trigrams else bigram_rarity,
        'unseen_ngram_ratio': (sum(_TABLES[len(g)].get(g, 0) == 0 for g in grams) / len(grams)
                               if grams else None),
    }


def extract_dga_features(qname: str) -> dict:
    """Normalize ``qname`` and return the label features plus the normalization context.

    ``features`` is None when the name cannot be scored (``status='unknown'``, see ``reason``).
    """
    norm = normalize_domain(qname)
    features = label_features(norm['dga_label']) if norm['status'] == 'ok' else None
    if features is not None:
        features['domain_length'] = len(norm['registered_domain'])
    return {**norm, 'features': features}
