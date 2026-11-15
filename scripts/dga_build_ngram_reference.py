"""Regenerate app/dga/ngram_reference.py from the public UMUDGA English n-gram tables.

Only this one-off build step needs the network; the detector reads the generated, fixed
table offline. Downloads are verified against the SHA256 published by Mendeley Data.
Run: python -m scripts.dga_build_ngram_reference [--raw-dir reports/dga_raw]
"""
import argparse
import csv
import hashlib
import sys
import urllib.request
from pathlib import Path

DATASET = 'UMUDGA - University of Murcia Domain Generation Algorithm Dataset, v1'
DOI = '10.17632/y8ph45msv8.1'
LICENSE = 'MIT (Mendeley Data record licence field)'
CORPUS = 'English word list of the Leipzig Corpora Collection (UMUDGA "Language Data/English/nGrams")'
SOURCES = {
    2: ('https://data.mendeley.com/public-files/datasets/y8ph45msv8/files/'
        'e79acec1-ff7a-4a5b-ade4-5bb3d5e196a6/file_downloaded',
        '8cd48075f6c39bccb4183df21fea6f6f10be4ebf47356fe9957ceb386506e411'),
    3: ('https://data.mendeley.com/public-files/datasets/y8ph45msv8/files/'
        '0facb806-8d03-4d68-8de5-083652d5d785/file_downloaded',
        'ab4af22c5e9ccb5eade8a718e6a765ebdf1342cd594e17728075ac99873ccf2f'),
}
TARGET = Path(__file__).resolve().parents[1] / 'app' / 'dga' / 'ngram_reference.py'


def fetch(url, sha, path):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(url, headers={'User-Agent': 'dns-tls-analyzer-tv1'})
        with urllib.request.urlopen(request, timeout=120) as response:
            path.write_bytes(response.read())
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != sha:
        raise ValueError(f'SHA256 mismatch for {path}: {digest}')
    return path


def read_counts(path, n):
    counts = {}
    with path.open(encoding='utf-8', newline='') as f:
        for row in csv.DictReader(f, delimiter='\t'):
            token, count = row['Token'], int(row['Count'])
            if len(token) != n:
                raise ValueError(f'Unexpected token {token!r} in {path}')
            if count > 0:
                counts[token] = count
    return dict(sorted(counts.items()))


def render(tables):
    def literal(counts):
        items = [f'{k!r}: {v}' for k, v in counts.items()]
        rows = [', '.join(items[i:i + 8]) for i in range(0, len(items), 8)]
        return '{\n    ' + ',\n    '.join(rows) + ',\n}'
    return f'''"""Fixed n-gram reference table for TV1 DGA rarity. GENERATED - do not edit by hand.

Source: {DATASET}, DOI {DOI}, licence {LICENSE}.
Corpus: {CORPUS}.
Alphabet: a-z and 0-9 (36 symbols). Only n-grams with count > 0 are stored; every other
n-gram over the alphabet has count 0 and is handled by the smoothing in app/dga/features.py.
This is a static frequency table (reference statistics), not a trained model.
Regenerate with: python -m scripts.dga_build_ngram_reference
"""

SOURCE = {{'dataset': {DATASET!r}, 'doi': {DOI!r}, 'licence': {LICENSE!r}, 'corpus': {CORPUS!r},
          'bigram_sha256': {SOURCES[2][1]!r},
          'trigram_sha256': {SOURCES[3][1]!r}}}

ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'

BIGRAM_COUNTS = {literal(tables[2])}

TRIGRAM_COUNTS = {literal(tables[3])}
'''


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--raw-dir', default='reports/dga_raw/ngrams')
    args = p.parse_args(argv)
    try:
        tables = {n: read_counts(fetch(url, sha, Path(args.raw_dir) / f'{n}.csv'), n)
                  for n, (url, sha) in SOURCES.items()}
        TARGET.write_text(render(tables), encoding='utf-8')
        print(f'Wrote {TARGET}: {len(tables[2])} bigrams, {len(tables[3])} trigrams')
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
