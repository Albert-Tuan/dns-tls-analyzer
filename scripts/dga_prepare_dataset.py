"""Build the labelled TV1 domain dataset (dev/test) from the public UMUDGA lists.

Order of operations (fixed before any detector output is looked at):
1. download each list in samples/dga/sources.json and verify its SHA256;
2. normalize with the shared PSL helper; drop names that cannot be scored (counted);
   drop DGA entries whose generated string sits below a shared registered domain
   (dynamic-DNS hosting such as ``x1y2.ddns.net``): the scored label would be ``ddns``;
3. de-duplicate by registered domain, drop registered domains seen with both labels;
4. de-duplicate by DGA label (``google.com``/``google.co.in`` share one label), so identical
   feature vectors can never sit in both splits;
5. benign: every remaining domain; DGA: at most N per family, chosen by SHA256 order (no seed);
6. split by SHA256 of the DGA label: dev if digest mod 100 < dev_percent, else test.
Only step 1 needs the network. Run: python -m scripts.dga_prepare_dataset
"""
import argparse
import csv
import hashlib
import json
import sys
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

from app.dga.normalizer import normalize_domain
from app.tunneling.reporting import write_json

ROOT = Path(__file__).resolve().parents[1]


def _digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def fetch(entry, raw_dir):
    path = Path(raw_dir) / f"{entry['family']}_{entry['file']}"
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(entry['url'], headers={'User-Agent': 'dns-tls-analyzer-tv1'})
        with urllib.request.urlopen(request, timeout=120) as response:
            path.write_bytes(response.read())
    if hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
        raise ValueError(f'SHA256 mismatch for {path}')
    return path


def build(sources, raw_dir, per_family, dev_percent):
    stats = {'raw_lines': Counter(), 'dropped_unscorable': Counter(), 'dropped_duplicate_domain': Counter(),
             'dropped_dga_in_subdomain': Counter(), 'dropped_label_conflict': 0, 'dropped_duplicate_label': Counter(), 'dropped_family_cap': Counter()}
    by_domain = {}
    labels_seen = defaultdict(set)
    for entry in sources['files']:
        family, label = entry['family'], entry['label']
        for line in fetch(entry, raw_dir).read_text(encoding='utf-8', errors='replace').splitlines():
            name = line.strip()
            if not name:
                continue
            stats['raw_lines'][family] += 1
            norm = normalize_domain(name)
            if norm['status'] != 'ok':
                stats['dropped_unscorable'][norm['reason']] += 1
                continue
            if label == 'dga' and norm['subdomain']:
                stats['dropped_dga_in_subdomain'][family] += 1
                continue
            domain = norm['registered_domain']
            labels_seen[domain].add(label)
            if domain in by_domain:
                stats['dropped_duplicate_domain'][family] += 1
                continue
            by_domain[domain] = {'domain': domain, 'dga_label': norm['dga_label'], 'label': label,
                                 'family': family, 'source_name': name}
    conflicts = {d for d, seen in labels_seen.items() if len(seen) > 1}
    stats['dropped_label_conflict'] = len(conflicts)
    rows, seen_labels = [], {}
    for domain in sorted(by_domain, key=_digest):
        row = by_domain[domain]
        if domain in conflicts:
            continue
        previous = seen_labels.get(row['dga_label'])
        if previous is not None:
            stats['dropped_duplicate_label'][row['family']] += 1
            if previous != row['label']:
                stats['dropped_label_conflict'] += 1
            continue
        seen_labels[row['dga_label']] = row['label']
        rows.append(row)
    kept, per_family_count = [], Counter()
    for row in rows:  # already in SHA256 order of the registered domain
        if row['label'] == 'dga' and per_family_count[row['family']] >= per_family:
            stats['dropped_family_cap'][row['family']] += 1
            continue
        per_family_count[row['family']] += 1
        row['split'] = 'dev' if int(_digest(row['dga_label']), 16) % 100 < dev_percent else 'test'
        kept.append(row)
    kept.sort(key=lambda r: (r['split'], r['label'], r['family'], r['domain']))
    counts = Counter((r['split'], r['label']) for r in kept)
    summary = {
        'unit': 'one row = one registered domain (scored on its DGA label)',
        'per_family_cap': per_family, 'dev_percent': dev_percent,
        'counts': {f'{s}_{l}': counts[(s, l)] for s in ('dev', 'test') for l in ('benign', 'dga')},
        'total': len(kept),
        'families_dga': len({r['family'] for r in kept if r['label'] == 'dga'}),
        'per_family_kept': dict(sorted(per_family_count.items())),
        **{k: (dict(sorted(v.items())) if isinstance(v, Counter) else v) for k, v in stats.items()},
    }
    return kept, summary


def main(argv=None):
    p = argparse.ArgumentParser(description='Prepare the labelled TV1 DGA dataset')
    p.add_argument('--sources', default='samples/dga/sources.json')
    p.add_argument('--raw-dir', default='reports/dga_raw/lists')
    p.add_argument('--output', default='samples/dga/dga_dataset.csv')
    p.add_argument('--summary', default='samples/dga/dataset_summary.json')
    p.add_argument('--per-family', type=int, default=200)
    p.add_argument('--dev-percent', type=int, default=30)
    args = p.parse_args(argv)
    try:
        if not 0 < args.dev_percent < 100 or args.per_family < 1:
            raise ValueError('dev-percent must be in 1..99 and per-family >= 1')
        sources = json.loads(Path(args.sources).read_text(encoding='utf-8'))
        rows, summary = build(sources, args.raw_dir, args.per_family, args.dev_percent)
        summary['sources_sha256'] = hashlib.sha256(Path(args.sources).read_bytes()).hexdigest()
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open('w', encoding='utf-8', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['domain', 'dga_label', 'label', 'family', 'split', 'source_name'])
            writer.writeheader()
            writer.writerows(rows)
        summary['dataset_sha256'] = hashlib.sha256(out.read_bytes()).hexdigest()
        write_json(args.summary, summary)
        print(json.dumps(summary['counts']), f"families={summary['families_dga']}")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
