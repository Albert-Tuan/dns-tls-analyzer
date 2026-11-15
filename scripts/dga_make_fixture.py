"""Labelled DNS PCAP for checking TV1 scores/reasons through the shared CLI. Writes files only.

Domains are taken from the TEST split without looking at detector output: the first N benign
and first N DGA rows (distinct families) in SHA256 order of the registered domain. Each domain
gets a query + response; one DGA domain is queried under three subdomains to show grouping.
Run: python -m scripts.dga_make_fixture
"""
import argparse
import csv
import hashlib
from pathlib import Path

from scripts.make_demo_pcap import T0, query, response, save
from app.tunneling.reporting import file_sha256, write_json


def pick(dataset, per_label):
    with Path(dataset).open(encoding='utf-8', newline='') as f:
        rows = [r for r in csv.DictReader(f) if r['split'] == 'test']
    rows.sort(key=lambda r: hashlib.sha256(r['domain'].encode()).hexdigest())
    benign = [r for r in rows if r['label'] == 'benign'][:per_label]
    dga, families = [], set()
    for r in rows:
        if r['label'] == 'dga' and r['family'] not in families:
            families.add(r['family'])
            dga.append(r)
        if len(dga) == per_label:
            break
    return benign + dga


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--dataset', default='samples/dga/dga_dataset.csv')
    p.add_argument('--pcap', default='samples/dga_labeled_dns.pcap')
    p.add_argument('--manifest', default='samples/dga/fixture_manifest.json')
    p.add_argument('--per-label', type=int, default=5)
    args = p.parse_args(argv)
    chosen = pick(args.dataset, args.per_label)
    packets, i = [], 0
    for row in chosen:
        names = [f"www.{row['domain']}"]
        if row is chosen[-1]:
            names = [f"{sub}.{row['domain']}" for sub in ('a', 'b', 'c')]
        for name in names:
            q = query(name, i, stamp=T0 + i, ip='192.0.2.20')
            packets.extend([q, response(q)])
            i += 1
    save(args.pcap, packets)
    write_json(args.manifest, {
        'dataset_type': 'public labelled lists (UMUDGA), test split; packets synthetic (Scapy, offline)',
        'pcap': Path(args.pcap).name, 'sha256': file_sha256(args.pcap),
        'expected_dns_queries': i, 'expected_domains': len(chosen),
        'labels': [{'registered_domain': r['domain'], 'label': r['label'], 'family': r['family']} for r in chosen]})
    print(f'Wrote {args.pcap}: {i} queries, {len(chosen)} labelled domains')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
