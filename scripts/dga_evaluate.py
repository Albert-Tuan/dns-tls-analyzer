"""Evaluate the frozen TV1 DGA config on the held-out TEST split (one row = one domain).

Writes the per-domain CSV, metrics JSON, a score-distribution SVG and the team metrics table
that keeps TV1 (domain) and TV2 (window) units in separate rows.
Run: python -m scripts.dga_evaluate
"""
import argparse
import csv
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from app.dga.detector import DgaConfig
from app.dga.evaluation import load_dataset, metrics, predict
from app.tunneling.reporting import write_json

CSV_COLUMNS = ['split', 'domain', 'dga_label', 'family', 'true_label', 'classification', 'predicted_label',
               'outcome', 'score', 'reasons', 'signal_groups', 'length', 'entropy', 'digit_ratio',
               'vowel_ratio', 'unique_character_ratio', 'ngram_score', 'bigram_rarity', 'trigram_rarity',
               'unseen_ngram_ratio', 'hyphen_count', 'domain_length']


def write_csv(path, rows, columns):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def per_family(rows):
    groups = defaultdict(list)
    for r in rows:
        groups[r['family']].append(r)
    out = {}
    for family, items in sorted(groups.items()):
        hits = sum(r['predicted_label'] == 'dga' for r in items)
        key = 'flag_rate' if family == 'legit' else 'recall'
        out[family] = {'n': len(items), 'flagged': hits, key: hits / len(items)}
    return out


def examples(rows, outcome, limit):
    picked = [r for r in rows if r['outcome'] == outcome]
    picked.sort(key=lambda r: (-(r['score'] or 0), r['domain']) if outcome == 'FP'
                else (r['family'], r['domain']))
    if outcome == 'FN':  # one per family first, so the examples show different failure modes
        seen, first = set(), []
        for r in picked:
            if r['family'] not in seen:
                seen.add(r['family'])
                first.append(r)
        picked = first
    keys = ['domain', 'family', 'score', 'reasons', 'length', 'entropy', 'digit_ratio', 'vowel_ratio', 'ngram_score']
    return [{k: r.get(k) for k in keys} for r in picked[:limit]]


def score_svg(rows, path):
    """Grouped bar chart of score counts (benign vs DGA) on the test split; no plotting library."""
    scores = sorted({r['score'] for r in rows if r['score'] is not None})
    counts = {lab: Counter(r['score'] for r in rows if r['true_label'] == lab and r['score'] is not None)
              for lab in ('benign', 'dga')}
    peak = max(max(c.values(), default=1) for c in counts.values())
    w, h, left, bottom, top = 640, 360, 60, 50, 40
    slot = (w - left - 20) / max(len(scores), 1)
    colors = {'benign': '#2f7ed8', 'dga': '#d9534f'}
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" font-family="sans-serif" font-size="12">',
             f'<rect width="{w}" height="{h}" fill="#ffffff"/>',
             '<text x="10" y="22" font-size="14">TV1 DGA: phân bố điểm trên tập test (mỗi cột = số domain)</text>']
    for i, s in enumerate(scores):
        for j, lab in enumerate(('benign', 'dga')):
            n = counts[lab][s]
            bh = (h - bottom - top) * n / peak
            x = left + i * slot + 4 + j * (slot - 8) / 2
            y = h - bottom - bh
            parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{(slot - 8) / 2:.1f}" height="{bh:.1f}" fill="{colors[lab]}"/>')
            parts.append(f'<text x="{x + (slot - 8) / 4:.1f}" y="{y - 3:.1f}" text-anchor="middle" font-size="10">{n}</text>')
        parts.append(f'<text x="{left + i * slot + slot / 2:.1f}" y="{h - bottom + 16}" text-anchor="middle">{s}</text>')
    parts.append(f'<line x1="{left}" y1="{h - bottom}" x2="{w - 20}" y2="{h - bottom}" stroke="#333"/>')
    parts.append(f'<text x="{(w + left) / 2:.0f}" y="{h - 12}" text-anchor="middle">heuristic risk score (không phải xác suất)</text>')
    for j, lab in enumerate(('benign', 'dga')):
        parts.append(f'<rect x="{w - 150}" y="{top + j * 18}" width="12" height="12" fill="{colors[lab]}"/>')
        parts.append(f'<text x="{w - 132}" y="{top + 10 + j * 18}">{lab}</text>')
    parts.append('</svg>')
    Path(path).write_text('\n'.join(parts) + '\n', encoding='utf-8')


def team_rows(dga_metrics, tv2_path):
    rows = [{'owner': 'TV1 Sony', 'detector': 'dga', 'unit': 'registered domain', 'split': 'test',
             'dataset_type': 'public labelled lists (UMUDGA)',
             **{k: dga_metrics[k] for k in ('n', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall', 'f1',
                                            'false_positive_rate')}}]
    if tv2_path and Path(tv2_path).is_file():
        tv2 = json.loads(Path(tv2_path).read_text(encoding='utf-8'))
        m = tv2['metrics']
        rows.append({'owner': 'TV2 Tuấn Anh', 'detector': 'dns_tunnel',
                     'unit': f"(capture, client IP, registered domain, {tv2['window_seconds']}s window)",
                     'split': tv2['split'], 'dataset_type': tv2['dataset_type'],
                     **{k: m[k] for k in ('n', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall', 'f1',
                                          'false_positive_rate')}})
    return rows


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--dataset', default='samples/dga/dga_dataset.csv')
    p.add_argument('--config', default='configs/dga_frozen.json')
    p.add_argument('--output', default='reports/dga_evaluation.csv')
    p.add_argument('--metrics', default='reports/dga_metrics.json')
    p.add_argument('--svg', default='reports/dga_score_distribution.svg')
    p.add_argument('--tv2-metrics', default='handoff/evidence/test_metrics.json')
    p.add_argument('--team-output', default='reports/team_metrics.csv')
    args = p.parse_args(argv)
    try:
        inputs = {Path(v).resolve() for v in (args.dataset, args.config, args.tv2_metrics)}
        outputs = [Path(v).resolve() for v in (args.output, args.metrics, args.svg, args.team_output)]
        if len(set(outputs)) != len(outputs) or inputs & set(outputs):
            raise ValueError('Output paths must be distinct and cannot overwrite inputs')
        cfg = DgaConfig.from_file(args.config)
        dev_rows = predict(load_dataset(args.dataset, 'dev'), cfg)
        test_rows = predict(load_dataset(args.dataset, 'test'), cfg)
        write_csv(args.output, test_rows, CSV_COLUMNS)
        test_metrics = metrics(test_rows)
        result = {
            'unit': 'one row = one registered domain, scored on its DGA label',
            'dataset': args.dataset,
            'dataset_sha256': hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
            'config': cfg.to_dict(), 'config_source': args.config,
            'dev_metrics': metrics(dev_rows), 'test_metrics': test_metrics,
            'test_per_family': per_family(test_rows),
            'test_false_positive_examples': examples(test_rows, 'FP', 10),
            'test_false_negative_examples': examples(test_rows, 'FN', 12),
            'test_reason_counts': {lab: dict(Counter(reason for r in test_rows if r['true_label'] == lab
                                                     for reason in r['reasons'].split(';') if reason).most_common())
                                   for lab in ('benign', 'dga')},
            'interpretation': 'score is a heuristic risk score, not a probability; benign = not flagged by rules',
        }
        write_json(args.metrics, result)
        score_svg(test_rows, args.svg)
        team = team_rows(test_metrics, args.tv2_metrics)
        write_csv(args.team_output, team, list(team[0]))
        m = test_metrics
        print(f"TV1 DGA test (n={m['n']} domains): TP={m['tp']} FP={m['fp']} TN={m['tn']} FN={m['fn']} "
              f"P={m['precision']:.4f} R={m['recall']:.4f} F1={m['f1']:.4f} FPR={m['false_positive_rate']:.4f}")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
