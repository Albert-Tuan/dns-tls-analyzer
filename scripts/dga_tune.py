"""Select the TV1 DGA configuration on the DEV split only. Never reads test rows.

Grid (declared before tuning): calibration percentile {90,95,99} x weight set
{equal, ngram_weighted} x alert score {40,50,60,70,80}. Objective: max F1, ties -> fewer FP,
then grid order. Run: python -m scripts.dga_tune
"""
import argparse
import hashlib
import sys
from pathlib import Path

from app.dga.evaluation import candidate_grid, load_dataset, metrics, predict
from app.tunneling.reporting import write_json


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--dataset', default='samples/dga/dga_dataset.csv')
    p.add_argument('--output', default='configs/dga_frozen.json')
    args = p.parse_args(argv)
    try:
        out = Path(args.output)
        if out.resolve() == Path(args.dataset).resolve():
            raise ValueError('Output cannot overwrite the dataset')
        dev = load_dataset(args.dataset, 'dev')
        candidates = []
        for cfg in candidate_grid(dev):
            candidates.append({'config': cfg.to_dict(), 'metrics': metrics(predict(dev, cfg))})
        best = max(candidates, key=lambda c: (c['metrics']['f1'] or 0, -c['metrics']['fp']))
        write_json(out, best['config'])
        write_json(out.with_suffix('.selection.json'), {
            'split': 'dev', 'unit': 'registered domain', 'dataset': args.dataset,
            'dataset_sha256': hashlib.sha256(Path(args.dataset).read_bytes()).hexdigest(),
            'objective': 'max F1 then min FP; stable grid order',
            'threshold_rule': 'feature threshold = nearest-rank percentile of dev benign labels '
                              '(length >= min_label_length); low-direction features use 100-p',
            'candidates': candidates, 'selected': best})
        m = best['metrics']
        print(f"Frozen DGA config (dev only): {out}; dev F1={m['f1']:.4f} P={m['precision']:.4f} "
              f"R={m['recall']:.4f} FP={m['fp']}")
        return 0
    except (OSError, ValueError, KeyError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
