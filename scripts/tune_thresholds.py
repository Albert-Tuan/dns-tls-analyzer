"""Small declared grid on DEV only. Never reads the held-out test manifest."""
import argparse,sys
from pathlib import Path
from dataclasses import replace
from app.tunneling.detector import DetectorConfig
from app.tunneling.evaluation import load_dataset,evaluate_loaded
from app.tunneling.reporting import write_json,file_sha256

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--manifest',required=True);p.add_argument('--output',required=True)
    a=p.parse_args(argv)
    try:
        manifest,loaded=load_dataset(a.manifest)
        if manifest['split']!='dev':raise ValueError('Tuning requires split=dev; test is forbidden')
        out=Path(a.output)
        protected={Path(a.manifest).resolve()}
        protected.update((Path(a.manifest).parent/c['path']).resolve() for c in manifest['captures'])
        if out.resolve() in protected or out.with_suffix('.selection.json').resolve() in protected:
            raise ValueError('Output cannot overwrite dataset inputs')
        candidates=[]
        for score in (60,75,100):
            for minimum in (10,20):
                cfg=replace(DetectorConfig(),alert_score=score,min_queries=minimum,window_seconds=manifest['window_seconds'])
                result=evaluate_loaded(manifest,loaded,cfg)
                candidates.append({'config':cfg.to_dict(),'metrics':result['metrics']})
        # Deterministic ties: prefer fewer FP, then earlier (simpler) grid candidate.
        best=max(candidates,key=lambda c:(c['metrics']['f1'] or 0,-c['metrics']['fp']))
        write_json(out,best['config'])
        write_json(out.with_suffix('.selection.json'),{'split':'dev','dataset_type':manifest['dataset_type'],
            'manifest_sha256':file_sha256(a.manifest),'objective':'max F1 then min FP; stable grid order',
            'candidates':candidates,'selected':best})
        print('Frozen development config:',out);return 0
    except (OSError,ValueError,KeyError,TypeError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
