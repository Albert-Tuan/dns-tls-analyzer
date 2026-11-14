import argparse,csv,sys
from pathlib import Path
from app.tunneling.detector import DetectorConfig
from app.tunneling.evaluation import load_dataset,evaluate_loaded
from app.tunneling.reporting import write_json

def main(argv=None):
    p=argparse.ArgumentParser(description='Evaluate strict, fully labelled windows from PCAP manifest')
    p.add_argument('--manifest',required=True);p.add_argument('--config');p.add_argument('--output',required=True)
    args=p.parse_args(argv)
    try:
        cfg=DetectorConfig.from_file(args.config) if args.config else DetectorConfig()
        manifest,loaded=load_dataset(args.manifest)
        out=Path(args.output)
        if out.suffix.lower()!='.json': raise ValueError('Evaluation output must end in .json (CSV is a companion file)')
        protected={Path(args.manifest).resolve()}
        protected.update((Path(args.manifest).parent/c['path']).resolve() for c in manifest['captures'])
        if args.config: protected.add(Path(args.config).resolve())
        if out.resolve() in protected or out.with_suffix('.csv').resolve() in protected:
            raise ValueError('Outputs cannot overwrite dataset/config inputs')
        result=evaluate_loaded(manifest,loaded,cfg);write_json(out,result)
        with out.with_suffix('.csv').open('w',newline='',encoding='utf-8') as f:
            writer=csv.DictWriter(f,fieldnames=list(result['rows'][0]));writer.writeheader();writer.writerows(result['rows'])
        print(result['dataset_type'],result['split'],result['metrics']);return 0
    except (ValueError,KeyError,TypeError,OSError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);return 2
if __name__=='__main__': raise SystemExit(main())
