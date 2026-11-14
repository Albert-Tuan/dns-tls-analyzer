"""Standalone CLI; exits 2 for controlled input/config errors."""
import argparse,json,sys
from pathlib import Path
from app.tunneling.detector import DetectorConfig
from app.tunneling.reporting import analyze_pcap,write_json,write_windows_csv

def main(argv=None):
    p=argparse.ArgumentParser(description='TV2 offline UDP/53 DNS analysis')
    p.add_argument('--pcap',required=True);p.add_argument('--output',required=True)
    p.add_argument('--config');p.add_argument('--csv');p.add_argument('--events-output')
    args=p.parse_args(argv)
    try:
        paths=[Path(v).resolve() for v in (args.output,args.csv,args.events_output) if v]
        inputs=[Path(v).resolve() for v in (args.pcap,args.config) if v]
        if len(paths)!=len(set(paths)) or any(v in inputs for v in paths):
            raise ValueError('Output paths must be distinct and cannot overwrite inputs')
        cfg=DetectorConfig.from_file(args.config) if args.config else DetectorConfig()
        report=analyze_pcap(args.pcap,cfg)
        write_json(args.output,report)
        if args.csv: write_windows_csv(args.csv,report['dns_windows'])
        if args.events_output: write_json(args.events_output,report['dns_events'])
        print(json.dumps(report['summary'],ensure_ascii=False))
        for warning in report['metadata']['warnings']: print(f'WARNING: {warning}',file=sys.stderr)
        print(f'Saved: {args.output}')
        return 0
    except (OSError,ValueError,TypeError,KeyError) as exc:
        print(f'ERROR: {exc}',file=sys.stderr);return 2
if __name__=='__main__': raise SystemExit(main())
