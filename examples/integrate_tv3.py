"""Run from project root: python -m examples.integrate_tv3 --pcap ... --output ...

This is a TV2 fragment example, not a replacement for the group's app/main.py.
"""
from app.dns.parser import parse_dns_pcap_detailed
from app.tunneling.detector import detect_tunnels,DetectorConfig
from app.tunneling.reporting import write_json

def build_tv2_fragment(pcap_path,config=None):
    parsed=parse_dns_pcap_detailed(pcap_path)
    events=parsed.events                 # TV1 must consume this same list
    findings=detect_tunnels(events,config)
    fragment={'dns_events_summary':parsed.stats,'dns_tunnel_findings':findings,
              'warnings':parsed.warnings}
    return events,fragment

def main():
    import argparse
    p=argparse.ArgumentParser();p.add_argument('--pcap',required=True);p.add_argument('--output',required=True)
    p.add_argument('--config');a=p.parse_args()
    from pathlib import Path
    if Path(a.output).resolve() in {Path(v).resolve() for v in (a.pcap,a.config) if v}:
        p.error('Output cannot overwrite input')
    cfg=DetectorConfig.from_file(a.config) if a.config else DetectorConfig()
    events,fragment=build_tv2_fragment(a.pcap,cfg)
    write_json(a.output,{'dns_events':events,**fragment})
    print(f'TV2 integration fragment: {len(events)} events, {len(fragment["dns_tunnel_findings"])} alerts')
if __name__=='__main__': main()
