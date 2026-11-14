"""TV2 report fragment; does not claim that DGA/TLS analysis ran."""
from datetime import datetime,timezone
from dataclasses import asdict
from pathlib import Path
from hashlib import sha256
import csv,json,os,tempfile
from .detector import DetectorConfig,analyze_windows
from app.dns.parser import parse_dns_pcap_detailed

def file_sha256(path):
    h=sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def write_json(path,data):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    text=json.dumps(data,ensure_ascii=False,indent=2,allow_nan=False)+'\n'
    fd,tmp=tempfile.mkstemp(prefix=path.name+'.',dir=path.parent)
    try:
        with os.fdopen(fd,'w',encoding='utf-8') as f: f.write(text)
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)

def analyze_pcap(path,config=None):
    cfg=config or DetectorConfig()
    parsed=parse_dns_pcap_detailed(str(path)); windows=analyze_windows(parsed.events,cfg)
    alerts=[w for w in windows if w['classification']=='suspected_dns_tunnel']
    return {'metadata':{'schema_version':'tv2-1.0','input_file':str(path),
        'input_sha256':file_sha256(path),'generated_at':datetime.now(timezone.utc).isoformat(),
        'scope':'offline classic DNS UDP/53; TV2 only','total_packets':parsed.stats['total_packets'],
        'warnings':parsed.warnings,'config':asdict(cfg),
        'limitations':['TCP DNS and IP fragment reassembly unsupported','DoH/DoT payload not inspected',
                       'single DNS question per packet only','no query-response correlation; NXDOMAIN ratio null',
                       'heuristic score is not probability','events retained in memory; default limit 1000000']},
        'summary':{'dns_events':len(parsed.events),'dns_queries':parsed.stats['dns_queries'],
                   'dns_responses':parsed.stats['dns_responses'],'dns_windows':len(windows),
                   'dns_tunnel_alerts':len(alerts)},
        'dns_events_summary':parsed.stats,'dns_events':parsed.events,
        'dns_tunnel_findings':alerts,'dns_windows':windows}

def write_windows_csv(path,windows):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    columns=['src_ip','registered_domain','window_start','window_seconds','classification','score','query_count',
             'unique_subdomain_ratio','avg_subdomain_length','avg_subdomain_entropy','txt_ratio','reasons']
    with path.open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=columns);writer.writeheader()
        for w in windows:
            flat={**w,**w['features'],'reasons':';'.join(w['reasons'])}
            writer.writerow({c:flat[c] for c in columns})
