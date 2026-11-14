"""Deterministic synthetic fixtures. Only writes files; never sends packets."""
import argparse,random,json
from pathlib import Path
from scapy.all import Ether,IP,IPv6,UDP,TCP,DNS,DNSQR,DNSRR,Raw,PcapWriter,PcapNgWriter,wrpcap
from app.tunneling.reporting import file_sha256,write_json
T0=1794000000

def query(name,i=0,stamp=None,ip='192.0.2.10',qtype='A',ipv6=False):
    net=IPv6(src='2001:db8::10',dst='2001:db8::53') if ipv6 else IP(src=ip,dst='192.0.2.53')
    p=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/net/UDP(sport=40000+i%20000,dport=53)/DNS(id=i%65536,rd=1,qd=DNSQR(qname=name,qtype=qtype))
    p.time=T0+i if stamp is None else stamp
    return p

def response(q,rcode=0):
    r=q.copy();r.src,qsrc=q.dst,q.src;r.dst=qsrc
    layer=IP if IP in r else IPv6
    r[layer].src,r[layer].dst=q[layer].dst,q[layer].src
    r[UDP].sport,r[UDP].dport=q[UDP].dport,q[UDP].sport
    r[DNS].qr=1;r[DNS].rcode=rcode;r.time=float(q.time)+0.1
    if rcode==0:r[DNS].an=DNSRR(rrname=q[DNS].qd[0].qname,type='A',ttl=60,rdata='198.51.100.9')
    return r

def save(path,packets):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    if packets: wrpcap(str(path),packets)
    else:
        with PcapWriter(str(path),linktype=1,sync=True) as w: w.write_header(None)

def scenario_packets(kind,rng,start,ip):
    # Intent labels originate here, before parsing/prediction; no encoded payload.
    count={'ordinary':8,'repeated':45,'cdn_short':40,'telemetry_long':35,
           'tunnel_dense':40,'tunnel_medium':20,'tunnel_slow':5}[kind]
    packets=[]
    for i in range(count):
        if kind=='ordinary': sub=['www','mail','api','docs'][i%4]
        elif kind=='repeated': sub='health'
        elif kind=='cdn_short': sub=f'edge{i:04d}'
        else: sub=''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(38))
        q=query(sub+'.example.com',i,stamp=start+i*min(1,50/count),ip=ip,
                qtype='TXT' if kind.startswith('tunnel') else 'A')
        packets.extend([q,response(q,3 if i%9==0 else 0)])
    return packets

def generate(base='samples'):
    base=Path(base);base.mkdir(parents=True,exist_ok=True)
    benign=[query(n,i,stamp=T0+i*4) for i,n in enumerate(['www.example.com','mail.example.com','www.example.org','docs.example.org'])]
    rng=random.Random(20261109)
    tunnel=[query(''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(38))+'.example.com',i,ip='192.0.2.11',qtype='TXT') for i in range(40)]
    save(base/'benign_dns.pcap',benign);save(base/'synthetic_tunnel_like_dns.pcap',tunnel)
    save(base/'query_response.pcap',[benign[0],response(benign[0])])
    save(base/'empty.pcap',[])
    nodns=Ether(src='02:00:00:00:00:01',dst='02:00:00:00:00:02')/IP(src='192.0.2.10',dst='198.51.100.1')/TCP(dport=443,flags='S')
    nodns.time=T0
    save(base/'no_dns.pcap',[nodns])
    save(base/'ipv6_dns.pcap',[query('www.example.org',ipv6=True)])
    with PcapNgWriter(str(base/'dns.pcapng')) as w:
        for p in benign: w.write(p)
    generated=[]
    for split,seed in [('dev',1211),('test',2011)]:
        rng=random.Random(seed);packets=[];labels=[]
        kinds=['ordinary','repeated','cdn_short','telemetry_long','tunnel_dense','tunnel_medium','tunnel_slow']
        for repetition in range(3):
            for kind in kinds:
                index=len(labels);start=T0+(index+(0 if split=='dev' else 100))*60
                ip='192.0.2.'+str(10+repetition)
                packets.extend(scenario_packets(kind,rng,start,ip))
                labels.append({'src_ip':ip,'registered_domain':'example.com','window_start':start,
                               'label':'tunnel' if kind.startswith('tunnel') else 'benign',
                               'scenario':kind,'provenance':'synthetic generator intent'})
        filename=f'{split}.pcap';save(base/filename,packets)
        write_json(base/f'{split}_manifest.json',{'dataset_type':'synthetic','split':split,
             'window_seconds':60,'description':'Offline fixtures; not real malware/exfiltration',
             'captures':[{'path':filename,'sha256':file_sha256(base/filename),'labels':labels}]})
        generated.append(filename)
    write_json(base/'provenance.json',{'type':'synthetic','generator':'scripts.make_demo_pcap',
        'seeds':{'demo':20261109,'dev':1211,'test':2011},
        'claims':'No real attack payload, no network transmission; labels reflect scenario intent.',
        'files':{p.name:file_sha256(p) for p in (base / name for name in (
            'benign_dns.pcap', 'synthetic_tunnel_like_dns.pcap', 'query_response.pcap',
            'empty.pcap', 'no_dns.pcap', 'ipv6_dns.pcap', 'dns.pcapng', *generated))}})
    print(f'Generated offline fixtures in {base}; all data SYNTHETIC.')

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output-dir',default='samples')
    generate(p.parse_args().output_dir)
