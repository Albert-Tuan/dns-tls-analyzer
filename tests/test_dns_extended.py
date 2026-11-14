import json,struct,socket
import pytest
from scapy.all import Ether,IP,UDP,TCP,DNS,DNSQR,Raw,PcapNgWriter
from app.dns.parser import parse_dns_pcap,parse_dns_pcap_detailed
from app.dns.capture_validation import CaptureError,validate_capture
from app.dns.normalization import normalize_qname
from scripts.make_demo_pcap import query,response,save

def parse(tmp_path,packets):
    p=tmp_path/'case.pcap';save(p,packets);return parse_dns_pcap_detailed(str(p))

@pytest.mark.parametrize('name,domain,sub',[
    ('Ab.Example.Co.Uk.','example.co.uk','ab'),('ab.example.com.vn','example.com.vn','ab'),
    ('foo.example.test','example.test','foo'),('host.unknownsuffixzz',None,None),
    ('localhost',None,None),('1.0.0.127.in-addr.arpa',None,None),
    ('_sip._tcp.example.com','example.com','_sip._tcp'),('www.bücher.de','xn--bcher-kva.de','www'),
    ('foo.blogspot.com','blogspot.com','foo')])
def test_normalization_policy(name,domain,sub):
    n=normalize_qname(name);assert n['registered_domain']==domain;assert n['subdomain']==sub

@pytest.mark.parametrize('name',['','bad..com','bad.example.com..','a'*64+'.com',' a.com','192.0.2.1',b'\xff.com','a/'+'example.com'])
def test_invalid_names(name):assert normalize_qname(name) is None

def test_offline_psl(monkeypatch):
    import app.dns.normalization as n
    n._extractor.cache_clear()
    def forbidden(*a,**kw):raise AssertionError('Network forbidden')
    monkeypatch.setattr(socket,'socket',forbidden)
    assert n.normalize_qname('x.example.co.uk')['registered_domain']=='example.co.uk'

def test_ipv6(tmp_path):
    result=parse(tmp_path,[query('www.example.com',ipv6=True)])
    assert result.events[0]['src_ip']=='2001:db8::10'

def test_responses_do_not_double_count(tmp_path):
    q=query('www.example.com');r=response(q,3)
    result=parse(tmp_path,[q,r]);assert result.stats['dns_queries']==1
    assert result.stats['dns_responses']==1
    assert result.events[0]['rcode'] is None;assert result.events[1]['rcode']=='NXDOMAIN'

def test_unknown_suffix_retained(tmp_path):
    r=parse(tmp_path,[query('x.unknownsuffixzz')])
    assert len(r.events)==1 and r.events[0]['registered_domain'] is None
    assert r.warnings[0]['code']=='unknown_suffix_or_reverse_name'

def test_multiple_questions_explicit_skip(tmp_path):
    q=query('x.example.com');q[DNS].qd=[DNSQR(qname='a.example.com'),DNSQR(qname='b.example.com')]
    r=parse(tmp_path,[q]);assert not r.events
    assert r.warnings[0]['code']=='unsupported_question_count'

def test_malformed_dns_warning(tmp_path):
    q=query('x.example.com');q[UDP].remove_payload();q[UDP].add_payload(Raw(b'\x00\x01bad'))
    r=parse(tmp_path,[q]);assert not r.events
    assert r.warnings[0]['code']=='malformed_dns_packet'

def test_tcp_unsupported_warning(tmp_path):
    q=query('x.example.com');q[IP].remove_payload();q[IP].add_payload(TCP(sport=40000,dport=53))
    r=parse(tmp_path,[q]);assert not r.events
    assert r.warnings[0]['code']=='tcp_dns_not_supported'

def test_fragment_unsupported_warning(tmp_path):
    q=query('x.example.com');q[IP].flags='MF'
    r=parse(tmp_path,[q]);assert not r.events
    assert r.warnings[0]['code']=='ip_fragment_not_reassembled'

def test_truncated_udp_warning(tmp_path):
    q=query('x.example.com');q[UDP].len=999
    r=parse(tmp_path,[q]);assert not r.events
    assert r.warnings[0]['code']=='malformed_dns_packet'

def test_empty_valid_capture(tmp_path):assert parse(tmp_path,[]).events==[]

@pytest.mark.parametrize('blob',[b'',b'not pcap',b'\xd4\xc3\xb2\xa1',b'\x0a\x0d\x0d\x0a'])
def test_invalid_capture(tmp_path,blob):
    p=tmp_path/'bad.pcap';p.write_bytes(blob)
    with pytest.raises(CaptureError):parse_dns_pcap(str(p))

@pytest.mark.parametrize('cut',[1,5,20])
def test_truncated_record(tmp_path,cut):
    p=tmp_path/'case.pcap';save(p,[query('www.example.com')]);p.write_bytes(p.read_bytes()[:-cut])
    with pytest.raises(CaptureError):parse_dns_pcap(str(p))

def test_pcapng_and_corrupt_trailer(tmp_path):
    p=tmp_path/'case.pcapng'
    with PcapNgWriter(str(p)) as w:w.write(query('www.example.com'))
    assert len(parse_dns_pcap(str(p)))==1
    raw=p.read_bytes();p.write_bytes(raw[:-4]+b'\x00'*4)
    with pytest.raises(CaptureError):parse_dns_pcap(str(p))

def test_event_limit(tmp_path):
    p=tmp_path/'case.pcap';save(p,[query('a.example.com'),query('b.example.com',1)])
    with pytest.raises(CaptureError,match='limit'):parse_dns_pcap_detailed(str(p),max_events=1)

def test_wrong_port_ignored(tmp_path):
    q=query('a.example.com');q[UDP].dport=5353
    r=parse(tmp_path,[q]);assert not r.events

def test_extended_rcode(tmp_path):
    import dns.message,dns.rcode
    q=query('a.example.com');m=dns.message.make_query('a.example.com','A',use_edns=0)
    r=dns.message.make_response(m);r.set_rcode(dns.rcode.BADVERS)
    q[UDP].remove_payload();q[UDP].add_payload(Raw(r.to_wire()))
    result=parse(tmp_path,[q]);assert result.events[0]['rcode']=='BADVERS'


def test_dns_with_ethernet_trailer(tmp_path):
    original = query('www.example.com')
    padded = Ether(bytes(original) + bytes(8))
    result = parse(tmp_path, [padded])
    assert result.warnings == []
    assert len(result.events) == 1
    assert result.events[0]['qname'] == 'www.example.com'
    assert result.events[0]['packet_length'] == len(padded)


def test_tls_clienthello_only(tmp_path):
    from pathlib import Path
    from scapy.all import TCP, rdpcap
    from app.tunneling.detector import detect_tunnels

    capture = Path(__file__).resolve().parents[1] / 'samples' / 'tls_clienthello_only.pcap'
    frame, = rdpcap(str(capture))
    record = bytes(frame[TCP].payload)
    assert int(frame[TCP].dport) == 443
    assert record[0] == 22 and record[5] == 1  # TLS handshake, ClientHello
    assert int.from_bytes(record[3:5], 'big') == len(record) - 5
    parsed = parse_dns_pcap_detailed(str(capture))
    assert parsed.stats['total_packets'] == 1
    assert parsed.events == []
    assert detect_tunnels(parsed.events) == []
