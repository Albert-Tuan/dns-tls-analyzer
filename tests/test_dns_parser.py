import pytest

import scapy
import tldextract
import dns

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, UDP, wrpcap
from app.dns.parser import parse_dns_pcap
from app.dns.normalization import normalize_qname


def test_normalize_multilabel_suffix_offline():
    n = normalize_qname("Foo.Example.CO.UK.")
    assert n["qname"] == "foo.example.co.uk"
    assert n["registered_domain"] == "example.co.uk"
    assert n["subdomain"] == "foo"


def test_invalid_qname():
    assert normalize_qname("") is None
    assert normalize_qname("invalid..example.com") is None


def test_parser_query_and_response(tmp_path):
    q = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(sport=53001, dport=53)/DNS(
        id=1234, qr=0, qd=DNSQR(qname="www.example.com", qtype="A"))
    r = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.53", dst="192.0.2.10")/UDP(sport=53, dport=53001)/DNS(
        id=1234, qr=1, rcode=0, qd=DNSQR(qname="www.example.com", qtype="A"),
        an=DNSRR(rrname="www.example.com", type="A", ttl=60, rdata="198.51.100.9"))
    q.time = 1800000000.0
    r.time = 1800000000.2
    path = tmp_path/"dns.pcap"
    wrpcap(str(path), [q, r])
    parsed = parse_dns_pcap(str(path))
    assert len(parsed) == 2
    assert parsed[0]["is_query"] is True
    assert parsed[0]["rcode"] is None
    assert parsed[0]["registered_domain"] == "example.com"
    assert parsed[1]["is_query"] is False
    assert parsed[1]["rcode"] == "NOERROR"


def test_parser_no_dns(tmp_path):
    p = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")/IP(src="192.0.2.10", dst="192.0.2.53")/UDP(sport=1234, dport=1234)/b"hello"
    file = tmp_path/"nodns.pcap"
    wrpcap(str(file), [p])
    assert parse_dns_pcap(str(file)) == []


def test_missing_pcap():
    with pytest.raises(FileNotFoundError):
        parse_dns_pcap("/this-file-should-not-exist.pcap")
