"""Offline UDP/53 parser: IPv4/IPv6, PCAP/PCAPNG, structured diagnostics."""
from collections import Counter
from dataclasses import dataclass, field
from math import isfinite
from pathlib import Path
import logging

from .normalization import normalize_qname
from .capture_validation import validate_capture, CaptureError
LOG=logging.getLogger(__name__)

@dataclass
class ParseResult:
    events: list = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)

def parse_dns_pcap_detailed(pcap_path: str, max_events: int = 1_000_000) -> ParseResult:
    from scapy.all import PcapReader, IP, IPv6, UDP, TCP, IPv6ExtHdrFragment
    from scapy.error import Scapy_Exception
    import dns.message
    import dns.flags
    import dns.rcode
    import dns.rdatatype
    import dns.exception
    if type(max_events) is not int or max_events<1:
        raise ValueError('max_events must be a positive integer')
    path=Path(pcap_path)
    if not path.is_file(): raise FileNotFoundError(f'PCAP not found: {path}')
    validate_capture(path)
    events=[]; stats=Counter(total_packets=0,dns_packets=0,dns_queries=0,dns_responses=0)
    issues=Counter(); first_frames={}
    def note(code,frame):
        issues[code]+=1; first_frames.setdefault(code,frame)
    try:
        with PcapReader(str(path)) as reader:
            for frame,packet in enumerate(reader,1):
                stats['total_packets']+=1
                if IP not in packet and IPv6 not in packet: continue
                ip=packet[IP] if IP in packet else packet[IPv6]
                if (IP in packet and (int(ip.frag)>0 or int(ip.flags)&1)) or IPv6ExtHdrFragment in packet:
                    note('ip_fragment_not_reassembled',frame); continue
                if TCP in packet:
                    if 53 in (int(packet[TCP].sport),int(packet[TCP].dport)):
                        note('tcp_dns_not_supported',frame)
                    continue
                if UDP not in packet: continue
                udp=packet[UDP]
                if 53 not in (int(udp.sport),int(udp.dport)): continue
                try:
                    stamp=float(packet.time)
                    if not isfinite(stamp): raise ValueError('non-finite timestamp')
                    # Scapy may attach Ethernet padding below the decoded DNS layer.
                    # original contains the bytes passed down by the enclosing IP layer.
                    datagram = udp.original
                    declared_length = int(udp.len or 0)
                    if declared_length < 8 or declared_length > len(datagram):
                        raise ValueError('truncated or inconsistent UDP length')
                    wire = datagram[8:declared_length]
                    msg=dns.message.from_wire(wire,ignore_trailing=False)
                    if msg.opcode()!=0:
                        note('non_standard_dns_opcode',frame); continue
                    if len(msg.question)!=1:
                        note('unsupported_question_count',frame); continue
                    q=msg.question[0]
                    # Preserve raw DNS labels: do not interpret escaped dots as separators.
                    labels=q.name.labels[:-1]
                    if any(b'.' in label or b'\\' in label for label in labels):
                        note('unsupported_binary_qname',frame); continue
                    pieces=normalize_qname(b'.'.join(labels))
                    if pieces is None:
                        note('invalid_or_unsupported_qname',frame); continue
                    if pieces['registered_domain'] is None:
                        note('unknown_suffix_or_reverse_name',frame)
                    is_query=not bool(msg.flags & dns.flags.QR)
                    if len(events)>=max_events:
                        raise CaptureError(f'Event limit {max_events} exceeded; split the capture')
                    events.append({'timestamp':stamp,'src_ip':str(ip.src),'dst_ip':str(ip.dst),
                        'dns_id':msg.id,'is_query':is_query,**pieces,
                        'qtype':dns.rdatatype.to_text(q.rdtype),
                        'rcode':None if is_query else dns.rcode.to_text(msg.rcode()),
                        'packet_length':len(packet),'frame_number':frame})
                    stats['dns_packets']+=1
                    stats['dns_queries' if is_query else 'dns_responses']+=1
                except CaptureError:
                    raise
                except (dns.exception.DNSException,ValueError,TypeError,UnicodeError,AttributeError) as exc:
                    note('malformed_dns_packet',frame)
    except CaptureError: raise
    except (OSError,ValueError,EOFError,Scapy_Exception) as exc:
        raise CaptureError(f'Could not read PCAP: {exc}') from exc
    warnings=[{'code':code,'count':count,'first_frame':first_frames[code]} for code,count in sorted(issues.items())]
    stats['events_without_registered_domain']=sum(e['registered_domain'] is None for e in events)
    return ParseResult(events,dict(stats),warnings)

def parse_dns_pcap(pcap_path: str) -> list[dict]:
    """Stable team API. One event per single-question DNS packet, capture order.

    Unknown suffixes retain the event with null registered_domain/subdomain.
    Unsupported or malformed packets are skipped with warnings. Invalid capture
    containers raise CaptureError. Query RCODE remains null (no correlation).
    """
    result=parse_dns_pcap_detailed(pcap_path)
    for warning in result.warnings: LOG.warning('DNS parser: %s',warning)
    return result.events
