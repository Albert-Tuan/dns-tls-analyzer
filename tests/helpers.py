"""Hàm dùng chung cho các test: dựng PCAP tối thiểu và cấu hình TShark giả."""
from __future__ import annotations

import contextlib
import json
import os
import struct
import sys
from unittest import mock

FAKE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_tshark.py")

# Fixture giả (chuỗi hex tùy ý) — chỉ để kiểm thử parser, không phải fingerprint thật.
JA3_A, JA3_B, JA3S_A = "a" * 32, "b" * 32, "c" * 32
JA4_A = "t13d0000h2_aaaaaaaaaaaa_bbbbbbbbbbbb"

ALL_FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len", "tcp.stream", "tcp.srcport", "tcp.dstport",
    "tcp.len", "tcp.flags.syn", "tcp.flags.ack", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst",
    "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.version",
    "tls.handshake.extensions_supported_version", "tls.handshake.ciphersuite",
    "tls.handshake.extensions_alpn_str", "tls.handshake.extension.type",
    "tls.handshake.ja3", "tls.handshake.ja3s", "tls.handshake.ja4",
]

C, S = "192.0.2.10", "198.51.100.20"  # dải ví dụ RFC 5737


def _strs(rows):
    """Dòng parse từ TShark luôn là chuỗi; mô phỏng đúng như vậy."""
    return [{k: str(v) for k, v in r.items()} for r in rows]


def hello_rows():
    return _strs([
        {  # stream 0: ClientHello (có GREASE + ECH)
            "frame.number": 4, "frame.time_epoch": "1794000000.1", "tcp.stream": 0,
            "tcp.srcport": 49152, "tcp.dstport": 443, "ip.src": C, "ip.dst": S,
            "tls.handshake.type": "1", "tls.handshake.extensions_server_name": "example.org",
            "tls.handshake.version": "0x0303",
            "tls.handshake.extensions_supported_version": "0x0a0a,0x0304,0x0303",
            "tls.handshake.ciphersuite": "0x0a0a,0x1301,0xc02f",
            "tls.handshake.extensions_alpn_str": "h2,http/1.1",
            "tls.handshake.extension.type": "0,10,65037",
            "tls.handshake.ja3": JA3_A, "tls.handshake.ja4": JA4_A,
        },
        {  # stream 0: ServerHello (TLS 1.3)
            "frame.number": 6, "frame.time_epoch": "1794000000.2", "tcp.stream": 0,
            "tcp.srcport": 443, "tcp.dstport": 49152, "ip.src": S, "ip.dst": C,
            "tls.handshake.type": "2", "tls.handshake.version": "0x0303",
            "tls.handshake.extensions_supported_version": "0x0304",
            "tls.handshake.ciphersuite": "0x1301", "tls.handshake.ja3s": JA3S_A,
        },
        {  # stream 1: chỉ có ClientHello, cùng JA3 với stream 0, không có SNI
            "frame.number": 20, "frame.time_epoch": "1794000001.0", "tcp.stream": 1,
            "tcp.srcport": 50000, "tcp.dstport": 443, "ip.src": "192.0.2.11", "ip.dst": S,
            "tls.handshake.type": "1", "tls.handshake.version": "0x0303",
            "tls.handshake.ciphersuite": "0xc02f", "tls.handshake.ja3": JA3_A,
        },
    ])


def tcp_rows():
    def r(frame, stream, src, sport, flen, plen, syn=0, ack=1):
        return {"frame.number": frame, "tcp.stream": stream, "ip.src": src, "tcp.srcport": sport,
                "frame.len": flen, "tcp.len": plen, "tcp.flags.syn": syn, "tcp.flags.ack": ack}
    return _strs([
        r(1, 0, C, 49152, 74, 0, syn=1, ack=0),
        r(2, 0, S, 443, 74, 0, syn=1, ack=1),
        r(3, 0, C, 49152, 66, 0),
        r(4, 0, C, 49152, 314, 248),
        r(5, 0, S, 443, 66, 0),
        r(6, 0, S, 443, 1200, 1134),
        r(7, 0, S, 443, 1200, 1134),  # retransmission của frame 6
        r(8, 0, C, 49152, 150, 84),
        r(20, 1, "192.0.2.11", 50000, 500, 434),
    ])


def write_fake_data(directory: str, *, drop_fields=(), hello=None, tcp=None, retrans=(7,), fail_exit=False) -> str:
    path = os.path.join(directory, "fake_tshark_data.json")
    data = {
        "fields": [f for f in ALL_FIELDS if f not in set(drop_fields)],
        "hello_rows": hello_rows() if hello is None else hello,
        "tcp_rows": tcp_rows() if tcp is None else tcp,
        "retrans_frames": list(retrans),
        "fail_exit": fail_exit,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    return path


@contextlib.contextmanager
def fake_tshark(directory: str, **kwargs):
    """Trong context: TShark giả được dùng và phát lại dữ liệu fixture."""
    data_path = write_fake_data(directory, **kwargs)
    cmd = [sys.executable, FAKE]
    with mock.patch.dict(os.environ, {"FAKE_TSHARK_DATA": data_path}), \
            mock.patch("app.tls.extractor.get_tshark_cmd", return_value=cmd), \
            mock.patch("app.tls.flow_stats.get_tshark_cmd", return_value=cmd):
        yield


@contextlib.contextmanager
def no_tshark():
    with mock.patch("app.tls.extractor.get_tshark_cmd", return_value=None), \
            mock.patch("app.tls.flow_stats.get_tshark_cmd", return_value=None):
        yield


def write_pcap(path: str, packets: int = 1, truncate_last: int = 0) -> str:
    """PCAP cổ điển tối thiểu (Ethernet) với `packets` packet rỗng nội dung 4 byte."""
    blob = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for i in range(packets):
        blob += struct.pack("<IIII", 1794000000 + i, 0, 4, 4) + b"\x00\x01\x02\x03"
    if truncate_last:
        blob = blob[:-truncate_last]
    with open(path, "wb") as f:
        f.write(blob)
    return path


def write_pcapng(path: str, packets: int = 1) -> str:
    shb = struct.pack("<IIIHHqI", 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    epb = struct.pack("<IIIIIIII", 6, 32, 0, 0, 0, 0, 0, 32)
    with open(path, "wb") as f:
        f.write(shb + epb * packets)
    return path
