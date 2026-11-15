"""Kiểm tra nhanh file PCAP/PCAPNG bằng thư viện chuẩn (không cần TShark).

Mục đích: (1) phát hiện file hỏng/không phải PCAP *trước* khi chạy pipeline,
(2) đếm số packet cho metadata, (3) tính SHA-256 để người chấm đối chiếu đúng file.
"""
from __future__ import annotations

import hashlib
import os
import struct

CLASSIC_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", "pcap"),
    b"\xa1\xb2\xc3\xd4": (">", "pcap"),
    b"\x4d\x3c\xb2\xa1": ("<", "pcap-nsec"),
    b"\xa1\xb2\x3c\x4d": (">", "pcap-nsec"),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
MAX_RECORD = 256 * 1024 * 1024


class PcapError(ValueError):
    """File không phải PCAP/PCAPNG hợp lệ hoặc bị cắt cụt."""


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_exact(f, n: int, what: str) -> bytes:
    data = f.read(n)
    if len(data) != n:
        raise PcapError(f"file bị cắt cụt khi đọc {what} (cần {n} byte, còn {len(data)})")
    return data


def _count_classic(f, endian: str) -> int:
    _read_exact(f, 20, "global header")  # magic đã đọc 4 byte
    count = 0
    while True:
        hdr = f.read(16)
        if not hdr:
            return count
        if len(hdr) != 16:
            raise PcapError("file bị cắt cụt ở packet header")
        incl_len = struct.unpack(endian + "IIII", hdr)[2]
        if incl_len > MAX_RECORD:
            raise PcapError(f"độ dài packet bất thường ({incl_len}); file có thể hỏng")
        _read_exact(f, incl_len, "dữ liệu packet")
        count += 1


def _count_pcapng(f) -> int:
    count = 0
    endian = None
    first = True
    while True:
        head = f.read(8)
        if not head:
            return count
        if len(head) != 8:
            raise PcapError("file pcapng bị cắt cụt ở block header")
        if first:
            bom = _read_exact(f, 4, "byte-order magic")
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapError("pcapng: byte-order magic không hợp lệ")
            btype, blen = struct.unpack(endian + "II", head)
            consumed = 12
            first = False
        else:
            btype, blen = struct.unpack(endian + "II", head)
            consumed = 8
        if blen < 12 or blen % 4:
            raise PcapError(f"pcapng: độ dài block không hợp lệ ({blen})")
        _read_exact(f, blen - consumed, "nội dung block")
        if btype in (6, 3, 2):  # Enhanced / Simple / (obsolete) Packet Block
            count += 1


def inspect_pcap(path: str) -> dict:
    """Trả {format, packet_count, size_bytes, sha256}. Ném PcapError/OSError nếu không đọc được."""
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    size = os.path.getsize(path)
    if size < 12:
        raise PcapError(f"file quá nhỏ ({size} byte) để là PCAP/PCAPNG")
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic in CLASSIC_MAGIC:
            endian, fmt = CLASSIC_MAGIC[magic]
            packets = _count_classic(f, endian)
        elif magic == PCAPNG_MAGIC:
            f.seek(0)
            fmt = "pcapng"
            packets = _count_pcapng(f)
        else:
            raise PcapError("không phải PCAP/PCAPNG (magic number không khớp)")
    return {"format": fmt, "packet_count": packets, "size_bytes": size, "sha256": _sha256(path)}
