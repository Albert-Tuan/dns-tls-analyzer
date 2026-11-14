"""Streaming container checks: detect truncated records that readers may treat as EOF."""
import struct
from pathlib import Path

class CaptureError(ValueError):
    pass

def validate_capture(path):
    path=Path(path)
    size=path.stat().st_size
    with path.open('rb') as f:
        magic=f.read(4)
        formats={b'\xd4\xc3\xb2\xa1':'<',b'\xa1\xb2\xc3\xd4':'>',
                 b'\x4d\x3c\xb2\xa1':'<',b'\xa1\xb2\x3c\x4d':'>'}
        if magic in formats:
            endian=formats[magic]
            rest=f.read(20)
            if len(rest)!=20:
                raise CaptureError('Truncated PCAP global header')
            major,minor,_,_,snap,_=struct.unpack(endian+'HHIIII',rest)
            if (major,minor)!=(2,4) or snap==0:
                raise CaptureError('Unsupported PCAP header/version')
            while f.tell()<size:
                header=f.read(16)
                if len(header)!=16: raise CaptureError('Truncated PCAP record header')
                _,_,captured,original=struct.unpack(endian+'IIII',header)
                if captured>snap or captured>original or captured>size-f.tell():
                    raise CaptureError('Invalid/truncated PCAP record length')
                f.seek(captured,1)
        elif magic==b'\x0a\x0d\x0d\x0a':
            f.seek(0); endian=None
            while f.tell()<size:
                start=f.tell(); header=f.read(8)
                if len(header)!=8: raise CaptureError('Truncated PCAPNG block header')
                if header[:4]==magic:
                    bom=f.read(4)
                    endian={b'\x4d\x3c\x2b\x1a':'<',b'\x1a\x2b\x3c\x4d':'>'}.get(bom)
                    if not endian: raise CaptureError('Invalid PCAPNG byte-order magic')
                if endian is None: raise CaptureError('Missing PCAPNG section')
                length=struct.unpack(endian+'I',header[4:])[0]
                minimum=28 if header[:4]==magic else 12
                if length<minimum or length%4 or start+length>size:
                    raise CaptureError('Invalid/truncated PCAPNG block length')
                f.seek(start+length-4)
                if struct.unpack(endian+'I',f.read(4))[0]!=length:
                    raise CaptureError('PCAPNG block trailer mismatch')
        else:
            raise CaptureError('Not a PCAP/PCAPNG file (a zero-byte file is invalid)')
