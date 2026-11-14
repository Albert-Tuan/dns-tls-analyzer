"""Compare the team parser with TShark for the single-question DNS fixtures."""
import argparse
from ipaddress import ip_address
from math import isfinite
import shutil
import subprocess

import dns.rdatatype

from app.dns.parser import parse_dns_pcap


FIELDS = (
    "frame.number", "frame.time_epoch", "ip.src", "ipv6.src",
    "dns.id", "dns.flags", "dns.qry.name", "dns.qry.type",
)


class ParityError(ValueError):
    """A reference row is invalid or differs from the parser."""


def unsigned16(value):
    """TShark uses decimal or prefixed hexadecimal depending on the field."""
    base = 16 if value.lower().startswith("0x") else 10
    number = int(value, base)
    if not 0 <= number <= 65535:
        raise ValueError("expected an unsigned 16-bit integer")
    return number


def compare_row(path, line, event):
    values = line.split("\t")
    frame = event["frame_number"]
    context = f"{path}, parser frame {frame}"
    if len(values) != len(FIELDS):
        raise ParityError(f"{context}: expected {len(FIELDS)} columns, got {len(values)}: {line!r}")
    row = dict(zip(FIELDS, values))

    def decode(field, convert):
        value = row[field]
        try:
            return convert(value)
        except (ValueError, TypeError) as exc:
            raise ParityError(f"{context}, {field}: invalid TShark value {value!r} ({exc})") from exc

    def check(field, reference, actual):
        if reference != actual:
            raise ParityError(f"{context}, {field}: TShark={reference!r}, parser={actual!r}")

    check("frame.number", decode("frame.number", int), frame)
    stamp = decode("frame.time_epoch", float)
    if not isfinite(stamp) or not abs(stamp - event["timestamp"]) < 1e-5:
        raise ParityError(f"{context}, frame.time_epoch: TShark={stamp!r}, parser={event['timestamp']!r}")
    family = "ip.src" if row["ip.src"] else "ipv6.src"
    check(family, decode(family, ip_address), ip_address(event["src_ip"]))
    check("dns.id", decode("dns.id", unsigned16), event["dns_id"])
    flags = decode("dns.flags", unsigned16)
    is_query = (flags & 0x8000) == 0
    check(f"dns.flags QR (raw={row['dns.flags']}) / is_query", is_query, event["is_query"])
    check("dns.qry.name", row["dns.qry.name"].removesuffix(".").lower(), event["qname"])
    qtype = decode("dns.qry.type", unsigned16)
    check("dns.qry.type", dns.rdatatype.to_text(qtype), event["qtype"])


def verify(path):
    if not shutil.which("tshark"):
        raise ParityError("tshark executable not found")
    command = [
        "tshark", "-n", "-r", str(path), "-Y", "udp.port == 53 && dns",
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
    ]
    for field in FIELDS:
        command.extend(["-e", field])
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic produced"
        raise ParityError(f"{path}: tshark exited {result.returncode}: {detail}")
    lines = result.stdout.splitlines()
    events = parse_dns_pcap(str(path))
    if len(lines) != len(events):
        raise ParityError(f"{path}, DNS packet count: TShark={len(lines)}, parser={len(events)}")
    for line, event in zip(lines, events):
        compare_row(path, line, event)
    return len(events)


if __name__ == "__main__":
    cli = argparse.ArgumentParser()
    cli.add_argument("--pcap", required=True)
    args = cli.parse_args()
    try:
        print("TShark parity PASS:", verify(args.pcap), "DNS packets")
    except (OSError, ValueError) as exc:
        cli.exit(2, f"ERROR: {exc}\n")
