"""Packet-size sequence có chiều cho từng TCP stream (không giải mã nội dung).

Định nghĩa đã chọn (ghi cả trong README/báo cáo):
  * Kích thước = frame.len (độ dài cả frame trên dây, gồm header Ethernet/IP/TCP).
  * Chỉ tính packet CÓ payload TCP (tcp.len > 0); ACK thuần bị bỏ qua.
  * Dấu: '+' client -> server, '-' server -> client.
  * Packet bị TShark đánh dấu retransmission được BỎ QUA (không đếm hai lần).
  * Giới hạn max_packets (mặc định 50) packet đầu tiên của mỗi stream; truncated=True nếu còn nữa.
  * Mỗi stream xử lý độc lập, không trộn packet giữa các stream.
Xác định client theo thứ tự ưu tiên: (1) bên gửi ClientHello, (2) bên gửi SYN không kèm ACK,
(3) bên gửi packet đầu tiên thấy trong stream (suy đoán -> ghi direction_basis).
"""
from __future__ import annotations

import os

from app.tls.tshark import (
    DEFAULT_TIMEOUT,
    TSharkCapabilities,
    TSharkError,
    TSharkNotFoundError,
    get_tshark_cmd,
    probe_tshark,
    run_tshark,
)

DEFAULT_MAX_PACKETS = 50
LENGTH_FIELD = "frame.len"

DEFINITION = {
    "length_field": LENGTH_FIELD,
    "sign": "+ = client->server, - = server->client",
    "counted_packets": "chỉ packet có payload TCP (tcp.len > 0)",
    "retransmissions": "bỏ qua packet TShark đánh dấu retransmission",
    "max_packets": DEFAULT_MAX_PACKETS,
}

_RETRANS_FILTER = (
    "tcp.analysis.retransmission || tcp.analysis.fast_retransmission "
    "|| tcp.analysis.spurious_retransmission"
)


def _truthy(value: str) -> bool:
    return value.strip().lower() in ("1", "true")


def _int(value: str) -> int | None:
    try:
        return int(value.strip().split(",")[0])
    except (ValueError, AttributeError):
        return None


def _first(value: str) -> str:
    return value.split(",")[0].strip() if value else ""


def _pick_client(pkts: list[dict], hint: tuple[str, int] | None):
    if hint:
        return hint, "client_hello"
    for p in pkts:
        if p["syn"] and not p["ack"]:
            return (p["ip"], p["port"]), "syn"
    first = pkts[0]
    return (first["ip"], first["port"]), "first_packet"


def series_from_rows(
    rows: list[dict],
    flow_prefix: str,
    retrans_frames: set[int] | None = None,
    client_hints: dict[int, tuple[str, int]] | None = None,
    max_packets: int = DEFAULT_MAX_PACKETS,
    only_streams: set[int] | None = None,
) -> dict[str, dict]:
    """Hàm thuần (không gọi TShark) để dễ test. rows là dict theo tên field của TShark."""
    retrans_frames = retrans_frames or set()
    client_hints = client_hints or {}
    by_stream: dict[int, list[dict]] = {}
    for row in rows:
        stream = _int(row.get("tcp.stream", ""))
        if stream is None or (only_streams is not None and stream not in only_streams):
            continue
        ip = _first(row.get("ip.src", "")) or _first(row.get("ipv6.src", ""))
        port = _int(row.get("tcp.srcport", ""))
        if not ip or port is None:
            continue
        by_stream.setdefault(stream, []).append(
            {
                "frame": _int(row.get("frame.number", "")),
                "ip": ip,
                "port": port,
                "len": _int(row.get(LENGTH_FIELD, "")),
                "payload": _int(row.get("tcp.len", "")) or 0,
                "syn": _truthy(row.get("tcp.flags.syn", "")),
                "ack": _truthy(row.get("tcp.flags.ack", "")),
            }
        )

    flows: dict[str, dict] = {}
    for stream, pkts in by_stream.items():
        client, basis = _pick_client(pkts, client_hints.get(stream))
        sizes: list[int] = []
        eligible = 0
        retrans_skipped = 0
        no_payload_skipped = 0
        for p in pkts:
            if p["payload"] <= 0 or not p["len"]:
                no_payload_skipped += 1
                continue
            if p["frame"] in retrans_frames:
                retrans_skipped += 1
                continue
            eligible += 1
            if len(sizes) < max_packets:
                sign = 1 if (p["ip"], p["port"]) == client else -1
                sizes.append(sign * p["len"])
        flows[f"{flow_prefix}:tcp:{stream}"] = {
            "packet_sizes_signed": sizes,
            "payload_packets_total": eligible,
            "truncated": eligible > len(sizes),
            "retransmissions_skipped": retrans_skipped,
            "no_payload_skipped": no_payload_skipped,
            "direction_basis": basis,
        }
    return flows


def _parse_rows(output: str, columns: list[str]) -> list[dict]:
    rows = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        parts += [""] * (len(columns) - len(parts))
        rows.append(dict(zip(columns, parts)))
    return rows


def extract_packet_size_series(
    pcap_path: str,
    client_hints: dict[int, tuple[str, int]] | None = None,
    max_packets: int = DEFAULT_MAX_PACKETS,
    caps: TSharkCapabilities | None = None,
    only_streams: set[int] | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:
    """Trả {'definition', 'flows': {flow_id: {...}}, 'warnings': [...]}.

    Ném TSharkNotFoundError nếu không có TShark, TSharkError nếu TShark lỗi.
    """
    warnings: list[str] = []
    if caps is None:
        cmd = get_tshark_cmd()
        if cmd is None:
            raise TSharkNotFoundError("không tìm thấy TShark")
        caps = probe_tshark(cmd)

    ip_fields = [f for f in ("ip.src", "ipv6.src") if caps.has(f)]
    wanted = ["frame.number", "tcp.stream", "tcp.srcport", LENGTH_FIELD, "tcp.len",
              "tcp.flags.syn", "tcp.flags.ack"] + ip_fields
    missing = [f for f in wanted if not caps.has(f)]
    if missing:
        raise TSharkError(f"TShark thiếu field cần cho packet-size: {', '.join(missing)}")

    base = ["-r", pcap_path, "-n", "-T", "fields", "-E", "header=n", "-E", "separator=/t",
            "-E", "occurrence=f"]
    out = run_tshark(caps.cmd, base + ["-Y", "tcp"] + [a for f in wanted for a in ("-e", f)], timeout)
    rows = _parse_rows(out, wanted)

    retrans: set[int] = set()
    try:
        r_out = run_tshark(caps.cmd, base + ["-Y", _RETRANS_FILTER, "-e", "frame.number"], timeout)
        for line in r_out.splitlines():
            n = _int(line)
            if n is not None:
                retrans.add(n)
    except TSharkError as exc:
        warnings.append(
            f"retransmission_detection_unavailable: không lọc được retransmission ({exc}); "
            "chuỗi packet-size có thể gồm cả packet gửi lại"
        )

    prefix = os.path.basename(pcap_path)
    flows = series_from_rows(rows, prefix, retrans, client_hints, max_packets, only_streams)
    definition = dict(DEFINITION, max_packets=max_packets)
    return {"definition": definition, "flows": flows, "warnings": warnings}
