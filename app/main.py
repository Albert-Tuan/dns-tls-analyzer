"""CLI: python -m app.main analyze --pcap samples/demo.pcap --output reports/demo.json

Exit code:
  0  thành công (có thể kèm warning trong báo cáo/stderr)
  1  lỗi đầu vào: file không tồn tại / không phải PCAP / bị cắt cụt / output trùng input — KHÔNG ghi báo cáo
  2  sai cú pháp dòng lệnh (argparse)
  3  chạy được nhưng thiếu năng lực (không có TShark, thiếu module) VÀ bật --strict (báo cáo vẫn được ghi)
  4  không ghi được file báo cáo
  5  một module con (TV1/TV2) ném exception — báo cáo một phần vẫn được ghi kèm lý do

Chính sách thiếu TShark (thống nhất toàn dự án): mặc định KHÔNG fail — phần DNS vẫn chạy, `tls_observations`
rỗng, `metadata.tshark.available = false` và có warning rõ ràng; dùng --strict để biến nó thành exit code 3.
"""
from __future__ import annotations

import argparse
import importlib
import logging
import os
import platform
import sys
from typing import Callable

from app.core.pcap_utils import PcapError, inspect_pcap
from app.core.report_exporter import build_report, write_report_json
from app.core.schemas import SchemaError
from app.tls.extractor import analyze_tls
from app.tls.flow_stats import DEFAULT_MAX_PACKETS
from app.tls.tshark import TSharkError, TSharkNotFoundError

log = logging.getLogger("tls_dns_analyzer")

EXIT_OK, EXIT_INPUT, EXIT_STRICT, EXIT_WRITE, EXIT_MODULE = 0, 1, 3, 4, 5

# Vị trí các module của TV1/TV2 chưa chốt trong đề -> thử lần lượt, thiếu thì báo cáo rõ (không bịa kết quả).
# Giả định chữ ký: parse_dns_pcap(pcap_path)->list[dict]; analyze_dns_domains(dns_events)->list[dict];
# detect_tunnels(dns_events)->list[dict]. Sửa danh sách này khi TV1/TV2 chốt đường dẫn thật.
MODULE_CANDIDATES: dict[str, list[str]] = {
    "parse_dns_pcap": ["app.dns.parser", "app.dns.dns_parser", "app.dns.pcap_parser"],
    "analyze_dns_domains": ["app.dga.analyzer", "app.dga.dga_detector", "app.dga.detector"],
    "detect_tunnels": ["app.tunneling.detector", "app.dns.tunnel", "app.dns.tunnel_detector", "app.dns.detector"],
}


def resolve_functions() -> dict[str, Callable | None]:
    found: dict[str, Callable | None] = {}
    for func_name, modules in MODULE_CANDIDATES.items():
        found[func_name] = None
        for mod_name in modules:
            try:
                module = importlib.import_module(mod_name)
            except ImportError:
                continue
            func = getattr(module, func_name, None)
            if callable(func):
                found[func_name] = func
                break
    return found


def _call_module(name: str, func: Callable | None, arg, warnings: list[str], status: dict) -> list[dict]:
    if func is None:
        status[name] = "missing"
        warnings.append(f"module_missing:{name}: chưa tìm thấy hàm {name} (TV1/TV2 chưa tích hợp); kết quả tương ứng rỗng.")
        return []
    try:
        result = func(arg)
        if not isinstance(result, list):
            raise TypeError(f"{name} phải trả list, nhận {type(result).__name__}")
    except Exception as exc:  # noqa: BLE001 - cố ý bắt rộng để giữ nguyên nhân và không mất báo cáo
        log.debug("chi tiết lỗi %s", name, exc_info=True)
        status[name] = f"error:{type(exc).__name__}"
        warnings.append(f"module_error:{name}: {type(exc).__name__}: {exc}")
        return []
    status[name] = "ok"
    return result


def run_pipeline(pcap_path: str, funcs: dict[str, Callable | None] | None = None, max_packets: int = DEFAULT_MAX_PACKETS):
    """Chạy toàn bộ pipeline. Trả (report, flags) với flags = {'degraded': bool, 'module_error': bool}.

    Ném FileNotFoundError / PcapError nếu đầu vào không hợp lệ (caller xử lý -> exit 1).
    """
    pcap_info = inspect_pcap(pcap_path)  # có thể ném FileNotFoundError / PcapError
    funcs = funcs if funcs is not None else resolve_functions()
    warnings: list[str] = []
    status: dict[str, str] = {}
    flags = {"degraded": False, "module_error": False}
    dns_events: list[dict] = []
    dga: list[dict] = []
    tunnels: list[dict] = []
    tls_obs: list[dict] = []
    tshark_meta: dict = {"available": False}
    pkt_def: dict = {}

    if not pcap_path.lower().endswith((".pcap", ".pcapng", ".cap")):
        warnings.append("unusual_extension: phần mở rộng không phải .pcap/.pcapng/.cap (đã xác nhận bằng magic number).")

    if pcap_info["packet_count"] == 0:
        warnings.append("pcap_has_no_packets: file hợp lệ nhưng không có packet; bỏ qua các bước phân tích.")
        for name in ("parse_dns_pcap", "analyze_dns_domains", "detect_tunnels", "tls_extractor"):
            status[name] = "skipped_empty_pcap"
    else:
        dns_events = _call_module("parse_dns_pcap", funcs.get("parse_dns_pcap"), pcap_path, warnings, status)
        if status["parse_dns_pcap"] == "ok":
            dga = _call_module("analyze_dns_domains", funcs.get("analyze_dns_domains"), dns_events, warnings, status)
            tunnels = _call_module("detect_tunnels", funcs.get("detect_tunnels"), dns_events, warnings, status)
        else:
            status["analyze_dns_domains"] = status["detect_tunnels"] = "skipped_no_dns_events"

        try:
            result = analyze_tls(pcap_path, max_packets=max_packets)
            tls_obs = result.observations
            warnings.extend(result.warnings)
            pkt_def = result.packet_size_definition
            tshark_meta = {
                "available": True,
                "version": result.tshark_version,
                "command": result.tshark_cmd,
                "fields_supported": result.fields_supported,
            }
            status["tls_extractor"] = "ok"
        except TSharkNotFoundError as exc:
            status["tls_extractor"] = "tshark_unavailable"
            tshark_meta = {"available": False, "reason": str(exc)}
            warnings.append(f"tshark_unavailable: {exc} tls_observations rỗng; phần DNS vẫn được phân tích.")
        except TSharkError as exc:
            status["tls_extractor"] = "tshark_error"
            tshark_meta = {"available": False, "reason": str(exc)}
            warnings.append(f"tshark_error: {exc} tls_observations rỗng.")

    flags["degraded"] = any(
        v in ("missing", "tshark_unavailable", "tshark_error") for v in status.values()
    )
    flags["module_error"] = any(v.startswith("error:") for v in status.values())
    report = build_report(
        pcap_path, dns_events, dga, tunnels, tls_obs,
        pcap_info=pcap_info, warnings=warnings, tshark=tshark_meta,
        module_status=status, packet_size_definition=pkt_def,
    )
    report["metadata"]["python_version"] = platform.python_version()
    return report, flags


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m app.main",
        description="Phân tích PCAP offline: DNS (DGA, tunnel) và TLS fingerprint (JA3/JA3S/JA4 nếu TShark hỗ trợ).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    an = sub.add_parser("analyze", help="phân tích một file PCAP/PCAPNG và xuất báo cáo JSON")
    an.add_argument("--pcap", required=True, help="đường dẫn file .pcap/.pcapng")
    an.add_argument("--output", required=True, help="đường dẫn file báo cáo .json")
    an.add_argument("--strict", action="store_true",
                    help="thoát mã 3 nếu thiếu TShark/module (mặc định: chỉ cảnh báo trong báo cáo)")
    an.add_argument("--max-packets", type=int, default=DEFAULT_MAX_PACKETS,
                    help=f"số packet tối đa trong chuỗi packet-size mỗi flow (mặc định {DEFAULT_MAX_PACKETS})")
    an.add_argument("--verbose", "-v", action="store_true", help="in chi tiết lỗi để debug")
    return parser


def _print_summary(report: dict, output: str) -> None:
    s, m = report["summary"], report["metadata"]
    print(f"Đã phân tích: {m['pcap_file']} ({m['packet_count']} packet, {m['pcap_format']})")
    print(f"  DNS events           : {s['dns_event_count']}")
    print(f"  DGA findings         : {s['dga_findings_count']} (nghi ngờ: {s['dga_suspicious_count']})")
    print(f"  DNS tunnel findings  : {s['dns_tunnel_findings_count']} (nghi ngờ: {s['dns_tunnel_suspected_count']})")
    print(f"  TLS observations     : {s['tls_observation_count']} (có JA3: {s['tls_flows_with_ja3']}, có JA4: {s['tls_flows_with_ja4']})")
    print(f"  Báo cáo              : {output}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s", stream=sys.stderr)
    if args.max_packets < 1:
        print("LỖI: --max-packets phải >= 1", file=sys.stderr)
        return EXIT_INPUT
    if os.path.abspath(args.pcap) == os.path.abspath(args.output):
        print("LỖI: --output trùng với --pcap; từ chối ghi đè file đầu vào.", file=sys.stderr)
        return EXIT_INPUT
    try:
        report, flags = run_pipeline(args.pcap, max_packets=args.max_packets)
    except FileNotFoundError:
        print(f"LỖI: không tìm thấy file PCAP: {args.pcap}", file=sys.stderr)
        return EXIT_INPUT
    except PcapError as exc:
        print(f"LỖI: file PCAP không hợp lệ ({args.pcap}): {exc}", file=sys.stderr)
        return EXIT_INPUT
    except OSError as exc:
        print(f"LỖI: không đọc được file PCAP: {exc}", file=sys.stderr)
        return EXIT_INPUT

    try:
        write_report_json(report, args.output)
    except (OSError, SchemaError) as exc:
        print(f"LỖI: không ghi được báo cáo: {exc}", file=sys.stderr)
        return EXIT_WRITE

    _print_summary(report, args.output)
    for w in report["metadata"]["warnings"]:
        print(f"WARNING: {w}", file=sys.stderr)
    if flags["module_error"]:
        print("LỖI: một module con ném exception; báo cáo một phần đã được ghi (xem metadata.warnings).", file=sys.stderr)
        return EXIT_MODULE
    if args.strict and flags["degraded"]:
        print("STRICT: thiếu TShark hoặc module; thoát mã 3.", file=sys.stderr)
        return EXIT_STRICT
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
