"""Gộp kết quả ba module thành một báo cáo JSON theo contract.

Số lượng trong `summary` luôn đếm từ chính các record truyền vào, không hard-code, không ước lượng.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import Counter
from datetime import datetime, timezone

from app.core.schemas import (
    FP_COMPLETE,
    FP_PARTIAL,
    FP_UNAVAILABLE,
    REPORT_VERSION,
    SchemaError,
    json_safe,
    validate_report,
)
from app.tls.fingerprint import group_shared_fingerprints

DISCLAIMER = (
    "Kết quả DGA/DNS tunnel là dấu hiệu NGHI NGỜ theo quy tắc, chưa phải kết luận mẫu độc hại. "
    "JA3/JA3S/JA4 là dấu vân tay TLS, không tự kết luận độc hại; nhiều ứng dụng có thể chia sẻ cùng fingerprint. "
    "TLS 1.3 không để lộ Certificate khi quan sát thụ động; ECH có thể che SNI thật."
)

_SUSPECT_PREFIXES = ("suspicious", "suspected")


def _is_suspect(record: dict) -> bool:
    return str(record.get("classification", "")).lower().startswith(_SUSPECT_PREFIXES)


def summarize_dns_events(dns_events: list[dict]) -> dict:
    """Tóm tắt sự kiện DNS. Response không được tính là query mới (theo contract)."""
    queries = [e for e in dns_events if e.get("is_query") is True]
    responses = [e for e in dns_events if e.get("is_query") is False]
    times = [e["timestamp"] for e in dns_events if isinstance(e.get("timestamp"), (int, float))]
    top = Counter(e.get("registered_domain") for e in queries if e.get("registered_domain"))
    return {
        "total_events": len(dns_events),
        "query_count": len(queries),
        "response_count": len(responses),
        "unique_qnames": len({e.get("qname") for e in queries if e.get("qname")}),
        "qtype_counts": dict(Counter(e.get("qtype") for e in queries if e.get("qtype"))),
        "top_registered_domains": [{"registered_domain": d, "query_count": n} for d, n in top.most_common(10)],
        "first_timestamp": min(times) if times else None,
        "last_timestamp": max(times) if times else None,
    }


def build_report(
    pcap_path: str,
    dns_events: list[dict],
    dga_results: list[dict],
    tunnel_results: list[dict],
    tls_observations: list[dict],
    *,
    pcap_info: dict | None = None,
    warnings: list[str] | None = None,
    tshark: dict | None = None,
    module_status: dict | None = None,
    packet_size_definition: dict | None = None,
) -> dict:
    """Giao diện public theo đề bài (các tham số keyword-only phía sau là phần mở rộng, có mặc định)."""
    pcap_info = pcap_info or {}
    shared_ja3 = group_shared_fingerprints(tls_observations, "ja3")
    shared_ja4 = group_shared_fingerprints(tls_observations, "ja4")
    status_counts = {s: 0 for s in (FP_COMPLETE, FP_PARTIAL, FP_UNAVAILABLE)}
    for obs in tls_observations:
        status_counts[obs.get("fingerprint_status")] = status_counts.get(obs.get("fingerprint_status"), 0) + 1

    dns_summary = summarize_dns_events(dns_events)
    report = {
        "metadata": {
            "report_version": REPORT_VERSION,
            "pcap_file": os.path.basename(pcap_path),
            "pcap_format": pcap_info.get("format"),
            "pcap_size_bytes": pcap_info.get("size_bytes"),
            "pcap_sha256": pcap_info.get("sha256"),
            "packet_count": pcap_info.get("packet_count"),
            "analyzed_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tshark": tshark or {"available": False},
            "module_status": module_status or {},
            "packet_size_definition": packet_size_definition or {},
            "warnings": list(dict.fromkeys(warnings or [])),
        },
        "summary": {
            "dns_event_count": dns_summary["total_events"],
            "dga_findings_count": len(dga_results),
            "dga_suspicious_count": sum(1 for r in dga_results if _is_suspect(r)),
            "dns_tunnel_findings_count": len(tunnel_results),
            "dns_tunnel_suspected_count": sum(1 for r in tunnel_results if _is_suspect(r)),
            "tls_observation_count": len(tls_observations),
            "tls_fingerprint_status_counts": status_counts,
            "tls_flows_with_ja3": sum(1 for o in tls_observations if o.get("ja3")),
            "tls_flows_with_ja4": sum(1 for o in tls_observations if o.get("ja4")),
            "tls_shared_ja3_groups": shared_ja3,
            "tls_shared_ja4_groups": shared_ja4,
            "disclaimer": DISCLAIMER,
        },
        "dns_events_summary": dns_summary,
        "dga_findings": list(dga_results),
        "dns_tunnel_findings": list(tunnel_results),
        "tls_observations": list(tls_observations),
    }
    return json_safe(report)


def write_report_json(report: dict, output_path: str) -> None:
    """Kiểm tra contract rồi ghi JSON chuẩn (allow_nan=False). Ghi qua file tạm để không để lại file dở."""
    errors = validate_report(report)
    if errors:
        raise SchemaError("report không đúng schema: " + "; ".join(errors[:5]))
    text = json.dumps(report, ensure_ascii=False, indent=2, allow_nan=False)
    directory = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        os.replace(tmp, output_path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
