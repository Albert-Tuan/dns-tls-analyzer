"""Hợp đồng dữ liệu (contract) dùng chung cho cả nhóm — khóa từ 07/11.

Chỉ dùng thư viện chuẩn. Các hàm validate_* trả về *danh sách lỗi* (rỗng = hợp lệ)
để test và CLI có thể báo lỗi rõ ràng thay vì crash.

Quy ước: không đổi tên key của contract. Có thể THÊM key mới (additive) cho TLS observation,
nhưng các key gốc trong TLS_CONTRACT_KEYS luôn phải có.
"""
from __future__ import annotations

import math
from typing import Any

REPORT_VERSION = "1.0"

RECORD_TLS = "tls_observation"

# fingerprint_status
FP_COMPLETE = "complete"        # thấy cả ClientHello + ServerHello, JA3 và JA3S đều có giá trị
FP_PARTIAL = "partial"          # thiếu một phía handshake hoặc thiếu một fingerprint
FP_UNAVAILABLE = "unavailable"  # TShark runtime không hỗ trợ trường JA3/JA3S
FINGERPRINT_STATUSES = (FP_COMPLETE, FP_PARTIAL, FP_UNAVAILABLE)

# Key bắt buộc của TLS observation (theo Phụ lục B) -> kiểu chấp nhận được
TLS_CONTRACT_KEYS: dict[str, tuple[type, ...]] = {
    "record_type": (str,),
    "flow_id": (str,),
    "src_ip": (str,),
    "dst_ip": (str,),
    "sni": (str, type(None)),
    "ja3": (str, type(None)),
    "ja3s": (str, type(None)),
    "ja4": (str, type(None)),
    "fingerprint_status": (str,),
    "packet_sizes_signed": (list,),
}

REPORT_KEYS = (
    "metadata",
    "summary",
    "dns_events_summary",
    "dga_findings",
    "dns_tunnel_findings",
    "tls_observations",
)

REPORT_LIST_KEYS = ("dga_findings", "dns_tunnel_findings", "tls_observations")
REPORT_DICT_KEYS = ("metadata", "summary", "dns_events_summary")


class SchemaError(ValueError):
    """Dữ liệu không đúng contract."""


def validate_tls_observation(obs: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(obs, dict):
        return [f"tls_observation phải là dict, nhận {type(obs).__name__}"]
    for key, types in TLS_CONTRACT_KEYS.items():
        if key not in obs:
            errors.append(f"thiếu key '{key}'")
        elif not isinstance(obs[key], types):
            errors.append(
                f"key '{key}' sai kiểu: cần {[t.__name__ for t in types]}, nhận {type(obs[key]).__name__}"
            )
    if "record_type" in obs and obs["record_type"] != RECORD_TLS:
        errors.append(f"record_type phải là '{RECORD_TLS}'")
    if "fingerprint_status" in obs and obs["fingerprint_status"] not in FINGERPRINT_STATUSES:
        errors.append(f"fingerprint_status không hợp lệ: {obs['fingerprint_status']!r}")
    sizes = obs.get("packet_sizes_signed")
    if isinstance(sizes, list):
        for i, v in enumerate(sizes):
            if isinstance(v, bool) or not isinstance(v, int) or v == 0:
                errors.append(f"packet_sizes_signed[{i}] phải là số nguyên khác 0, nhận {v!r}")
                break
    return errors


def validate_report(report: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return [f"report phải là dict, nhận {type(report).__name__}"]
    for key in REPORT_KEYS:
        if key not in report:
            errors.append(f"thiếu key '{key}'")
    for key in REPORT_LIST_KEYS:
        if key in report and not isinstance(report[key], list):
            errors.append(f"'{key}' phải là list")
    for key in REPORT_DICT_KEYS:
        if key in report and not isinstance(report[key], dict):
            errors.append(f"'{key}' phải là dict")
    meta = report.get("metadata")
    if isinstance(meta, dict) and not isinstance(meta.get("warnings", []), list):
        errors.append("metadata.warnings phải là list")
    tls = report.get("tls_observations")
    if isinstance(tls, list):
        for i, obs in enumerate(tls):
            for e in validate_tls_observation(obs):
                errors.append(f"tls_observations[{i}]: {e}")
    return errors


def json_safe(value: Any) -> Any:
    """Đệ quy chuyển dữ liệu về dạng JSON chuẩn: NaN/Inf -> None, set/tuple -> list, key -> str."""
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (set, frozenset)):
        return [json_safe(v) for v in sorted(value, key=str)]
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    if value is None or isinstance(value, (str, int, bool)):
        return value
    return str(value)
