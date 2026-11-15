"""Fingerprint TLS: tên field TShark, trạng thái, nhóm flow dùng chung fingerprint.

Nguyên tắc: JA3/JA3S/JA4 chỉ là giá trị do TShark (dissector của Wireshark) báo cáo.
Module này KHÔNG tự tính hay bịa hash. Một fingerprint chung giữa nhiều flow KHÔNG có nghĩa là độc hại:
nó phản ánh bộ thư viện TLS + cấu hình của client, và nhiều ứng dụng dùng chung cùng thư viện.
"""
from __future__ import annotations

from app.core.schemas import FP_COMPLETE, FP_PARTIAL, FP_UNAVAILABLE

# key nội bộ -> tên field Wireshark. Field nào runtime không có thì bị bỏ khỏi lệnh và ghi warning.
OPTIONAL_FIELDS: dict[str, str] = {
    "sni": "tls.handshake.extensions_server_name",
    "hello_version": "tls.handshake.version",
    "supported_versions": "tls.handshake.extensions_supported_version",
    "ciphersuite": "tls.handshake.ciphersuite",
    "alpn": "tls.handshake.extensions_alpn_str",
    "ext_types": "tls.handshake.extension.type",
    "ja3": "tls.handshake.ja3",
    "ja3s": "tls.handshake.ja3s",
    "ja4": "tls.handshake.ja4",
}

# Tên field đổi giữa các bản Wireshark -> thử lần lượt, dùng tên đầu tiên có trong `tshark -G fields`.
# Dữ liệu trong parser luôn được gán lại về tên chuẩn (khóa của OPTIONAL_FIELDS).
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "supported_versions": (
        "tls.handshake.extensions.supported_version",   # Wireshark 4.6.8 (đã gặp lỗi field cũ ở bản này)
        "tls.handshake.extensions_supported_version",
    ),
}


def resolve_field(key: str, available) -> str | None:
    """Trả tên field thật có trong runtime cho khóa nội bộ, hoặc None nếu không có."""
    for name in FIELD_ALIASES.get(key, ()) + (OPTIONAL_FIELDS[key],):
        if name in available:
            return name
    return None


ECH_EXTENSION_TYPE = 0xFE0D  # extension encrypted_client_hello (ECH), mã 65037 trong sổ đăng ký IANA

VERSION_NAMES = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# Chỉ một vài bộ mã phổ biến để dễ đọc; giá trị hex mới là dữ liệu gốc.
CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

# Mã lý do khi một giá trị là null (xem bảng trong docs/TV3_TLS_INTEGRATION_REPORT.md)
R_NO_CLIENT_HELLO = "client_hello_not_captured"
R_NO_SERVER_HELLO = "server_hello_not_captured"
R_FIELD_UNSUPPORTED = "field_not_supported_by_tshark"
R_ABSENT_OR_HIDDEN = "extension_absent_or_hidden"
R_NOT_REPORTED = "not_reported_by_tshark"


def to_int(value: str) -> int | None:
    """'0x1301' -> 4865; '4865' -> 4865; không đọc được -> None."""
    v = value.strip()
    if not v:
        return None
    try:
        return int(v, 0)
    except ValueError:
        try:
            return int(v, 16)
        except ValueError:
            return None


def is_grease(n: int) -> bool:
    """GREASE (RFC 8701): hai byte giống nhau và nibble thấp = 0xA (0x0a0a, 0x1a1a, ... 0xfafa)."""
    return (n >> 8) == (n & 0xFF) and (n & 0x0F) == 0x0A


def hex16(n: int) -> str:
    return f"0x{n:04x}"


def version_name(n: int | None) -> str | None:
    if n is None:
        return None
    return VERSION_NAMES.get(n, hex16(n))


def cipher_info(n: int | None) -> dict | None:
    if n is None:
        return None
    return {"id": hex16(n), "name": CIPHER_NAMES.get(n)}


def fingerprint_status(
    client_seen: bool,
    server_seen: bool,
    ja3: str | None,
    ja3s: str | None,
    ja3_supported: bool,
    ja3s_supported: bool,
) -> str:
    """complete: đủ 2 phía + JA3 và JA3S đều có. unavailable: runtime không có cả hai field. Còn lại: partial.

    JA4 là P1 nên không bắt buộc cho 'complete'.
    """
    if not ja3_supported and not ja3s_supported:
        return FP_UNAVAILABLE
    if client_seen and server_seen and ja3 and ja3s:
        return FP_COMPLETE
    return FP_PARTIAL


def group_shared_fingerprints(observations: list[dict], key: str = "ja3") -> list[dict]:
    """Nhóm các flow có cùng giá trị fingerprint (chỉ trả nhóm >= 2 flow).

    Chỉ là thống kê mô tả; không có ý nghĩa kết luận độc hại.
    """
    groups: dict[str, list[str]] = {}
    for obs in observations:
        value = obs.get(key)
        if value:
            groups.setdefault(value, []).append(obs.get("flow_id", ""))
    out = [
        {key: value, "flow_count": len(ids), "flow_ids": ids}
        for value, ids in groups.items()
        if len(ids) >= 2
    ]
    out.sort(key=lambda g: (-g["flow_count"], g[key]))
    return out


JA4_NOTE = (
    "JA4 chỉ có khi TShark/Wireshark >= 4.2.0 và runtime có field tls.handshake.ja4; "
    "nếu không, ja4 = null kèm warning (không tự tính)."
)
