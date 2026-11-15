"""Trích xuất quan sát TLS (không giải mã) bằng TShark.

Chỉ báo cáo những gì TShark thực sự in ra. Thiếu dữ liệu -> null + mã lý do trong `null_reasons`;
KHÔNG suy diễn, KHÔNG điền giá trị. Một observation là một TCP stream có ít nhất một Hello.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from app.core.schemas import RECORD_TLS
from app.tls import fingerprint as fp
from app.tls.flow_stats import (
    DEFAULT_MAX_PACKETS,
    _parse_rows,
    extract_packet_size_series,
)
from app.tls.tshark import (
    DEFAULT_TIMEOUT,
    TSharkCapabilities,
    TSharkError,
    TSharkNotFoundError,
    get_tshark_cmd,
    probe_tshark,
    run_tshark,
)

HELLO_FILTER = "tls.handshake.type == 1 || tls.handshake.type == 2"
BASE_COLUMNS = ["frame.number", "frame.time_epoch", "tcp.stream", "tcp.srcport", "tcp.dstport"]
IP_COLUMNS = ["ip.src", "ip.dst", "ipv6.src", "ipv6.dst"]
REQUIRED_FIELDS = BASE_COLUMNS + ["tls.handshake.type"]


@dataclass
class TLSAnalysis:
    observations: list[dict] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tshark_version: str | None = None
    tshark_cmd: str | None = None
    fields_supported: dict[str, bool] = field(default_factory=dict)
    packet_size_definition: dict = field(default_factory=dict)


def _values(text: str) -> list[str]:
    return [v.strip() for v in (text or "").split(",") if v.strip()]


def _first(text: str) -> str | None:
    vals = _values(text)
    return vals[0] if vals else None


def _float(text: str) -> float | None:
    try:
        return float(_first(text) or "")
    except ValueError:
        return None


def _int(text: str) -> int | None:
    try:
        return int(_first(text) or "")
    except ValueError:
        return None


def _addr(row: dict, a: str, b: str) -> str | None:
    return _first(row.get(f"ip.{a}", "")) or _first(row.get(f"ipv6.{a}", ""))


def _versions(text: str) -> list[int]:
    out = []
    for v in _values(text):
        n = fp.to_int(v)
        if n is not None and not fp.is_grease(n):
            out.append(n)
    return out


def _hello(row: dict, multi: bool) -> dict:
    """Thông tin một Hello lấy từ một frame. multi=True: frame chứa cả Client+Server Hello."""
    info = {
        "frame": _int(row.get("frame.number", "")),
        "ts": _float(row.get("frame.time_epoch", "")),
        "src_ip": _addr(row, "src", "src"),
        "dst_ip": _addr(row, "dst", "dst"),
        "src_port": _int(row.get("tcp.srcport", "")),
        "dst_port": _int(row.get("tcp.dstport", "")),
        "sni": _first(row.get("tls.handshake.extensions_server_name", "")),
        "ja3": _first(row.get("tls.handshake.ja3", "")),
        "ja3s": _first(row.get("tls.handshake.ja3s", "")),
        "ja4": _first(row.get("tls.handshake.ja4", "")),
        "alpn": _values(row.get("tls.handshake.extensions_alpn_str", "")),
        "ambiguous": multi,
    }
    if multi:  # không biết giá trị thuộc Hello nào -> không gán
        info.update(hello_version=None, supported=[], ciphers=[], ext_types=[])
    else:
        hv = _versions(row.get("tls.handshake.version", ""))
        info["hello_version"] = hv[0] if hv else None
        info["supported"] = _versions(row.get("tls.handshake.extensions_supported_version", ""))
        info["ciphers"] = [
            n for n in (fp.to_int(v) for v in _values(row.get("tls.handshake.ciphersuite", "")))
            if n is not None and not fp.is_grease(n)
        ]
        info["ext_types"] = [
            n for n in (fp.to_int(v) for v in _values(row.get("tls.handshake.extension.type", "")))
            if n is not None
        ]
    return info


def build_observations(rows: list[dict], pcap_name: str, supported: dict[str, bool]) -> tuple[list[dict], dict[int, tuple[str, int]]]:
    """Hàm thuần: rows (đã parse từ TShark) -> (observations, client_hints cho flow_stats).

    supported: key nội bộ ('sni','ja3','ja3s','ja4',...) -> runtime có field đó không.
    """
    streams: dict[int, dict] = {}
    for row in rows:
        stream = _int(row.get("tcp.stream", ""))
        if stream is None:
            continue
        types = set(_values(row.get("tls.handshake.type", "")))
        is_ch, is_sh = "1" in types, "2" in types
        if not (is_ch or is_sh):
            continue
        st = streams.setdefault(stream, {"client": None, "server": None})
        info = _hello(row, multi=is_ch and is_sh)
        if is_ch and st["client"] is None:  # giữ ClientHello đầu tiên (bỏ qua bản gửi lại)
            st["client"] = info
        if is_sh and st["server"] is None:  # giữ ServerHello đầu tiên (xem giới hạn HRR trong báo cáo)
            st["server"] = info

    observations: list[dict] = []
    hints: dict[int, tuple[str, int]] = {}
    for stream, st in streams.items():
        c, s = st["client"], st["server"]
        if c:
            src_ip, src_port, dst_ip, dst_port = c["src_ip"], c["src_port"], c["dst_ip"], c["dst_port"]
        else:  # chỉ thấy ServerHello: client là bên nhận
            src_ip, src_port, dst_ip, dst_port = s["dst_ip"], s["dst_port"], s["src_ip"], s["src_port"]
        if src_ip and src_port is not None:
            hints[stream] = (src_ip, src_port)

        ja3 = c["ja3"] if c else None
        ja4 = c["ja4"] if c else None
        ja3s = s["ja3s"] if s else None
        sni = c["sni"] if c else None

        def why(side_seen: bool, key: str, value) -> str | None:
            if value is not None:
                return None
            if not side_seen:
                return fp.R_NO_CLIENT_HELLO if key in ("sni", "ja3", "ja4") else fp.R_NO_SERVER_HELLO
            if not supported.get(key, False):
                return fp.R_FIELD_UNSUPPORTED
            return fp.R_ABSENT_OR_HIDDEN if key == "sni" else fp.R_NOT_REPORTED

        reasons = {
            k: r
            for k, r in (
                ("sni", why(bool(c), "sni", sni)),
                ("ja3", why(bool(c), "ja3", ja3)),
                ("ja3s", why(bool(s), "ja3s", ja3s)),
                ("ja4", why(bool(c), "ja4", ja4)),
            )
            if r
        }

        ech = bool(c) and fp.ECH_EXTENSION_TYPE in c["ext_types"]
        notes: list[str] = []
        if not c:
            notes.append("Không thấy ClientHello: src/dst suy từ ServerHello; SNI/JA3/JA4 = null.")
        if not s:
            notes.append("Không thấy ServerHello: JA3S = null, phiên thương lượng không xác định.")
        if ech:
            notes.append("Có extension ECH: SNI (nếu có) là SNI ngoài, không chắc là tên miền đích thật.")
        if (c and c["ambiguous"]) or (s and s["ambiguous"]):
            notes.append("Một frame chứa cả ClientHello và ServerHello: version/cipher không được gán.")

        selected_version = None
        if s:
            selected_version = (s["supported"][0] if s["supported"] else s["hello_version"])

        obs = {
            "record_type": RECORD_TLS,
            "flow_id": f"{pcap_name}:tcp:{stream}",
            "src_ip": src_ip or "",
            "dst_ip": dst_ip or "",
            "sni": sni,
            "ja3": ja3,
            "ja3s": ja3s,
            "ja4": ja4,
            "fingerprint_status": fp.fingerprint_status(
                bool(c), bool(s), ja3, ja3s, supported.get("ja3", False), supported.get("ja3s", False)
            ),
            "packet_sizes_signed": [],
            # --- key bổ sung (additive, không đổi tên key của contract) ---
            "tcp_stream": stream,
            "src_port": src_port,
            "dst_port": dst_port,
            "timestamp": (c or s)["ts"],
            "first_frame": min(x["frame"] for x in (c, s) if x and x["frame"] is not None) if any(
                x and x["frame"] is not None for x in (c, s)) else None,
            "handshakes_observed": [n for n, x in (("client_hello", c), ("server_hello", s)) if x],
            "client_hello_version": fp.version_name(c["hello_version"]) if c else None,
            "client_supported_versions": [fp.version_name(v) for v in c["supported"]] if c else [],
            "negotiated_version": fp.version_name(selected_version),
            "cipher_suites_offered": [fp.hex16(n) for n in c["ciphers"]] if c else [],
            "cipher_suite_selected": fp.cipher_info(s["ciphers"][0]) if s and s["ciphers"] else None,
            "alpn_offered": c["alpn"] if c else [],
            "ech_extension_observed": ech,
            "null_reasons": reasons,
            "notes": notes,
            "packet_sizes_truncated": False,
            "packet_size_direction_basis": None,
        }
        observations.append(obs)

    observations.sort(key=lambda o: (o["first_frame"] is None, o["first_frame"] or 0))
    return observations, hints


def analyze_tls(
    pcap_path: str,
    max_packets: int = DEFAULT_MAX_PACKETS,
    timeout: int = DEFAULT_TIMEOUT,
) -> TLSAnalysis:
    """Chạy toàn bộ phân tích TLS và trả cả observation lẫn warning/capability.

    Ném TSharkNotFoundError (không có TShark) hoặc TSharkError (TShark lỗi / thiếu dissector TLS).
    """
    cmd = get_tshark_cmd()
    if cmd is None:
        raise TSharkNotFoundError(
            "Không tìm thấy TShark. Cài Wireshark/TShark hoặc đặt biến môi trường TSHARK_PATH."
        )
    caps: TSharkCapabilities = probe_tshark(cmd)
    result = TLSAnalysis(tshark_version=caps.version, tshark_cmd=" ".join(cmd))

    missing_req = [f for f in REQUIRED_FIELDS if not caps.has(f)]
    if missing_req:
        raise TSharkError(f"TShark thiếu field bắt buộc: {', '.join(missing_req)} (dissector TLS không khả dụng?)")

    resolved = {key: fp.resolve_field(key, caps.fields) for key in fp.OPTIONAL_FIELDS}
    supported = {key: name is not None for key, name in resolved.items()}
    result.fields_supported = {
        (resolved[key] or canonical): resolved[key] is not None for key, canonical in fp.OPTIONAL_FIELDS.items()
    }
    for key, canonical in fp.OPTIONAL_FIELDS.items():
        if not supported[key]:
            extra = f" {fp.JA4_NOTE}" if key == "ja4" else ""
            result.warnings.append(
                f"field_unsupported:{canonical}: TShark '{caps.version}' không có field này; giá trị tương ứng = null.{extra}"
            )

    fixed = BASE_COLUMNS + [f for f in IP_COLUMNS if caps.has(f)] + ["tls.handshake.type"]
    asked = fixed + [resolved[k] for k in fp.OPTIONAL_FIELDS if supported[k]]               # tên gửi cho TShark
    columns = fixed + [fp.OPTIONAL_FIELDS[k] for k in fp.OPTIONAL_FIELDS if supported[k]]   # tên chuẩn để parse
    args = ["-r", pcap_path, "-n", "-Y", HELLO_FILTER, "-T", "fields", "-E", "header=n",
            "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for col in asked:
        args += ["-e", col]
    rows = _parse_rows(run_tshark(caps.cmd, args, timeout), columns)

    pcap_name = os.path.basename(pcap_path)
    observations, hints = build_observations(rows, pcap_name, supported)
    result.observations = observations

    if observations:
        try:
            series = extract_packet_size_series(
                pcap_path,
                client_hints=hints,
                max_packets=max_packets,
                caps=caps,
                only_streams={o["tcp_stream"] for o in observations},
                timeout=timeout,
            )
            result.packet_size_definition = series["definition"]
            result.warnings.extend(series["warnings"])
            for obs in observations:
                flow = series["flows"].get(obs["flow_id"])
                if flow:
                    obs["packet_sizes_signed"] = flow["packet_sizes_signed"]
                    obs["packet_sizes_truncated"] = flow["truncated"]
                    obs["packet_size_direction_basis"] = flow["direction_basis"]
        except TSharkError as exc:
            result.warnings.append(f"packet_sizes_unavailable: {exc}; packet_sizes_signed = []")
    return result


def extract_tls_observations(pcap_path: str) -> list[dict]:
    """Giao diện public theo đề bài. Ném TSharkNotFoundError / TSharkError khi không chạy được TShark.

    Dùng analyze_tls() nếu cần cả warning và thông tin capability.
    """
    return analyze_tls(pcap_path).observations
