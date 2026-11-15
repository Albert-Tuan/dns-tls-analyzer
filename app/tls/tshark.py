"""Lớp bọc mỏng quanh TShark. Mọi lệnh đều chạy qua subprocess.run(shell=False, timeout=...).

Không có giá trị nào được "đoán": nếu TShark thiếu hoặc lỗi, ném TSharkNotFoundError / TSharkError
để tầng trên quyết định (cảnh báo hoặc fail) theo chính sách đã ghi trong README.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

DEFAULT_TIMEOUT = 180  # giây

_WINDOWS_DEFAULTS = (
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
)


class TSharkError(RuntimeError):
    """TShark chạy lỗi (exit code != 0, timeout, hoặc thiếu dissector cần thiết)."""


class TSharkNotFoundError(TSharkError):
    """Không tìm thấy TShark trên máy."""


def get_tshark_cmd() -> list[str] | None:
    """Trả về lệnh gọi TShark (list để dùng với shell=False), hoặc None nếu không có.

    Thứ tự: biến môi trường TSHARK_PATH -> PATH -> vị trí cài mặc định trên Windows.
    """
    env = os.environ.get("TSHARK_PATH")
    if env:
        return [env] if os.path.isfile(env) else None
    found = shutil.which("tshark")
    if found:
        return [found]
    for candidate in _WINDOWS_DEFAULTS:
        if os.path.isfile(candidate):
            return [candidate]
    return None


def run_tshark(cmd: list[str], args: list[str], timeout: int = DEFAULT_TIMEOUT) -> str:
    """Chạy TShark và trả stdout. Ném TSharkError nếu exit code != 0 hoặc timeout."""
    full = list(cmd) + list(args)
    try:
        proc = subprocess.run(
            full,
            shell=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise TSharkNotFoundError(f"không chạy được TShark: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise TSharkError(f"TShark quá thời gian chờ {timeout}s") from exc
    except OSError as exc:
        raise TSharkError(f"lỗi hệ điều hành khi chạy TShark: {exc}") from exc
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip().replace("\n", " ")[:400]
        raise TSharkError(f"TShark thoát với exit code {proc.returncode}: {stderr or '(không có stderr)'}")
    return proc.stdout


@dataclass
class TSharkCapabilities:
    cmd: list[str]
    version: str
    fields: frozenset[str] = field(default_factory=frozenset)

    def has(self, name: str) -> bool:
        return name in self.fields


def parse_version(output: str) -> str:
    for line in output.splitlines():
        if line.strip():
            return line.strip()
    return "unknown"


def parse_fields(output: str) -> frozenset[str]:
    """Đọc đầu ra của `tshark -G fields`: dòng 'F<TAB>tên<TAB>abbrev<TAB>kiểu...'."""
    names = set()
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0] == "F":
            names.add(parts[2])
    return frozenset(names)


def probe_tshark(cmd: list[str], timeout: int = 60) -> TSharkCapabilities:
    """Kiểm tra capability lúc chạy: phiên bản + danh sách field thực sự có (`tshark -G fields`)."""
    version = parse_version(run_tshark(cmd, ["--version"], timeout))
    fields = parse_fields(run_tshark(cmd, ["-G", "fields"], timeout))
    return TSharkCapabilities(cmd=list(cmd), version=version, fields=fields)
