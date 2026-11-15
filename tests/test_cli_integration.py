"""Test tích hợp CLI + pipeline + exporter. Chạy được bằng unittest hoặc pytest.

DNS/DGA/tunnel dùng hàm giả theo đúng contract (TV1/TV2 chưa nối); TLS dùng TShark GIẢ (tests/fake_tshark.py).
Vì vậy đây là kiểm thử logic tích hợp, KHÔNG thay cho demo chạy thật với TShark và PCAP thật (xem README).
"""
import contextlib
import io
import json
import math
import os
import tempfile
import unittest
from unittest import mock

from app import main as cli
from app.core.pcap_utils import PcapError, inspect_pcap
from app.core.report_exporter import build_report
from app.core.schemas import validate_report
from tests import helpers as h

DNS_EVENTS = [
    {"timestamp": 1794000000.0, "src_ip": "192.0.2.10", "dst_ip": "192.0.2.53", "dns_id": 1234, "is_query": True,
     "qname": "ab12.example.test", "registered_domain": "example.test", "subdomain": "ab12", "qtype": "A",
     "rcode": None, "packet_length": 91, "frame_number": 15},
    {"timestamp": 1794000000.1, "src_ip": "192.0.2.53", "dst_ip": "192.0.2.10", "dns_id": 1234, "is_query": False,
     "qname": "ab12.example.test", "registered_domain": "example.test", "subdomain": "ab12", "qtype": "A",
     "rcode": 0, "packet_length": 120, "frame_number": 16},
]
DGA = [{"detector": "dga", "classification": "suspicious_dga", "target": "ab12.example.test", "score": 65,
        "features": {"entropy": 1.98}, "reasons": ["high_digit_ratio"]}]
TUNNEL = [{"detector": "dns_tunnel", "classification": "suspected_dns_tunnel", "src_ip": "192.0.2.10",
           "registered_domain": "example.test", "window_start": 1794000000.0, "window_seconds": 60, "score": 70,
           "features": {"query_count": 30}, "reasons": ["many_unique_subdomains"]}]

FAKE_FUNCS = {
    "parse_dns_pcap": lambda pcap: list(DNS_EVENTS),
    "analyze_dns_domains": lambda events: list(DGA),
    "detect_tunnels": lambda events: list(TUNNEL),
}


def run_cli(pcap, output, *extra, funcs=None):
    """Chạy main() trong tiến trình; trả (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    funcs = FAKE_FUNCS if funcs is None else funcs
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(cli, "resolve_functions", return_value=funcs):
        code = cli.main(["analyze", "--pcap", pcap, "--output", output, *extra])
    return code, out.getvalue(), err.getvalue()


def strict_json_load(path):
    def reject(const):
        raise ValueError(f"JSON không chuẩn: {const}")
    with open(path, encoding="utf-8") as f:
        return json.load(f, parse_constant=reject)


class CLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = self.tmp.name
        self.out = os.path.join(self.dir, "reports", "out.json")
        self.pcap = h.write_pcap(os.path.join(self.dir, "demo.pcap"), packets=3)

    # --- lỗi đầu vào: exit != 0 và KHÔNG sinh báo cáo ---
    def test_missing_file_exits_1_and_writes_nothing(self):
        code, _, err = run_cli(os.path.join(self.dir, "nope.pcap"), self.out)
        self.assertEqual(code, 1)
        self.assertIn("không tìm thấy", err)
        self.assertFalse(os.path.exists(self.out))

    def test_garbage_file_exits_1(self):
        bad = os.path.join(self.dir, "bad.pcap")
        with open(bad, "wb") as f:
            f.write(b"this is definitely not a pcap file at all")
        code, _, err = run_cli(bad, self.out)
        self.assertEqual(code, 1)
        self.assertIn("không hợp lệ", err)
        self.assertFalse(os.path.exists(self.out))

    def test_truncated_pcap_exits_1(self):
        bad = h.write_pcap(os.path.join(self.dir, "cut.pcap"), packets=2, truncate_last=2)
        code, _, _ = run_cli(bad, self.out)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(self.out))

    def test_output_equal_to_input_is_refused(self):
        code, _, err = run_cli(self.pcap, self.pcap)
        self.assertEqual(code, 1)
        self.assertIn("trùng", err)

    # --- PCAP trống ---
    def test_empty_pcap_gives_valid_empty_report(self):
        empty = h.write_pcap(os.path.join(self.dir, "empty.pcap"), packets=0)
        code, _, _ = run_cli(empty, self.out)
        self.assertEqual(code, 0)
        rep = strict_json_load(self.out)
        self.assertEqual(validate_report(rep), [])
        self.assertEqual(rep["metadata"]["packet_count"], 0)
        self.assertEqual(rep["tls_observations"], [])
        self.assertTrue(any("pcap_has_no_packets" in w for w in rep["metadata"]["warnings"]))

    # --- mixed: ba module chạy qua cùng CLI ---
    def test_mixed_pipeline_with_fake_tshark_and_fixtures(self):
        with h.fake_tshark(self.dir):
            code, stdout, _ = run_cli(self.pcap, self.out)
        self.assertEqual(code, 0)
        rep = strict_json_load(self.out)
        self.assertEqual(validate_report(rep), [])
        s = rep["summary"]
        # số lượng đếm theo record thật
        self.assertEqual((s["dns_event_count"], s["dga_findings_count"], s["dns_tunnel_findings_count"],
                          s["tls_observation_count"]), (2, 1, 1, 2))
        self.assertEqual(s["dga_suspicious_count"], 1)
        self.assertEqual(rep["dns_events_summary"]["query_count"], 1)      # response không bị tính là query
        self.assertEqual(rep["dns_events_summary"]["response_count"], 1)
        self.assertEqual(s["tls_shared_ja3_groups"][0]["flow_count"], 2)
        self.assertEqual(rep["metadata"]["packet_count"], 3)
        self.assertEqual(rep["metadata"]["module_status"]["tls_extractor"], "ok")
        self.assertTrue(rep["metadata"]["tshark"]["available"])
        self.assertIn("Đã phân tích: demo.pcap", stdout)

    def test_tls_only_pcap_has_no_dns_findings(self):
        funcs = {"parse_dns_pcap": lambda p: [], "analyze_dns_domains": lambda e: [], "detect_tunnels": lambda e: []}
        with h.fake_tshark(self.dir):
            code, _, _ = run_cli(self.pcap, self.out, funcs=funcs)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertEqual((rep["dga_findings"], rep["dns_tunnel_findings"]), ([], []))
        self.assertEqual(len(rep["tls_observations"]), 2)

    def test_dns_only_pcap_has_empty_tls(self):
        with h.fake_tshark(self.dir, hello=[], tcp=[]):
            code, _, _ = run_cli(self.pcap, self.out)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertEqual(rep["tls_observations"], [])
        self.assertEqual(rep["summary"]["dga_findings_count"], 1)

    # --- thiếu TShark / JA4 ---
    def test_missing_tshark_default_policy_warns_and_keeps_dns(self):
        with h.no_tshark():
            code, _, err = run_cli(self.pcap, self.out)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertFalse(rep["metadata"]["tshark"]["available"])
        self.assertEqual(rep["tls_observations"], [])
        self.assertEqual(rep["summary"]["dga_findings_count"], 1)
        self.assertTrue(any(w.startswith("tshark_unavailable") for w in rep["metadata"]["warnings"]))
        self.assertIn("WARNING: tshark_unavailable", err)

    def test_missing_tshark_strict_exits_3_but_still_writes_report(self):
        with h.no_tshark():
            code, _, _ = run_cli(self.pcap, self.out, "--strict")
        self.assertEqual(code, 3)
        self.assertTrue(os.path.exists(self.out))

    def test_tshark_without_ja4_pipeline_ok_with_null_ja4_and_warning(self):
        with h.fake_tshark(self.dir, drop_fields=["tls.handshake.ja4"]):
            code, _, _ = run_cli(self.pcap, self.out)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertTrue(all(o["ja4"] is None for o in rep["tls_observations"]))
        self.assertEqual(rep["summary"]["tls_flows_with_ja4"], 0)
        self.assertTrue(any("tls.handshake.ja4" in w for w in rep["metadata"]["warnings"]))

    def test_tshark_failure_on_file_degrades_with_reason(self):
        with h.fake_tshark(self.dir, fail_exit=True):
            code, _, _ = run_cli(self.pcap, self.out)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertEqual(rep["metadata"]["module_status"]["tls_extractor"], "tshark_error")
        self.assertEqual(rep["tls_observations"], [])

    # --- module TV1/TV2 thiếu hoặc lỗi ---
    def test_missing_dns_modules_are_reported_not_faked(self):
        none_funcs = {"parse_dns_pcap": None, "analyze_dns_domains": None, "detect_tunnels": None}
        with h.fake_tshark(self.dir):
            code, _, _ = run_cli(self.pcap, self.out, funcs=none_funcs)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 0)
        self.assertEqual(rep["summary"]["dns_event_count"], 0)
        self.assertTrue(any(w.startswith("module_missing:parse_dns_pcap") for w in rep["metadata"]["warnings"]))
        code2, _, _ = run_cli(self.pcap, self.out, "--strict", funcs=none_funcs)
        self.assertEqual(code2, 3)

    def test_module_exception_exits_5_with_cause_and_partial_report(self):
        def boom(events):
            raise RuntimeError("lỗi giả lập của module DGA")
        funcs = dict(FAKE_FUNCS, analyze_dns_domains=boom)
        with h.fake_tshark(self.dir):
            code, _, _ = run_cli(self.pcap, self.out, funcs=funcs)
        rep = strict_json_load(self.out)
        self.assertEqual(code, 5)
        self.assertTrue(any("module_error:analyze_dns_domains: RuntimeError" in w for w in rep["metadata"]["warnings"]))
        self.assertEqual(len(rep["dns_tunnel_findings"]), 1)  # phần còn lại vẫn được giữ

    def test_argparse_requires_pcap_and_output(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            cli.main(["analyze", "--pcap", self.pcap])
        self.assertEqual(ctx.exception.code, 2)


class ExporterAndPcapUtilsTests(unittest.TestCase):
    def test_build_report_sanitizes_nan_and_validates(self):
        dga = [{"classification": "suspicious_dga", "score": float("nan"), "features": {"entropy": float("inf")}}]
        rep = build_report("x.pcap", [], dga, [], [])
        self.assertEqual(validate_report(rep), [])
        text = json.dumps(rep, allow_nan=False)  # không ném lỗi = không còn NaN/Inf
        self.assertNotIn("NaN", text)
        self.assertTrue(math.isfinite(1.0))
        self.assertIsNone(rep["dga_findings"][0]["score"])

    def test_validate_report_detects_missing_and_wrong_types(self):
        errs = validate_report({"metadata": {}, "tls_observations": [{"record_type": "tls_observation"}]})
        self.assertTrue(any("thiếu key 'summary'" in e for e in errs))
        self.assertTrue(any("tls_observations[0]" in e for e in errs))

    def test_inspect_pcap_counts_classic_and_pcapng(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(inspect_pcap(h.write_pcap(os.path.join(d, "a.pcap"), 4))["packet_count"], 4)
            info = inspect_pcap(h.write_pcapng(os.path.join(d, "b.pcapng"), 2))
            self.assertEqual((info["format"], info["packet_count"]), ("pcapng", 2))
            self.assertEqual(len(info["sha256"]), 64)
            with self.assertRaises(PcapError):
                inspect_pcap(h.write_pcap(os.path.join(d, "c.pcap"), 2, truncate_last=1))


if __name__ == "__main__":
    unittest.main()
