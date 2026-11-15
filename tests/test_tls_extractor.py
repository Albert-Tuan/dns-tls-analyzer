"""Test TLS extractor / flow_stats / fingerprint. Chạy được bằng unittest hoặc pytest.

Các test dùng TShark GIẢ (tests/fake_tshark.py) phát lại dữ liệu fixture; xem README.
"""
import copy
import tempfile
import unittest

from app.core.schemas import FP_COMPLETE, FP_PARTIAL, FP_UNAVAILABLE, validate_tls_observation
from app.tls import extractor, flow_stats
from app.tls.extractor import analyze_tls, build_observations
from app.tls.fingerprint import group_shared_fingerprints, is_grease
from app.tls.tshark import TSharkError, TSharkNotFoundError
from tests import helpers as h

ALL_SUPPORTED = {k: True for k in ("sni", "ja3", "ja3s", "ja4", "hello_version", "supported_versions",
                                   "ciphersuite", "alpn", "ext_types")}


def by_flow(observations):
    return {o["flow_id"]: o for o in observations}


class TLSExtractorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    # --- gộp ClientHello/ServerHello ---
    def test_complete_tls13_flow_merges_both_hellos(self):
        obs, _ = build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)
        o = by_flow(obs)["cap.pcap:tcp:0"]
        self.assertEqual(validate_tls_observation(o), [])
        self.assertEqual((o["src_ip"], o["dst_ip"]), (h.C, h.S))
        self.assertEqual(o["sni"], "example.org")
        self.assertEqual((o["ja3"], o["ja3s"], o["ja4"]), (h.JA3_A, h.JA3S_A, h.JA4_A))
        self.assertEqual(o["fingerprint_status"], FP_COMPLETE)
        self.assertEqual(o["handshakes_observed"], ["client_hello", "server_hello"])
        self.assertEqual(o["negotiated_version"], "TLS 1.3")
        self.assertEqual(o["cipher_suite_selected"]["id"], "0x1301")
        self.assertEqual(o["null_reasons"], {})

    def test_grease_values_are_removed(self):
        self.assertTrue(is_grease(0x0A0A) and is_grease(0xFAFA))
        self.assertFalse(is_grease(0x1301))
        obs, _ = build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)
        o = by_flow(obs)["cap.pcap:tcp:0"]
        self.assertEqual(o["cipher_suites_offered"], ["0x1301", "0xc02f"])
        self.assertEqual(o["client_supported_versions"], ["TLS 1.3", "TLS 1.2"])

    def test_tls13_output_makes_no_certificate_claim(self):
        obs, _ = build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)
        for o in obs:
            self.assertFalse([k for k in o if "cert" in k.lower()])

    def test_client_hello_only_is_partial_with_reasons(self):
        o = by_flow(build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)[0])["cap.pcap:tcp:1"]
        self.assertEqual(o["fingerprint_status"], FP_PARTIAL)
        self.assertIsNone(o["ja3s"])
        self.assertEqual(o["null_reasons"]["ja3s"], "server_hello_not_captured")
        self.assertEqual(o["null_reasons"]["sni"], "extension_absent_or_hidden")
        self.assertIsNone(o["negotiated_version"])

    def test_server_hello_only_derives_client_from_destination(self):
        rows = [r for r in h.hello_rows() if r["tls.handshake.type"] == "2"]
        obs, hints = build_observations(rows, "cap.pcap", ALL_SUPPORTED)
        o = obs[0]
        self.assertEqual((o["src_ip"], o["dst_ip"]), (h.C, h.S))
        self.assertEqual(o["fingerprint_status"], FP_PARTIAL)
        self.assertIsNone(o["ja3"])
        self.assertEqual(o["null_reasons"]["ja3"], "client_hello_not_captured")
        self.assertEqual(hints[0], (h.C, 49152))

    def test_ech_extension_flagged_and_noted(self):
        o = by_flow(build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)[0])["cap.pcap:tcp:0"]
        self.assertTrue(o["ech_extension_observed"])
        self.assertTrue(any("ECH" in n for n in o["notes"]))

    def test_flow_id_uses_pcap_basename(self):
        obs, _ = build_observations(h.hello_rows(), "capture.pcap", ALL_SUPPORTED)
        self.assertTrue(all(o["flow_id"].startswith("capture.pcap:tcp:") for o in obs))

    def test_unsupported_field_gives_specific_reason(self):
        sup = dict(ALL_SUPPORTED, ja4=False)
        rows = copy.deepcopy(h.hello_rows())
        for r in rows:
            r.pop("tls.handshake.ja4", None)
        o = by_flow(build_observations(rows, "cap.pcap", sup)[0])["cap.pcap:tcp:0"]
        self.assertIsNone(o["ja4"])
        self.assertEqual(o["null_reasons"]["ja4"], "field_not_supported_by_tshark")

    def test_fingerprint_unavailable_when_runtime_lacks_ja3_and_ja3s(self):
        sup = dict(ALL_SUPPORTED, ja3=False, ja3s=False)
        o = build_observations(h.hello_rows(), "cap.pcap", sup)[0][0]
        self.assertEqual(o["fingerprint_status"], FP_UNAVAILABLE)

    # --- nhóm fingerprint dùng chung ---
    def test_shared_ja3_groups_flows_without_verdict(self):
        obs, _ = build_observations(h.hello_rows(), "cap.pcap", ALL_SUPPORTED)
        groups = group_shared_fingerprints(obs, "ja3")
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["flow_count"], 2)
        self.assertNotIn("malicious", str(groups).lower())

    # --- end-to-end qua TShark giả ---
    def test_analyze_tls_attaches_packet_sizes_from_correct_stream(self):
        with h.fake_tshark(self.tmp.name):
            res = analyze_tls("/x/cap.pcap")
        o = by_flow(res.observations)
        self.assertEqual(o["cap.pcap:tcp:0"]["packet_sizes_signed"], [314, -1200, 150])
        self.assertEqual(o["cap.pcap:tcp:1"]["packet_sizes_signed"], [500])  # không lẫn stream 0
        self.assertEqual(o["cap.pcap:tcp:0"]["packet_size_direction_basis"], "client_hello")
        self.assertIn("4.2.2", res.tshark_version)

    def test_analyze_tls_without_ja4_field_warns_and_does_not_crash(self):
        with h.fake_tshark(self.tmp.name, drop_fields=["tls.handshake.ja4"]):
            res = analyze_tls("cap.pcap")
        self.assertTrue(any("field_unsupported:tls.handshake.ja4" in w for w in res.warnings))
        self.assertTrue(all(o["ja4"] is None for o in res.observations))
        self.assertTrue(all(o["null_reasons"].get("ja4") for o in res.observations))
        self.assertEqual(by_flow(res.observations)["cap.pcap:tcp:0"]["ja3"], h.JA3_A)

    def test_pcap_without_tls_returns_empty_list(self):
        with h.fake_tshark(self.tmp.name, hello=[], tcp=[]):
            self.assertEqual(extractor.extract_tls_observations("dns_only.pcap"), [])

    def test_missing_tshark_raises_not_found(self):
        with h.no_tshark():
            with self.assertRaises(TSharkNotFoundError):
                extractor.extract_tls_observations("cap.pcap")

    def test_tshark_nonzero_exit_raises_tshark_error_with_stderr(self):
        with h.fake_tshark(self.tmp.name, fail_exit=True):
            with self.assertRaises(TSharkError) as ctx:
                analyze_tls("broken.pcap")
        self.assertIn("exit code 2", str(ctx.exception))
        self.assertIn("damaged", str(ctx.exception))


class FieldAliasTests(unittest.TestCase):
    def test_resolve_prefers_new_name_and_falls_back_to_old(self):
        from app.tls.fingerprint import resolve_field
        new, old = "tls.handshake.extensions.supported_version", "tls.handshake.extensions_supported_version"
        self.assertEqual(resolve_field("supported_versions", {new}), new)
        self.assertEqual(resolve_field("supported_versions", {old}), old)
        self.assertIsNone(resolve_field("supported_versions", {"tls.handshake.ja3"}))
        self.assertEqual(resolve_field("ja4", {"tls.handshake.ja4"}), "tls.handshake.ja4")


class PacketSizeSeriesTests(unittest.TestCase):
    def test_sign_follows_client_direction_and_skips_ack_and_retransmission(self):
        flows = flow_stats.series_from_rows(h.tcp_rows(), "cap.pcap", retrans_frames={7})
        f = flows["cap.pcap:tcp:0"]
        self.assertEqual(f["packet_sizes_signed"], [314, -1200, 150])
        self.assertEqual(f["retransmissions_skipped"], 1)
        self.assertEqual(f["direction_basis"], "syn")  # không có hint -> dùng SYN

    def test_client_hint_overrides_syn_inference(self):
        flows = flow_stats.series_from_rows(h.tcp_rows(), "cap.pcap", {7}, client_hints={0: (h.S, 443)})
        self.assertEqual(flows["cap.pcap:tcp:0"]["packet_sizes_signed"], [-314, 1200, -150])

    def test_series_truncated_to_max_packets(self):
        rows = h._strs([{"frame.number": i, "tcp.stream": 5, "ip.src": h.C, "tcp.srcport": 1000,
                         "frame.len": 100 + i, "tcp.len": 10, "tcp.flags.syn": 0, "tcp.flags.ack": 1}
                        for i in range(1, 121)])
        f = flow_stats.series_from_rows(rows, "big.pcap", max_packets=50)["big.pcap:tcp:5"]
        self.assertEqual(len(f["packet_sizes_signed"]), 50)
        self.assertTrue(f["truncated"])
        self.assertEqual(f["payload_packets_total"], 120)
        self.assertEqual(f["direction_basis"], "first_packet")  # không SYN, không hint

    def test_only_streams_filter(self):
        flows = flow_stats.series_from_rows(h.tcp_rows(), "cap.pcap", only_streams={1})
        self.assertEqual(list(flows), ["cap.pcap:tcp:1"])


if __name__ == "__main__":
    unittest.main()
