import pytest
from scripts.verify_tshark import compare_row, ParityError


def row(flags="0x0100", ident="0010", name="www.example.com.", address="192.0.2.10"):
    return "\t".join(["1", "1794000000.000000000", address, "", ident, flags, name, "1"])


def event(is_query=True):
    return dict(frame_number=1, timestamp=1794000000.0, src_ip="192.0.2.10",
                dns_id=10, is_query=is_query, qname="www.example.com", qtype="A")


@pytest.mark.parametrize("flags,query", [("0x0100", True), ("33152", False)])
def test_qr_from_dns_header(flags, query):
    compare_row("sample.pcap", row(flags=flags, ident="0x000a"), event(query))


def test_dns_id_decimal_display():
    compare_row("sample.pcap", row(), event())


def test_incorrect_query_flag_reports_frame_and_values():
    with pytest.raises(ParityError, match=r"sample.pcap, parser frame 1.*QR.*TShark=False, parser=True"):
        compare_row("sample.pcap", row("0x8180"), event())


def test_non_numeric_flags_do_not_pass_as_response():
    with pytest.raises(ParityError, match=r"dns.flags.*invalid TShark value"):
        compare_row("sample.pcap", row("unknown"), event(False))


def test_other_mismatches_still_fail():
    with pytest.raises(ParityError, match=r"dns.qry.name.*other.example.com.*www.example.com"):
        compare_row("sample.pcap", row(name="other.example.com"), event())


def test_runner_records_attempted_failure(tmp_path, monkeypatch):
    import json
    import subprocess
    from types import SimpleNamespace
    from scripts import run_all

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(run_all, "ROOT", tmp_path)
    monkeypatch.setattr(run_all.shutil, "which", lambda name: "/test/tshark")

    def fixture_command(cmd, **kwargs):
        failed = cmd[2] == "scripts.verify_tshark"
        return subprocess.CompletedProcess(cmd, int(failed), "", "field mismatch" if failed else "")

    monkeypatch.setattr(run_all, "subprocess", SimpleNamespace(run=fixture_command))
    assert run_all.main() == 1
    report = json.loads((tmp_path / "reports/acceptance.json").read_text())
    assert (report["status"], report["tshark_parity"]) == ("failed", "failed")
    assert report["steps"][-1]["step"] == "10_tshark_0"
