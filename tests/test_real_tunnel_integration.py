from pathlib import Path

from app.main import run_pipeline


def test_cli_routes_tunnel_fixture_to_real_detector():
    capture = Path(__file__).resolve().parents[1] / "samples" / "synthetic_tunnel_like_dns.pcap"
    report, flags = run_pipeline(str(capture))

    assert not flags["module_error"]
    assert report["metadata"]["module_status"]["detect_tunnels"] == "ok"
    assert report["dns_events_summary"]["query_count"] == 40
    findings = report["dns_tunnel_findings"]
    assert len(findings) == 1
    assert findings[0]["classification"] == "suspected_dns_tunnel"
    assert findings[0]["registered_domain"] == "example.com"
