from app.dns.windowing import group_dns_windows
from app.tunneling.features import extract_tunnel_features, shannon_entropy
from app.tunneling.detector import detect_tunnels


def event(i, sub="", ip="192.0.2.10", domain="example.com", timestamp=None, query=True):
    return {
        "timestamp": 1800000000 + i if timestamp is None else timestamp,
        "src_ip": ip,
        "dst_ip": "192.0.2.53",
        "registered_domain": domain,
        "subdomain": sub,
        "qname": (sub + "." if sub else "") + domain,
        "qtype": "TXT",
        "is_query": query,
    }


def test_entropy_known_value():
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("ab") == 1


def test_single_long_query_not_tunnel():
    assert detect_tunnels([event(0, "a" * 50)]) == []


def test_many_repeated_names_are_not_unique():
    many = [event(i, "same") for i in range(40)]
    windows = group_dns_windows(many)
    assert len(windows) == 1
    features = extract_tunnel_features(windows[0])
    assert features["query_count"] == 40
    assert features["unique_subdomain_count"] == 1
    assert features["unique_subdomain_ratio"] == 0.025
    assert detect_tunnels(many) == []


def test_synthetic_tunnel_like_traffic_is_flagged():
    # Deterministic 40 distinct long names containing a numeric prefix.
    names = [f"{i:04d}" + ("abcdefghijklmnopqrstuv" * 2)[i % 3:i % 3 + 36] for i in range(40)]
    many = [event(i, s) for i, s in enumerate(names)]
    alerts = detect_tunnels(many)
    assert len(alerts) == 1
    assert alerts[0]["classification"] == "suspected_dns_tunnel"
    assert len(alerts[0]["reasons"]) >= 3


def test_response_is_not_counted():
    events = [event(i, "same", query=False) for i in range(40)]
    assert group_dns_windows(events) == []
    assert detect_tunnels(events) == []


def test_separate_clients():
    many = [event(i, f"x{i:03d}" + "abcdef" * 6, ip="192.0.2.10") for i in range(30)]
    many += [event(i, f"z{i:03d}" + "abcdef" * 6, ip="192.0.2.11") for i in range(30)]
    assert len(group_dns_windows(many)) == 2


def test_window_boundary():
    # Windows anchored to Unix epoch, not first-packet timestamp.
    events = [event(0, "a", timestamp=59.999), event(1, "b", timestamp=60.0)]
    assert sorted(w["window_start"] for w in group_dns_windows(events)) == [0.0, 60.0]


def test_out_of_order_events():
    events = [event(4, "a"), event(1, "b"), event(2, "c")]
    windows = group_dns_windows(events)
    assert len(windows) == 1
    stamps = [e["timestamp"] for e in windows[0]["events"]]
    assert stamps == sorted(stamps)


def test_invalid_window_size():
    import pytest
    with pytest.raises(ValueError):
        group_dns_windows([], seconds=0)


def test_empty_window_features():
    f = extract_tunnel_features({"events": []})
    assert f["query_count"] == 0
    assert f["nxdomain_ratio"] is None
    assert f["mean_interarrival_seconds"] is None
