"""Demonstrate rule-only features without Scapy (using synthetic event objects)."""
from app.tunneling.detector import detect_tunnels
from app.dns.windowing import group_dns_windows
from app.tunneling.features import extract_tunnel_features
import json
import random


def main():
    rng = random.Random(20261109)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    events = []
    for i in range(40):
        sub = "".join(rng.choice(alphabet) for _ in range(38))
        events.append({
            "is_query": True, "timestamp": 1794000000 + i,
            "src_ip": "192.0.2.11", "registered_domain": "example.com",
            "qname": f"{sub}.example.com", "subdomain": sub, "qtype": "TXT",
        })
    windows = group_dns_windows(events)
    alerts = detect_tunnels(events)
    print(json.dumps({"windows": len(windows), "features": extract_tunnel_features(windows[0]),
                      "alerts": alerts}, indent=2, allow_nan=False))
    print("Synthetic simulation, not proof of a real attack.")


if __name__ == "__main__":
    main()
