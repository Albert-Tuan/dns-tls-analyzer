# PCAP trong gói

Tất cả là synthetic offline, không phải malware thật. Xem `provenance.json`, `dev_manifest.json`, `test_manifest.json` và `../docs/DATASET_AND_EVALUATION.md`. Chạy lại bằng `python -m scripts.make_demo_pcap`.

`empty.pcap` có header hợp lệ nhưng không packet; zero-byte file là invalid. `no_dns.pcap` chứa TCP SYN port 443, **không phải TLS handshake thật**. `dns.pcapng` dùng để test định dạng container.

File cố định `tls_clienthello_only.pcap` chứa một ClientHello sinh từ Python/OpenSSL MemoryBIO cho www.example.org và được đóng gói vào một TCP frame bằng Scapy. Test dùng file này để kiểm tra capture chỉ có TLS cho 0 DNS event. File có sẵn sau khi clone và độc lập với generator DNS.
