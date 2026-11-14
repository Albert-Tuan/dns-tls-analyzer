# Tuấn Anh contract v1.0 — căn cứ bản phân công không AI/ML

## APIs

```python
parse_dns_pcap(pcap_path: str) -> list[dict]
parse_dns_pcap_detailed(pcap_path: str, max_events: int = 1_000_000) -> ParseResult
group_dns_windows(dns_events: list[dict], seconds: int = 60) -> list[dict]
extract_tunnel_features(window: dict) -> dict
detect_tunnels(dns_events: list[dict], config: DetectorConfig | None = None) -> list[dict]
analyze_windows(dns_events: list[dict], config: DetectorConfig | None = None) -> list[dict]
normalize_qname(qname: str | bytes) -> dict | None
```

`ParseResult` có `.events`, `.stats`, `.warnings`. API list cũ ghi warning bằng logging; API detailed trả warning để xuất report. `CaptureError` kế thừa `ValueError`. Thiếu file: `FileNotFoundError`. Container corrupt/zero-byte: lỗi; container hợp lệ không packet: list rỗng. Malformed DNS bên trong capture hợp lệ: bỏ packet, warning.

## DNS event

| Key | Type | Ý nghĩa |
|---|---|---|
| timestamp | float hữu hạn | Epoch seconds, theo capture |
| src_ip / dst_ip | str | Hướng thực tế của packet |
| dns_id | int | Transaction ID |
| is_query | bool | true cho query |
| qname | str | ASCII/IDNA lower-case, bỏ đúng một dấu chấm cuối |
| registered_domain | str hoặc null | PSL bundled; không download |
| subdomain | str hoặc null | Có domain nhưng là apex: chuỗi rỗng; suffix unknown: null |
| qtype | str | A, AAAA, TXT, TYPE... |
| rcode | str hoặc null | Query null; response NOERROR/NXDOMAIN/... |
| packet_length | int | Số byte packet captured được decode, không phải độ dài dây gốc |
| frame_number | int | Bắt đầu từ 1, tính cả packet không DNS |

Không sửa events khi group/detect. Parser giữ thứ tự capture; windows sắp theo start, IP, domain; events trong window sắp timestamp.

Window có `src_ip`, `registered_domain`, `window_start`, `window_seconds`, `events`. Cửa sổ không chồng lấn: `[floor(t / seconds)*seconds, start+seconds)`.

## Finding / window assessment

Các key hợp đồng: `detector="dns_tunnel"`, `classification="suspected_dns_tunnel"`, `src_ip`, `registered_domain`, `window_start`, `window_seconds`, `score`, `features`, `reasons`.

Key bổ sung tương thích: `signal_groups` (list), `eligible` (bool). `analyze_windows` còn trả các window có classification `not_flagged`. `detect_tunnels` chỉ trả findings nghi ngờ, vì vậy vẫn dùng được khi Nhi đếm `len(findings)`.

Features: query_count, unique_qnames, unique_subdomain_count/ratio, avg/max_subdomain_length, avg_subdomain_entropy, qtype_distribution, txt_ratio, queries_per_second, mean_interarrival_seconds, interarrival_cv, nxdomain_ratio. Mẫu số ratio uniqueness và TXT là toàn bộ query trong window. Length/entropy loại dấu chấm và lấy trung bình cả query apex (giá trị 0), tránh tăng giả chỉ vì bỏ các query không subdomain. Dùng độ chính xác đầy đủ khi so ngưỡng. Không tính NXDOMAIN ratio vì chưa ghép response.

## Các warning

`ip_fragment_not_reassembled`, `tcp_dns_not_supported`, `non_standard_dns_opcode`, `unsupported_question_count`, `unsupported_binary_qname`, `invalid_or_unsupported_qname`, `unknown_suffix_or_reverse_name`, `malformed_dns_packet`.

Mỗi warning có số lượng và frame đầu tiên. Warnings fragment có thể bao gồm packet không DNS vì chưa reassembly để biết upper protocol đầy đủ. Unknown-suffix là event được giữ; các warning skip khác thường không tạo event.

## Thay đổi so với starter

- Không còn bỏ im lặng domain không có suffix: giữ event và cảnh báo, bỏ khỏi detector.
- `.test` hỗ trợ rõ cho lab; private PSL entries không bật.
- Window được sắp thời gian trước IP/domain.
- Average length/entropy bao gồm query apex; quyết định không dựa trên số đã làm tròn.
- Length và entropy cùng nhóm shape, không tính là hai tín hiệu độc lập.
- Thêm detailed parse, toàn bộ window assessments, config, CSV, evaluation; API và key P0 giữ nguyên.
