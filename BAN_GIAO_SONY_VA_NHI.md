# Tuấn Anh bàn giao phần DNS cho Sony và Nhi

## Gói bàn giao và quyền sở hữu

Tuấn Anh giao thư mục `app/dns/`, `app/tunneling/`, cấu hình `configs/frozen.json`, các tests và samples liên quan. Giữ nguyên `app/__init__.py` của repo nhóm. Không đè `app/main.py`, `app/core/`, `app/dga/`, `app/tls/`.

Dependencies runtime: `scapy`, `dnspython`, `tldextract`; tests dùng `pytest`. Bản chạy đã kiểm tra dùng Scapy 2.8.0, dnspython 2.9.2, tldextract 5.4.0, pytest 9.2.0. Nhi hợp nhất requirements; không thay nguyên file dependencies nhóm nếu có thư viện khác.

## Sony: nhận event, tái sử dụng domain normalization

```python
from app.dns.normalization import normalize_qname
from app.dns.parser import parse_dns_pcap

parts = normalize_qname("Foo.Example.CO.UK.")
assert parts["registered_domain"] == "example.co.uk"
events = parse_dns_pcap("samples/benign_dns.pcap")
query_events = [e for e in events if e["is_query"] and e["registered_domain"]]
# Truyền query_events vào hàm analyze_dns_domains của Sony.
```

Trong pipeline chung Sony không tự gọi parser lần nữa: nhận `events` do Nhi truyền. Alias `app.dns.normalize` cùng export `normalize_qname` để tương thích tên import cũ. `.test` được tách riêng cho fixture; suffix lạ có registered_domain null. Không dùng `split('.')[-2:]` để thay helper.

## Nhi: parse một lần và ghép report

```python
from app.dns.parser import parse_dns_pcap_detailed
from app.tunneling.detector import DetectorConfig, detect_tunnels

parsed = parse_dns_pcap_detailed(pcap_path)
dns_events = parsed.events
cfg = DetectorConfig.from_file("configs/frozen.json")

# dga_findings = analyze_dns_domains(dns_events)
# tls_observations = extract_tls_observations(pcap_path)
tunnel_findings = detect_tunnels(dns_events, cfg)

report["dns_events_summary"] = parsed.stats
report["dns_tunnel_findings"] = tunnel_findings
report["summary"]["dns_queries"] = parsed.stats["dns_queries"]
report["summary"]["dns_tunnel_alerts"] = len(tunnel_findings)
report.setdefault("metadata", {}).setdefault("warnings", []).extend(parsed.warnings)
# Giữ nguyên các key metadata/dga_findings/tls_observations do nhóm đã xây dựng.
```

Đây là đoạn chèn vào code hiện tại, không phải file chạy độc lập vì `report`/hai hàm đồng đội do nhóm sở hữu. Ví dụ chạy độc lập, không cần hai module kia:

```bash
python -m examples.integrate_tv3 \
  --pcap samples/synthetic_tunnel_like_dns.pcap \
  --config configs/frozen.json \
  --output reports/tv3_fragment.json
```

Kỳ vọng 40 events, 1 alert. Output này chỉ là fragment Tuấn Anh, không gọi là kết quả end-to-end của cả nhóm.

## Hợp đồng bắt buộc

- Public API cũ còn nguyên: `parse_dns_pcap`, `group_dns_windows`, `extract_tunnel_features`, `detect_tunnels`.
- List chứa dict, không phụ thuộc dataclass/Pydantic riêng của Nhi.
- `timestamp`/`window_start`: Unix epoch seconds UTC. `score`: int 0–100.
- Query có `rcode=null`, response có RCODE dạng chuỗi.
- Responses mang IP theo đúng hướng của gói phản hồi; detector chỉ dùng query và `src_ip` chính là client tại vị trí capture.
- DNS không thấy được/không đủ điều kiện không được chuyển thành kết luận benign.
- Warning là object `{code,count,first_frame}`; nếu exporter hiện tại chỉ nhận chuỗi, Nhi chuyển ở tầng trình bày, không sửa logic parser.
- JSON chuẩn: `allow_nan=False`. Không ép null thành 0.

## Nghiệm thu sau khi ráp

1. Chạy tests Tuấn Anh từ thư mục gốc; không đổi import thành đường dẫn tuyệt đối.
2. Chạy ví dụ fragment bên trên và đối chiếu `reports/tv3_fragment.json`.
3. CLI chung `python -m app.main analyze --pcap ... --output ...` do Nhi cung cấp: kết quả tunnel phải khớp script Tuấn Anh.
4. DNS parser chỉ chạy một lần; DGA và tunnel dùng cùng events.
5. Query/response có 1 query; benign 0 alert; suspicious 1 alert.
6. TLS-only không sinh DNS alert; invalid capture báo lỗi có kiểm soát.
7. Kiểm tra hai phần DGA/TLS với các test của chủ module.

Bộ gói này đã kiểm tra các API và ví dụ fragment. Chưa thể khẳng định bước 3–7 chạy đúng trong repo nhóm vì chưa có source thực tế của Sony/Nhi.

## Sony nhận dữ liệu DGA

Đọc `handoff/evidence/query_response_events.json`. Dữ liệu mẫu có hai events. Hàm `analyze_dns_domains(dns_events)` của Sony lấy một query với QNAME www.example.com. Domain đăng ký là example.com. Mốc nhận bàn giao là khi hàm của Sony đọc được list này, lọc response và trả findings theo schema trong phiếu Sony. Đối với thống kê chung, lấy confusion matrix tunnel từ `handoff/evidence/test_metrics.csv` theo đơn vị window. Báo cáo DGA dùng đơn vị domain của Sony.

## Nhi ghép vào CLI chung

`build_tv2_fragment(pcap_path, config)` trong `examples/integrate_tv3.py` trả về `events, fragment`. Bên trong CLI, gọi một lần, chuyển events sang hàm của Sony, đưa `fragment["dns_tunnel_findings"]` và `fragment["dns_events_summary"]` vào report, rồi nối warnings vào metadata. Gọi `extract_tls_observations(pcap_path)` từ module của Nhi để bổ sung TLS. File đối chiếu là `handoff/evidence/tv3_fragment.json`.

Sau khi ghép, chạy CLI chung trên benign_dns, synthetic_tunnel_like_dns, query_response và tls_clienthello_only. Số query/alert tunnel tương ứng phải là 4/0, 40/1, 1/0, 0/0. Dùng các fixture của Nhi để xác nhận ServerHello và TLS fingerprint. Ghi kết quả vào PR tích hợp và mời Sony, Tuấn Anh review phần dữ liệu của họ.
