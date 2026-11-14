# Phát hiện và phân loại lưu lượng mã hóa và DNS độc hại

| Vai trò | Thành viên | Phụ trách | Nhánh |
|---|---|---|---|
| TV1 | Sony | DGA và tổng hợp metrics | feature/dga-no-ml |
| TV2 | Tuấn Anh | Parser DNS và phát hiện tunneling | feature/dns-tunnel |
| TV3 | Nhi | TLS, CLI chung và tích hợp | feature/tls-integration |

[Bản phân công có tên](docs/phan_cong/) · [Kết quả rà soát](docs/NGHIEM_THU.md) · [Bàn giao Sony và Nhi](BAN_GIAO_SONY_VA_NHI.md) · [Tạo repo GitHub](docs/GITHUB.md)

Bản khởi đầu repo nhóm ngày 14/11 chứa phần chạy độc lập của Tuấn Anh. Thư mục [handoff/evidence](handoff/evidence/) lưu kết quả tham chiếu để mọi người có thể đọc ngay sau khi clone. Chạy quy trình bên dưới để sinh kết quả trên máy riêng trong reports/.


Bộ mã dành cho đồ án **không AI/ML**, phân tích PCAP/PCAPNG offline. Ngày chuẩn bị: 14/11/2026. Hạn nhóm: 20/11/2026.

**Đã kiểm tra:** 94 tests pass; demo parser → detector → JSON/CSV; chọn ngưỡng trên dev; đánh giá test; ví dụ hợp đồng tích hợp Nhi. Có source, PCAP, nhãn, log, kết quả và chương báo cáo.

**Giới hạn nghiệm thu:** chưa chạy cùng source thật của Sony/Nhi (chưa được cung cấp); chưa đối chiếu TShark trong môi trường tạo gói; dữ liệu thực nghiệm trong gói là **synthetic**, không phải malware hay exfiltration thật. Chưa xác nhận bản mới trên Python 3.14/Fedora của bạn: lệnh bên dưới thực hiện bước đó.

## 1. Chạy ngay trên Fedora

Giải nén vào thư mục mới, không chép đè bộ starter đang có. Mở terminal tại `dns-tls-analyzer`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-lock.txt
python -m scripts.run_all
```

Bạn đã cài `wireshark-cli`; nếu máy khác chưa có:

```bash
sudo dnf install python3 python3-pip wireshark-cli
```

Không dùng sudo để chạy Python. Chỉ bước cài dependencies cần Internet; phân tích, tạo fixture và chạy tests không cần mạng. `requirements-lock.txt` ghi phiên bản đã dùng; `requirements.txt` là khoảng phiên bản trực tiếp. Nếu có lỗi cài đặt, giữ nguyên log để đối chiếu, không tự nâng tất cả dependencies.

Lệnh `run_all` thực hiện lần lượt:

1. Tạo PCAP và nhãn mô phỏng có seed cố định; không gửi packet.
2. Chạy toàn bộ tests, lưu JUnit và log.
3. Chọn cấu hình trên `dev_manifest.json`; ghi `configs/frozen.json`.
4. Phân tích benign, tunnel-like, query/response, xuất JSON + CSV + event JSON.
5. Tính metrics từ kết quả đọc PCAP dev/test; kiểm tra SHA256 và độ phủ nhãn.
6. Chạy ví dụ tích hợp Tuấn Anh → Nhi.
7. Nếu có TShark: đối chiếu frame, timestamp, IP, DNS ID, QR, QNAME, QTYPE trên 5 capture.

Lệnh ghi lại `reports/` và `configs/frozen.json`. Muốn giữ một lần thực nghiệm, sao chép thư mục reports và config trước khi chạy lại. Không dùng `run_all` để hiệu chỉnh dữ liệu thật: nó tạo lại các fixture demo; với dữ liệu khác dùng lệnh riêng bên dưới.

## 2. Kết quả cần thấy

| Capture | Queries | Responses | Alerts |
|---|---:|---:|---:|
| benign_dns.pcap | 4 | 0 | 0 |
| synthetic_tunnel_like_dns.pcap | 40 | 0 | 1 |
| query_response.pcap | 1 | 1 | 0 |

Thông báo cuối: `TV2 core acceptance: passed`. Trên Fedora có TShark, trường `tshark_parity` trong `reports/acceptance.json` phải là `passed`. Nếu là `pending_tshark_not_installed`, phần này chưa được nghiệm thu. Nếu bước nào lỗi, runner dừng, trả mã khác 0 và lưu log của bước lỗi.

Đọc:

```bash
python -m json.tool reports/acceptance.json
python -m json.tool reports/synthetic_tunnel_like_dns.json
python -m json.tool reports/test_metrics.json
```

Test mô phỏng hiện tại: 21 windows, TP=6, FP=3, TN=9, FN=3; Precision/Recall/F1 ≈ 0.667, FPR=0.25. Đây là phép đo trên các kịch bản tự tạo, **không thể suy ra độ chính xác trong thực tế**.

## 3. Chạy PCAP của bạn

```bash
python -m scripts.run_tv2 \
  --pcap /duong/dan/traffic.pcap \
  --config configs/frozen.json \
  --output reports/my_capture.json \
  --csv reports/my_windows.csv \
  --events-output reports/my_events.json
```

Không đặt output trùng input. Exit 0 = phân tích hoàn tất, kể cả có cảnh báo tunnel; exit 2 = lỗi đầu vào/cấu hình. `not_flagged` chỉ có nghĩa chưa đủ điều kiện quy tắc, không khẳng định benign.

## 4. Ráp vào phần nhóm

Sony dùng chung `normalize_qname` và list DNS event. Nhi chỉ parse một lần:

```python
from app.dns.parser import parse_dns_pcap_detailed
from app.tunneling.detector import DetectorConfig, detect_tunnels

parsed = parse_dns_pcap_detailed(pcap_path)
dns_events = parsed.events
cfg = DetectorConfig.from_file("configs/frozen.json")
tunnel_findings = detect_tunnels(dns_events, cfg)
# Truyền cùng dns_events cho hàm DGA thật của TV1.
# Ghép tunnel_findings vào report["dns_tunnel_findings"] của TV3.
# Ghép parsed.warnings vào report["metadata"]["warnings"].
```

Đọc **`BAN_GIAO_SONY_VA_NHI.md`** trước khi chép module. Không thay `app/main.py`, `app/core/schemas.py` hoặc code TLS/DGA của nhóm bằng ví dụ trong gói này. Bộ này không tạo DGA/TLS giả để làm báo cáo trông đủ thành phần.

## 5. Các file chính

| File | Dùng để |
|---|---|
| app/dns/ | Kiểm tra capture, parse, chuẩn hóa PSL, chia cửa sổ |
| app/tunneling/ | Features, quy tắc, reporting, evaluation |
| configs/frozen.json | Cấu hình được chọn chỉ từ dev |
| configs/frozen.selection.json | Tất cả ứng viên và lý do chọn |
| scripts/run_all.py | Chạy toàn bộ nghiệm thu tự động |
| scripts/run_tv2.py | Phân tích capture đơn lẻ |
| scripts/evaluate_dataset.py | Đánh giá đúng theo windows có nhãn |
| scripts/verify_tshark.py | Đối chiếu field với TShark |
| examples/integrate_tv3.py | Ví dụ tích hợp chạy được |
| samples/ | PCAP, manifest nhãn, nguồn gốc và hash |
| reports/ | Kết quả thực sự được chạy, không phải output viết tay |
| docs/THUC_HAN_VA_DEMO.md | Các thao tác thực hành và kịch bản bảo vệ |
| docs/TV2_DNS_TUNNELING_REPORT.md | Chương báo cáo đã có số đo và hạn chế |
| docs/INTEGRATION_CONTRACT.md | Schema, kiểu, nullable, API, lỗi |
| docs/DATASET_AND_EVALUATION.md | Cách thêm dữ liệu thật, chia dev/test, nhãn |
| docs/VALIDATION.md | Môi trường và phạm vi kiểm chứng |

## 6. Phạm vi chính xác

Hỗ trợ IPv4/IPv6, UDP port 53, PCAP/PCAPNG, một question/packet, query/response và RCODE response. Không reassemble IP fragments/TCP DNS; không giải mã DoH/DoT; không ghép query–response nên `nxdomain_ratio=null`. Multiple-question, opcode khác QUERY, tên binary không hỗ trợ được bỏ qua với warning. Unknown suffix/reverse DNS được giữ event với registered domain null và không đưa vào detector.

Đọc packet tuần tự, nhưng API trả list và giữ events/windows trong RAM; giới hạn mặc định 1 triệu event và dừng có lỗi khi vượt giới hạn. Không quảng cáo đây là hệ thống streaming cho capture không giới hạn. Query retry/retransmission vẫn là một quan sát query; chưa deduplicate giao dịch.
