# Thực hành và demo — chỉ cần chạy theo thứ tự

## A. Nghiệm thu tự động

Tại thư mục gốc, sau khi tạo venv/cài dependencies:

```bash
source .venv/bin/activate
python -m scripts.run_all
```

Giữ `reports/acceptance.json`, `reports/junit.xml`, logs, manifest, frozen config và metrics làm bằng chứng. Không dùng ảnh terminal từ máy khác để nhận là kết quả Fedora của bạn.

## B. Quan sát bằng TShark

```bash
tshark -r samples/query_response.pcap \
  -T fields -e frame.number -e frame.time_epoch -e ip.src \
  -e dns.id -e dns.flags.response -e dns.qry.name -e dns.qry.type -e dns.flags.rcode

python -m scripts.verify_tshark --pcap samples/query_response.pcap
python -m scripts.verify_tshark --pcap samples/synthetic_tunnel_like_dns.pcap
```

Đọc hai dòng query/response: cùng ID và QNAME, hướng IP ngược nhau, QR khác nhau. TShark có thể hiển thị header RCODE của query là 0; event contract vẫn để null vì chưa có kết quả response ghép vào query.

## C. Quan sát bằng Wireshark

Nếu mới cài wireshark-cli thì chưa chắc đã có GUI. Có thể chỉ dùng TShark hoặc cài thêm:

```bash
sudo dnf install wireshark
wireshark samples/query_response.pcap
```

Display filters:

```text
dns
dns.flags.response == 0
dns.flags.response == 1
dns.qry.type == 16
```

Chụp ba ảnh của chính bạn để đưa vào báo cáo:

1. Query/response: hiển thị ID, flags, name, type và IP.
2. Tunnel-like: nhiều QNAME dài khác nhau trong một window.
3. Terminal kết quả `reports/test_metrics.json`, ghi rõ synthetic.

Ảnh không phải điều kiện để code chạy, nhưng hữu ích khi bảo vệ. Gói không cung cấp screenshot giả.

## D. Đọc kết quả và thử giới hạn

```bash
python -m json.tool reports/synthetic_tunnel_like_dns.json
python -m scripts.run_tv2 --pcap samples/test.pcap \
  --config configs/frozen.json --output reports/test_full.json --csv reports/test_windows.csv
```

Mở CSV bằng trình soạn thảo hoặc spreadsheet. So sánh với `reports/test_metrics.csv`:

- `telemetry_long`: nhãn benign nhưng bị cảnh báo → FP.
- `tunnel_slow`: nhãn tunnel nhưng ít query → FN.
- `tunnel_dense`, `tunnel_medium`: được phát hiện.
- `ordinary`, `repeated`, `cdn_short`: không bị cảnh báo.

Không đổi nhãn sau khi thấy output để làm metrics đẹp hơn. Không hiệu chỉnh ngưỡng bằng test rồi tiếp tục báo đó là kết quả độc lập.

## E. Kịch bản trình bày 3–4 phút

**0:00–0:40:** “Phần của em đọc DNS UDP/53 từ PCAP offline, chuẩn hóa domain dùng chung với module DGA, sau đó đánh giá hành vi theo client, registered domain và cửa sổ 60 giây.”

**0:40–1:20:** Mở query/response, chỉ QR và giải thích query_count chỉ tăng một lần. Cho xem benign 0 alert.

**1:20–2:10:** Chạy PCAP tunnel-like, mở reasons/features: volume, diversity, length và entropy. Giải thích score là tổng điểm quy tắc, không phải xác suất nhiễm mã độc.

**2:10–3:10:** Mở test_metrics, nêu rõ dữ liệu synthetic và đơn vị window. Chỉ ra FP telemetry và FN low-rate, không né hai lỗi này.

**3:10–4:00:** Cho xem ví dụ tích hợp và giải thích Nhi parse một lần để hai detector dùng chung. Nêu giới hạn TCP, DoH/DoT, vị trí capture và chưa có kiểm chứng trên lưu lượng sản xuất.

## F. Khi có lỗi

| Hiện tượng | Cách xử lý |
|---|---|
| `No module named app` | Đứng tại thư mục `dns-tls-analyzer`, dùng `python -m ...` |
| Thiếu scapy/dns/tldextract | Kích hoạt đúng .venv rồi cài requirements-lock.txt |
| TShark pending | Kiểm tra `tshark --version`; cài wireshark-cli, chạy lại |
| Label coverage mismatch | Kiểm tra host/domain/window, query thực sự tồn tại; không bỏ nhãn lỗi |
| Capture SHA256 mismatch | Capture đã đổi, cần xác minh nguồn/nhãn rồi tạo manifest phiên bản mới |
| Suffix unknown | Xem warning; không dùng tách hai nhãn cuối để ép dữ liệu vào detector |
| Zero-byte PCAP | File rỗng không phải capture hợp lệ; dùng samples/empty.pcap để test |
| Corrupt/truncated capture | Xuất/tải lại file; không báo sạch chỉ vì parser không đọc được |
| `Operation not permitted` ngay khi import Scapy | Đây là lỗi môi trường hạn chế dò card mạng; không dùng sudo mù quáng. Fedora thông thường đã chạy starter được. Gửi log nếu gặp ở bản mới. |

Không tự kết luận sample thật là tunnel chỉ vì score cao. Dùng alert như đầu mối điều tra.
