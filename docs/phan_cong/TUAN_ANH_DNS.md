# PHÂN CÔNG TUẤN ANH (TV2) — DNS PARSER & DNS TUNNELING KHÔNG AI/ML

**Vai trò:** DNS Networking Owner, PCAP Parser, DNS Tunneling Heuristic Detection  
**Deadline:** 20/11/2026 | **Khóa tính năng:** 17/11/2026  
**Branch:** `feature/dns-tunnel`  
**Độ khó dự kiến:** 8/10 | **Công sức mục tiêu:** 28–36 giờ  
**Trọng tâm:** DNS/Networking 50%; Python/PCAP 35%; thống kê hành vi và kiểm thử 15%.

> **Nhiệm vụ của bạn:** Tạo dòng dữ liệu DNS chính xác từ PCAP để Sony dùng chung, đồng thời nhận diện **hành vi** DNS Tunneling theo client, registered domain và cửa sổ thời gian. Không cần ML. Phân biệt dấu hiệu tunneling với DNS hợp lệ có nhiều subdomain.

## 1. Phạm vi và cam kết đầu ra

**Phải làm (P0):** DNS UDP/53 parser; phân biệt query/response; lấy timestamp/IP/QNAME/QTYPE/RCODE/packet length; chuẩn hóa event; gom `client_ip + registered_domain + 60-second window`; query counts, unique-subdomain ratio, avg/max length, entropy và loại record; rule-based alert có reasons; unit/integration tests và demo PCAP.  
**Làm nếu còn thời gian (P1):** hỗ trợ TCP/53 đầy đủ (DNS có thể có length prefix và segmentation), inter-arrival time, NXDOMAIN ratio ghép query–response, TXT ratio, biểu đồ time-series.  
**Không làm (P2):** DNS-over-HTTPS/DoT payload parsing, live capture, phát sinh DNS tunnel thực trên Internet, AI/ML, raw packet replay tấn công.

**File bạn sở hữu:**

```text
app/dns/parser.py
app/dns/normalization.py
app/dns/windowing.py
app/tunneling/features.py
app/tunneling/detector.py
tests/test_dns_parser.py
tests/test_tunnel_detector.py
samples/README.md
docs/TV2_DNS_TUNNELING_REPORT.md
```

**Giao diện public phải thống nhất:**

```python
def parse_dns_pcap(pcap_path: str) -> list[dict]: ...
def group_dns_windows(dns_events: list[dict], seconds: int = 60) -> list[dict]: ...
def extract_tunnel_features(window: dict) -> dict: ...
def detect_tunnels(dns_events: list[dict]) -> list[dict]: ...
```

`parse_dns_pcap` trả DNS events theo schema phụ lục (query và response có `is_query` rõ ràng); `detect_tunnels` **chỉ đếm query**, không double count response.

## 2. Checklist theo hạng mục kỹ thuật

### 2.1. Nghiên cứu giao thức / mô hình đe dọa

- [ ] Giải thích DNS header, transaction ID, QNAME/QTYPE, query/response, rcode, các loại A/AAAA/TXT/CNAME.
- [ ] Mô tả DNS Tunneling: nhúng dữ liệu vào nhãn truy vấn, truyền nhiều yêu cầu qua resolver; chỉ phân tích trên dữ liệu được phép.
- [ ] Nêu sự khác biệt DNS Tunneling với DGA: tunnel là **hành vi theo luồng thời gian**; DGA là **đặc trưng tên miền**.
- [ ] Nêu false positives: CDN, telemetry, tracking, antivirus, DNS testing và domain có subdomain dài.
- [ ] Chốt với Sony cách xác định registered domain/subdomain. Tái sử dụng **cùng helper** hoặc cùng cấu hình public suffix list, không tạo hai bộ tách domain mâu thuẫn.

### 2.2. Đọc PCAP và trích DNS events

- [ ] Dùng Scapy `PcapReader`/`rdpcap` đọc PCAP offline; phân tích UDP/53 trước. Không đọc toàn bộ dữ liệu vào RAM nếu PCAP lớn.
- [ ] Chỉ trích packet có DNS thực; phân biệt `DNS.qr == 0` (query) và `DNS.qr == 1` (response).
- [ ] Trích `timestamp` (float), `src_ip`, `dst_ip`, `dns_id`, `is_query`, `qname`, `qtype`, `rcode` (nếu có), `packet_length`, `frame_number`.
- [ ] Decode qname từ wire format an toàn, bỏ dấu chấm cuối, chuẩn hóa chữ thường; phát hiện invalid/malformed và ghi log cảnh báo.
- [ ] Xử lý `DNSQR` có nhiều question nếu gặp; trường hợp không hỗ trợ phải ghi rõ hạn chế.
- [ ] Dùng một hàm public suffix dùng chung để có `registered_domain` và `subdomain`; khi không tách được thì đánh dấu unknown/skip, không crash.
- [ ] Đảm bảo query-response không bị nhân đôi trong `query_count`, và nếu ghép response thì dùng đủ `dns_id`, IP/port, thời gian để tránh ghép nhầm.
- [ ] Có thể đọc PCAP rỗng, PCAP không DNS, truncated packet; trả dữ liệu rỗng/log lỗi phù hợp.

### 2.3. Phân tích theo thời gian

- [ ] Gom theo `src_ip` (client) + `registered_domain`, chia cửa sổ **không chồng lấn 60 giây** tính từ epoch; ghi rõ lựa chọn.
- [ ] Đếm query_count, unique_qnames, unique_subdomain_ratio, độ dài subdomain trung bình/lớn nhất.
- [ ] Tính entropy trung bình của subdomain (không đánh đồng entropy của từng label với cả domain).
- [ ] Tính qtype distribution, TXT ratio nếu có; rcode/NXDOMAIN ratio chỉ khi có đủ response ghép hợp lệ.
- [ ] Loại hoặc đánh dấu window ít query để không kết luận từ 1–2 gói.
- [ ] Sắp xếp kết quả theo thời gian; cho ra `window_start`, `window_seconds`, `src_ip`, `registered_domain`.

### 2.4. Phát hiện DNS Tunneling bằng quy tắc

- [ ] Định nghĩa score 0–100 có trọng số công khai: số lượng truy vấn, tỷ lệ subdomain duy nhất, độ dài, entropy, TXT ratio và/hoặc tần suất.
- [ ] Tạo **điều kiện tối thiểu số truy vấn** và **ít nhất hai dấu hiệu độc lập** trước khi đưa ra `suspected_dns_tunnel`.
- [ ] Các ngưỡng là ví dụ ban đầu và phải hiệu chỉnh trên bộ dev; không chọn ngưỡng dựa trên test cuối.
- [ ] Mỗi alert xuất `features`, `reasons`, window, host, registered domain; không dùng `malicious` như sự thật chắc chắn.
- [ ] Đảm bảo domain hợp lệ với rất nhiều subdomain không bị kết luận tunnel chỉ do entropy/length cao.
- [ ] Không xây dựng hay chạy công cụ exfiltration thật; chỉ dùng PCAP/lab mô phỏng và dataset được phép.

### 2.5. Kiểm thử và dataset

- [ ] Chọn ít nhất 01 tập PCAP DNS bình thường và 01 tập PCAP/dataset DNS tunneling có nhãn; kiểm tra thực sự có PCAP (nhiều bộ dữ liệu chỉ chứa CSV).
- [ ] Tạo test fixture offline (Scapy-generated DNS packets giả lập query bình thường và nhiều query dạng `random.example.test`), không gửi gói ra mạng.
- [ ] Kiểm thử query/response cùng ID: query_count vẫn là 1, không phải 2.
- [ ] Kiểm thử file không DNS, file rỗng, DNS malformed, không có registered domain, out-of-order timestamps.
- [ ] Kiểm thử cùng domain nhưng **hai IP khác nhau** không bị trộn vào một window.
- [ ] Kiểm thử window 60 giây: gói ở giây 59 và 61 thuộc hai bucket khác nhau (theo epoch).
- [ ] Đánh giá trên đơn vị **window hoặc phiên**, nêu rõ ground truth; tính TP/FP/TN/FN và tỷ lệ false positives.
- [ ] Chọn tối thiểu 2 ví dụ benign dễ báo nhầm (tracking/CDN) nếu bộ dữ liệu cho phép và giải thích hướng giảm sai.

### 2.6. Phối hợp

- [ ] Bàn giao JSON event thật cho Sony và Nhi **trước 09/11**.
- [ ] Khi thấy mismatch schema, sửa tại parser (owner của event) và thông báo ngay nhóm.
- [ ] Cung cấp ít nhất 2 PCAP demo: bình thường và nghi tunneling, kèm nguồn gốc/nhãn và hướng dẫn chạy.
- [ ] Gửi Sony bảng metrics cùng định nghĩa cửa sổ để tổng hợp không sai mẫu số.
- [ ] Viết chương DNS/DNS Tunneling và mô tả dữ liệu thí nghiệm trước 18/11.

## 3. Lịch làm việc theo ngày — DEADLINE CỨNG

| Ngày | Việc phải làm | Bằng chứng giao cho leader |
|---|---|---|
| **07/11** | Nghiên cứu DNS/Tunneling, chốt event schema, tập PCAP demo | PR schema review + link nguồn dữ liệu |
| **08/11** | Parser UDP/53, DNS query/response, qname/qtype/ip/time | `parser.py`, fixture pcap, ≥5 test |
| **09/11** | Event chuẩn có registered domain + gửi Sony/Nhi | `samples/events.json`, kiểm thử parser pass |
| **10/11** | Windowing 60s, query/unique/length/entropy features | `windowing.py`, `features.py` |
| **11/11** | Detector alpha với score/reasons và demo 2 loại traffic | `detector.py`, output JSON |
| **12/11** | Chạy benign/tunnel dataset, hiệu chỉnh ngưỡng trên dev | Bảng threshold, logs |
| **13/11** | Tích hợp cùng Nhi; sửa parser/schema incompatibility | CLI xuất được cảnh báo tunnel |
| **14/11** | Test false positive/negative, xử lý dữ liệu thiếu | `test_tunnel_detector.py`, test report |
| **15/11** | Demo nhóm trên PCAP bình thường/nghi tunnel | Terminal log + buglist |
| **16/11** | Chốt metric, viết báo cáo thống kê và ví dụ traffic | Bảng TP/FP/TN/FN, ảnh Wireshark |
| **17/11** | Feature freeze; chỉ sửa bug P0 | PR/tag, test pass |
| **18/11** | Hoàn thiện chương DNS Tunneling trong báo cáo | Draft cuối + nguồn dữ liệu |
| **19/11** | Tổng duyệt câu hỏi DNS/PCAP/windowing | Script nói 3–4 phút, backup PCAP |
| **20/11** | Nộp và hỗ trợ bảo vệ | Có mặt hỏi đáp |

## 4. Test cases bắt buộc và tiêu chí nghiệm thu

| Case | Mong đợi |
|---|---|
| 1 query + 1 response | Query count = 1; response rcode có thể ghép nếu hỗ trợ |
| 50 query cùng subdomain | Không coi là 50 subdomain duy nhất |
| 40 query đến 40 subdomain từ một client | Tăng các feature tần suất/uniqueness, chưa tự động kết luận từ một feature |
| 2 máy gửi cùng domain | Tách nhóm theo src_ip |
| PCAP TLS-only | DNS events và tunnel alerts rỗng, không crash |
| Input PCAP truncated / corrupt | Thông báo lỗi có kiểm soát |
| Domain có nhiều dấu chấm/case khác nhau | Chuẩn hóa consistent với Sony |

**Điều kiện leader nghiệm thu:**

- [ ] Parse đúng P0 với PCAP offline, có ví dụ output JSON.
- [ ] Cả Sony và Nhi dùng được schema DNS event mà không có adapter tùy tiện.
- [ ] Detector hoạt động theo client+domain+window, kết hợp ≥2 tín hiệu và có minimum sample rule.
- [ ] Có ít nhất 12 unit/integration tests, cả benign và suspicious fixture chạy được.
- [ ] Có đánh giá trên dữ liệu gắn nhãn; số liệu thật, chỉ ra FP/FN và hạn chế.
- [ ] Báo cáo DNS/protocol/tunneling hoàn thành, có minh chứng từ Wireshark.

## 5. Rủi ro và đường lui

- **Không có PCAP public tunneling dùng được:** dùng fixture offline do nhóm sinh từ chuỗi truy vấn đã định nhãn **synthetic**, phân biệt rõ kết quả thử thuật toán với kết quả trên dữ liệu thực.
- **TCP DNS khó parse:** giữ UDP/53 là P0, ghi TCP/53 thuộc hạn chế P1. Không nhận là đã hỗ trợ nếu chưa test reassembly.
- **NXDOMAIN ratio không có response:** `null` và ghi lý do; không mặc định là 0 vì sẽ sai thống kê.
- **Phát hiện nhầm CDN/telemetry:** nâng ngưỡng minimum query, kết hợp ≥2 feature và ghi FP trong báo cáo; không che giấu lỗi.
- **Parser bàn giao trễ:** Sony dùng fixture contract, Nhi tích hợp stub cho đến khi parser pass; owner phải ưu tiên sửa trước 13/11.

## 6. Câu hỏi bảo vệ Tuấn Anh phải trả lời

1. DNS Tunneling khác DGA ra sao? Vì sao phải phân tích theo thời gian?
2. Trong PCAP, trường nào xác định DNS query/response? Vì sao không được double-count?
3. Tại sao unique-subdomain ratio và entropy có thể báo nhầm hoạt động hợp lệ?
4. Vì sao kết quả được đánh giá theo window/host/domain thay vì từng packet?
5. Công cụ có phát hiện được DoH, DoT và DNS-over-QUIC hay không? Vì sao?

---

## PHỤ LỤC CHUNG — Áp dụng bắt buộc cho cả 3 thành viên

### A. Quy định dự án và phạm vi

- **Tên đồ án:** Phát hiện và phân loại lưu lượng mã hóa và DNS độc hại.
- **Hạn nộp:** **20/11/2026**; hoàn thành bản có thể nộp trước tối **19/11/2026**.
- **Cách triển khai:** Python 3.11+, phân tích PCAP/PCAPNG **offline**; CLI chạy một lệnh và xuất JSON/CSV. Không phát triển giao diện, bắt gói live, backend API hoặc mô hình AI/ML.
- **Kỹ thuật cốt lõi:** Scapy/dnspython (DNS); Python chuẩn và thư viện xử lý dữ liệu nhẹ; TShark/Wireshark (TLS); Shannon entropy, n-gram thống kê, các quy tắc phát hiện (heuristics), phân tích cửa sổ thời gian.
- **Ưu tiên P0 (bắt buộc):** đọc PCAP, trích DNS và TLS, đánh giá DGA, phát hiện DNS Tunneling, ghi nhận JA3 và mô tả JA4, xuất báo cáo, có test/demo. **P1:** JA4 nếu TShark hỗ trợ, CSV đẹp, biểu đồ cơ bản. **P2:** live capture, GUI, phát hiện DoH/DoT/QUIC, ML (không làm trong đồ án này).
- **Không suy diễn:** DGA/tunneling là **nghi ngờ**, chưa phải kết luận mẫu độc hại; JA3/JA4 là dấu vân tay TLS, **không tự kết luận độc hại**; TLS 1.3 không để lộ Certificate qua quan sát thụ động thông thường và ECH có thể che SNI thực.

### B. Hợp đồng dữ liệu (contract) — khóa từ 07/11

**DNS event — do Tuấn Anh sản xuất, Sony/Nhi sử dụng:**

```json
{
  "timestamp": 1794000000.0,
  "src_ip": "192.0.2.10",
  "dst_ip": "192.0.2.53",
  "dns_id": 1234,
  "is_query": true,
  "qname": "ab12.example.test",
  "registered_domain": "example.test",
  "subdomain": "ab12",
  "qtype": "A",
  "rcode": null,
  "packet_length": 91,
  "frame_number": 15
}
```

`rcode` chỉ được điền khi có response tương ứng hoặc khi event là response. Không được coi các response là query mới khi đếm tần suất. IP dùng dải ví dụ RFC 5737, thời gian/số liệu trên chỉ để minh họa schema.

**DGA result — do Sony sản xuất:**

```json
{
  "detector": "dga",
  "classification": "suspicious_dga",
  "target": "ab12.example.test",
  "score": 65,
  "features": {"entropy": 1.98, "length": 4, "digit_ratio": 0.50, "ngram_score": 0.21},
  "reasons": ["high_digit_ratio", "unusual_ngrams"]
}
```

**Tunnel result — do Tuấn Anh sản xuất:**

```json
{
  "detector": "dns_tunnel",
  "classification": "suspected_dns_tunnel",
  "src_ip": "192.0.2.10",
  "registered_domain": "example.test",
  "window_start": 1794000000.0,
  "window_seconds": 60,
  "score": 70,
  "features": {"query_count": 30, "unique_subdomain_ratio": 0.97, "avg_subdomain_length": 35.0},
  "reasons": ["many_unique_subdomains", "long_subdomain_labels"]
}
```

**TLS observation — do Nhi sản xuất:**

```json
{
  "record_type": "tls_observation",
  "flow_id": "capture.pcap:tcp:3",
  "src_ip": "192.0.2.10",
  "dst_ip": "198.51.100.20",
  "sni": "example.org",
  "ja3": "<hash-neu-co>",
  "ja3s": null,
  "ja4": null,
  "fingerprint_status": "partial",
  "packet_sizes_signed": [314, -1200, -640]
}
```

Không giả mạo JA3/JA4: khi thiếu trường, dùng `null` và ghi lý do. Các điểm `score` 0–100 chỉ là điểm quy tắc minh họa, **không gọi là xác suất**; trọng số/ngưỡng phải có bảng mô tả và thử trên dữ liệu phát triển độc lập với dữ liệu kiểm thử.

**CLI chuẩn:**

```bash
python -m app.main analyze --pcap samples/demo.pcap --output reports/demo.json
```

**Report chuẩn:** `metadata` (file, thời gian, số packet, warnings), `summary`, `dns_events_summary`, `dga_findings`, `dns_tunnel_findings`, `tls_observations`.

### C. Git, trách nhiệm và quy tắc phối hợp

- Branch cố định: `feature/dga-no-ml` (Sony), `feature/dns-tunnel` (Tuấn Anh), `feature/tls-integration` (Nhi).
- Chốt `app/core/schemas.py` vào **07/11**. Mọi thay đổi contract phải có thảo luận và cập nhật cả test phụ thuộc; không được tự ý đổi tên key.
- Mỗi PR gồm: mục tiêu, thay đổi, lệnh chạy, đầu ra mẫu, test đã chạy, hạn chế chưa giải quyết. **Không merge khi test bị fail.**
- Check-in **21:30 mỗi ngày**: `đã làm / minh chứng commit / test pass-fail / blocker / việc ngày sau`.
- Review nhóm: **09/11, 11/11, 13/11, 15/11, 17/11, 19/11**.
- Module nào lỗi thì **owner của module sửa**. Nhi chịu trách nhiệm nối pipeline và CLI, không gánh logic DGA/tunneling cho người khác.
- PCAP, CSV có dữ liệu thật phải được ẩn IP nhạy cảm hoặc dùng bộ dữ liệu công khai; không commit dữ liệu cá nhân, secrets, keylog; chỉ phân tích traffic được phép.

### D. Lịch chung không được trễ

| Ngày | Gate / sự kiện | Quyết định của leader |
|---|---|---|
| **07/11** | Chốt kiến trúc, contract, repo, dataset và PCAP kiểm thử | Không làm phần khác khi chưa chốt interface |
| **09/11** | DNS parser + DGA features + TLS extractor bước đầu chạy | Nếu thiếu sample, tạo fixture hợp lệ để test ngay |
| **11/11** | Ba module có bản chạy riêng (MVP alpha) | Bỏ P1 nếu P0 chưa đạt |
| **13/11** | Tích hợp chạy qua CLI (integration beta) | Dừng phát triển P2 hoàn toàn |
| **15/11** | Demo lần 1 trên PCAP đã chuẩn bị | Chỉ ưu tiên bug, false positive, đầu ra báo cáo |
| **17/11** | **Feature freeze** và nghiệm thu P0 | Không thêm thuật toán, GUI hoặc tính năng phụ |
| **18/11** | Hoàn thành bản báo cáo và hình/bảng kết quả | Soát lại số liệu và mô tả phương pháp |
| **19/11** | Tổng duyệt, đóng gói bản nộp, bản sao lưu | Bắt buộc chạy demo từ môi trường sạch |
| **20/11** | Nộp và bảo vệ theo yêu cầu môn | Chỉ sửa lỗi khẩn cấp ngăn nộp |

### E. Định nghĩa hoàn thành (Definition of Done)

- [ ] Code có thể chạy trên môi trường sạch theo README, không phụ thuộc đường dẫn tuyệt đối của máy tác giả.
- [ ] Có kiểm thử tự động tối thiểu cho ca bình thường, ca nghi ngờ, ca lỗi/thiếu dữ liệu.
- [ ] Có ví dụ đầu vào/đầu ra thực, không dùng số liệu bịa để chứng minh độ chính xác.
- [ ] Kết quả giữ đúng schema, xuất JSON hợp lệ, phân biệt nghi ngờ với kết luận độc hại.
- [ ] Có phần báo cáo mô tả phương pháp, thí nghiệm, sai số/hạn chế và nguồn dữ liệu.
- [ ] Có commit/PR được review và demo thực tế trước hạn.

### F. Tài liệu tham chiếu kỹ thuật

- Wireshark TLS field reference: https://www.wireshark.org/docs/dfref/t/tls.html
- RFC 8446 TLS 1.3: https://www.rfc-editor.org/rfc/rfc8446
- MITRE ATT&CK T1071.004 (DNS): https://attack.mitre.org/techniques/T1071/004/
- Scapy: https://scapy.readthedocs.io/
- dnspython: https://dnspython.readthedocs.io/
- JA4 technical details: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
