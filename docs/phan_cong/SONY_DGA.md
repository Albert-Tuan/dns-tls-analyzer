# PHÂN CÔNG SONY (TV1) — DGA DETECTION KHÔNG AI/ML

**Vai trò:** Domain Analysis, Heuristic DGA Detection, thống kê đánh giá toàn hệ thống  
**Deadline:** 20/11/2026 | **Khóa tính năng:** 17/11/2026  
**Branch:** `feature/dga-no-ml`  
**Độ khó dự kiến:** 6/10 | **Công sức mục tiêu:** 25–34 giờ  
**Trọng tâm:** Python/thuật toán 45%; thống kê và phân tích chuỗi 35%; kiểm thử, biểu đồ, báo cáo 20%.

> **Nhiệm vụ của bạn:** Từ domain do Tuấn Anh trích từ PCAP, tính được các đặc trưng chuỗi và phát hiện tên miền nghi có dấu hiệu DGA **bằng quy tắc**, không huấn luyện AI/ML. Ngoài ra bạn là người tổng hợp bảng metrics và biểu đồ kiểm thử cho cả nhóm. Điểm số nghi ngờ không phải xác suất độc hại.

## 1. Phạm vi và cam kết đầu ra

**Phải làm (P0):** chuẩn hóa domain; trích registered domain/nhãn DGA; entropy; domain/label length; tỷ lệ chữ số; tỷ lệ nguyên âm; n-gram rarity theo bảng tần suất cố định; hệ thống chấm điểm giải thích được; kiểm thử; báo cáo kết quả thực nghiệm.  
**Làm nếu còn thời gian (P1):** so sánh ít nhất hai bộ trọng số; biểu đồ phân phối điểm hoặc threshold sweep.  
**Không làm (P2):** train/test mô hình supervised, neural network, random forest, API/dashboards, phân loại DGA family.

**File bạn sở hữu:**

```text
app/dga/normalizer.py
app/dga/features.py
app/dga/ngram_reference.py
app/dga/detector.py
tests/test_dga_features.py
tests/test_dga_detector.py
reports/dga_evaluation.csv
docs/TV1_DGA_REPORT.md
```

**Giao diện public cần chốt với nhóm:**

```python
def normalize_domain(qname: str) -> dict: ...
def extract_dga_features(qname: str) -> dict: ...
def score_domain(qname: str) -> dict: ...
def analyze_dns_domains(dns_events: list[dict]) -> list[dict]: ...
```

`analyze_dns_domains` chỉ lấy các DNS **query**, loại trùng domain khi thống kê riêng domain, có thể đính kèm số lần quan sát. **Không** lấy toàn bộ tên miền kèm TLD làm chuỗi tính entropy mặc định nếu thuật toán được thiết kế cho nhãn registered domain; mô tả rõ lựa chọn.

## 2. Checklist theo hạng mục kỹ thuật

### 2.1. Nghiên cứu và định nghĩa phát hiện

- [ ] Giải thích DGA là gì, malware dùng DGA làm gì, vì sao tên miền DGA thường trông khác domain tự nhiên.
- [ ] Nêu hạn chế: wordlist DGA có thể trông như ngôn ngữ tự nhiên; CDN/domain hợp lệ cũng có chuỗi entropy cao.
- [ ] Định nghĩa **đơn vị phân tích:** nhãn đứng trước public suffix trong registered domain; phân biệt `a1b2.example.test` (subdomain) với `example.test` (registered domain).
- [ ] Viết một trang mô tả từng feature: công thức, ý nghĩa, trường hợp gây false positive.
- [ ] Thống nhất schema với Tuấn Anh: `qname`, `registered_domain`, `is_query`, `timestamp`.

### 2.2. Domain normalization

- [ ] Nhận domain dạng chuỗi, bỏ dấu chấm cuối, trim khoảng trắng, lower-case; từ chối chuỗi rỗng/không hợp lệ.
- [ ] Xử lý IDN/Punycode có chủ đích và ghi rõ tính feature trên dạng ASCII hay Unicode; không để chương trình crash vì ký tự lạ.
- [ ] Tách registered domain bằng public suffix list **offline** (ví dụ `tldextract` cấu hình không tải mạng); ghi rõ độ chính xác tùy snapshot PSL.
- [ ] Với địa chỉ IP, hostname nội bộ, domain 1 nhãn hoặc suffix không nhận ra: trả `classification = unknown` hoặc bỏ qua kèm lý do, không tự gắn nhãn DGA.
- [ ] Có test cho `WWW.Example.COM.`, `ab12.example.test`, domain invalid và domain Unicode/Punycode.

### 2.3. Feature engineering thuần quy tắc

- [ ] Viết Shannon entropy: `H = -sum(p_i * log2(p_i))`; xử lý chuỗi dài 0 hoặc 1 ký tự không chia cho 0.
- [ ] Viết `label_length`, `digit_ratio`, `vowel_ratio`, `unique_character_ratio`; giải thích ưu/nhược điểm.
- [ ] Viết n-gram (bigram/trigram): tách chuỗi thành nhóm 2 hoặc 3 ký tự liên tiếp; chuẩn hóa kí tự trước khi so sánh.
- [ ] Tạo bảng n-gram frequency/rank cố định từ một **corpus tham chiếu công khai hoặc do nhóm thống nhất**; đây là thống kê tham chiếu, **không phải mô hình ML**.
- [ ] Xử lý n-gram chưa có trong bảng bằng smoothing cố định và mô tả rõ công thức.
- [ ] Đảm bảo feature là deterministic: cùng đầu vào → cùng kết quả; không phụ thuộc Internet/seed.

### 2.4. Rule-based detector

- [ ] Định nghĩa các điều kiện nghi ngờ và điểm số 0–100, bảng trọng số giải thích được.
- [ ] Không sao chép cứng các ngưỡng ví dụ trong chat; chọn ngưỡng dựa trên tập hiệu chỉnh nhỏ, **không** dựa trên test cuối.
- [ ] Kết hợp ít nhất 3 tín hiệu (ví dụ entropy + digit ratio + n-gram rarity); không đánh dấu malicious chỉ từ 1 tín hiệu.
- [ ] Nhãn đầu ra: `suspicious_dga`, `benign`, `unknown`; số điểm là **heuristic risk score**, không phải `% probability`.
- [ ] Mỗi cảnh báo có `features`, `reasons`; kết quả không thể tính được phải có lý do.
- [ ] Bảo đảm tên miền hợp lệ `example.com`, domain dài có số, IDN và domain chứa từ tự nhiên không bị gắn nghi ngờ chỉ do một quy tắc đơn lẻ.

### 2.5. Dữ liệu, kiểm thử, đánh giá

- [ ] Chọn nguồn domain lành tính và DGA có nhãn, ghi nguồn, số lượng, giấy phép/sự cho phép sử dụng.
- [ ] Loại trùng lặp **trước khi** chia bộ dev/test; loại rò rỉ nhãn, không lấy TLD làm shortcut bất hợp lý.
- [ ] Dùng bộ dev để điều chỉnh ngưỡng và bộ test độc lập để báo cáo cuối. Không gọi việc này là train ML.
- [ ] Tạo test cases: benign đơn giản, chuỗi ngẫu nhiên, rất ngắn, rất dài, toàn số, domain quốc tế, domain lỗi.
- [ ] Tạo confusion matrix TP/FP/TN/FN và công thức Precision/Recall/F1, nêu kích thước mẫu.
- [ ] Báo cáo ít nhất 3 ví dụ false positive hoặc false negative **nếu dữ liệu có**, giải thích nguyên nhân; nếu không xuất hiện, nêu rõ số mẫu.
- [ ] Xuất bảng CSV kết quả từng domain và 1 biểu đồ so sánh phân bố điểm benign/DGA nếu kịp.

### 2.6. Hỗ trợ toàn nhóm

- [ ] Nhận DNS event mẫu từ Tuấn Anh trước 09/11 và test `analyze_dns_domains` trên schema thật.
- [ ] Tổng hợp bảng metrics do Tuấn Anh cung cấp, ghi cùng định nghĩa đơn vị đánh giá (domain, window, session) để tránh cộng sai.
- [ ] Hỗ trợ Nhi kiểm thử JSON exporter trên các case: không có DNS, toàn domain lặp, lỗi domain.
- [ ] Viết phần báo cáo DGA và phần phương pháp đánh giá chung, gửi nhóm trước 18/11.

## 3. Lịch làm việc theo ngày — DEADLINE CỨNG

| Ngày | Việc phải làm | Bằng chứng giao cho leader |
|---|---|---|
| **07/11** | Đọc yêu cầu, chốt feature/schema, chọn nguồn domain và cấu trúc test | `docs/TV1_DGA_REPORT.md` phần phương pháp, PR contract review |
| **08/11** | Normalizer, registered domain extraction, unit tests | `normalizer.py`, ≥6 ca test |
| **09/11** | Entropy/length/ratios và kết nối `dns_event` | `features.py`, test pass, mẫu output |
| **10/11** | Bigram/trigram rarity, n-gram reference, thiết kế ngưỡng | `ngram_reference.py`, bảng ngưỡng lý giải |
| **11/11** | Detector rule-based bản alpha; đủ 3 nhãn + reasons | Demo 10 domain và kết quả JSON |
| **12/11** | Dọn dữ liệu benign/DGA, tách dev/test, chọn ngưỡng trên dev | Script/README dữ liệu + counts |
| **13/11** | Ghép DGA với CLI nhờ Nhi, vá mismatch schema | PR tích hợp, lệnh chạy được |
| **14/11** | Chạy test độc lập, confusion matrix, phân tích lỗi | `dga_evaluation.csv`, bảng TP/FP/TN/FN |
| **15/11** | Demo thử cùng nhóm, sửa lỗi false positive nghiêm trọng | Video/terminal log, buglist |
| **16/11** | Viết bảng/biểu đồ chung và báo cáo chi tiết | Metrics + draft báo cáo |
| **17/11** | Feature freeze, chuyển trạng thái P0 DONE | Test pass, PR cuối, tag phiên bản |
| **18/11** | Hoàn thiện chương DGA và experimental setup | File báo cáo, ảnh minh họa thật |
| **19/11** | Tổng duyệt: giải thích entropy/n-gram/threshold/FP | Script nói 3–4 phút, backup data |
| **20/11** | Nộp/bảo vệ | Có mặt hỗ trợ hỏi đáp |

## 4. Test cases bắt buộc và tiêu chí nghiệm thu

| Case | Mong đợi |
|---|---|
| Input `example.com` | Trả feature hợp lệ, không có lỗi runtime |
| Domain nghi DGA trong tập đã gắn nhãn | Có score/reasons; đánh giá so với nhãn thực |
| `foo.example.com` lặp lại 100 lần | Không xuất 100 cảnh báo domain riêng trùng nhau |
| IP hoặc chuỗi rỗng | `unknown` hoặc skip có lý do rõ |
| Subdomain dài của domain hợp lệ | DGA feature không nhầm toàn subdomain với registered label |
| Không có DNS trong PCAP | Danh sách phát hiện rỗng, không crash |

**Điều kiện leader nghiệm thu:**

- [ ] Có chức năng tính tất cả feature P0, có n-gram rarity theo corpus tĩnh.
- [ ] Rule-based score có tài liệu về từng ngưỡng và trọng số.
- [ ] Kết quả JSON đúng contract, chạy được qua CLI của Nhi.
- [ ] Có ít nhất 12 unit test có ý nghĩa và test run không lỗi.
- [ ] Có một bảng đánh giá số liệu thực (không bịa F1), nguồn dữ liệu và hạn chế.
- [ ] Phần báo cáo DGA đã hoàn thiện, chủ module tự trình bày được.

## 5. Rủi ro và đường lui

- **Không đủ thời gian làm n-gram chi tiết:** dùng bảng n-gram tần suất cố định nhỏ và mô tả là baseline; không bỏ hẳn N-gram vì nằm trong đề tài.
- **Không tìm được dataset đúng định dạng:** sử dụng tập domain công khai có nhãn và tập benign công khai; ghi rõ nguồn và giới hạn mẫu, không tạo nhãn tuỳ tiện.
- **Kết quả accuracy thấp:** trình bày trung thực và phân tích FP/FN; không cố tinh chỉnh trên tập test.
- **Tuấn Anh giao parser muộn:** dùng JSON fixture theo contract 07/11 để phát triển độc lập, sau đó chuyển sang event thực.

## 6. Câu hỏi bảo vệ Sony phải trả lời

1. Shannon entropy khác gì độ dài domain? Domain ngắn entropy cao có đáng tin không?
2. N-gram score được tính ra sao khi không dùng ML? Bảng tần suất lấy từ đâu?
3. Vì sao một domain có score cao chỉ là `suspicious_dga`?
4. Ngưỡng được lựa chọn thế nào và tại sao không dùng tập test để chỉnh ngưỡng?
5. DGA dùng từ tự nhiên có thể làm detector của nhóm thất bại như thế nào?

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
