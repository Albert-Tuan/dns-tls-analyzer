# PHÂN CÔNG NHI (TV3) — TLS FINGERPRINTING & SYSTEM INTEGRATION KHÔNG AI/ML

**Vai trò:** TLS Analysis Owner, Technical Integrator, CLI/Exporter, E2E Testing  
**Deadline:** 20/11/2026 | **Khóa tính năng:** 17/11/2026  
**Branch:** `feature/tls-integration`  
**Độ khó dự kiến:** 9/10 | **Công sức mục tiêu:** 30–38 giờ  
**Trọng tâm:** TLS/Networking 45%; Python/Software Engineering 35%; tích hợp/kiểm thử 20%.

> **Nhiệm vụ của bạn:** Trích xuất handshake TLS/HTTPS **không giải mã** bằng TShark, ghi nhận fingerprint JA3/JA3S và JA4 **nếu được hỗ trợ**, thống kê kích thước/hướng packet. Đồng thời tạo CLI và nối ba module thành một pipeline. Bạn không chịu trách nhiệm sửa thuật toán DGA/tunnel của Sony/Tuấn Anh.

## 1. Phạm vi và cam kết đầu ra

**Phải làm (P0):** kiểm tra TShark; đọc PCAP TLS; trích ClientHello/ServerHello, SNI nếu quan sát được, cipher suites/version/extension thông dụng theo khả năng dissector, JA3/JA3S nếu công cụ có; giải thích JA4 và tính nếu công cụ hỗ trợ; 5-tuple hoặc tcp.stream; packet-size sequence có chiều; CLI chung; JSON report + warnings; E2E tests; demo và tài liệu.  
**Làm nếu còn thời gian (P1):** JA4 TShark 4.2+ đã xác nhận, CSV exports, TLS 1.2 certificate khi rõ không mã hóa, biểu đồ số flow.  
**Không làm (P2):** tự triển khai TLS stack, decrypt payload, suy luận malware chỉ từ JA3, QUIC/HTTP3 parser, TLS MITM, web dashboard, AI/ML.

**File bạn sở hữu:**

```text
app/core/schemas.py
app/tls/extractor.py
app/tls/fingerprint.py
app/tls/flow_stats.py
app/core/report_exporter.py
app/main.py
tests/test_tls_extractor.py
tests/test_cli_integration.py
README.md
docs/TV3_TLS_INTEGRATION_REPORT.md
```

**Giao diện public cần triển khai:**

```python
def extract_tls_observations(pcap_path: str) -> list[dict]: ...
def extract_packet_size_series(pcap_path: str) -> dict: ...
def build_report(pcap_path: str, dns_events: list[dict],
                 dga_results: list[dict], tunnel_results: list[dict],
                 tls_observations: list[dict]) -> dict: ...
```

Phải chạy CLI:

```bash
python -m app.main analyze --pcap samples/demo.pcap --output reports/demo.json
```

Nếu thiếu TShark/JA4, chương trình phải hiển thị rõ trạng thái và không sinh dữ liệu giả. Có thể chọn chính sách fail có thông báo rõ khi không có TShark hoặc xuất phần DNS kèm `warning` và TLS trống; tài liệu phải mô tả chính sách thống nhất.

## 2. Checklist theo hạng mục kỹ thuật

### 2.1. Nghiên cứu TLS chính xác

- [ ] Vẽ và giải thích TLS 1.2 vs TLS 1.3 handshake; phân biệt ClientHello/ServerHello và dữ liệu ứng dụng.
- [ ] Nắm SNI, supported_versions, cipher suites, extensions, ALPN và supported groups.
- [ ] Viết đúng giới hạn: trong TLS 1.3, Certificate được mã hóa ở pha handshake, không đọc thụ động theo cách thông thường.
- [ ] Viết đúng giới hạn ECH: SNI thật có thể không quan sát được; `null` không đồng nghĩa không có SNI.
- [ ] Nắm JA3 (ClientHello fingerprint), JA3S (ServerHello fingerprint), JA4 và lý do fingerprint không đồng nghĩa độc hại.
- [ ] Viết mục `JA3 vs JA4`: trường sử dụng, vấn đề GREASE/thứ tự extension, phạm vi và giới hạn; nguồn kỹ thuật đáng tin.

### 2.2. Phân tích capabilities của TShark trước khi code

- [ ] Cài và lưu phiên bản `tshark --version` trong `docs/TV3_TLS_INTEGRATION_REPORT.md`.
- [ ] Dùng `tshark -G fields` kiểm tra những trường thực tế có mặt; **không viết giả định** mọi bản đều hỗ trợ JA4.
- [ ] Xác minh `tls.handshake.ja3`, `tls.handshake.ja3s`, `tls.handshake.ja4`; trường JA4 có từ Wireshark 4.2.0 trở lên theo tài liệu tham chiếu, nhưng vẫn phải kiểm tra runtime.
- [ ] Dùng công cụ qua `subprocess.run([...], shell=False, timeout=...)` và xử lý exit code/stderr.
- [ ] Không phụ thuộc tên field không được runtime hỗ trợ; nếu thiếu thì bỏ `-e` tương ứng và ghi warning rõ ràng.
- [ ] Có lưu câu lệnh TShark thực tế trong README để giảng viên tự kiểm tra kết quả.

Ví dụ bắt đầu (phải chỉnh tùy fields cài sẵn):

```bash
tshark -G fields | grep -E 'tls\.handshake\.ja3|tls\.handshake\.ja4'
tshark -r samples/demo.pcap -Y 'tls.handshake.type == 1' \
  -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream \
  -e tls.handshake.extensions_server_name -e tls.handshake.ja3
```

### 2.3. TLS extractor, fingerprint và flow stats

- [ ] Trích timestamp, IP/port, tcp.stream, handshake type, SNI quan sát được, cipher suites/versions, JA3/JA3S/JA4 nếu hỗ trợ.
- [ ] Thiết kế `flow_id = <pcap_basename>:tcp:<stream_id>` để tránh trùng stream ID giữa PCAP khác nhau.
- [ ] Gộp ClientHello/ServerHello theo flow cẩn thận; nếu chỉ có một phía thì đánh dấu `partial`, không tự điền giá trị vắng mặt.
- [ ] Phân biệt dữ liệu quan sát được và dữ liệu suy ra; SNI null có thể do thiếu/ẩn/không bắt được handshake.
- [ ] Packet size sequence: định nghĩa **frame.len** hoặc **ip.len** (chọn 1), chuẩn hóa dấu `+` cho client→server, `-` cho server→client; chỉ lấy các packet thuộc đúng stream.
- [ ] Giới hạn length của chuỗi packet size (ví dụ 50 packet đầu), mô tả cách xử lý retransmission và missing data.
- [ ] Không gọi `tls_observation` là alert độc hại. Nếu không có threat intel/context thì chỉ tổng hợp fingerprint.
- [ ] Có test handshake thiếu, PCAP không TLS, nhiều TCP streams và TShark không có JA4.

### 2.4. CLI, JSON exporter, sự ổn định

- [ ] Khởi tạo cấu trúc `app/`, `tests/`, `samples/`, `reports/`, `docs/`, `requirements.txt`, `.gitignore`.
- [ ] Tạo `app/core/schemas.py` với contract thống nhất và chia sẻ từ 07/11.
- [ ] Triển khai CLI qua `argparse`: subcommand `analyze`, bắt buộc `--pcap`, `--output`; kiểm tra file, loại extension/cảnh báo thích hợp.
- [ ] Lần lượt gọi: Tuấn Anh `parse_dns_pcap` → Sony `analyze_dns_domains` → Tuấn Anh `detect_tunnels` → TLS extractor → exporter.
- [ ] Không để exception của module con làm mất dấu nguyên nhân: log lỗi thân thiện, exit code khác 0 cho lỗi nghiêm trọng, ghi warning cho tính năng không hỗ trợ.
- [ ] JSON report chứa `metadata`, `summary`, `dns_events_summary`, `dga_findings`, `dns_tunnel_findings`, `tls_observations`; số lượng alert theo record thật.
- [ ] Tạo `README.md`: yêu cầu Python/TShark, các lệnh cài đặt và chạy, cấu trúc file, output mẫu, giới hạn của tool.
- [ ] Không commit PCAP nhạy cảm, file keylog TLS, private keys, hay secrets; dùng data công khai/fixture.

### 2.5. Integration & E2E tests

- [ ] Từ **09/11** chạy smoke test với Tuấn Anh DNS event giả lập và Sony DGA result giả lập.
- [ ] Đến **13/11**, chạy thật cả 3 module qua cùng CLI, không hard-code kết quả phát hiện.
- [ ] Test CLI trên: PCAP chỉ DNS, PCAP chỉ TLS, PCAP hỗn hợp, PCAP trống, file không tồn tại, file hỏng.
- [ ] Test JSON luôn parse được qua `json.load` và các trường có type đúng; không thể có `NaN` không hợp lệ trong JSON chuẩn.
- [ ] Test thiếu TShark/JA4: warning và hành vi nhất quán, không báo kết quả fingerprint không tồn tại.
- [ ] Tạo một bản demo có bước 1–5, đầu ra minh họa từ **chạy thật**; lưu stdout/stderr rút gọn.
- [ ] Trước 19/11 chạy lại trong virtualenv sạch theo README từ đầu, ghi phiên bản Python/TShark.

### 2.6. Báo cáo và phối hợp

- [ ] Hoàn thành chương TLS/JA3/JA4, mô tả chính xác các trường handshake có thể quan sát, kèm screenshot Wireshark.
- [ ] Vẽ kiến trúc: PCAP → DNS parser / TLS extractor → DGA + tunnel → JSON reporter.
- [ ] Giao việc sửa lỗi đúng owner: DGA Sony, parser/tunnel Tuấn Anh, TLS/CLI/export Nhi.
- [ ] Cùng Sony rà soát metrics, không viết rằng JA3/JA4 accuracy phát hiện malware nếu không có bộ kiểm chứng.
- [ ] Đóng gói bản nộp: source, requirements, README, báo cáo, demo fixture an toàn, file kết quả, slides do nhóm tổng hợp.

## 3. Lịch làm việc theo ngày — DEADLINE CỨNG

| Ngày | Việc phải làm | Bằng chứng giao cho leader |
|---|---|---|
| **07/11** | Tạo repo/skeleton/contract, xác minh TShark và field JA3/JA4 | PR `schemas.py`, output `tshark --version` |
| **08/11** | TLS extractor ClientHello/ServerHello và sample PCAP TLS | `extractor.py`, output thật |
| **09/11** | JA3/JA3S + check JA4 khả dụng; nhận DNS event Tuấn Anh | TLS observation JSON, smoke test |
| **10/11** | Packet size flow, flow grouping, warnings thiếu trường | `flow_stats.py`, tests |
| **11/11** | TLS alpha hoàn thành và CLI skeleton | Lệnh analyze in được summary |
| **12/11** | Exporter JSON, validation types, tích hợp qua fixtures | `report_exporter.py`, test schema |
| **13/11** | Tích hợp thật Sony+Tuấn Anh, giải quyết mismatch | **Một lệnh CLI chạy đủ pipeline** |
| **14/11** | E2E test PCAP DNS-only/TLS-only/mixed | `test_cli_integration.py`, logs |
| **15/11** | Demo lần 1 cả nhóm, liệt kê lỗi P0 | Demo log + issue list |
| **16/11** | Sửa bug quan trọng; hoàn thiện README/tài liệu kiến trúc | PR, README chạy được |
| **17/11** | Feature freeze, tạo release candidate | Test pass + tag |
| **18/11** | Tổng hợp chương TLS/kiến trúc/báo cáo của nhóm | Draft cuối, ảnh thật |
| **19/11** | Thử chạy từ môi trường sạch, tổng duyệt và backup | Demo script, ZIP nộp |
| **20/11** | Nộp/bảo vệ, trực hỗ trợ | Không thay đổi kiến trúc |

## 4. Test cases bắt buộc và tiêu chí nghiệm thu

| Case | Mong đợi |
|---|---|
| PCAP TLS 1.2 chứa ClientHello | Thấy phiên, SNI nếu có, JA3 nếu được hỗ trợ |
| PCAP TLS 1.3 chứa ServerHello | Hiển thị field quan sát được; không tuyên bố đọc plaintext Certificate |
| TShark không có `tls.handshake.ja4` | JA4 = `null`, warning đúng, pipeline không crash |
| PCAP chỉ DNS | TLS observations rỗng, phần DGA/Tunnel vẫn có kết quả |
| PCAP chỉ TLS | DNS findings rỗng, TLS observations hợp lệ |
| File lỗi hoặc không tồn tại | Lỗi rõ, exit code khác 0, không xuất báo cáo giả |
| Hai flow cùng JA3 | Hiển thị hai flow có thể chia sẻ fingerprint, không tự đánh là malware |
| Packet size sequence | Dấu và độ dài chuẩn, không trộn các TCP streams |

**Điều kiện leader nghiệm thu:**

- [ ] TShark được kiểm tra capability runtime, JA3/JA4 không bị bịa giá trị.
- [ ] TLS observation đúng schema, có xử lý partial/missing data và packet-size sequence.
- [ ] CLI một lệnh chạy toàn hệ thống trên ít nhất một PCAP demo, output JSON hợp lệ.
- [ ] Có ít nhất 10 unit/integration tests, trong đó có test E2E và thiếu TShark/JA4.
- [ ] README ghi đầy đủ lệnh cài/chạy và hạn chế; có demo từ môi trường sạch.
- [ ] Báo cáo TLS/JA3/JA4/kiến trúc và slides được rà soát, nộp trước 20/11.

## 5. Rủi ro và đường lui

- **JA4 không có trong TShark hiện tại:** dùng JA3/JA3S cho demo thực nghiệm; hoàn thành báo cáo cơ chế JA4 dựa trên tài liệu, nêu giới hạn phiên bản, KHÔNG tự tạo hash JA4 ngẫu nhiên.
- **PCAP không bắt trọn handshake:** xuất `partial`, SNI/JA3 là `null` khi vắng; cần PCAP demo khác đủ gói.
- **TLS 1.3 Certificate không đọc được:** giải thích là hạn chế của thiết kế giao thức, không đánh giá là lỗi chương trình.
- **Sony/Tuấn Anh trễ:** chạy integration bằng fixtures theo schema, mở issue có owner; leader ưu tiên giao bản alpha trước 13/11.
- **Thiếu thời gian viết UI:** bỏ hoàn toàn UI; CLI + JSON + ảnh Wireshark đủ cho MVP.

## 6. Câu hỏi bảo vệ Nhi phải trả lời

1. Vì sao có thể fingerprint TLS mà không giải mã HTTPS? Những trường nào quan sát được?
2. JA3 khác JA4 thế nào? Vì sao hai phần mềm khác nhau có thể có fingerprint giống nhau?
3. Tại sao TLS 1.3 Certificate không đọc thụ động như TLS 1.2 trong nhiều trường hợp?
4. ECH ảnh hưởng gì đến SNI và giới hạn của công cụ?
5. Pipeline của nhóm tích hợp ba module thế nào và nếu thiếu TShark thì chương trình xử lý ra sao?

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
