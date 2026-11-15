# Phát hiện và phân loại lưu lượng mã hóa và DNS độc hại — phần TV3 (TLS + tích hợp)

Công cụ CLI phân tích PCAP/PCAPNG **offline**: DNS (DGA, DNS tunnel — do TV1/TV2) và **TLS fingerprinting không giải mã**
(JA3/JA3S, JA4 nếu TShark hỗ trợ — phần TV3), xuất một báo cáo JSON.

> DGA/tunnel chỉ là **nghi ngờ**; JA3/JA4 là dấu vân tay TLS, **không tự kết luận độc hại**.

## Yêu cầu

- Python **3.11+** (đã chạy test trên 3.12.3)
- **TShark** (đi kèm Wireshark). JA3/JA3S cần dissector TLS của Wireshark; **JA4 chỉ có từ Wireshark 4.2.0** — chương trình kiểm tra lúc chạy, không giả định.
- Windows: nếu TShark không nằm trên `PATH`, đặt biến `TSHARK_PATH` (mặc định cũng thử `C:\Program Files\Wireshark\tshark.exe`).

## Cài đặt và chạy

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate      Windows: .venv\Scripts\activate
pip install -r requirements.txt
tshark --version                               # ghi lại phiên bản vào docs/TV3_TLS_INTEGRATION_REPORT.md
tshark -G fields | grep -E 'tls\.handshake\.ja3|tls\.handshake\.ja4'   # Windows: findstr /R "tls.handshake.ja"

python -m app.main analyze --pcap samples/demo.pcap --output reports/demo.json
```

Tuỳ chọn: `--strict` (thiếu TShark/module → exit 3), `--max-packets N` (mặc định 50), `--verbose`.

### Exit code

| Mã | Ý nghĩa | Có ghi báo cáo? |
|---|---|---|
| 0 | Thành công (có thể kèm warning) | có |
| 1 | Lỗi đầu vào: không có file / không phải PCAP / bị cắt cụt / `--output` trùng `--pcap` | **không** |
| 2 | Sai cú pháp dòng lệnh | không |
| 3 | Thiếu TShark hoặc module, **và** có `--strict` | có |
| 4 | Không ghi được file báo cáo | không |
| 5 | Module con (TV1/TV2) ném exception — báo cáo một phần kèm nguyên nhân | có |

### Chính sách thiếu TShark / JA4 (thống nhất cho cả nhóm)

- **Không có TShark** (hoặc TShark lỗi trên file): phần DNS vẫn chạy, `tls_observations = []`,
  `metadata.tshark.available = false`, có warning `tshark_unavailable` / `tshark_error` (in cả ra stderr). Không sinh dữ liệu giả.
- **TShark không có field JA4** (hoặc field khác): bỏ `-e` tương ứng, giá trị = `null`, warning `field_unsupported:<field>`,
  và `null_reasons` trong từng observation ghi lý do. Pipeline không crash.
- Muốn fail cứng thay vì cảnh báo: dùng `--strict`.

## Lệnh TShark thực tế được gọi (để giảng viên tự đối chiếu)

Tất cả chạy bằng `subprocess.run([...], shell=False, timeout=180)`. Cột nào TShark runtime không có thì bị bỏ.

```bash
# 1) Handshake Hello (gộp theo tcp.stream)
tshark -r X.pcap -n -Y "tls.handshake.type == 1 || tls.handshake.type == 2" \
  -T fields -E header=n -E separator=/t -E occurrence=a -E aggregator=, \
  -e frame.number -e frame.time_epoch -e tcp.stream -e tcp.srcport -e tcp.dstport \
  -e ip.src -e ip.dst -e ipv6.src -e ipv6.dst -e tls.handshake.type \
  -e tls.handshake.extensions_server_name -e tls.handshake.version \
  -e tls.handshake.extensions_supported_version -e tls.handshake.ciphersuite \
  -e tls.handshake.extensions_alpn_str -e tls.handshake.extension.type \
  -e tls.handshake.ja3 -e tls.handshake.ja3s -e tls.handshake.ja4

# 2) Packet-size: các packet TCP
tshark -r X.pcap -n -Y tcp -T fields -E header=n -E separator=/t -E occurrence=f \
  -e frame.number -e tcp.stream -e tcp.srcport -e frame.len -e tcp.len \
  -e tcp.flags.syn -e tcp.flags.ack -e ip.src -e ipv6.src

# 3) Retransmission (để loại khỏi chuỗi packet-size)
tshark -r X.pcap -n -Y "tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission" \
  -T fields -e frame.number
```

## Cấu trúc

```text
app/main.py                  CLI + pipeline (TV2 parse -> TV1 DGA -> TV2 tunnel -> TLS -> exporter)
app/core/schemas.py          contract, validate_report, json_safe
app/core/report_exporter.py  build_report(...), write_report_json(...)
app/core/pcap_utils.py       kiểm tra/đếm packet PCAP/PCAPNG (stdlib) — phát hiện file hỏng
app/tls/tshark.py            gọi TShark, probe version + field
app/tls/extractor.py         extract_tls_observations(pcap_path), analyze_tls(...)
app/tls/flow_stats.py        extract_packet_size_series(pcap_path)
app/tls/fingerprint.py       field, trạng thái fingerprint, nhóm flow dùng chung JA3/JA4
tests/                       unit + integration (37 test); fake_tshark.py = TShark giả cho test
docs/TV3_TLS_INTEGRATION_REPORT.md   chương TLS/JA3/JA4/kiến trúc
```

## Định dạng báo cáo (rút gọn)

`metadata` (file, sha256, packet_count, thời gian, `tshark`, `module_status`, `warnings`) · `summary` (số lượng **đếm từ record thật**,
nhóm flow cùng JA3/JA4, `disclaimer`) · `dns_events_summary` · `dga_findings` · `dns_tunnel_findings` · `tls_observations`.

Mỗi `tls_observation` có đủ key của contract (`record_type, flow_id, src_ip, dst_ip, sni, ja3, ja3s, ja4, fingerprint_status,
packet_sizes_signed`) và thêm key bổ sung (không đổi tên key gốc): `tcp_stream, src_port, dst_port, timestamp, handshakes_observed,
negotiated_version, cipher_suites_offered, cipher_suite_selected, alpn_offered, ech_extension_observed, null_reasons, notes, ...`.

- `flow_id = <tên file pcap>:tcp:<tcp.stream>`.
- `fingerprint_status`: `complete` (thấy cả ClientHello + ServerHello, có JA3 và JA3S) · `partial` · `unavailable` (runtime không có field JA3/JA3S).
- `packet_sizes_signed`: `frame.len` của packet **có payload TCP**, `+` client→server, `−` server→client, bỏ retransmission, tối đa 50 packet đầu mỗi stream.

## Kiểm thử

```bash
python -m unittest discover -s tests -t .      # hoặc: pytest
```

**Trạng thái đã xác minh (12/11/2026):** 37/37 test pass trên Python 3.12.3. Các test TLS dùng **TShark giả** (`tests/fake_tshark.py`)
phát lại dữ liệu fixture, và DNS/DGA/tunnel dùng hàm giả đúng contract — nên chúng kiểm chứng logic parse/gộp/CLI,
**chưa** thay thế việc chạy TShark thật. Việc còn phải làm trên máy có TShark: xem mục dưới.

## Việc cần làm trên máy có TShark thật (chưa làm được trong môi trường sinh code)

1. Chạy `tshark --version`, `tshark -G fields | grep ja` và dán kết quả vào báo cáo (mục 2).
2. Chạy CLI trên ít nhất 1 PCAP TLS công khai (TLS 1.2 và TLS 1.3) → lưu `reports/demo.json` và stdout/stderr thật làm demo.
3. Đối chiếu JA3/JA3S trong JSON với cột `tls.handshake.ja3` trong Wireshark GUI; chụp ảnh đưa vào báo cáo.
4. Điền đường dẫn module thật của TV1/TV2 vào `MODULE_CANDIDATES` trong `app/main.py` (xem dưới) và chạy lại E2E.
5. Chạy lại từ virtualenv sạch theo README trước 19/11.

## Tích hợp TV1/TV2

`app/main.py` tự tìm `parse_dns_pcap`, `analyze_dns_domains`, `detect_tunnels` trong các module ứng viên (`MODULE_CANDIDATES`).
**Giả định chữ ký:** `parse_dns_pcap(pcap_path) -> list[dict]`, `analyze_dns_domains(dns_events) -> list[dict]`,
`detect_tunnels(dns_events) -> list[dict]` (đề bài không nêu đường dẫn/chữ ký). Nếu khác, sửa danh sách/adapter tại đó.
Nếu chưa có module: báo cáo ghi `module_missing:<tên>` và kết quả rỗng — không bịa.

## Giới hạn

- Chỉ TCP/TLS; không QUIC/HTTP3, không giải mã, không MITM, không UI, không ML.
- TLS 1.3: Certificate bị mã hóa ở pha handshake → không đọc thụ động được (không phải lỗi chương trình). ECH: SNI quan sát được có thể là SNI ngoài.
- `sni = null` có thể do không có extension, bị ECH che, hoặc handshake không được bắt (xem `null_reasons`).
- Chỉ giữ ServerHello **đầu tiên** của mỗi flow (nếu có HelloRetryRequest, JA3S là của HRR).
- Handshake bị phân mảnh qua nhiều TCP segment phụ thuộc khả năng reassembly của TShark.
- Hướng packet-size suy từ ClientHello; nếu không có thì dùng SYN, cuối cùng là packet đầu tiên thấy (`packet_size_direction_basis`).
- Không commit PCAP nhạy cảm, keylog TLS, private key (đã chặn trong `.gitignore`).
