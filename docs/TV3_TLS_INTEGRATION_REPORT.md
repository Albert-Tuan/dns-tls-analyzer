# Báo cáo TV3 — TLS Fingerprinting & Tích hợp hệ thống

> Các mục đánh dấu **[ĐIỀN SAU KHI CHẠY THẬT]** cần số liệu/ảnh từ máy có TShark; không được điền bằng dữ liệu tự nghĩ ra.

## 1. Kiến trúc

```text
                         ┌────────────────────┐   dns_events    ┌─────────────────┐
                         │ DNS parser (TV2)   │────────────────▶│ DGA (TV1)       │──┐ dga_results
                         │ parse_dns_pcap     │        │        │ analyze_dns_... │  │
  PCAP/PCAPNG ──▶ kiểm   ├────────────────────┤        │        └─────────────────┘  │
  (offline)      tra     │                    │        └───────▶┌─────────────────┐  │
                 magic   │                    │                 │ Tunnel (TV2)    │──┤ tunnel_results
                 + đếm   │                    │                 │ detect_tunnels  │  │
                 packet  ├────────────────────┤                 └─────────────────┘  │
                         │ TLS extractor (TV3)│── tls_observations ──────────────────┤
                         │ TShark (-T fields) │                                      ▼
                         └────────────────────┘                          ┌──────────────────────┐
                                                                         │ report_exporter (TV3)│ → JSON
                                                                         └──────────────────────┘
```

Điều phối bởi `app/main.py` (CLI `analyze`). Mỗi bước độc lập: một module lỗi/thiếu không làm mất kết quả các module còn lại.

## 2. Môi trường TShark

| Mục | Giá trị |
|---|---|
| `tshark --version` | **[ĐIỀN SAU KHI CHẠY THẬT]** |
| Python | **[ĐIỀN]** (test đã chạy trên 3.12.3) |
| `tls.handshake.ja3` / `ja3s` có trong `tshark -G fields`? | **[ĐIỀN]** |
| `tls.handshake.ja4` có trong `tshark -G fields`? | **[ĐIỀN]** (theo tài liệu tham chiếu có từ Wireshark 4.2.0, nhưng phải kiểm tra runtime) |

Chương trình tự ghi `metadata.tshark.version` và `metadata.tshark.fields_supported` vào mỗi báo cáo JSON, nên bảng này có thể
đối chiếu trực tiếp với file `reports/demo.json`.

## 3. TLS 1.2 và TLS 1.3 handshake

**TLS 1.2 (full handshake, 2 RTT)** — phần lớn thông điệp đi **plaintext**:

```text
Client                                              Server
 ClientHello  ───────────────────────────────────▶
              ◀─────────────────  ServerHello, Certificate, ServerKeyExchange, ServerHelloDone
 ClientKeyExchange, ChangeCipherSpec, Finished ──▶
              ◀─────────────────  [NewSessionTicket], ChangeCipherSpec, Finished
 ===== Application Data (mã hóa) =====
```

**TLS 1.3 (1 RTT, RFC 8446)** — chỉ Hello còn plaintext, phần còn lại mã hóa bằng khóa handshake:

```text
Client                                              Server
 ClientHello (+key_share, supported_versions, SNI…) ─▶
              ◀──────── ServerHello (+key_share)            ← plaintext
              ◀──────── {EncryptedExtensions, Certificate, CertificateVerify, Finished}   ← MÃ HÓA
 {Finished} ───────────────────────────────────────▶
 ===== Application Data (mã hóa) =====
```

Phân biệt: **ClientHello/ServerHello** là thông điệp *handshake* (quan sát được); **Application Data** là dữ liệu HTTP/ứng dụng đã mã hóa
(không đọc được và công cụ **không** giải mã). Ở TLS 1.3, trường `legacy_version` của ServerHello là 0x0303; phiên bản thật nằm
trong extension `supported_versions` — vì vậy code ưu tiên `supported_versions` khi tính `negotiated_version`.

### Các trường quan sát được từ ClientHello/ServerHello

| Trường | Ý nghĩa | Ghi chú giới hạn |
|---|---|---|
| SNI (`server_name`) | Tên máy chủ client muốn kết nối | Có thể vắng, hoặc bị ECH che |
| `supported_versions` | Danh sách phiên bản client hỗ trợ / phiên bản server chọn | Loại giá trị GREASE |
| Cipher suites | Bộ mã client đề xuất / server chọn | Loại GREASE |
| Extensions | Danh sách extension | Thứ tự có thể bị ngẫu nhiên hóa bởi client |
| ALPN | Giao thức tầng ứng dụng (vd. `h2`, `http/1.1`) | Chỉ phần client đề xuất được báo cáo |
| `supported_groups` | Nhóm đường cong/trao đổi khóa | Dùng nội bộ trong JA3/JA4, không xuất riêng |

### Giới hạn bắt buộc phải nêu đúng

1. **TLS 1.3 Certificate bị mã hóa.** Sau ServerHello, hai bên suy ra khóa handshake từ trao đổi khóa (ECDHE); `EncryptedExtensions`,
   `Certificate`, `CertificateVerify`, `Finished` được gửi dưới khóa này. Người quan sát thụ động không có khóa nên không đọc được.
   Ở TLS 1.2, Certificate gửi plaintext. Đây là đặc tính thiết kế giao thức, không phải lỗi chương trình. Code **không** có trường certificate nào.
2. **ECH (Encrypted Client Hello).** ClientHello bên ngoài mang SNI "công khai" của máy chủ trung gian; ClientHello bên trong (chứa SNI thật)
   được mã hóa. Vì vậy `sni` quan sát được có thể không phải đích thật, và `sni = null` **không** đồng nghĩa không có SNI.
   Code đánh dấu `ech_extension_observed` khi thấy extension 0xfe0d (65037) và thêm ghi chú.
3. **Fingerprint ≠ độc hại.** Không có threat-intel hay tập kiểm chứng, báo cáo chỉ *mô tả* fingerprint; không đưa ra accuracy phát hiện malware.

## 4. JA3 vs JA4

| | JA3 / JA3S | JA4 |
|---|---|---|
| Đối tượng | JA3: ClientHello. JA3S: ServerHello | ClientHello (họ JA4+ có thêm biến thể khác) |
| Dữ liệu | Chuỗi `SSLVersion,Ciphers,Extensions,EllipticCurves,PointFormats` (giá trị thập phân, nối bằng `-`) → **MD5** | Dạng `a_b_c`: (a) giao thức TCP/QUIC/DTLS, phiên bản TLS, có SNI hay không, số cipher, số extension, ALPN; (b) hash SHA-256 rút gọn của cipher đã **sắp xếp**; (c) hash rút gọn của extension đã **sắp xếp** + signature algorithms |
| GREASE | Loại bỏ giá trị GREASE | Bỏ qua GREASE |
| Thứ tự extension | **Nhạy cảm** với thứ tự → client ngẫu nhiên hóa thứ tự (vd. trình duyệt hiện đại) làm JA3 đổi liên tục | Sắp xếp trước khi hash → ổn định hơn trước ngẫu nhiên hóa |
| Đọc được bằng mắt | Không (chỉ hash) | Phần (a) đọc được: biết ngay TLS 1.3, có SNI, số cipher… |
| Giới hạn | Trùng lặp giữa nhiều ứng dụng dùng cùng thư viện; dễ bị client giả mạo/đổi | Tương tự: phản ánh *thư viện + cấu hình TLS*, không phản ánh ứng dụng hay ý đồ |

Nguồn: đặc tả JA4 tại `https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md`; tham chiếu field Wireshark
`https://www.wireshark.org/docs/dfref/t/tls.html`. **Cần đối chiếu lại chi tiết định dạng với đặc tả trước khi nộp.**

**Quy tắc của công cụ:** giá trị JA3/JA3S/JA4 chỉ lấy từ TShark; không tự tính, không tự tạo hash. Nếu runtime thiếu `tls.handshake.ja4`
thì `ja4 = null` + warning + `null_reasons.ja4 = field_not_supported_by_tshark`.

## 5. Thiết kế extractor

- **Một observation = một TCP stream** có ít nhất một Hello. `flow_id = <tên pcap>:tcp:<tcp.stream>` (tránh trùng stream ID giữa các PCAP).
- Gộp ClientHello + ServerHello theo `tcp.stream`. Giữ Hello **đầu tiên** của mỗi loại (bỏ bản gửi lại).
- Chỉ một phía → `fingerprint_status = partial`; phía vắng → `null` + `null_reasons`. Không điền giá trị suy ra.
- `src_ip` là phía client. Nếu chỉ thấy ServerHello thì client = bên nhận (ghi chú trong `notes`).

### Mã lý do `null_reasons`

| Mã | Nghĩa |
|---|---|
| `client_hello_not_captured` | PCAP không có ClientHello của flow (SNI/JA3/JA4 không thể có) |
| `server_hello_not_captured` | PCAP không có ServerHello (JA3S không thể có) |
| `field_not_supported_by_tshark` | Runtime TShark không có field tương ứng |
| `extension_absent_or_hidden` | Thấy Hello nhưng không có SNI: extension vắng, hoặc bị ẩn (ECH) |
| `not_reported_by_tshark` | Field có, Hello có, nhưng TShark không in giá trị |

### Packet-size sequence

`frame.len` (chọn 1 trong `frame.len`/`ip.len`), chỉ packet có payload TCP, `+` client→server / `−` server→client, bỏ retransmission,
tối đa 50 packet đầu/stream, xử lý từng stream riêng. Hướng được xác định theo ClientHello → SYN → packet đầu tiên (ghi trong
`packet_size_direction_basis`). **Missing data:** nếu PCAP bắt giữa chừng (không có SYN/ClientHello) hướng chỉ là suy đoán.

## 6. Kiểm thử

| Nhóm | Số test | Nội dung |
|---|---|---|
| `test_tls_extractor.py` | 19 | gộp Hello, GREASE, TLS 1.3, partial, chỉ ServerHello, ECH, JA4 thiếu, PCAP không TLS, TShark thiếu/lỗi exit code, packet-size (dấu, retransmission, cắt 50, không lẫn stream), nhóm JA3 dùng chung |
| `test_cli_integration.py` | 18 | file không tồn tại/hỏng/cắt cụt/trùng output (exit 1, không ghi báo cáo), PCAP trống, mixed/TLS-only/DNS-only, thiếu TShark (mặc định & `--strict`), thiếu JA4, module thiếu/lỗi (exit 5), JSON chuẩn không NaN, validate schema, PCAP/pcapng |

Kết quả đã chạy: **37/37 pass** (Python 3.12.3). Lưu ý trung thực: test dùng TShark giả và module DNS giả đúng contract.
Kết quả đo trên PCAP thật: **[ĐIỀN SAU KHI CHẠY THẬT]** (stdout/stderr rút gọn, đường dẫn `reports/demo.json`, ảnh Wireshark).

## 7. Hạn chế đã biết

- Chỉ TCP/TLS; không QUIC/HTTP3, không giải mã, không MITM.
- HelloRetryRequest (TLS 1.3): JA3S lấy từ ServerHello đầu tiên, có thể là của HRR.
- Phụ thuộc phiên bản Wireshark cho tên field và JA4.
- Đường dẫn/chữ ký module TV1/TV2 là giả định (xem README) — cần xác nhận khi tích hợp.

## 8. Câu hỏi bảo vệ

**1. Vì sao fingerprint TLS mà không giải mã HTTPS? Quan sát được trường nào?**
Hello được gửi *trước* khi có khóa mã hóa nên plaintext. Từ đó thấy phiên bản, cipher suites, extensions, ALPN, supported groups, SNI (nếu không bị ECH)
và dẫn xuất JA3/JA3S/JA4. Nội dung ứng dụng thì không đọc được và công cụ không cố giải mã.

**2. JA3 khác JA4? Vì sao hai phần mềm khác nhau có thể có cùng fingerprint?**
JA3 là MD5 của chuỗi trường theo đúng thứ tự (nhạy thứ tự extension); JA4 có phần đọc được và sắp xếp cipher/extension trước khi hash nên bền hơn trước ngẫu nhiên hóa.
Fingerprint phản ánh *thư viện TLS + cấu hình* — nhiều ứng dụng dùng chung cùng thư viện (hoặc cùng cấu hình mặc định) nên trùng nhau; vì thế không dùng nó một mình để kết luận ứng dụng hay độc hại.

**3. Tại sao Certificate của TLS 1.3 không đọc thụ động như TLS 1.2?**
TLS 1.3 mã hóa mọi thông điệp sau ServerHello bằng khóa handshake suy ra từ ECDHE; người quan sát không có khóa. TLS 1.2 gửi Certificate plaintext.

**4. ECH ảnh hưởng gì đến SNI và giới hạn của công cụ?**
SNI thật nằm trong ClientHello bên trong (mã hóa); thứ quan sát được là SNI ngoài. Do đó `sni` có thể không phải đích thật và `null` không có nghĩa là không có SNI. Công cụ chỉ gắn cờ `ech_extension_observed`, không cố suy ra SNI thật.

**5. Pipeline tích hợp ba module thế nào? Thiếu TShark thì sao?**
`main.py` gọi tuần tự parse DNS → DGA → tunnel → TLS extractor → exporter; mỗi bước có trạng thái trong `metadata.module_status`. Thiếu TShark: mặc định báo cáo DNS vẫn xuất,
`tls_observations` rỗng, `tshark.available=false` và warning rõ ràng, exit code 0; với `--strict` thì exit 3. Không bao giờ sinh dữ liệu TLS giả.
