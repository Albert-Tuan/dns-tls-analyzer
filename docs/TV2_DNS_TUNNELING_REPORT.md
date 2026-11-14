# Tuấn Anh — Phân tích DNS và phát hiện dấu hiệu DNS tunneling bằng quy tắc

**Phạm vi báo cáo:** phần DNS của đồ án không AI/ML. Bản thực nghiệm 14/11/2026; số liệu lấy từ chương trình chạy trong gói, không phải ước lượng. Báo cáo này chưa thay thế phần TLS/DGA do Nhi/Sony viết.

## 1. Mục tiêu

Xây dựng module đọc PCAP/PCAPNG offline, trích DNS event theo hợp đồng chung và đánh giá các nhóm truy vấn có hành vi tương tự DNS tunneling. Module cung cấp list event cho detector DGA và trả cảnh báo có lý do để tích hợp vào CLI chung. Cảnh báo là nghi ngờ cần điều tra, không phải khẳng định mã độc hay exfiltration.

## 2. Phương pháp

Parser đọc tuần tự packet bằng Scapy, chọn UDP với source hoặc destination port 53 và IPv4/IPv6. Kiểm tra cấu trúc container trước để phát hiện các trường hợp capture bị cắt mà reader có thể xem như EOF. DNS wire message được kiểm tra bằng dnspython. Mỗi message có một question hợp lệ tạo một event; QR quyết định query/response. Chỉ query đi vào thống kê hành vi; RCODE query là null, response có RCODE tương ứng trong message. Chưa ghép giao dịch query–response.

QNAME được chuẩn hóa chữ thường, IDNA, bỏ dấu chấm kết thúc, kiểm tra chiều dài và ký tự phù hợp hostname/service label. tldextract dùng PSL bundled offline, private domains không bật. `.test` được hỗ trợ rõ cho lab; suffix chưa biết, reverse name và single-label được giữ event với registered_domain null. Những event này không đưa vào detector. Không giả định hai nhãn cuối luôn là registered domain.

Gom query theo client IP và registered domain, cửa sổ không chồng lấn 60 giây bám epoch. Timestamp đầu vào không cần đúng thứ tự; module sắp lại trong window. Hai client khác nhau không bị trộn. Vị trí bắt gói quyết định ý nghĩa client IP: khi capture ở sau recursive resolver, source quan sát được có thể là resolver, không còn là endpoint ban đầu.

Features gồm query_count, unique QNAME, số/tỷ lệ subdomain duy nhất, độ dài subdomain trung bình/tối đa, Shannon entropy, qtype distribution, TXT ratio và interarrival. Độ dài/entropy tính trên subdomain đã bỏ dấu chấm; query apex đóng góp 0. Entropy là `-sum(p_i log2 p_i)`, không phải xác suất tấn công. TXT ratio là thông tin hỗ trợ, không phải điều kiện bắt buộc vì tunnel có thể dùng loại record khác.

## 3. Bộ quy tắc

| Quy tắc | Ngưỡng ban đầu | Điểm | Nhóm |
|---|---|---:|---|
| high_query_count | ≥30 query/window | 25 | volume |
| many_unique_subdomains | ≥10 subdomain duy nhất và ratio ≥0.8 | 25 | diversity |
| long_subdomain_labels | Average length ≥25 ký tự, bỏ dấu chấm | 25 | shape |
| high_subdomain_entropy | Average entropy ≥3.6 bit/ký tự | 25 | shape |

Điều kiện cảnh báo: ít nhất 10 query, ít nhất 2 nhóm tín hiệu và score ≥60. Với bốn quy tắc cùng trọng số, score ≥60 thực tế cần ít nhất 3 quy tắc (75 điểm). Length và entropy có tương quan nên cùng nhóm shape. Không gọi các nhóm này là độc lập thống kê. Score 0–100 là tổng trọng số, không calibration thành xác suất.

Chọn cấu hình bằng grid score={60,75,100}, min_queries={10,20}, chỉ trên dev; tối đa hóa F1 rồi ưu tiên ít FP hơn. Cấu hình frozen được chọn: window=60, min_queries=10, min_unique_count=10, high_query_count=30, unique_ratio=0.8, average length=25, average entropy=3.6, alert_score=60, min_independent_signals=2. Đây chỉ là lựa chọn trên fixture dev.

## 4. Dữ liệu và thiết kế thực nghiệm

Dữ liệu được tạo bằng Scapy, chỉ ghi file, không gửi DNS ra mạng và không mang payload exfiltration. Có bộ demo cơ bản, query/response, IPv6, PCAPNG, empty và no-DNS. Dev và test mỗi tập có 21 windows: 7 kịch bản × 3 client, 12 benign và 9 tunnel-intent. Seed, thời gian riêng; nhãn được tạo từ ý định kịch bản trước prediction và đi kèm hash capture.

Bốn kịch bản benign là truy vấn thông thường, lặp health name, CDN-like tên ngắn và telemetry-like tên dài ngẫu nhiên. Ba kịch bản tunnel-intent là dense, medium và slow. Các tên này mô tả mô phỏng, không phải traffic được capture từ các ứng dụng thực tế. Dev/test cùng họ generator; vì vậy kết quả không chứng minh tổng quát hóa.

Đơn vị đánh giá là capture + client + registered domain + cửa sổ thời gian. Evaluator đọc capture, tự chạy detector, đối chiếu toàn bộ nhãn; thiếu nhãn hoặc không có window tương ứng đều báo lỗi. Ground truth không lấy từ output của detector.

## 5. Kết quả đo

Bộ kiểm thử tự động gồm **94 tests**, toàn bộ pass trên Python 3.12.14 với Scapy 2.8.0, dnspython 2.9.2, tldextract 5.4.0, pytest 9.2.0. Do môi trường chặn dò giao diện mạng, bộ khởi chạy kiểm thử tắt riêng interface/route discovery của Scapy; phần PCAP I/O, DNS parser, feature extraction và detector không thay đổi. Chưa chạy bản mới trên Fedora/Python 3.14, và chưa chạy đối chiếu TShark tại môi trường tạo gói. `scripts.run_all` sẽ thực hiện các bước đó khi chạy trên máy người dùng có TShark.

| Demo | DNS queries | Responses | Windows | Tunnel alerts |
|---|---:|---:|---:|---:|
| benign_dns.pcap | 4 | 0 | 2 | 0 |
| synthetic_tunnel_like_dns.pcap | 40 | 0 | 1 | 1 |
| query_response.pcap | 1 | 1 | 1 | 0 |

| Tập | N windows | TP | FP | TN | FN | Precision | Recall | F1 | FPR |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Dev synthetic | 21 | 6 | 3 | 9 | 3 | 0.6667 | 0.6667 | 0.6667 | 0.2500 |
| Test synthetic | 21 | 6 | 3 | 9 | 3 | 0.6667 | 0.6667 | 0.6667 | 0.2500 |

Nguồn số liệu: `reports/dev_metrics.json`, `reports/test_metrics.json`, CSV từng window, logs và `configs/frozen.selection.json`. Test không dùng để chọn cấu hình. Cùng confusion matrix giữa dev/test phản ánh cùng thiết kế kịch bản, không phải hai xác nhận thực địa độc lập.

## 6. Phân tích sai số

Ba FP đều là telemetry-like với nhiều tên dài, thay đổi và entropy cao. Các đặc trưng này tương tự dữ liệu mã hóa trong DNS nên bộ quy tắc không phân biệt được chỉ từ query. Không nên dùng allowlist tạo sau khi nhìn test để xóa FP khỏi báo cáo. Hướng cải thiện cần dữ liệu benign thật, bối cảnh client/application, baseline theo tổ chức và đánh giá allowlist riêng trên dev.

Ba FN là tunnel-intent chỉ có 5 query/window, thấp hơn minimum query gate. Gate giúp tránh kết luận từ rất ít dữ liệu nhưng làm bỏ sót low-and-slow. Cửa sổ dài hoặc nhiều thang thời gian có thể được nghiên cứu sau; thay window phải xây lại ground truth và thử lại trên tập độc lập.

Không phát hiện C2/beaconing chỉ vì interarrival đều. Trường interarrival hiện chỉ mô tả dữ liệu; không phải một module beacon detection được xác nhận.

## 7. Giới hạn

- Phân tích classic DNS UDP/53; không TCP reassembly, IP fragment reassembly, DoH/DoT/DoQ hay live capture.
- Một question/message; multiple-question và opcode khác QUERY bị bỏ có warning.
- Không nhận mọi DNS binary label như hostname, không gán domain cho suffix chưa biết.
- Không ghép response nên không công bố NXDOMAIN ratio; response vẫn xuất RCODE.
- Không deduplicate query retry; qtype CNAME trong question không đồng nghĩa đã phân tích toàn bộ answer chain.
- Scapy đọc packet tuần tự nhưng list API giữ event trong RAM, có giới hạn 1 triệu event mặc định.
- Danh sách suffix phụ thuộc snapshot của phiên bản tldextract; pin phiên bản để tái lập.
- Chưa chứng minh trên dataset thực; chưa xác minh integration với source thật Sony/Nhi.

## 8. Tích hợp và tái lập

API giữ đúng bản phân công không AI/ML: parse_dns_pcap, group_dns_windows, extract_tunnel_features, detect_tunnels. Nhi parse một lần, truyền cùng events cho Sony và Tuấn Anh, ghép findings vào report chung. Mẫu fragment đã chạy: 40 events và 1 alert. CLI chung `app.main` vẫn thuộc Nhi.

Từ venv sạch chạy `pip install -r requirements-lock.txt`, sau đó `python -m scripts.run_all`. Lưu acceptance, JUnit, logs, config frozen, manifests và hash. Thực hiện thêm ảnh Wireshark của chính nhóm theo `THUC_HAN_VA_DEMO.md` để hoàn thiện bằng chứng trình bày.

## 9. Tài liệu tham chiếu

- Scapy Usage: https://scapy.readthedocs.io/en/stable/usage.html
- tldextract và lựa chọn PSL offline: https://github.com/john-kurkowski/tldextract
- dnspython: https://dnspython.readthedocs.io/
- DNS message format: https://www.rfc-editor.org/rfc/rfc1035.html#section-4.1
- MITRE ATT&CK DNS: https://attack.mitre.org/techniques/T1071/004/
- Nghiên cứu/dataset CIC-Bell-DNS-EXF-2021: https://www.unb.ca/cic/datasets/dns-exf-2021.html

Các nguồn là tài liệu nền/phương pháp; không ghi rằng PCAP trong gói được tải từ các nguồn này.
