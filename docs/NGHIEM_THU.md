# Rà soát phần DNS của Tuấn Anh ngày 14/11/2026

| Tiêu chí trong phiếu Tuấn Anh | Bằng chứng | Trạng thái |
|---|---|---|
| Đọc UDP/53, DNS event đúng field, demo JSON thật | parser, tests/test_dns_parser.py, handoff/evidence/query_response_events.json | Đạt trong phạm vi capture được hỗ trợ |
| Sony và Nhi dùng cùng schema | tests/test_pipeline.py kiểm tra API, examples/integrate_tv3.py đã chạy | Đạt kiểm thử giao diện, chờ hai module thật |
| Window 60s theo client/domain, ≥2 nhóm tín hiệu, minimum query, lý do cảnh báo | windowing.py, detector.py, các test boundary/client/response/shape | Đạt |
| Tối thiểu 12 ca, hai demo và ca input lỗi/TLS-only | 94 ca pass, gồm ca frame có byte đệm và TLS ClientHello | Đạt tại môi trường kiểm thử |
| Dataset có nhãn, đánh giá theo window, phân tích FP/FN | test_metrics.csv, frozen.selection.json, chương báo cáo | Đạt theo phương án mô phỏng được phép trong phiếu |
| Chương báo cáo, minh chứng Wireshark | docs/TV2_DNS_TUNNELING_REPORT.md và hướng dẫn đối chiếu | Đã viết, Tuấn Anh bổ sung ảnh và kết quả TShark trên Fedora |

Trong sáu tiêu chí nghiệm thu của phiếu TV2, bốn tiêu chí có đủ bằng chứng trong phạm vi cục bộ/mô phỏng và hai tiêu chí còn cần xác nhận khi bàn giao. Các mốc GitHub, review của nhóm và buổi demo chung tính riêng.

Bản ngày 12/11 có thể bỏ frame DNS hợp lệ khi Scapy gắn byte đệm Ethernet dưới payload. Bản này đọc số byte do UDP header khai báo trong datagram gốc. Test hồi quy xác nhận cả query có thêm tám byte ở cuối frame và ca UDP bị cắt. Thêm một PCAP ClientHello thực sự sinh offline, xác nhận 1 packet và 0 DNS events. Số liệu test theo window giữ nguyên với 6 TP, 3 FP, 9 TN, 3 FN trên 21 window mô phỏng. Lưu lượng ít query bị bỏ sót, telemetry có tên dài gây báo nhầm.

Python 3.12.14 với Scapy 2.8.0. Môi trường kiểm thử tắt riêng khâu dò interface khi khởi tạo Scapy. Đối chiếu TShark trên Fedora, xác nhận bằng source DGA/TLS thật và hiệu quả trên PCAP tunneling thực tế chưa được chứng minh. TCP DNS reassembly và ghép query-response để tính NXDOMAIN là P1.

Tuấn Anh chạy `python -m scripts.run_all` trên Fedora và kiểm tra hai trường `status` và `tshark_parity` của reports/acceptance.json. Chụp cặp query/response trong Wireshark và phần QNAME dài của demo tunnel để ghi vào báo cáo. Sony kiểm tra list events bằng hàm DGA. Nhi chạy CLI chung với source của cả ba và ghi kết quả vào PR tích hợp. Mốc đề xuất là demo 15/11, khóa tính năng 17/11 và nộp 20/11.

Rà bổ sung ngoài 94 ca tự động: chạy một capture có 50 truy vấn cùng subdomain cho kết quả query_count=50, unique_subdomain_count=1, classification=not_flagged. Tiện ích evaluate_windows trên CSV cho cùng confusion matrix với evaluator. demo_from_events chạy thành công. run_all.sh đạt kiểm tra cú pháp Bash.
