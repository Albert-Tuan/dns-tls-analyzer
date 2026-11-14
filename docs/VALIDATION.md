# Phạm vi kiểm chứng bản giao

## Đã chạy

- Python 3.12.14, Scapy 2.8.0, dnspython 2.9.2, tldextract 5.4.0, pytest 9.2.0.
- 94 tests pass, không skip; log trong `reports/02_tests.log`, JUnit trong `reports/junit.xml`.
- Workflow `python -m scripts.run_all` hoàn tất các bước core; `reports/acceptance.json` ghi kết quả từng lệnh.
- Demo PCAP → DNS → windows → findings → JSON/CSV; event export, fragment integration.
- Chọn ngưỡng dev, đóng băng, chạy test có nhãn; giữ FP/FN thật.

## Điều chỉnh riêng của máy kiểm thử

Máy tạo gói không cho phép Scapy dùng netlink để dò card mạng. Bộ khởi chạy kiểm thử đã đặt `conf.route_autoload=False`, `conf.route6_autoload=False` và tạm tắt `NetworkInterfaceDict.reload` chỉ trong lúc import Scapy. Không sửa packet parser, generator, capture reader, DNS wire parser, detector hay test assertions. File mô tả đầy đủ trong `validation_environment/sitecustomize.py`; để tái lập ở container tương tự, thêm thư mục này vào PYTHONPATH.

File đó không nằm ở root/import path mặc định; người dùng Fedora chạy lệnh bình thường trong README, không cần sử dụng. Không dùng kết quả này để khẳng định đã kiểm tra quyền capture live/network sockets.

## Chưa xác minh tại nơi tạo gói

- TShark field parity: không có TShark trong môi trường; runner ghi trạng thái pending, không ghi pass.
- Fedora/Python 3.14: chỉ starter cũ đã được người dùng xác nhận 15 tests; bản giao hiện tại cần chạy trên Fedora bằng `run_all`.
- Source thật của Sony/Nhi và CLI chung: chưa được cung cấp. Đã test public API/fragment, chưa test full team end-to-end.
- Dữ liệu thật và generalization: toàn bộ dataset trong gói là synthetic.

Không có tuyên bố “100% hoàn thành toàn bộ đồ án”. Đây là module Tuấn Anh có code, tests, thực nghiệm mô phỏng và tài liệu bàn giao đầy đủ trong phạm vi P0.
