# Dataset và đánh giá

## Bộ dữ liệu trong gói

Toàn bộ PCAP được sinh offline bằng Scapy. Không chứa payload dữ liệu đánh cắp, không gọi send/sniff/sr/ARP, không chạy tunnel hay malware. MAC đã chỉ định tĩnh để tránh tự tìm MAC đích. IP dùng dải tài liệu; domain example.com/example.org hoặc .test trong tests.

Hai tập dev/test mỗi tập 21 window: 7 kịch bản × 3 client. Mỗi window thuộc một client và example.com. Seed, timestamp, source IP và label được tạo trước khi chạy detector. Test có seed/thời gian riêng; SHA256 capture được giữ trong manifest. Query/response được sinh để kiểm chứng không double count.

| Kịch bản | Nhãn ý định | Query/window | Kết quả của cấu hình frozen |
|---|---|---:|---|
| ordinary | benign | 8 | TN |
| repeated | benign | 45 | TN |
| cdn_short | benign | 40 | TN |
| telemetry_long | benign | 35 | FP |
| tunnel_dense | tunnel | 40 | TP |
| tunnel_medium | tunnel | 20 | TP |
| tunnel_slow | tunnel | 5 | FN |

Tên kịch bản chỉ biểu diễn hành vi giả lập, **không phải capture từ CDN/telemetry/tunnel thực**. Dev và test cùng họ generator nên sự giống nhau về metrics là dễ hiểu; không có giá trị xác nhận tổng quát hóa. Các mẫu này không đại diện tỷ lệ tấn công thật trong mạng.

## Chọn ngưỡng và đóng băng

`configs/default.json` là ngưỡng ban đầu. Grid khai báo trước: score 60/75/100 × min_queries 10/20; các ngưỡng khác giữ nguyên. Chỉ đọc dev, tối đa hóa F1, hòa thì ưu tiên ít FP hơn, sau đó giữ thứ tự grid. `configs/frozen.selection.json` ghi mọi ứng viên. Cấu hình chọn hiện tại trùng default; không tuyên bố đã tối ưu cho mạng thực.

```bash
python -m scripts.tune_thresholds --manifest samples/dev_manifest.json --output configs/frozen.json
python -m scripts.evaluate_dataset --manifest samples/test_manifest.json \
  --config configs/frozen.json --output reports/test_metrics.json
```

Tuner từ chối manifest có `split=test`. Đây là kiểm soát quy trình, không thể ngăn người dùng cố tình sửa nhãn split; người làm thí nghiệm vẫn chịu trách nhiệm không rò rỉ test.

## Định nghĩa metrics

Đơn vị: `(capture, client IP, registered domain, window_start)` với window 60 giây. Tất cả windows quan sát được phải có nhãn; tất cả windows được gắn nhãn phải có query quan sát được. Capture identity là đường dẫn trong manifest, không gộp các capture trùng thời gian.

- TP: label tunnel và detector cảnh báo.
- FP: label benign và detector cảnh báo.
- TN: label benign và detector không cảnh báo.
- FN: label tunnel và detector không cảnh báo.
- Precision = TP/(TP+FP); Recall = TP/(TP+FN).
- F1 = 2TP/(2TP+FP+FN); FPR = FP/(FP+TN).
- Mẫu số bằng 0 → null (không giả định 0%).

`predicted_label=benign` trong CSV chỉ là ký hiệu cho “not_flagged” nhằm tính confusion matrix; không phải kết luận forensic.

## Thêm capture có nhãn thật

Không dùng một PCAP malware bất kỳ làm nhãn tunneling: có malware không đồng nghĩa có DNS tunnel. Kiểm tra tài liệu nguồn, license, thời điểm và host/domain cụ thể. Có thể tham khảo trang CIC-Bell-DNS-EXF-2021 của UNB để nghiên cứu nguồn dữ liệu; trang mô tả cả feature dataset, nên cần xác minh có packet capture đúng yêu cầu thay vì đưa CSV vào parser:
https://www.unb.ca/cic/datasets/dns-exf-2021.html

Manifest JSON mẫu (thay mọi placeholder bằng dữ liệu đã xác minh):

```json
{
  "dataset_type": "real",
  "split": "test",
  "window_seconds": 60,
  "captures": [
    {
      "path": "verified_capture.pcap",
      "sha256": "SHA256_THAT_CUA_FILE",
      "labels": [
        {
          "src_ip": "192.0.2.10",
          "registered_domain": "example.com",
          "window_start": 1794000000,
          "label": "benign",
          "provenance": "URL/write-up hoặc mô tả lab và bằng chứng xác minh"
        }
      ]
    }
  ]
}
```

Trên Fedora dùng `sha256sum verified_capture.pcap`. Lấy danh sách windows bằng `scripts.run_tv2 --csv ...`, nhưng **không lấy classification của detector làm ground truth**. Đối chiếu từng window với nhãn độc lập. Nếu không biết nhãn, chỉ phân tích/điều tra, không đưa vào tính precision/recall. Không tự gán tất cả phần còn lại là benign.

Chia dev/test theo capture/phiên thu thập, tránh ngẫu nhiên chia từng packet. Không sửa ngưỡng dựa vào test. Lưu config, hash, nguồn, quy trình label và log cùng kết quả. Nếu không tìm được PCAP công khai phù hợp trước hạn, dùng phương án synthetic đúng như bản phân công cho phép và công khai giới hạn.
