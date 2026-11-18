# Dữ liệu DGA của Sony (TV1)

Mỗi dòng của `dga_dataset.csv` là **một registered domain**. Detector chấm nhãn đứng trước public suffix (`dga_label`).

| File | Nội dung |
|---|---|
| `sources.json` | 51 danh sách nguồn: URL, SHA256, giấy phép, trích dẫn |
| `dga_dataset.csv` | `domain, dga_label, label (benign/dga), family, split (dev/test), source_name` |
| `dataset_summary.json` | Số dòng gốc, số dòng bị loại theo từng lý do, số lượng mỗi split, SHA256 của CSV |
| `fixture_manifest.json` | Nhãn của `samples/dga_labeled_dns.pcap` (10 domain lấy từ tập test) |

## Nguồn và giấy phép

UMUDGA (University of Murcia Domain Generation Algorithm Dataset), v1, DOI [10.17632/y8ph45msv8.1](https://data.mendeley.com/datasets/y8ph45msv8/1). Trường licence của bản ghi Mendeley Data ghi **MIT**. Trích dẫn: M. Zago, M. Gil Pérez, G. Martínez Pérez, *UMUDGA: A dataset for profiling algorithmically generated domain names in botnet detection*, Data in Brief 30 (2020) 105400, doi:10.1016/j.dib.2020.105400.

- **DGA:** tệp `1000.txt` của 50 họ/biến thể (thư mục *Fully Qualified Domain Names/<họ>/list*). Nhãn họ do nhóm tác giả UMUDGA gán.
- **Lành tính:** tệp `10000.txt` của danh sách `legit` trong cùng bộ dữ liệu (các tên miền hạng cao của Alexa). Có trong danh sách hạng cao không đồng nghĩa với việc tên miền chắc chắn an toàn.
- **Bảng n-gram:** bigram/trigram tiếng Anh của Leipzig Corpora Collection, cũng do UMUDGA phát hành (*Language Data/English/nGrams*). Bảng này không lấy từ danh sách domain đem đi đánh giá. Xem `app/dga/ngram_reference.py`.

## Cách tạo (đã cố định trước khi xem kết quả detector)

1. Tải từng danh sách và kiểm tra SHA256 theo `sources.json`. Cả 51 hash khớp với hash do Mendeley công bố.
2. Chuẩn hóa bằng helper PSL dùng chung với Tuấn Anh (offline, tldextract 5.4.0, không bật private PSL).
3. Loại mẫu DGA có chuỗi sinh ra nằm **dưới** một registered domain dùng chung (DNS động như `x1y2.ddns.net`), vì khi đó nhãn được chấm là `ddns`, không phải chuỗi DGA. Bị loại: corebot 1000, kraken_v1 1000, kraken_v2 504, symmi 1000. Vì vậy chỉ còn 47 họ.
4. Loại trùng theo registered domain (116 dòng), rồi loại trùng theo nhãn DGA (`google.com`/`google.co.in` có chung nhãn `google`; 1.427 dòng). Không có domain mang cả hai nhãn.
5. Giữ toàn bộ domain lành tính. Với DGA, giữ tối đa 200 domain mỗi họ, chọn theo thứ tự SHA256 của domain (không dùng seed).
6. Chia split theo SHA256 của nhãn DGA: `dev` nếu digest mod 100 < 30, còn lại là `test`. Cùng một nhãn không thể xuất hiện ở cả hai split.

| Split | Lành tính | DGA | Tổng |
|---|---:|---:|---:|
| dev | 2.745 | 2.764 | 5.509 |
| test | 6.522 | 6.636 | 13.158 |

Tạo lại (bước 1 cần Internet, các bước còn lại offline):

```bash
python -m scripts.dga_prepare_dataset
python -m scripts.dga_build_ngram_reference
python -m scripts.dga_make_fixture
```

`samples/dga_labeled_dns.pcap` do Scapy sinh offline: mỗi domain có một query và một response, riêng domain cuối được hỏi dưới ba subdomain. Gói tin là tổng hợp; chỉ nhãn domain lấy từ UMUDGA.
