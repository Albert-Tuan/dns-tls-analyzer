"""TShark GIẢ chỉ dành cho kiểm thử tự động (chạy được trên cả Windows/Linux qua `python fake_tshark.py`).

Nó chỉ phát lại dữ liệu JSON do test cung cấp (biến môi trường FAKE_TSHARK_DATA) theo đúng định dạng
`-T fields` của TShark. Mục đích: kiểm thử logic parse/gộp flow/CLI khi không có TShark thật.
Các giá trị JA3/JA4 trong fixture chỉ là chuỗi giả để test parser, KHÔNG phải kết quả đo thực tế.
"""
import json
import os
import sys


def main(argv):
    if "--version" in argv:
        print("TShark (Wireshark) 4.2.2 (FAKE tshark for unit tests)")
        return 0
    data = json.load(open(os.environ["FAKE_TSHARK_DATA"], encoding="utf-8"))
    if argv[:2] == ["-G", "fields"]:
        for name in data["fields"]:
            print(f"F\tField {name}\t{name}\tFT_STRING\tparent\t0\t0x0\t")
        return 0
    if data.get("fail_exit"):
        print("tshark: The file appears to be damaged or corrupt.", file=sys.stderr)
        return 2
    display_filter = argv[argv.index("-Y") + 1] if "-Y" in argv else ""
    columns = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    if "retransmission" in display_filter:
        rows = [{"frame.number": str(n)} for n in data.get("retrans_frames", [])]
    elif "tls.handshake.type" in display_filter:
        rows = data.get("hello_rows", [])
    else:
        rows = data.get("tcp_rows", [])
    for row in rows:
        print("\t".join(str(row.get(c, "")) for c in columns))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
