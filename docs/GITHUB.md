# Tạo repo và làm việc theo nhánh

Nếu sao chép nguyên hai thư mục vào repo đã có, hãy giữ nguyên lịch sử Git của repo đó.

Chạy trong thư mục dns-tls-analyzer vừa giải nén. Dùng tài khoản GitHub có quyền tạo repo. Ví dụ dưới đây dùng Albert-Tuan và tên repo dns-tls-analyzer. Nếu nhóm có repo sẵn, clone repo đó, tạo nhánh feature/dns-tunnel từ nhánh mặc định rồi ghép phần DNS của Tuấn Anh theo tài liệu bàn giao.

## Tuấn Anh khởi tạo repo mới trên Fedora

Cài Git và GitHub CLI nếu cần. Chọn GitHub.com, HTTPS và đăng nhập trình duyệt. Dùng gh auth status để kiểm tra tài khoản đang hoạt động.

```bash
sudo dnf install git gh
gh auth login
gh auth status
gh auth setup-git
git init -b main
git commit --allow-empty -m "chore: initialize team repository"
gh repo create Albert-Tuan/dns-tls-analyzer --private --source=. --remote=origin --push
git switch -c feature/dns-tunnel
git add .
git diff --cached --stat
git commit -m "feat(dns): analyze offline DNS traffic and hand off tunnel findings"
git push -u origin feature/dns-tunnel
gh pr create --base main --head feature/dns-tunnel --title "Bàn giao DNS parser và tunnel detector" --body-file docs/NGHIEM_THU.md
```

Nếu Git yêu cầu danh tính trước commit đầu tiên, đặt `git config user.name "Tuấn Anh"` và `git config user.email` với địa chỉ GitHub đã xác minh của bạn, rồi chạy lại lệnh commit. Khi gặp 403, kiểm tra `gh auth status`, `git remote -v`, owner của repo và quyền write của tài khoản. Nếu tạo bằng web, dùng https://github.com/new, chọn Private và để repo trống. Thay lệnh gh repo create bằng `git remote add origin https://github.com/Albert-Tuan/dns-tls-analyzer.git` và `git push -u origin main`.

Trong Settings → Collaborators → Add people, mời bằng GitHub username chính xác của Sony và Nhi. Sau khi hai bạn chấp nhận, gửi link PR. Nhóm có thể đọc và chạy ngay code ở nhánh feature/dns-tunnel trong khi PR chờ duyệt. Sau khi review và merge, main chứa code DNS để tạo hai nhánh tiếp theo.

## Sony và Nhi lấy source

```bash
git clone https://github.com/Albert-Tuan/dns-tls-analyzer.git
cd dns-tls-analyzer
git switch main
git pull --ff-only
```

Sau khi PR DNS đã merge, Sony chạy `git switch -c feature/dga-no-ml`. Nhi chạy `git switch -c feature/tls-integration`. Mỗi người push nhánh của mình bằng `git push -u origin HEAD` sau commit, rồi mở PR về main. Các lệnh cài venv và chạy kiểm thử nằm trong README. ZIP đã kèm các bản kết quả tham chiếu trong handoff/evidence.
