# Công cụ kiểm tra An ninh, An toàn thông tin (ANATTT)

Công cụ hỗ trợ **cơ quan quản lý** (Tổ An ninh, an toàn thông tin) trong công tác
**kiểm tra thiết bị máy tính**: tự động thu thập thông tin cấu hình/an ninh trên máy
Windows theo phương thức **thụ động (chỉ đọc)** và điền sẵn vào **Biên bản kiểm tra
an ninh, an toàn thông tin** (`.docx`).

> **Nguyên tắc:** Công cụ **không** gửi gói tin tấn công, **không** khai thác lỗ hổng,
> **không** thay đổi cấu hình máy được kiểm tra. Chỉ đọc dữ liệu sẵn có trên máy
> (tương đương các lệnh `Get-HotFix`, `Get-Process`, đọc Registry...).

## Tính năng chính

- Thu thập: hệ điều hành + trạng thái bản quyền, cấu hình phần cứng, MAC/IP,
  phần mềm diệt virus, phần mềm thường dùng, tình trạng mật khẩu đăng nhập,
  phân loại mạng (nội bộ / độc lập / Internet).
- **Đối chiếu lỗ hổng**: so khớp bản vá (KB đã cài / số build) với danh mục CVE công khai
  trong `windows_vulnerabilities.txt`.
- **Đối chiếu dấu hiệu mã độc (IOC)**: tiến trình, SHA256, tên file, domain trong cache DNS,
  IP kết nối — theo `malware_signatures.txt`.
- **Lịch sử thiết bị ngoại vi**: USB lưu trữ, điện thoại, máy in USB... (đọc Registry).
- Tự điền biên bản `.docx`, giao diện Tkinter, tương thích **Windows 7 → 11**.

## Cài đặt & chạy

```bash
pip install -r requirements.txt
python auto_fill_bien_ban_V1.6.py            # mở giao diện nhập liệu
python auto_fill_bien_ban_V1.6.py --no-manual --no-open   # chạy nhanh, không giao diện
```

Chạy `--help` để xem đầy đủ tham số. Nên **chạy với quyền Administrator** (chuột phải →
"Chạy với quyền quản trị viên") để đọc đầy đủ hotfix và lịch sử thiết bị.

## File dữ liệu (đặt cùng thư mục, dễ cập nhật định kỳ)

| File | Nội dung |
|------|----------|
| `mau_bien_ban.docx` | Mẫu biên bản đầu vào |
| `windows_vulnerabilities.txt` | Danh mục CVE ↔ KB (`CVE\|Tên\|Mức độ\|KB;KB\|Build\|Ghi chú`) |
| `malware_signatures.txt` | Danh mục IOC theo họ mã độc (`process:`, `sha256:`, `file:`, `domain:`, `ip:`) |

## Biến môi trường

| Biến | Ý nghĩa | Mặc định |
|------|---------|----------|
| `ANATTT_ZIP_PASSWORD` | Mật khẩu nén file log sự cố | *(nên tự đặt)* |
| `ANATTT_NO_ELEVATE` | `1` = không tự nâng quyền (khi kiểm thử) | tắt |

## Kiểm thử

```bash
pytest -q          # kiểm thử các hàm phân tích dữ liệu (chạy đa nền tảng)
```

## Bản quyền

© 2026 Mã Đức Hiển. Xem file `LICENSE`.
