# Định hướng phát triển công cụ kiểm tra ANATTT

Tài liệu này đề xuất lộ trình nâng cấp công cụ để phục vụ tốt vai trò **cơ quan
quản lý đi kiểm tra hệ thống máy tính**, sắp xếp theo thứ tự ưu tiên.

---

## A. Ưu tiên cao — Tính chính danh & toàn vẹn bằng chứng

Đây là nhóm quan trọng nhất: một công cụ của cơ quan quản lý phải **minh bạch,
kiểm chứng được và không hành xử như mã độc**.

### A1. Bỏ hành vi né phần mềm diệt virus
Trong `schedule_self_cleanup`, các từ khóa `del` / `shutdown` đang bị **mã hóa
base64** với chú thích "để giảm cảnh báo của phần mềm diệt virus". Đây là kỹ
thuật **né phát hiện (AV evasion)** — làm công cụ hợp pháp mang đặc điểm của mã
độc, gây mất uy tín pháp lý và khó giải trình.
**Đề xuất:** viết mã trực tiếp, minh bạch; nếu bị AV cảnh báo thì xử lý bằng
**ký số (code signing)** hợp lệ, không phải bằng cách giấu từ khóa.

### A2. Cân nhắc bỏ / tách riêng tính năng tự xóa công cụ và tự tắt máy
Tự động **xóa công cụ** và **tắt máy đối tượng** sau khi kiểm tra:
- Làm mất công cụ khỏi hiện trường (khó tái kiểm chứng).
- Tắt máy người khác có thể gây mất dữ liệu đang mở, bị xem là **can thiệp
  thiết bị được kiểm tra** — trái nguyên tắc "giữ nguyên hiện trạng" mà chính
  biên bản đã cam kết.
**Đề xuất:** mặc định **tắt**, chỉ giữ như thao tác thủ công có xác nhận rõ ràng,
và **không bao giờ tự tắt máy đối tượng**.

### A3. Nhật ký kiểm tra + mã băm biên bản *(đã bổ sung ở bản này)*
Mỗi lần chạy xuất kèm `*_audit.json` chứa toàn bộ dữ liệu thu thập, thời điểm,
phiên bản công cụ và **SHA256 của biên bản** → phục vụ lưu vết và đối soát.
**Phát triển tiếp:** ký số file audit; ghi thêm hash của `windows_vulnerabilities.txt`
và `malware_signatures.txt` để biết đã đối chiếu theo phiên bản dữ liệu nào.

### A4. Đưa cấu hình nhạy cảm ra ngoài mã nguồn
Mật khẩu nén `Ca@11111` đang hard-code. **Đề xuất:** đọc từ biến môi trường /
file cấu hình `config.ini`, không lưu trong mã.

---

## B. Ưu tiên trung bình — Chất lượng & vận hành

### B1. Đổi tên file mã nguồn
`auto_fill_bien_ban_V1.6.py` chứa dấu chấm nên **không import được** (cản trở
đóng gói, kiểm thử). **Đề xuất:** `anattt_tool.py`, quản lý phiên bản bằng biến
`APP_VERSION` (hiện là `1.7` dù tên file là `V1.6` — cần đồng bộ).

### B2. Tách module
Tách file 2000+ dòng thành: `collectors/` (thu thập), `matching/` (đối chiếu
CVE/IOC), `report/` (điền docx + audit), `ui/` (Tkinter). Dễ bảo trì và test.

### B3. Mở rộng kiểm thử *(đã có bộ test cơ bản)*
Đã có `tests/` cho các hàm phân tích. **Tiếp theo:** mock `run_ps` để test các
collector, test điền docx đầu-cuối, tích hợp CI (GitHub Actions).

### B4. Cập nhật dữ liệu CVE/IOC an toàn
Hiện có ~751 CVE và ~53 họ mã độc. **Đề xuất:** script cập nhật định kỳ có
**xác thực nguồn** (MSRC, VNCERT/NCSC, abuse.ch) và **ký/kiểm tra hash** gói dữ
liệu trước khi áp dụng, tránh bị chèn IOC giả.

---

## C. Ưu tiên phát triển — Nâng tầm nghiệp vụ quản lý

### C1. Tổng hợp nhiều máy (đợt kiểm tra diện rộng)
Từ các file `*_audit.json`, sinh **báo cáo tổng hợp** (Excel/HTML): bao nhiêu máy
thiếu bản vá, máy nào dính IOC, tỷ lệ đặt mật khẩu, thống kê theo đơn vị. Đây là
giá trị lớn nhất cho cơ quan quản lý khi kiểm tra hàng loạt.

### C2. Xuất báo cáo HTML/PDF kèm mức rủi ro
Ngoài `.docx`, xuất bản tóm tắt có xếp hạng rủi ro (Critical/High) và khuyến nghị
vá cụ thể theo KB.

### C3. Phân loại mức độ & khuyến nghị tự động
Với mỗi lỗ hổng phát hiện, gợi ý hành động (cài KB nào, tắt dịch vụ nào) dựa trên
cột "Ghi chú" đã có sẵn trong `windows_vulnerabilities.txt`.

### C4. Hỗ trợ nền tảng khác
Cân nhắc collector cho Linux/macOS nếu phạm vi kiểm tra mở rộng ngoài Windows.

### C5. Ký số bản phát hành (.exe)
Đóng gói kèm chứng thư số để máy được kiểm tra và AV tin tưởng — thay cho việc né
AV ở mục A1.

---

## Tóm tắt lộ trình

| Giai đoạn | Nội dung |
|-----------|----------|
| **1 (ngay)** | A1–A4: minh bạch hóa, bỏ né-AV, bỏ tự tắt máy, audit + hash, tách cấu hình |
| **2** | B1–B4: đổi tên, tách module, mở rộng test/CI, cập nhật dữ liệu an toàn |
| **3** | C1–C5: tổng hợp diện rộng, báo cáo HTML/PDF, khuyến nghị tự động, ký số |
