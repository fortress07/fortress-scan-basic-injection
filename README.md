# Fortress Scan — Basic Injection

[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)

Công cụ phân tích tĩnh giúp **phát hiện sớm các lỗ hổng injection** trong mã nguồn. Cài về, trỏ vào
thư mục dự án, đọc báo cáo. Giao diện và báo cáo hoàn toàn bằng **tiếng Việt**.

---

## Công cụ này làm gì

Fortress Scan đọc mã nguồn của bạn và tìm những chỗ **dữ liệu từ bên ngoài có thể bị hiểu thành mã,
câu lệnh hoặc truy vấn**. Nó không dò từ khóa — nó truy ngược **đường đi của dữ liệu** từ nơi đi vào
đến nơi phát nổ, rồi in ra cả đường đi để bạn tự kiểm chứng.

```
$ python -m fortress_scan ./du-an-cua-toi

app/routes.py
   CRIT  42:4   Dữ liệu không tin cậy được nối thẳng vào câu lệnh SQL
        tham số truy vấn HTTP chạy tới cursor.execute() mà chưa được vô hiệu hóa
        FSB-SQL-001 | độ tin cậy high | CWE-89
        cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
        đường đi của dữ liệu:
          dòng 40  tham số truy vấn HTTP đi vào từ đây
          dòng 40  chảy vào biến name
          dòng 42  chạy tới cursor.execute()
```

**26 rule, phủ 12 họ injection:** SQL · NoSQL · LDAP · XPath · OS command · code injection
(`eval`/`exec`) · template (SSTI) · expression language · XSS · XXE · file inclusion · reflection.
Kèm 3 nhóm liên quan: giải tuần tự không an toàn, Trojan Source / ký tự ẩn, và script cài đặt tải mã
từ xa về chạy.

**Ngôn ngữ:** Python (sâu nhất), JavaScript, TypeScript, PHP, Java/JVM, Ruby, Go, C#, shell và
`package.json`.

Xem đầy đủ: `python -m fortress_scan --list-rules`

### Chỉ đọc và báo cáo — không làm gì khác

Điều này được **kiểm chứng bằng test tự động**, không phải lời hứa:

- **Không sửa gì** trong code của bạn — cây thư mục trước và sau khi quét giống hệt nhau
- **Không ghi file nào** trừ khi bạn tự yêu cầu bằng `-o` hoặc `--write-baseline`
- **Không đọc gì** ngoài thư mục bạn chỉ định
- **Không mở kết nối mạng**, không telemetry, không kiểm tra cập nhật — mã của bạn không đi đâu cả
- **Không chạy hay import** mã được quét, chỉ phân tích cú pháp
- **Không phụ thuộc thư viện ngoài** — 21 module đều thuộc thư viện chuẩn Python

---

## Mục đích

Đây là **dự án cá nhân**, viết ra vì mong muốn anh em dev Việt Nam có một công cụ **tiếng Việt** để
soi lại code **trước khi đưa lên production**.

Nó tồn tại như **một lớp tham khảo thêm** bên cạnh việc tự review — chạy nhanh, không cần cấu hình,
chỉ ra chỗ đáng ngờ kèm đường đi của dữ liệu, rồi phần còn lại là quyết định của bạn.

---

## Cài đặt

Yêu cầu **Python 3.9 trở lên**. Không cần gì thêm.

```bash
git clone https://github.com/fortress07/fortress-scan-basic-injection
cd fortress-scan-basic-injection
pip install -e .
python -m fortress_scan --version
```

### Cách dùng

```bash
python -m fortress_scan .                        # quét thư mục hiện tại
python -m fortress_scan ./src -v                 # kèm đường đi dữ liệu + cách khắc phục
python -m fortress_scan . --min-severity high    # chỉ xem lỗi nặng
python -m fortress_scan . -f markdown -o BAO-CAO.md
```

Sau khi cài còn có hai lệnh ngắn `fortress-scan` và `fscan`. Nếu shell báo không tìm thấy lệnh
(thư mục `Scripts` của Python chưa có trong PATH), cứ dùng `python -m fortress_scan`.

Thử ngay với bộ mẫu có sẵn:

```bash
python -m fortress_scan tests/samples/vulnerable --no-config -v   # phải ra 19 lỗi critical
python -m fortress_scan tests/samples/safe --no-config            # phải im lặng
```

Hai thư mục trên có **cùng chức năng**, chỉ khác ở chỗ một bên viết an toàn.

**Mã thoát cho CI:** `0` sạch · `1` có phát hiện · `2` sai cách dùng · `3` lỗi nội bộ.

---

## ⚠️ Giới hạn — xin đọc kỹ trước khi tin kết quả

> ### Công cụ đưa ra **GỢI Ý**, không phải phán quyết
>
> **Mọi kết quả cần được bạn tự xem xét và quyết định hướng xử lý.**
>
> Công cụ **KHÔNG cam đoan** rằng sửa theo gợi ý là đã vá xong lỗ hổng.
> Công cụ **KHÔNG cam đoan** đã tìm ra hết mọi lỗ hổng trong mã của bạn.
>
> Một báo cáo sạch là *bằng chứng tốt*, **không phải chứng minh là an toàn**. Hãy coi nó như một
> người rà soát thêm, không phải một chứng nhận bảo mật.

### Phạm vi hoạt động

Công cụ neo vào **tên API của thư viện** (`os.system`, `$_GET`, `cursor.execute`) — những cái tên cố
định. Vì vậy:

| Tình huống trong code của bạn | Kết quả |
| --- | --- |
| Đặt tên biến/hàm bằng tiếng Việt, Trung, Nhật (kể cả có dấu) | ✅ Không ảnh hưởng gì |
| Đổi tên thư viện — `import os as he_dieu_hanh` | ✅ Vẫn bắt được |
| Hàm bọc / tầng CSDL tự viết, **cùng tệp** | ✅ Tự học được, mức critical |
| Hàm bọc / tầng CSDL tự viết, **khác tệp trong dự án** | ⚠️ Chỉ còn mức medium, và báo ở file wrapper chứ không phải chỗ gọi |
| Framework hoặc helper lấy input tự viết mà công cụ chưa biết | ⚠️ Chỉ còn mức medium |
| Wrapper nằm trong **thư viện ngoài** (cài qua pip) | ❌ Bỏ sót |

**Ngôn ngữ bạn dùng để đặt tên không quan trọng. Cái quyết định là wrapper của bạn nằm ở đâu.**

### Các giới hạn khác

- **Chỉ phân tích trong phạm vi một tệp** — nguồn ở `a.py` chạy tới sink ở `b.py` qua `import` thì
  chưa nối được.
- **Ngoài Python là phân tích theo token**, không phải parser đầy đủ — độ bao phủ thấp hơn, và giá
  trị "độ tin cậy" trong báo cáo phản ánh đúng điều đó.
- **Không theo được dữ liệu lưu vào thuộc tính đối tượng**, và không phát hiện **injection bậc hai**
  (dữ liệu bẩn ghi vào CSDL rồi đọc ra dùng lại).
- **Chưa hỗ trợ:** CRLF/header injection, log injection, path traversal, SSRF, open redirect,
  prototype pollution, ReDoS, lỗi logic nghiệp vụ.
- Sẽ có **báo nhầm** (false positive) và **bỏ sót** (false negative) — phân tích tĩnh vốn không đầy
  đủ. Công cụ **bổ sung** cho code review, quét phụ thuộc và kiểm thử động, **không thay thế** cái
  nào cả.

### 🖥️ Nền tảng

> **Phát triển và kiểm thử trên Windows 11** — toàn bộ 479 test đều chạy qua.
>
> **Trên Linux và macOS: tác giả chưa chạy thử thực tế.** Mã nguồn viết theo hướng đa nền tảng và
> nhiều khả năng chạy bình thường, nhưng **chưa có bằng chứng thực nghiệm** — nếu bạn dùng
> Linux/macOS xin coi đây là phiên bản thử nghiệm.

### Khi quét mã không đáng tin

Chú thích `fortress-scan: ignore`, tệp `.fortress-scan.json` và `.gitignore` đều nằm **trong chính
mã được quét**, nên người viết mã có thể dùng chúng để giấu phát hiện. Khi review code lạ, hãy chạy:

```bash
python -m fortress_scan <duong-dan> --no-inline-suppressions --no-config --no-vcs-ignore
```

---

## Góp ý & báo lỗi

**Xin vui lòng KHÔNG mở issue trên GitHub.** Mọi góp ý, báo lỗi, đề xuất tính năng hay câu hỏi, xin
gửi trực tiếp qua email:

### vophuvinh15012007@gmail.com

Khi báo lỗi, xin kèm giúp: **phiên bản công cụ**, **hệ điều hành**, và **một đoạn mã tối thiểu tái
hiện được lỗi**. Nếu là lỗi bảo mật của chính công cụ, càng nên gửi riêng tư qua email thay vì công
khai.

Mình đọc và phản hồi tất cả, chỉ là có thể hơi chậm.

---

## Tác giả & lời cảm ơn

Được viết bởi **[fortress07](https://github.com/fortress07)** — dự án cá nhân, không liên quan tới
tổ chức hay trường học nào.

Dự án có **sự hỗ trợ của AI** (Claude) trong quá trình tham khảo cách triển khai và đẩy nhanh tiến
độ: phác thảo kiến trúc, sinh mã cho các engine phân tích, viết bộ test và soạn tài liệu. Toàn bộ
hướng đi, yêu cầu, quyết định thiết kế và việc kiểm thử đều do tác giả điều hướng và rà soát. Mình
ghi rõ điều này vì cho rằng người dùng có quyền biết mã họ đang chạy được tạo ra như thế nào.

Cảm ơn bạn đã dành thời gian đọc tới đây và tin dùng Fortress Scan. Nếu công cụ giúp ích được cho
bạn, một ngôi sao trên GitHub là nguồn động viên rất lớn.

---

## Giấy phép

[MIT](LICENSE) — dùng tự do cho cả mục đích cá nhân và thương mại, chỉ cần giữ lại thông báo bản
quyền.
