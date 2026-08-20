# Nhật ký thay đổi

Mọi thay đổi đáng kể của Fortress Scan Basic Injection được ghi ở đây.

Số bản theo [Semantic Versioning](https://semver.org/lang/vi/). Từ 0.1.0 trở đi, bộ mã rule
(`FSB-*`), khoá trong JSON/SARIF và các cờ dòng lệnh được coi là **giao diện ổn định**: chúng chỉ
đổi theo một bản minor mới, kèm ghi chú ở đây.

---

## 0.1.0 - bản chính thức đầu tiên

Bản này khép lại giai đoạn thử nghiệm. Trước nó, công cụ đã đi qua nhiều vòng dựng và tự kiểm
toán; toàn bộ lịch sử đó nằm trong git, còn đây là mốc đầu tiên được phát hành như một sản phẩm.

**35 rule / 17 họ injection · 14 ngôn ngữ và định dạng · 1035 kiểm tra tự động · 0 phụ thuộc ngoài.**

### Phân tích sâu hơn, kêu oan ít hơn

Mỗi mục dưới đây có một cặp kiểm tra "phải im lặng / phải bắn" trong `tests/test_precision_guards.py`.
Vế thứ hai đứng đó để chặn đúng một đường: cách sửa dễ nhất cho mọi báo nhầm luôn là tắt bớt rule,
và bộ test vẫn xanh trong khi công cụ mù thêm một chút.

- **Ngữ cảnh tệp** (`core/context.py`): phát hiện trong `tests/`, `examples/`, mã do máy sinh hay
  mã đi mượn bị hạ **đúng một nấc** độ tin cậy, được gắn nhãn `context:*`, và **không bao giờ bị
  giấu đi**. Tắt bằng `--no-context-demotion`. Phép phân loại khớp theo từng thành phần đường dẫn
  và theo ranh giới từ, nên `latest.py`, `contest/`, `sample_rate.py` vẫn là mã sản phẩm.
- **`assert x in CHO_PHEP`** được đọc như `if x not in CHO_PHEP: raise`.
- **Lớp `enum.Enum` do chính dự án khai báo** là một danh sách cho phép: `Lenh(gia_tri)` hoặc khớp
  một thành viên, hoặc ném `ValueError`.
- **`bang.get(khoa)`** không còn mang vết nhiễm của *khoá* sang giá trị trả về. Phép tra bằng ngoặc
  vuông vốn đã tính đúng; đây là cùng một sự việc viết bằng lời gọi phương thức.
- **Tham số đã được framework ép kiểu** không còn bị coi là chuỗi tự do: bộ chuyển kiểu trong route
  (`@app.route('/x/<int:so>')`) và chú thích kiểu của FastAPI (`def h(so: int)`).
- **`sqlalchemy.text('... :id')`** kèm tham số ràng buộc không còn bị gọi là "câu lệnh không phải hằng".
- **Phép ép kiểu tiền tố** (`[int]$args[0]` của PowerShell) được nhận là bộ khử độc.
- Ở các ngôn ngữ quét theo token, **trường của một giá trị bẩn giờ cũng bẩn**:
  `const q = req.query; exec(q.host)`. Trước đây chỉ tên đầy đủ mới được tra, nên cách viết phổ
  biến nhất của mọi framework rơi thẳng qua lưới.

### Bằng chứng đi kèm mọi phát hiện

Mỗi phát hiện mang theo trường `evidence`: nguồn nào, đường đi mấy bước, có qua ranh giới tệp
không, ngữ cảnh tệp có hạ mức không. Có mặt ở **cả bốn định dạng** — console (`-v`), JSON, SARIF
(trong `properties`) và Markdown. Ngưỡng `--min-confidence` được áp lại **sau** khi hiệu chỉnh, nên
con số người dùng đặt là con số họ nhận được.

### Phạm vi quét rộng hơn

- **4 ngôn ngữ mới**: Rust, PowerShell, Perl, Lua (kể cả OpenResty `ngx.*`).
- **Workflow GitHub Actions là mã nguồn** và có bộ phân tích riêng (`analysis/workflow.py`), với
  4 rule mới:
  - `FSB-CI-001` — biểu thức `${{ ... }}` không tin cậy dán thẳng vào khối `run:`;
  - `FSB-CI-002` — dán vào script inline của `actions/github-script`;
  - `FSB-CI-003` — "pwn request": workflow đặc quyền checkout mã của pull request;
  - `FSB-CI-004` — action bên thứ ba ghim bằng nhãn di chuyển được thay vì digest.

  Nhận cả `.gitea/workflows` và `.forgejo/workflows`, vì chúng chạy lại đúng bộ chạy đó.

### Hai tính năng cho việc dùng hằng ngày

- **`--diff patch`** — chỉ báo phát hiện chạm vào dòng vừa đổi. Đây là thứ khiến một bộ dò tĩnh
  sống được trong CI: pull request không còn đỏ vì nợ của người khác. Tệp **không đổi vẫn được
  phân tích**, vì sink cũ của nó có thể vừa được một tệp mới đổi gọi tới. Công cụ **không tự chạy
  `git`** — nó đọc patch anh em đưa vào, nên vẫn không sinh tiến trình con nào.
- **`--explain FSB-SQL-001`** — in đầy đủ vì sao rule đó là lỗ hổng và cách sửa đúng.
- **`--fail-on-confidence`** — chặn CI theo từng phát hiện đủ chắc chắn, không phải theo mức cao
  nhất của từng chiều gộp lại.

### Tự siết lại chính mình

Hai bộ đọc mới đều coi đầu vào là **không tin cậy**:

- patch có trần kích thước (8 MB), trần tổng số dòng thay đổi (200 000), và đường dẫn trong đó bị
  chặn không cho thoát ra ngoài cây quét (`..`, đường dẫn tuyệt đối, tên bị git trích dẫn);
- phép tra khoảng dòng dùng `bisect` thay vì quét tuyến tính, để một patch lớn không làm chính
  công cụ chậm theo cấp số nhân;
- mẫu `${{ ... }}` chỉ chạy trên dòng có chứa nó và bị cắt ở 16 KB, nên một tệp rải đầy `${{`
  không bao giờ đóng không biến công cụ thành nạn nhân của tệp nó đang đọc;
- bộ đọc workflow có trần số dòng, số biểu thức và số dòng mỗi khối.

### Thay đổi phá vỡ tương thích

- `Finding` có thêm hai trường `evidence` và `context`; chúng xuất hiện trong JSON và SARIF. Mã
  đọc báo cáo theo khoá cố định không bị ảnh hưởng; mã kiểm tra "tập khoá phải khớp đúng" thì có.
- `summary` trong JSON có thêm `out_of_diff`.
- **Vân tay (`fingerprint`) không đổi**, nên baseline cũ vẫn dùng được.
- Phát hiện nằm ngoài đường chạy sản phẩm giờ ra ở độ tin cậy thấp hơn một nấc. Nếu CI của anh em
  đang chặn theo `--min-confidence`, hãy chạy lại một lượt để xem con số mới trước khi tin.
