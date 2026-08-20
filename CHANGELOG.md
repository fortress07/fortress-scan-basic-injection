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

### Hai lỗ hổng từ chối dịch vụ trên chính bộ dò

Mô hình đe doạ rất cụ thể: kẻ tấn công không chạy được mã trên máy nạn nhân, nhưng đặt được nội
dung vào một repo và nhờ nạn nhân quét nó. Cả hai lỗi dưới đây đều kích hoạt bằng một tệp dưới
2 MB, và cả hai đều đã được **đo bằng đồng hồ** trước và sau khi vá.

- **`redact()` chạy bậc hai trên một dòng dài.** Mẫu bắt mật khẩu trong URL viết
  `[a-z][a-z0-9+.\-]*://`: lớp ký tự đó nuốt được cả chữ, số và dấu chấm, còn `:` thì không nằm
  trong nó — nên trên một dòng không có `://`, bộ máy quét tới cuối rồi lùi từng ký tự để dò dấu
  hai chấm, và làm lại như vậy ở **mọi** vị trí bắt đầu. Đo được **3,0 giây cho 32 KB**, tăng 16
  lần kích thước thì tốn gấp **276 lần** thời gian. `redact()` chạy trên từng dòng sinh ra trích
  đoạn của mọi phát hiện, nên một tệp JavaScript đã minify nằm trên một dòng là đủ để treo lượt
  quét hàng giờ. Đã ghim độ dài tên giao thức ở 30 ký tự ( dài nhất IANA từng đăng ký chưa tới
  30 ) và thêm trần 8 KB cho một lần gọi. Sau khi vá: **0,007 giây**, và phẳng.
- **Ba mẫu dò script vòng đời trong `package.json` quay lui 400 × 200 tổ hợp.** Đo được **23 giây
  cho 200 KB**. Đã thay bằng một lượt quét — tìm từ khoá bằng alternation của chuỗi cố định, rồi
  soi cửa sổ phía sau bằng `str.find`. Kết quả nhận dạng không đổi ( có test khoá lại cả bản bắt
  đúng lẫn bản không bắt bừa ); thời gian trên đường đi thật: **0,45 giây → 0,02 giây**.
  Thêm chặn trên **200 lệnh vòng đời** mỗi tệp: một khoá vòng đời nhận được cả danh sách, nên
  `{"postinstall": ["…4000 ký tự…", ×500]}` gói gọn trong 2 MB mà bắt bộ dò làm việc gấp 500 lần.

Kèm theo là hai bài kiểm tra mới:

- `tests/test_regex_complexity.py` **đo** — không phải đọc — mọi regex trong `src/` trên 18 hình
  dạng đầu vào thù địch, và bắt lỗi khi thời gian tăng phi tuyến. Nó tự áp dụng cho mọi regex viết
  thêm sau này, nên không ai phải nhớ bổ sung gì.
- `tests/test_denial_of_service.py` giữ lại đúng những hình dạng đã làm sập thật.

Ngoài ra, một loạt regex được viết lại cho **không còn chỗ quay lui** ngay cả trên giấy: thay `\s`
bằng `[ \t]` ở chỗ hai lớp ký tự chồng lấn nhau, thay `.{0,80}?` bằng `[^)]{0,80}`, bỏ các nhánh
alternation không bao giờ được chọn, và gỡ hằng `SHELL_METACHARACTERS` chết ( không nơi nào dùng,
mà ba nhánh cuối của nó bị chính lớp ký tự đứng đầu che mất ).

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
