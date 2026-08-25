# 🚀 Hướng dẫn phát hành và đẩy lên GitHub

Tài liệu này dành cho anh em tự tay chạy, từng bước một. Mỗi bước có **câu lệnh
chính xác** và **dấu hiệu để biết là đã đúng**, nên anh em không phải đoán.

> [!IMPORTANT]
> **Lần phát hành này có một chuyện đặc biệt: lịch sử commit vừa được viết lại.**
> Toàn bộ 44 commit cũ đã đổi mã băm ( để dọn loạn phiên bản và thống nhất giọng
> văn ), nên đẩy lên lần này **bắt buộc phải ép**. Phần dưới nói rõ chỗ nào ép,
> ép cái gì, và làm sao lùi lại nếu hỏng.

---

## 📋 Tình trạng hiện tại, đọc trước khi làm gì

| | Giá trị |
| :--- | :--- |
| Nhánh đang đứng | `release/0.1.0` |
| Số commit ở máy | 48 |
| Số commit trên `origin/main` | 44 |
| Nội dung đã có sẵn trên `origin/main` | 33 commit |
| **Nội dung thật sự MỚI** | **8 commit** |
| Điểm lùi an toàn | nhánh `backup/truoc-khi-viet-lai-lich-su` và tag `backup-before-rewrite` |

8 commit mang nội dung mới:

```
fix: mười chỗ cho kết quả sai nghiêm trọng, tìm bằng cách tự tấn công
fix: bốn lỗ hổng trên chính bộ dò, tìm bằng cách tự tấn công
feat: đối chiếu bộ rule theo OWASP Top 10:2025
docs: dựng lại README theo hướng trực quan và ghi nhật ký cho 0.1.0
docs: bảy hình minh hoạ sinh tự động, thay cho các khối chữ trong README
docs: hướng dẫn phát hành từng bước, viết cho đúng tình trạng kho hiện tại
docs: bỏ nền của hình minh hoạ, đổi sang lối vẽ tô nhạt theo màu nhấn
docs: cập nhật lại con số trong hướng dẫn phát hành cho khớp lịch sử hiện tại
```

Còn lại là 33 commit cũ **cùng nội dung nhưng khác mã băm** vì đã đổi thông điệp,
cộng với việc bỏ đi 4 commit gộp của pull request `#13` đến `#16` ( chúng chỉ là
bong bóng gộp, không mang nội dung riêng ).

---

## Bước 0 · Kiểm tra trước khi phát hành

Chạy đúng những gì CI sẽ chạy. **Cả sáu phải xanh** thì mới đi tiếp.

```bash
# 1. Lint
python -m ruff check src tests

# 2. Toàn bộ test
python -m pytest -q

# 3. Mẫu có lỗi PHẢI bị bắt ( lệnh này phải thoát KHÁC 0 )
python -m fortress_scan tests/samples/vulnerable --no-config --quiet; echo "ma thoat = $?"

# 4. Mẫu an toàn PHẢI im lặng
python -m fortress_scan tests/samples/safe --no-config --fail-on info

# 5. Công cụ tự quét chính nó
python -m fortress_scan src --fail-on low

# 6. Hình minh hoạ không được cũ hơn mã
python tools/generate_diagrams.py
git diff --exit-code docs/img && echo "hinh van dung"
```

**Dấu hiệu đúng:**
- bước 1 in `All checks passed!`
- bước 2 in `1185 passed, 2 skipped`
- bước 3 in `ma thoat = 1`
- bước 4 và 5 in `sạch`
- bước 6 in `hinh van dung` ( nghĩa là `git diff` không thấy gì đổi )

Nếu bước 6 báo có thay đổi, nghĩa là hình đang cũ hơn mã. Cứ `git add docs/img`
rồi commit lại trước khi đi tiếp.

---

## Bước 1 · Đồng bộ lại ref theo dõi ( QUAN TRỌNG, đừng bỏ qua )

Việc viết lại lịch sử cũng làm hỏng luôn các ref theo dõi remote ở máy, nên
**lúc này máy đang hiểu sai về tình trạng của GitHub**. Không chữa chỗ này thì
`--force-with-lease` ở bước sau sẽ so với một mốc sai.

```bash
git fetch origin --prune
```

Kiểm tra lại cho chắc:

```bash
git ls-remote --heads origin
```

Con số in ra phải khớp với `git for-each-ref refs/remotes/origin`. Khớp rồi thì
đi tiếp.

---

## Bước 2 · Nhìn kỹ đúng thứ sắp đẩy đi

Đây là bước rẻ nhất để bắt một sai lầm đắt.

```bash
# Lịch sử sắp đẩy
git log --oneline -10

# Nội dung khác biệt so với trunk hiện tại trên GitHub
git diff --stat origin/main HEAD | tail -5

# Commit nào mang nội dung THẬT SỰ mới ( dấu + )
git cherry -v origin/main HEAD | grep "^+"
```

Phải thấy đúng **8 dòng dấu `+`** như bảng ở đầu tài liệu. Nhiều hơn hoặc ít hơn
thì dừng lại xem lại, đừng đẩy.

---

## Bước 3 · Đẩy nhánh `release/0.1.0`

```bash
git push --force-with-lease origin release/0.1.0
```

**Vì sao là `--force-with-lease` chứ không phải `--force`:** `--force` đẩy đè bất
kể trên GitHub đang có gì. `--force-with-lease` chỉ đẩy khi GitHub vẫn đang ở
đúng chỗ mà máy anh em tưởng, nên nếu có ai đó vừa đẩy gì lên trong lúc anh em
làm việc, lệnh sẽ **bị từ chối** thay vì xoá mất công của họ.

Bị từ chối thì đừng thêm `--force`. Chạy lại `git fetch origin`, xem người ta
vừa đẩy gì lên, rồi quyết định.

---

## Bước 4 · Đưa `main` về cùng một mạch

`main` mới là trunk thật: CI chỉ chạy khi đẩy lên `main` hoặc khi mở pull
request. Có hai đường, anh em chọn một.

### Đường A · Mở pull request ( an toàn hơn, có CI gác )

```bash
gh pr create --base main --head release/0.1.0 \
  --title "release: 0.1.0" \
  --body "Bản chính thức đầu tiên. Xem CHANGELOG.md."
```

Rồi vào GitHub xem CI chạy. Xanh hết thì gộp.

> [!WARNING]
> Đường này **có một chỗ vướng**: `main` trên GitHub đang mang lịch sử CŨ, còn
> `release/0.1.0` vừa được viết lại, nên hai bên không còn tổ tiên chung. GitHub
> sẽ báo xung đột hoặc đòi gộp kiểu lạ. Nếu gặp, chuyển sang đường B.

### Đường B · Đưa thẳng `main` sang lịch sử mới

Đây là đường hợp với ý "làm lại mới từ đầu", vì nó khiến `main` mang đúng mạch
lịch sử đã dọn.

```bash
git checkout main
git reset --hard release/0.1.0
git push --force-with-lease origin main
git checkout release/0.1.0
```

**Cái gì mất đi:** 4 commit gộp của pull request `#13` đến `#16` biến khỏi lịch
sử `main`. Bản thân các pull request đó trên GitHub **vẫn còn**, vẫn hiện là đã
gộp, chỉ là commit gộp của chúng không còn nằm trong mạch `main` nữa.

**Cái gì KHÔNG mất:** toàn bộ nội dung mã. Đã đối chiếu: 33 commit cũ có nội
dung y hệt, chỉ khác thông điệp.

> [!CAUTION]
> Sau khi ép `main`, ai đã từng clone kho này phải clone lại hoặc chạy
> `git fetch origin && git reset --hard origin/main`. Lịch sử cũ ở máy họ không
> còn khớp nữa. Kho cá nhân thì chuyện này nhẹ, nhưng vẫn nên nói trước nếu có
> người khác đang dùng.

---

## Bước 5 · Gắn tag `v0.1.0`

Tag là thứ GitHub Release neo vào. Kho này **chưa có tag nào**, nên đây là tag
đầu tiên.

```bash
git tag -a v0.1.0 -m "Fortress Scan Basic Injection 0.1.0"
git push origin v0.1.0
```

Kiểm tra:

```bash
git ls-remote --tags origin
```

Phải thấy `refs/tags/v0.1.0`.

> [!NOTE]
> Đừng đẩy tag `backup-before-rewrite` lên GitHub. Nó là điểm lùi riêng ở máy
> anh em. Cũng đừng dùng `git push --all` hay `git push --mirror`, vì hai lệnh
> đó đẩy luôn cả nhánh backup lên.

---

## Bước 6 · Dựng gói cài đặt

```bash
python -m pip install --upgrade build
python -m build
```

Xong sẽ có hai tệp trong `dist/`:

```
fortress_scan_basic_injection-0.1.0.tar.gz     ( bản nguồn )
fortress_scan_basic_injection-0.1.0-py3-none-any.whl   ( bản cài nhanh )
```

Thử cài vào một môi trường sạch để chắc gói không hỏng:

```bash
python -m venv /tmp/thu-cai
/tmp/thu-cai/bin/pip install dist/*.whl     # Windows: /tmp/thu-cai/Scripts/pip.exe
/tmp/thu-cai/bin/fortress-scan --version
```

Phải in ra `fortress-scan 0.1.0`.

---

## Bước 7 · Tạo Release trên GitHub

### Cách 1 · Bằng `gh` ( nhanh hơn )

```bash
gh release create v0.1.0 \
  --title "Fortress Scan Basic Injection 0.1.0" \
  --notes-file docs/release-notes-0.1.0.md \
  dist/*
```

Chưa có tệp ghi chú thì viết nhanh một bản:

```bash
cat > docs/release-notes-0.1.0.md <<'EOF'
Bản chính thức đầu tiên, rời khỏi giai đoạn thử nghiệm.

**35 rule trên 17 họ injection, đối chiếu OWASP Top 10:2025.
14 ngôn ngữ và định dạng. 1185 kiểm tra tự động. Không phụ thuộc thư viện ngoài.**

Từ bản này trở đi, mã rule (`FSB-*`), khoá trong JSON/SARIF và các cờ dòng lệnh
được coi là giao diện ổn định.

Xem đầy đủ trong CHANGELOG.md.
EOF
```

### Cách 2 · Bằng giao diện web

1. Mở `https://github.com/fortress07/fortress-scan-basic-injection/releases/new`
2. Ô **Choose a tag**: chọn `v0.1.0` ( đã đẩy ở bước 5 )
3. Ô **Target**: chọn `main`
4. **Release title**: `Fortress Scan Basic Injection 0.1.0`
5. **Describe this release**: dán nội dung mục `0.1.0` trong `CHANGELOG.md`
6. Kéo hai tệp trong `dist/` thả vào ô đính kèm
7. Để trống ô **Set as a pre-release**, tích **Set as the latest release**
8. Bấm **Publish release**

---

## Bước 8 · Kiểm tra sau khi phát hành

```bash
# Tag đã lên chưa
git ls-remote --tags origin | grep v0.1.0

# Release đã hiện chưa
gh release view v0.1.0

# CI trên main xanh chưa
gh run list --branch main --limit 3
```

Rồi mở README trên GitHub xem **bảy hình minh hoạ có hiện đủ không**. Chúng nằm
trong `docs/img/`, nhúng bằng đường dẫn tương đối, nên chỉ hiện đúng sau khi đã
đẩy lên. Nếu thấy ô ảnh vỡ, kiểm tra lại là thư mục `docs/img/` đã được commit.

Thử luôn chế độ tối trên GitHub ( ảnh đại diện góc trên phải → Settings →
Appearance → Dark ) để chắc bản tối của hình cũng đúng.

---

## Bước 9 · Dọn dẹp

Khi đã chắc mọi thứ ổn, xoá điểm lùi và các ref rác của lần viết lại lịch sử:

```bash
# Ref gốc do git filter-branch để lại
git for-each-ref --format="%(refname)" refs/original | \
  xargs -n 1 git update-ref -d

# Điểm lùi ở máy
git branch -D backup/truoc-khi-viet-lai-lich-su
git tag   -d backup-before-rewrite

# Nhánh cũ đã bị xoá trên GitHub
git remote prune origin

# Thu gọn kho
git reflog expire --expire=now --all
git gc --prune=now --aggressive
```

> [!TIP]
> Chỉ chạy bước 9 khi đã kiểm tra xong bước 8. Xoá xong thì **không lùi lại
> được nữa**.

---

## 🆘 Nếu có gì hỏng, lùi lại thế nào

**Chưa đẩy lên GitHub:**

```bash
git reset --hard backup/truoc-khi-viet-lai-lich-su
```

**Đã đẩy rồi nhưng muốn lùi:**

```bash
git checkout release/0.1.0
git reset --hard backup/truoc-khi-viet-lai-lich-su
git push --force-with-lease origin release/0.1.0
```

**Lỡ xoá mất nhánh backup:**

```bash
git reflog                    # tìm mã băm cũ trong danh sách
git reset --hard <ma-bam>
```

`git reflog` giữ lại mọi chỗ `HEAD` từng đi qua trong 90 ngày, nên gần như lúc
nào cũng lùi được, miễn là chưa chạy `git gc --prune=now` ở bước 9.

---

## 🔁 Những lần phát hành sau

Từ lần sau sẽ nhẹ hơn nhiều vì không phải viết lại lịch sử nữa:

1. Sửa `version` trong `pyproject.toml`
2. Thêm mục mới vào đầu `CHANGELOG.md`
3. Chạy `python tools/generate_diagrams.py` rồi commit nếu hình đổi
4. Cập nhật con số trong README nếu số rule hoặc số test đổi
   ( bộ test sẽ tự bắt nếu quên: `test_readme_states_the_real_rule_count` )
5. Chạy lại **Bước 0**
6. `git push origin main`
7. `git tag -a vX.Y.Z -m "..." && git push origin vX.Y.Z`
8. `gh release create vX.Y.Z --title "..." --notes-file ... dist/*`

Không cần ép gì cả, và cũng không cần đụng tới bước 1, 4, 9.
