"""Ba cờ nhận tệp đọc vào phải kiểm giống hệt nhau.

`--config`, `--baseline` và `--diff` đều mở một tệp mà người dùng gõ tên. Xưa
nay mỗi cờ tự kiểm theo một kiểu, và một trong ba cái kiểm thiếu: `--baseline`
không hỏi "đây có phải tệp thường không", nên `--baseline /dev/zero` đi lọt --
`stat()` báo kích thước 0 nên qua được hạn mức, rồi `read_text()` đọc mãi
không hết. Một FIFO còn tệ hơn: lượt quét đứng im vô hạn, không lỗi, không
dấu vết.

Đây cũng chính là chỗ SonarCloud chỉ ra bằng `pythonsecurity:S8707` --
"validate the constructed path before accessing the file system".
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from fortress_scan.cli import main as cli_main
from fortress_scan.security import paths as safe_paths

EXIT_USAGE = 2

VULN = (
    "import os\n"
    "from flask import request\n"
    "def h():\n"
    "    os.system('ping ' + request.args['a'])\n"
)


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("flag", ["--config", "--baseline", "--diff"])
def test_a_directory_is_refused(tree: Path, flag: str):
    assert cli_main([str(tree), "--quiet", flag, str(tree)]) == EXIT_USAGE


@pytest.mark.parametrize("flag", ["--config", "--baseline", "--diff"])
def test_a_missing_file_is_refused(tree: Path, flag: str):
    assert cli_main([str(tree), "--quiet", flag, str(tree / "khong-co")]) == EXIT_USAGE


def test_an_oversized_file_is_refused(tree: Path):
    """Hạn mức kích thước chặn TRƯỚC khi đọc, không phải sau."""
    big = tree / "to.bin"
    big.write_text("x" * 4096, encoding="utf-8")
    with pytest.raises(safe_paths.PathConfinementError):
        safe_paths.validate_input_path(str(big), "tệp thử", 1024)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO chỉ có trên POSIX")
def test_a_fifo_is_refused_instead_of_hanging(tree: Path):
    """Đọc một FIFO không có người ghi sẽ chặn vô hạn.

    Không có phép kiểm "tệp thường" thì lượt quét đứng im mãi mãi -- kiểu hỏng
    tệ nhất cho một cổng CI, vì nó không để lại lỗi nào để truy.
    """
    fifo = tree / "ong-dan"
    os.mkfifo(str(fifo))
    with pytest.raises(safe_paths.PathConfinementError):
        safe_paths.validate_input_path(str(fifo), "tệp thử", 1024)


def test_a_regular_file_passes_through(tree: Path):
    target = tree / "that.json"
    target.write_text("{}", encoding="utf-8")
    resolved = safe_paths.validate_input_path(str(target), "tệp thử", 1024)
    assert resolved.is_file()
    assert resolved.name == "that.json"


def test_traversal_is_normalised_before_the_file_is_opened(tree: Path):
    """`..` được quy về đích thật rồi mới đem đi kiểm.

    Kiểm trên tên chưa phân giải là kiểm một thứ khác với thứ sẽ được mở.
    """
    nested = tree / "sau" / "nua"
    nested.mkdir(parents=True)
    target = tree / "that.json"
    target.write_text("{}", encoding="utf-8")
    walked = nested / ".." / ".." / "that.json"
    assert safe_paths.validate_input_path(str(walked), "tệp thử", 1024) == target.resolve()


def test_a_symlink_to_a_regular_file_is_still_accepted(tree: Path):
    """Liên kết do CHÍNH người dùng gõ ra thì đi theo là đúng ý họ.

    Khác hẳn tệp cấu hình mà công cụ tự tìm thấy trong cây bị quét: cái đó do
    người viết repo đặt nên mới bị từ chối.
    """
    target = tree / "that.json"
    target.write_text("{}", encoding="utf-8")
    link = tree / "lien-ket.json"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("không tạo được liên kết trên nền tảng/quyền hiện tại")
    assert safe_paths.validate_input_path(str(link), "tệp thử", 1024) == target.resolve()


def test_the_working_flags_still_work(tree: Path, tmp_path: Path):
    """Siết lại mà làm hỏng đường dùng bình thường thì là đổi lỗi lấy lỗi."""
    baseline = tmp_path / "baseline.json"
    assert cli_main([str(tree), "--quiet", "--write-baseline", str(baseline)]) == 1
    assert cli_main([str(tree), "--quiet", "--baseline", str(baseline)]) == 0

    config = tmp_path / "cau-hinh.json"
    config.write_text('{"min_severity": "critical"}', encoding="utf-8")
    assert cli_main([str(tree), "--quiet", "--config", str(config)]) == 1

    patch = tmp_path / "p.patch"
    patch.write_text(
        "--- a/app.py\n+++ b/app.py\n@@ -3,0 +4,1 @@\n+    os.system('x')\n",
        encoding="utf-8",
    )
    assert cli_main([str(tree), "--quiet", "--diff", str(patch)]) == 1
