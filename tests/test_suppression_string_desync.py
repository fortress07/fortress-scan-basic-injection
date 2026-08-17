"""Một chỉ thị nằm trong chuỗi không được tắt phát hiện nào.

README hứa thẳng điều này: `HELP = "# fortress-scan: ignore-file"` chỉ là dữ
liệu. Lời hứa đó phụ thuộc vào việc bộ mặt nạ chuỗi đóng chuỗi ĐÚNG CHỖ mà
ngôn ngữ thật đóng nó. Ở đâu nó đóng SỚM hơn, phần thân còn lại -- vẫn là nội
dung chuỗi với trình thông dịch -- được đọc như mã, một dấu `#` hay `//` trong
đó mở ra một "chú thích", và `ignore-file` tắt sạch phát hiện của cả tệp.

Mỗi test dưới đây là một cặp: cùng một lỗ hổng, cùng một dòng chỉ thị nằm
trong chuỗi, chỉ khác cách chuỗi được viết. Cả hai phải báo cáo như nhau.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan

BACKSLASH = chr(92)
DIRECTIVE = "fortress-scan: ignore-file"

# Lỗ hổng dùng chung: nguồn HTTP chạy thẳng vào os.system().
PY_SINK = (
    "import os\n"
    "import flask\n"
    "app = flask.Flask(__name__)\n"
    "@app.route('/p')\n"
    "def p():\n"
    "    host = flask.request.args.get('host')\n"
    "    os.system('ping ' + host)\n"
    "    return 'ok'\n"
)


def _scan(tmp_path: Path, name: str, source: str) -> Tuple[int, int]:
    """Trả về (số phát hiện, số phát hiện bị chú thích che)."""
    (tmp_path / name).write_text(source, encoding="utf-8")
    result = scan(str(tmp_path), Config())
    return len(result.findings), result.suppressed


class TestDirectiveInsideAStringNeverSuppresses:
    """Chỉ thị nằm trong chuỗi là dữ liệu, ở mọi cách viết chuỗi."""

    def test_escaped_delimiter_keeps_a_python_docstring_open(self, tmp_path: Path):
        # CPython coi dấu nháy sau gạch chéo ngược là dấu được thoát, nên cả ba
        # dòng dưới vẫn nằm trong docstring. Bộ mặt nạ từng đóng chuỗi ở dòng
        # thứ hai rồi đọc dòng thứ ba như một chú thích thật.
        source = (
            '"""tai lieu\n'
            "vi du " + BACKSLASH + '""" o day\n'
            "# " + DIRECTIVE + "\n"
            '"""\n'
        ) + PY_SINK
        # Chứng cứ độc lập: chính CPython nói dòng chỉ thị nằm trong docstring.
        assert DIRECTIVE in (ast.get_docstring(ast.parse(source)) or "")
        assert _scan(tmp_path, "app.py", source) == (1, 0)

    def test_line_continuation_keeps_a_python_string_open(self, tmp_path: Path):
        source = (
            'NOTE = "tai lieu ' + BACKSLASH + "\n"
            "# " + DIRECTIVE + '"\n'
        ) + PY_SINK
        assigned = ast.parse(source).body[0]
        assert DIRECTIVE in assigned.value.value
        assert _scan(tmp_path, "app.py", source) == (1, 0)

    @pytest.mark.parametrize(
        "name,source",
        [
            (
                "app.php",
                '<?php\n$note = "tai lieu\n# %s";\n$h = $_GET["h"];\nsystem("ping " . $h);\n'
                % DIRECTIVE,
            ),
            (
                "app.rb",
                'note = "tai lieu\n# %s"\nh = params[:h]\nsystem("ping " + h)\n' % DIRECTIVE,
            ),
            (
                "app.sh",
                '#!/bin/sh\nM="tai lieu\n# %s"\nread -r h\neval "ping $h"\n' % DIRECTIVE,
            ),
            (
                "App.cs",
                'class A {\n  const string N = @"tai lieu\n// %s";\n'
                '  void H() {\n    var q = Request.Query["q"];\n'
                "    var c = new SqlCommand(\"SELECT * FROM t WHERE a='\" + q + \"'\");\n"
                "  }\n}\n" % DIRECTIVE,
            ),
        ],
    )
    def test_natively_multiline_strings_stay_strings(
        self, tmp_path: Path, name: str, source: str
    ):
        # Chuỗi "..." và '...' của PHP, Ruby, shell bắc qua dòng mà không cần
        # dấu gì thêm; C# thì có chuỗi nguyên văn @"...". Bộ mặt nạ từng đóng
        # tất cả ở cuối dòng vì danh sách "dấu nháy bắc qua dòng" dùng chung
        # cho mọi ngôn ngữ và chỉ có backtick trong đó.
        assert _scan(tmp_path, name, source) == (1, 0)

    @pytest.mark.parametrize(
        "name,source",
        [
            (
                "app.php",
                '<?php\n$note = <<<EOT\n# %s\nEOT;\n$h = $_GET["h"];\nsystem("ping " . $h);\n'
                % DIRECTIVE,
            ),
            (
                "app.rb",
                "note = <<~EOT\n  # %s\nEOT\nh = params[:h]\nsystem(\"ping \" + h)\n"
                % DIRECTIVE,
            ),
            (
                "app.sh",
                '#!/bin/sh\ncat <<EOF\n# %s\nEOF\nread -r h\neval "ping $h"\n' % DIRECTIVE,
            ),
        ],
    )
    def test_heredoc_bodies_are_data(self, tmp_path: Path, name: str, source: str):
        assert _scan(tmp_path, name, source) == (1, 0)

    def test_java_text_block_body_is_data(self, tmp_path: Path):
        source = (
            'class A {\n  static String N = """\n// %s\n""";\n'
            "  void h(javax.servlet.http.HttpServletRequest r) throws Exception {\n"
            '    String q = r.getParameter("q");\n'
            '    Runtime.getRuntime().exec("ping " + q);\n  }\n}\n' % DIRECTIVE
        )
        assert _scan(tmp_path, "App.java", source) == (1, 0)


class TestHonestDirectivesStillWork:
    """Vá đường lách không được vô hiệu hoá chỉ thị thật của người dùng."""

    @pytest.mark.parametrize(
        "source",
        [
            "import os\n# fortress-scan: ignore-file\nos.system('ping ' + input())\n",
            "import os\nos.system('ping ' + input())  # fortress-scan: ignore\n",
            "import os\n# fortress-scan: ignore-next-line\nos.system('ping ' + input())\n",
        ],
    )
    def test_every_scope_still_suppresses(self, tmp_path: Path, source: str):
        assert _scan(tmp_path, "app.py", source) == (0, 1)

    def test_directive_after_a_closed_heredoc_is_a_real_comment(self, tmp_path: Path):
        # Nhãn kết thúc đóng heredoc lại, nên dòng sau nó là mã thật -- và một
        # chú thích ở đó là chú thích thật.
        source = (
            '<?php\n$note = <<<EOT\nchi la van ban\nEOT;\n'
            "# fortress-scan: ignore-file\n"
            '$h = $_GET["h"];\nsystem("ping " . $h);\n'
        )
        assert _scan(tmp_path, "app.php", source) == (0, 1)

    def test_a_label_prefix_does_not_close_the_heredoc(self, tmp_path: Path):
        # EOT không đóng EOTHER: đóng sớm sẽ phơi phần thân còn lại ra làm mã.
        source = (
            '<?php\n$note = <<<EOTHER\nEOT\n# %s\nEOTHER;\n'
            '$h = $_GET["h"];\nsystem("ping " . $h);\n' % DIRECTIVE
        )
        assert _scan(tmp_path, "app.php", source) == (1, 0)

    def test_ruby_left_shift_is_not_a_heredoc(self, tmp_path: Path):
        # `arr << item` không được biến thành heredoc nuốt trọn phần đuôi tệp,
        # kẻo chỉ thị thật ở dưới bị mất.
        source = (
            "arr = []\narr << item\n"
            "# fortress-scan: ignore-file\n"
            'h = params[:h]\nsystem("ping " + h)\n'
        )
        assert _scan(tmp_path, "app.rb", source) == (0, 1)


class TestMaskerNeverKillsTheScan:
    def test_unclosed_backtick_string_does_not_abort_the_run(self, tmp_path: Path):
        # Vùng còn mở phải trả về đúng dạng Pending. Trước đây nó trả về một
        # chuỗi một ký tự, nên `delimiter, keep = pending` ném ValueError --
        # và một tệp .js ba dòng là đủ để cả cây không được báo cáo.
        (tmp_path / "hostile.js").write_text(
            "TPL = `chua dong\n// fortress-scan: ghi chu\n", encoding="utf-8"
        )
        (tmp_path / "app.py").write_text(PY_SINK, encoding="utf-8")
        result = scan(str(tmp_path), Config())
        assert [f.rule_id for f in result.findings] == ["FSB-CMD-001"]
