"""Số dòng phải khớp nhau giữa mọi thành phần đếm dòng.

AnalysisUnit.lines, ast.parse, Tokenizer._line và find_code_points đều phải
hiểu "xuống dòng" theo cùng một nghĩa. Khi chúng lệch nhau, finding vẫn được
phát hiện đúng nhưng snippet đính kèm lại trỏ sang dòng khác -- bằng chứng
hiển thị cho người review bị làm giả mà nội dung finding vẫn trông bình thường.

Mọi ký tự thí nghiệm ở đây đều viết dạng escape, để chính tệp test này không
chứa ký tự điều khiển thô.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from fortress_scan.analysis.base import AnalysisUnit
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.languages import PYTHON
from fortress_scan.security.redaction import redact
from fortress_scan.security.text import make_snippet, normalize_newlines, split_lines

# Những ký tự str.splitlines() coi là xuống dòng nhưng ast.parse và lexer thì không.
EXTRA_SPLITLINES_BREAKS = (
    "\x0b",
    "\x0c",
    "\x1c",
    "\x1d",
    "\x1e",
    "\x85",
    "\u2028",
    "\u2029",
)


@pytest.mark.parametrize("char", EXTRA_SPLITLINES_BREAKS)
def test_split_lines_ignores_separators_that_python_does_not_honour(char: str):
    text = "# ghi chu%sx = 1" % char
    assert len(text.splitlines()) == 2  # hành vi cũ, sai
    assert len(split_lines(text)) == 1
    # ast đồng ý: cả dòng là comment, không còn câu lệnh nào.
    assert ast.parse(text).body == []


@pytest.mark.parametrize("char", EXTRA_SPLITLINES_BREAKS)
def test_snippet_stays_on_the_reported_line(char: str):
    source = (
        "import os\n"
        "# ghi chu%sSAFE_LOOKING_CODE = True\n"
        "\n"
        "def handler(user_input):\n"
        "    os.system(user_input)\n"
    ) % char
    findings = scan_source(source, PYTHON, "desync.py", Config())
    real_lines = source.split("\n")

    # Mọi finding: snippet phải đúng bằng nội dung thật của dòng nó báo.
    for finding in findings:
        expected = make_snippet(redact(real_lines[finding.line - 1]))
        assert finding.snippet == expected, "snippet lech khoi dong %d" % finding.line

    # Riêng finding tiêm lệnh: phải nằm ở dòng 5 và trưng ra đúng os.system().
    injection = [f for f in findings if f.rule_id == "FSB-CMD-003"]
    assert injection, "phải còn phát hiện được lỗi tiêm lệnh"
    for finding in injection:
        assert finding.line == 5
        assert "os.system(user_input)" in finding.snippet
        assert "SAFE_LOOKING_CODE" not in finding.snippet


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_line_numbers_agree_across_line_endings(ending: str):
    source = ending.join(
        ["import os", "x = 1", "def f(user_input):", "    os.system(user_input)", ""]
    )
    findings = scan_source(source, PYTHON, "endings.py", Config())
    assert findings
    for finding in findings:
        assert finding.line == 4
        assert "os.system" in finding.snippet


def test_generic_lexer_agrees_with_lines_on_cr_only_file(tmp_path: Path):
    # File xuống dòng kiểu CR: lexer chỉ đếm "\n" nên trước đây báo mọi thứ ở dòng 1.
    target = tmp_path / "cronly.js"
    target.write_bytes(b"var a = 1;\rvar SAFE = 2;\reval(location.hash);\r")
    result = scan(str(tmp_path), Config())
    assert result.findings
    for finding in result.findings:
        assert finding.line == 3
        assert "eval" in finding.snippet
        assert "SAFE" not in finding.snippet


@pytest.mark.parametrize("char", EXTRA_SPLITLINES_BREAKS)
def test_ignore_file_comment_cannot_smuggle_a_pattern(tmp_path: Path, char: str):
    """git chỉ tách .gitignore theo "\\n".

    Nếu scanner tách rộng hơn, phần đuôi của một dòng comment sẽ thành pattern
    thật và lặng lẽ loại thư mục đó khỏi phạm vi quét, trong khi git vẫn theo
    dõi bình thường -- tức là giấu được mã độc khỏi bản quét.
    """
    (tmp_path / ".gitignore").write_bytes(
        ("# ghi chu vo hai%ssecret/\n" % char).encode("utf-8")
    )
    secret = tmp_path / "secret"
    secret.mkdir()
    (secret / "payload.py").write_text("import os\nos.system(input())\n", encoding="utf-8")

    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 1
    assert any(f.rule_id == "FSB-CMD-001" for f in result.findings), (
        "tệp bị .gitignore giả mạo giấu khỏi bản quét"
    )


@pytest.mark.parametrize("char", EXTRA_SPLITLINES_BREAKS)
def test_inline_suppression_cannot_be_shifted_onto_another_line(char: str):
    """Chú thích ignore phải chỉ tắt đúng dòng nó đứng, không trượt sang dòng khác."""
    source = (
        "import os\n"
        "# ghi chu%s\n"
        "def f(user_input):\n"
        "    os.system(user_input)  # fortress-scan: ignore\n"
    ) % char
    kept = [f for f in scan_source(source, PYTHON, "supp.py", Config()) if f.rule_id != "FSB-UNI-004"]
    assert kept == []


def test_suppression_comment_cannot_reach_a_line_below_itself():
    """Hướng nguy hiểm hơn: chú thích ignore trượt xuống và bịt một finding thật.

    Chú thích ở dòng 2 chỉ được tắt dòng 2. Trước đây ba ký tự \\x0b ở dòng 1
    đẩy chỉ số của nó xuống 5, đúng dòng có os.system() -- finding biến mất mà
    không để lại dấu vết nào trong báo cáo.
    """
    source = (
        "# pad\x0b\x0b\x0b\n"
        "# fortress-scan: ignore\n"
        "import os\n"
        "def f(u):\n"
        "    os.system(u)\n"
    )
    findings = scan_source(source, PYTHON, "supp.py", Config())
    assert 5 in [f.line for f in findings if f.rule_id == "FSB-CMD-003"]


def test_analysis_unit_refuses_caller_supplied_lines():
    """Bất biến cấu trúc: không ai truyền được mảng dòng lệch vào nữa."""
    with pytest.raises(TypeError):
        AnalysisUnit(
            relative_path="a.py",
            language=PYTHON,
            source="x = 1\n",
            config=Config(),
            lines=("DONG GIA",),
        )


def test_split_lines_matches_splitlines_on_ordinary_text():
    """Không đổi hành vi với mã nguồn bình thường -- fingerprint baseline giữ nguyên."""
    for text in ("", "a", "a\n", "a\n\n", "a\nb\n", "a\nb", "\n"):
        assert list(split_lines(text)) == text.splitlines()


def test_normalize_newlines_is_idempotent_and_lf_only():
    for text in ("a\r\nb", "a\rb", "a\nb", "a\r\n\rb"):
        once = normalize_newlines(text)
        assert "\r" not in once
        assert normalize_newlines(once) == once


@pytest.mark.parametrize("char", EXTRA_SPLITLINES_BREAKS)
def test_unit_lines_count_matches_ast_line_count(char: str):
    """Bất biến cốt lõi: mảng dòng phải đủ dài để tra cứu mọi dòng ast báo."""
    source = "x = 1\n# c%sy = 2\nz = 3\n" % char
    unit = AnalysisUnit("m.py", PYTHON, source, Config())
    tree = ast.parse(unit.source)
    for node in tree.body:
        assert node.lineno <= len(unit.lines)
        assert unit.lines[node.lineno - 1].startswith(("x", "y", "z", "# c"))
