"""Bốn lỗ hổng tìm được bằng cách tự tấn công bản 0.1.0.

Mô hình đe doạ vẫn là mô hình cũ của cả dự án: kẻ tấn công không chạy được mã
trên máy nạn nhân, nhưng đặt được nội dung vào một repo rồi nhờ nạn nhân quét
nó. Bốn chỗ dưới đây đều đi đúng đường đó, và ba trong bốn nằm ở phần công cụ
tự nhận là đã siết.

* Hai chỗ TỪ CHỐI DỊCH VỤ trên chính bộ dò, cùng một gốc: `.gitignore` nằm
  trong cây được quét là dữ liệu không tin cậy, mà nó lại là tệp đầu vào duy
  nhất không có trần kích thước, và chi phí so khớp của nó không có trần cộng
  dồn nào.
* Một chỗ TIÊM CHUỖI THOÁT vào terminal qua tên tệp, đi vòng qua đúng lớp
  trung hoà mà công cụ dựng lên để chặn nó.
* Một họ đường LÁCH TẮT CẢNH BÁO: chỉ thị nằm trong hằng chuỗi của Ruby và
  Perl vẫn tắt được cả tệp, vì hai dạng chuỗi đó chưa được mô tả.

Mỗi kiểm tra đi theo cặp khi cần: vế "không tắt được nữa" đứng cạnh vế "chỉ
thị thật vẫn chạy", để cách sửa dễ nhất ( bỏ luôn tính năng ) không đi lọt.
"""

from __future__ import annotations

import time

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.core.ignore import _MAX_IGNORE_BYTES, IgnoreSet, MatchBudget
from fortress_scan.languages import PERL, PYTHON, RUBY

BUDGET_SECONDS = 25.0


def _rules(source: str, language: str):
    return [item.rule_id for item in scan_source(source, language, "mau", Config())]


# --------------------------------------------------------------------------
# 1. Tệp ignore không còn được đọc trọn vào RAM trước khi ai đó kịp đếm
# --------------------------------------------------------------------------


def test_oversized_ignore_file_is_dropped_without_being_read(tmp_path):
    """Trần kích thước phải đứng TRƯỚC phép đọc, không phải sau.

    Tệp dựng ở đây gồm toàn dòng chú thích, tức là không sinh ra lấy một quy
    tắc nào. Hạn mức đếm theo số mẫu vì thế không bao giờ chạm tới, và bản cũ
    vẫn nuốt trọn tệp vào bộ nhớ trước khi phát hiện ra điều đó.
    """
    ignore_file = tmp_path / ".gitignore"
    ignore_file.write_text(("# " + "p" * 200 + "\n") * 60_000, encoding="utf-8")
    assert ignore_file.stat().st_size > _MAX_IGNORE_BYTES

    loaded = IgnoreSet.from_file(ignore_file)
    assert loaded.overflowed, "tệp vượt trần phải bị bỏ hẳn"
    assert not loaded.matches("bat_ky/duong_dan.py", False), "bỏ hẳn thì không giấu gì"


def test_ignore_file_within_the_cap_still_works(tmp_path):
    """Vế thứ hai: trần không được cắt vào .gitignore thật."""
    ignore_file = tmp_path / ".gitignore"
    ignore_file.write_text("__pycache__/\n*.log\nbuild/\n", encoding="utf-8")

    loaded = IgnoreSet.from_file(ignore_file)
    assert not loaded.overflowed
    assert loaded.matches("app/debug.log", False)
    assert not loaded.matches("app/views.py", False)


# --------------------------------------------------------------------------
# 2. Chi phí so khớp có trần cộng dồn cho cả lượt quét
# --------------------------------------------------------------------------


def test_match_budget_stops_a_gitignore_built_to_burn_cpu():
    """`_MAX_TOTAL_TOKENS` chặn MỘT lần so, không chặn được cả lượt quét.

    walk() gọi matches() một lần cho mỗi entry, nên chi phí thật là
    tokens x độ_dài_đường_dẫn x số_entry. Mẫu dưới đây hợp lệ về mọi mặt và
    nằm gọn dưới mọi hạn mức cũ.
    """
    budget = MatchBudget()
    ignore = IgnoreSet.from_lines(["**a" * 166] * 30, budget=budget)
    assert not ignore.overflowed, "mẫu này hợp lệ, không được bị loại từ đầu"

    path = "b/" + ("aaaa" * 200) + "/x.py"
    started = time.perf_counter()
    for _ in range(400):
        ignore.matches(path, False)
    elapsed = time.perf_counter() - started

    assert budget.exhausted, "hạn mức cộng dồn phải chạm trần"
    assert elapsed < BUDGET_SECONDS, "tốn %.1fs" % elapsed
    # Cạn hạn mức thì ngả về phía KHÔNG giấu gì cả.
    assert not ignore.matches(path, False)


def test_exhausted_match_budget_is_reported_not_silent(tmp_path):
    """Phạm vi quét đổi thì báo cáo phải nói ra, đúng luật của mọi notice khác."""
    (tmp_path / ".gitignore").write_text(("**a" * 166 + "\n") * 30, encoding="utf-8")
    deep = tmp_path
    for index in range(12):
        deep = deep / ("a" * 40 + str(index))
    deep.mkdir(parents=True)
    for index in range(40):
        (deep / ("m%02d.py" % index)).write_text("x = 1\n", encoding="utf-8")

    result = scan(str(tmp_path), Config())
    kinds = {notice.kind for notice in result.notices}
    assert "ignore-budget-exhausted" in kinds


def test_literal_prefilter_keeps_a_real_gitignore_exact():
    """Phép lọc trước phải CHÍNH XÁC, không được đổi lấy một kết quả nào."""
    ignore = IgnoreSet.from_lines(
        ["__pycache__/", "*.py[cod]", "node_modules/", "build/", "*.log"]
    )
    assert ignore.matches("a/b/c.pyc", False)
    assert ignore.matches("server.log", False)
    # Mẫu kết thúc bằng "/" chỉ khớp thư mục, đúng như git.
    assert ignore.matches("deep/node_modules", True)
    assert ignore.matches("app/__pycache__", True)
    assert not ignore.matches("deep/node_modules", False)
    assert not ignore.matches("src/app.py", False)
    assert not ignore.matches("src/pycode/main.py", False)


def test_literal_prefilter_never_changes_an_answer():
    """Phép lọc trước là tối ưu, không phải một luật khớp mới.

    So thẳng kết quả có lọc với kết quả của chính bảng quy hoạch động khi bỏ
    qua phép lọc: một mẫu nào lệch nghĩa là công cụ vừa bắt đầu bỏ sót tệp
    trong im lặng, đúng kiểu hỏng mà cả dự án này sinh ra để chặn.
    """
    import random

    from fortress_scan.core.ignore import GlobMatcher, _tokenize

    random.seed(20250825)
    alphabet = "ab/.*[]?xy_"
    for _ in range(3000):
        pattern = "".join(
            random.choice(alphabet) for _ in range(random.randint(1, 12))
        )
        text = "".join(random.choice("ab/.xy_") for _ in range(random.randint(1, 20)))
        tokens = _tokenize(pattern)
        if not tokens:
            continue
        for anchored in (True, False):
            matcher = GlobMatcher(tokens, anchored)
            with_filter = matcher.matches(text)
            bare = object.__new__(GlobMatcher)
            bare._tokens = matcher._tokens
            bare._required = ""
            assert with_filter == bare.matches(text), (
                "lệch trên pattern=%r text=%r anchored=%s" % (pattern, text, anchored)
            )


# --------------------------------------------------------------------------
# 3. Tên tệp không tiêm được chuỗi thoát vào terminal
# --------------------------------------------------------------------------


def test_filename_reaching_cpython_warnings_is_neutralised():
    r"""CPython in tên tệp thẳng ra stderr, ngoài mọi lớp trung hoà của công cụ.

    `x = "\d"` sinh một SyntaxWarning, và thông báo đó mang theo tên tệp
    nguyên văn. Tên tệp thì do người viết cây thư mục đặt, nên đây là đường
    cho U+202E ( hợp lệ trong tên tệp trên cả Windows lẫn Linux ) và cho chuỗi
    thoát ANSI đi thẳng tới terminal của người chạy.
    """
    from fortress_scan.analysis.python.analyzer import _parse_filename

    hostile = "safe\u202egnp.yrotcaf\u202d\x1b[2K\x07_helper.py"
    cleaned = _parse_filename(hostile)

    for raw in ("\u202e", "\u202d", "\x1b", "\x07"):
        assert raw not in cleaned, "còn sót ký tự %r" % raw
    assert "_helper.py" in cleaned, "phần đọc được vẫn phải nhận ra"


def test_scanning_a_bidi_named_file_emits_no_raw_control_bytes(tmp_path, capsys):
    hostile = tmp_path / "safe\u202egnp.yrotcaf\u202d_helper.py"
    hostile.write_text('x = "\\d"\n', encoding="utf-8")

    scan(str(tmp_path), Config())
    captured = capsys.readouterr()
    assert "\u202e" not in (captured.out + captured.err)


# --------------------------------------------------------------------------
# 4. Chỉ thị nằm trong hằng chuỗi của Ruby và Perl không tắt được gì
# --------------------------------------------------------------------------

_DIRECTIVE = "fortress-scan: ignore-file"

# Mỗi mẫu đặt chỉ thị vào ĐÚNG một hằng chuỗi của ngôn ngữ thật. Ba mẫu Perl
# đã chạy thử trên perl 5.42: cả ba đều in ra chỉ thị dưới dạng DỮ LIỆU.
_HIDDEN_IN_STRING = (
    (RUBY, "n = %%q{# %s}\neval(params[:x])\n"),
    (RUBY, "n = %%Q(# %s)\neval(params[:x])\n"),
    (RUBY, "n = %%w[# %s]\neval(params[:x])\n"),
    (RUBY, "n = %%i{# %s}\neval(params[:x])\n"),
    (RUBY, "n = <<eot\n# %s\neot\neval(params[:x])\n"),
    (PERL, "my $n = <<eot;\n# %s\neot\nsystem($q->param('c'));\n"),
    (PERL, "my $n = <<eoT;\n# %s\neoT\nsystem($q->param('c'));\n"),
    (PERL, "my $n = <<~eot;\n# %s\n  eot\nsystem($q->param('c'));\n"),
    (PERL, "my $n = q(# %s);\nsystem($q->param('c'));\n"),
)


@pytest.mark.parametrize("language,template", _HIDDEN_IN_STRING)
def test_directive_inside_a_string_literal_hides_nothing(language, template):
    assert _rules(
        template % _DIRECTIVE, language
    ), "chỉ thị nằm trong hằng chuỗi vẫn tắt được cả tệp"


@pytest.mark.parametrize("language,template", _HIDDEN_IN_STRING)
def test_the_same_shape_without_a_directive_still_reports(language, template):
    """Đối chứng: mẫu này vốn phải bắn, nên vế trên mới có nghĩa."""
    assert _rules(template % "mot ghi chu binh thuong", language)


@pytest.mark.parametrize(
    "language,source",
    (
        (RUBY, "# %s\neval(params[:x])\n"),
        (PERL, "# %s\nsystem($q->param('c'));\n"),
        (PYTHON, "# %s\nimport os\nos.system(input())\n"),
    ),
)
def test_a_real_comment_directive_still_silences_the_file(language, source):
    """Vế thứ hai của cặp: chỉ thị THẬT không được vạ lây."""
    assert not _rules(source % _DIRECTIVE, language)
