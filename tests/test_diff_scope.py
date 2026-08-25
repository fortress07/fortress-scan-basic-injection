"""Phạm vi --diff: đọc unified diff và lọc phát hiện theo dòng vừa đổi.

Patch là dữ liệu không tin cậy ( CI sinh nó từ nhánh của người gửi ), nên bộ
đọc phải chịu được cả patch dị dạng lẫn patch cố tình phá. Và phần lọc phải
sai theo hướng an toàn: thà giữ lại một phát hiện cũ còn hơn vứt một phát
hiện mà chính pull request này vừa tạo ra.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortress_scan.cli import main as cli_main
from fortress_scan.core.config import Config
from fortress_scan.core.diffscope import DiffError, parse_patch, touches_change
from fortress_scan.core.engine import scan
from fortress_scan.core.model import (
    Category,
    Confidence,
    Finding,
    Severity,
    StepKind,
    TraceStep,
)

SIMPLE = (
    "diff --git a/app/api.py b/app/api.py\n"
    "index 1111111..2222222 100644\n"
    "--- a/app/api.py\n"
    "+++ b/app/api.py\n"
    "@@ -10,0 +11,3 @@ def handler():\n"
    "+    cmd = request.args['c']\n"
    "+    os.system(cmd)\n"
    "+\n"
)


def test_added_lines_are_collected():
    changed = parse_patch(SIMPLE)
    assert changed.paths == {"app/api.py"}
    assert changed.ranges_for("app/api.py") == ((11, 13),)
    assert changed.line_count == 3


def test_removed_lines_do_not_end_the_hunk_early():
    """Thân hunk đếm theo cả hai phía.

    `@@ -30,2 +33,1 @@` xoá hai dòng và thêm một. Đếm chung một bộ đếm thì
    hunk kết thúc ngay sau hai dòng `-`, và đúng dòng `+` cần bắt bị coi là
    nằm ngoài hunk -- tức là một dòng vừa thêm bị báo cáo bỏ qua.
    """
    patch = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -30,2 +33,1 @@\n"
        "-cu\n"
        "-cu2\n"
        "+moi\n"
    )
    assert parse_patch(patch).ranges_for("x.py") == ((33, 33),)


def test_context_lines_are_not_counted_as_changed():
    patch = (
        "--- a/x.py\n"
        "+++ b/x.py\n"
        "@@ -1,4 +1,5 @@\n"
        " giu nguyen\n"
        " giu nguyen\n"
        "+them moi\n"
        " giu nguyen\n"
        " giu nguyen\n"
    )
    assert parse_patch(patch).ranges_for("x.py") == ((3, 3),)


def test_deleted_file_is_ignored():
    patch = "--- a/x.py\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n"
    assert parse_patch(patch).paths == frozenset()


@pytest.mark.parametrize(
    "target",
    [
        "/etc/passwd",
        "b/../../etc/passwd",
        "C:/Windows/system32/x.py",
        '"ten\\tla.py"',
    ],
)
def test_paths_that_escape_the_tree_are_dropped(target: str):
    patch = "--- a/x\n+++ %s\n@@ -0,0 +1,1 @@\n+x\n" % target
    assert parse_patch(patch).paths == frozenset()


def test_oversized_patch_is_refused():
    with pytest.raises(DiffError):
        parse_patch("x" * (8 * 1024 * 1024 + 1))


@pytest.mark.parametrize(
    "patch",
    [
        "",
        "khong phai patch\n",
        "@@ -1 +1 @@\n+mo coi khong co tep\n",
        "+++ b/x.py\n@@ khong phai hunk @@\n+x\n",
        "+++ b/x.py\n@@ -1,1 +99999999999999999999,1 @@\n+x\n",
        "+++ b/x.py\n@@ -1,1 +1,1 @@\n\\ No newline at end of file\n",
    ],
)
def test_malformed_patches_do_not_raise(patch: str):
    parse_patch(patch)


def test_a_patch_with_no_changed_line_is_still_a_filter():
    """Rỗng khác None.

    Một patch không đổi dòng nào phải cho ra báo cáo rỗng, chứ không được
    rơi vào nhánh "không dùng patch" và báo cả cây. Chỗ gọi hay viết
    `if config.changed_lines:` nên đối tượng này không bao giờ được falsy.
    """
    assert bool(parse_patch("")) is True


def _finding(path: str, line: int, trace_path: str = "", trace_line: int = 0) -> Finding:
    trace = ()
    if trace_path:
        trace = (
            TraceStep(
                kind=StepKind.SINK,
                line=trace_line,
                column=0,
                label="sink",
                path=trace_path,
            ),
        )
    return Finding(
        rule_id="FSB-CMD-001",
        title="t",
        message="m",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        category=Category.COMMAND,
        path=path,
        line=line,
        column=0,
        end_line=line,
        end_column=0,
        language="python",
        trace=trace,
    )


def test_touches_matches_on_the_findings_own_line():
    changed = parse_patch(SIMPLE)
    assert touches_change(_finding("app/api.py", 12), changed)
    assert not touches_change(_finding("app/api.py", 40), changed)


def test_touches_matches_through_a_cross_file_step():
    """Nối một handler MỚI vào một sink CŨ vẫn là lỗ hổng của pull request này.

    Sink nằm ở tệp không đổi, nên nếu chỉ so dòng của chính phát hiện thì
    đúng kiểu lỗ hổng mà pull request thật hay tạo ra sẽ không bao giờ bị bắt.
    """
    changed = parse_patch(SIMPLE)
    finding = _finding("helpers/db.py", 400, trace_path="app/api.py", trace_line=12)
    assert touches_change(finding, changed)


VULN = (
    "import os\n"
    "from flask import request\n"
    "\n"
    "def cu():\n"
    "    os.system('ping ' + request.args['a'])\n"
    "\n"
    "def moi():\n"
    "    os.system('curl ' + request.args['b'])\n"
)

PATCH = (
    "diff --git a/app/api.py b/app/api.py\n"
    "--- a/app/api.py\n"
    "+++ b/app/api.py\n"
    "@@ -6,0 +7,2 @@\n"
    "+def moi():\n"
    "+    os.system('curl ' + request.args['b'])\n"
)


def _tree(tmp_path: Path) -> Path:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "api.py").write_text(VULN, encoding="utf-8")
    patch = tmp_path / "changes.patch"
    patch.write_text(PATCH, encoding="utf-8")
    return patch


def test_engine_keeps_only_findings_on_changed_lines(tmp_path: Path):
    patch = _tree(tmp_path)
    changed = parse_patch(patch.read_text(encoding="utf-8"))
    result = scan(str(tmp_path), Config(changed_lines=changed))
    assert [f.line for f in result.findings] == [8]
    assert result.out_of_diff == 1


def test_engine_says_what_it_held_back(tmp_path: Path):
    patch = _tree(tmp_path)
    changed = parse_patch(patch.read_text(encoding="utf-8"))
    result = scan(str(tmp_path), Config(changed_lines=changed))
    kinds = {notice.kind for notice in result.notices}
    assert "diff-scope-applied" in kinds


def test_files_outside_the_patch_are_still_analysed(tmp_path: Path):
    """Lọc ở phần BÁO CÁO, không phải ở phần duyệt cây.

    Tệp không đổi vẫn phải được phân tích, vì sink cũ của nó có thể vừa được
    một tệp mới đổi gọi tới.
    """
    patch = _tree(tmp_path)
    changed = parse_patch(patch.read_text(encoding="utf-8"))
    result = scan(str(tmp_path), Config(changed_lines=changed))
    assert result.stats.files_analyzed == 1


def test_cli_reads_a_patch_file(tmp_path: Path, capsys):
    patch = _tree(tmp_path)
    code = cli_main([str(tmp_path), "-f", "json", "--diff", str(patch)])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["summary"]["total"] == 1
    assert payload["summary"]["out_of_diff"] == 1


def test_cli_refuses_a_missing_patch(tmp_path: Path):
    _tree(tmp_path)
    assert cli_main([str(tmp_path), "--quiet", "--diff", str(tmp_path / "khong-co.patch")]) == 2
