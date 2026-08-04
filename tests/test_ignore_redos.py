from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.core.ignore import IgnoreSet, compile_rule

BUDGET_SECONDS = 5.0


def run_with_timeout(function, seconds: float = BUDGET_SECONDS):
    box = {}

    def target():
        started = time.monotonic()
        try:
            function()
        except BaseException as exc:
            box["error"] = exc
        finally:
            box["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=seconds)

    if thread.is_alive():
        return False, None

    error = box.get("error")
    if error is not None:
        raise AssertionError(
            "ham chay trong luong phu da nem loi thay vi hoan tat: %r" % error
        ) from error
    return True, box["elapsed"]


def test_timeout_helper_reports_a_crash_instead_of_hiding_it():
    def explode():
        raise RuntimeError("scan() vo no")

    with pytest.raises(AssertionError, match="nem loi"):
        run_with_timeout(explode)


def test_timeout_helper_reports_a_hang():
    def sleep_forever():
        time.sleep(30)

    finished, elapsed = run_with_timeout(sleep_forever, seconds=0.3)
    assert finished is False
    assert elapsed is None


def test_timeout_helper_reports_a_normal_return():
    finished, elapsed = run_with_timeout(lambda: None)
    assert finished is True
    assert elapsed is not None and elapsed >= 0


@pytest.mark.parametrize("groups", [8, 16, 32, 64])
def test_star_heavy_pattern_does_not_backtrack_exponentially(groups: int):
    rule = compile_rule("a*" * groups + "b")
    assert rule is not None
    text = "a" * 120

    finished, _ = run_with_timeout(lambda: rule.matcher.matches(text))
    assert finished, (
        "mau %d nhom khong hoan tat trong %.0f giay -> dau hieu backtracking mu"
        % (groups, BUDGET_SECONDS)
    )


def test_scan_is_not_hung_by_a_hostile_scanignore(tmp_path: Path):
    (tmp_path / ".fortress-scanignore").write_text("a*" * 30 + "b\n", encoding="utf-8")
    (tmp_path / ("a" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")

    finished, _ = run_with_timeout(lambda: scan(str(tmp_path), Config()))
    assert finished, "scan() bi treo boi .fortress-scanignore doc hai"


def test_scan_is_not_hung_by_a_hostile_gitignore(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("x*" * 30 + "y\n", encoding="utf-8")
    (tmp_path / ("x" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")

    finished, _ = run_with_timeout(lambda: scan(str(tmp_path), Config()))
    assert finished, "scan() bi treo boi .gitignore doc hai"


def test_scan_is_not_hung_by_a_hostile_exclude_flag(tmp_path: Path):
    (tmp_path / ("a" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")
    config = Config(exclude_patterns=("a*" * 30 + "b",))

    finished, _ = run_with_timeout(lambda: scan(str(tmp_path), config))
    assert finished, "scan() bi treo boi mau --exclude doc hai"


def test_a_large_ignore_file_within_budget_stays_bounded():
    lines = [("a*" * 5) + "b%d" % index for index in range(500)]
    ignore = IgnoreSet.from_lines(lines)

    assert not ignore.overflowed, (
        "phep thu chi co y nghia khi bo luat NAM TRONG han muc, "
        "neu bi bo sach thi dang do tap rong"
    )
    assert bool(ignore), "tap luat rong thi khong do duoc gi"

    path = "/".join(["a" * 40] * 6)
    finished, _ = run_with_timeout(lambda: ignore.matches(path, False))
    assert finished, "tep ignore lon nhung hop le lai khong khop xong trong %.0f giay" % (
        BUDGET_SECONDS,
    )


def test_an_over_budget_ignore_file_costs_nothing_because_it_is_discarded():
    lines = [("a*" * 50) + "b" for _ in range(5000)]
    ignore = IgnoreSet.from_lines(lines)

    assert ignore.overflowed
    assert not bool(ignore)
    path = "/".join(["a" * 40] * 6)
    finished, _ = run_with_timeout(lambda: ignore.matches(path, False))
    assert finished


def test_pattern_budget_fails_safe_by_keeping_files_visible(tmp_path: Path):
    filler = "\n".join(("z" * 100) for _ in range(2000))
    (tmp_path / ".fortress-scanignore").write_text(filler + "\nsecret.py\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    assert any(f.rule_id == "FSB-CMD-001" for f in result.findings), (
        "khi vuot han muc mau, cong cu phai quet THEM tep chu khong duoc bo qua"
    )


def test_budget_overflow_discards_every_rule_not_just_the_tail():
    filler = ["z" * 200 for _ in range(200)]
    ignore = IgnoreSet.from_lines(["*.min.js"] + filler + ["!keep.min.js"])

    assert ignore.overflowed
    assert not ignore.matches("app.min.js", False), (
        "luat dau tep van con hieu luc sau khi vuot han muc -> cat giua chung"
    )
    assert not ignore.matches("keep.min.js", False), (
        "luat phu dinh o cuoi bi cat khien tep bi GIAU -> fail-open"
    )


def test_budget_overflow_never_hides_a_file_a_negation_wanted_kept(tmp_path: Path):
    filler = "\n".join(("z" * 200) for _ in range(200))
    (tmp_path / ".fortress-scanignore").write_text(
        "*.py\n" + filler + "\n!keep.py\n", encoding="utf-8"
    )
    (tmp_path / "keep.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )

    result = scan(str(tmp_path), Config())
    assert any(f.rule_id == "FSB-CMD-001" for f in result.findings), (
        "luat '!keep.py' bi han muc cat mat khien tep bi giau khoi luot quet"
    )


def test_pattern_count_limit_also_discards_instead_of_truncating():
    short = ["a%d" % index for index in range(1100)]
    ignore = IgnoreSet.from_lines(["*.min.js"] + short + ["!keep.min.js"])

    assert ignore.overflowed, "vuot gioi han SO MAU cung phai bao overflow"
    assert not ignore.matches("app.min.js", False), (
        "luat dau tep van con hieu luc -> dang cat giua chung theo so mau"
    )
    assert not ignore.matches("keep.min.js", False), (
        "luat phu dinh o cuoi bi cat khien tep bi giau"
    )


def test_pattern_count_limit_is_reported_and_not_silent(tmp_path: Path):
    short = "\n".join("a%d" % index for index in range(1100))
    (tmp_path / ".fortress-scanignore").write_text(short, encoding="utf-8")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = scan(str(tmp_path), Config())
    assert any(error.reason == "ignore-file-too-complex" for error in result.errors)


def test_budget_overflow_is_reported_and_not_silent(tmp_path: Path):
    filler = "\n".join(("z" * 200) for _ in range(200))
    (tmp_path / ".fortress-scanignore").write_text(filler, encoding="utf-8")
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")

    result = scan(str(tmp_path), Config())
    assert any(error.reason == "ignore-file-too-complex" for error in result.errors), (
        "bo toan bo quy tac ma khong bao gi la im lang"
    )


def test_a_normal_sized_ignore_file_is_never_discarded():
    realistic = [
        "*.pyc",
        "__pycache__/",
        "node_modules/",
        "**/migrations/**",
        "docs/**",
        "*.min.js",
        "build/",
        "dist/",
        ".venv/",
        "!keep.min.js",
    ] * 20
    ignore = IgnoreSet.from_lines(realistic)
    assert not ignore.overflowed
    assert ignore.matches("app.min.js", False)
    assert not ignore.matches("keep.min.js", False)


def test_no_ignore_files_flag_disables_scanignore(tmp_path: Path):
    (tmp_path / ".fortress-scanignore").write_text("secret.py\n", encoding="utf-8")
    (tmp_path / "secret.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )

    hidden = scan(str(tmp_path), Config())
    assert hidden.findings == [], "mac dinh phai ton trong .fortress-scanignore"

    exposed = scan(str(tmp_path), Config(respect_ignore_files=False))
    assert any(f.rule_id == "FSB-CMD-001" for f in exposed.findings), (
        "respect_ignore_files=False phai lam lo tep bi giau"
    )


def test_no_ignore_files_flag_also_defeats_a_hostile_pattern(tmp_path: Path):
    (tmp_path / ".fortress-scanignore").write_text("a*" * 30 + "b\n", encoding="utf-8")
    (tmp_path / ("a" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")

    finished, _ = run_with_timeout(
        lambda: scan(str(tmp_path), Config(respect_ignore_files=False))
    )
    assert finished


def _write_project_with_every_suppression(root: Path) -> None:
    (root / ".fortress-scanignore").write_text("app.py\n", encoding="utf-8")
    (root / ".gitignore").write_text("app.py\n", encoding="utf-8")
    (root / ".fortress-scan.json").write_text(
        '{"disabled_rules": ["FSB-CMD-001"]}', encoding="utf-8"
    )
    (root / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system(request.args.get('c'))  # fortress-scan: ignore-file\n",
        encoding="utf-8",
    )


def _run_cli(arguments):
    from fortress_scan.cli import main
    from fortress_scan.security import runtime as sandbox

    try:
        return main(arguments)
    finally:
        sandbox.release()


def test_cli_without_flags_is_fully_silenced_by_the_scanned_tree(tmp_path: Path):
    _write_project_with_every_suppression(tmp_path)
    assert _run_cli([str(tmp_path), "--quiet"]) == 0, (
        "khong bat co nao thi ma duoc quet phai giau duoc phat hien"
    )


def test_cli_with_all_four_hardening_flags_defeats_every_suppression(tmp_path: Path):
    _write_project_with_every_suppression(tmp_path)
    code = _run_cli(
        [
            str(tmp_path),
            "--quiet",
            "--no-inline-suppressions",
            "--no-config",
            "--no-ignore-files",
            "--no-vcs-ignore",
        ]
    )
    assert code == 1, "bon co cung bat phai vo hieu moi duong giau phat hien"


@pytest.mark.parametrize(
    "missing_flag",
    ["--no-inline-suppressions", "--no-config", "--no-ignore-files", "--no-vcs-ignore"],
)
def test_every_hardening_flag_is_individually_necessary(tmp_path: Path, missing_flag: str):
    _write_project_with_every_suppression(tmp_path)
    flags = [
        flag
        for flag in (
            "--no-inline-suppressions",
            "--no-config",
            "--no-ignore-files",
            "--no-vcs-ignore",
        )
        if flag != missing_flag
    ]
    code = _run_cli([str(tmp_path), "--quiet"] + flags)
    assert code == 0, "thieu %s ma van bao duoc loi -> co nay thua" % missing_flag


def test_config_file_accepts_respect_ignore_files():
    from fortress_scan.core.config import build_config

    assert build_config({"respect_ignore_files": False}).respect_ignore_files is False
    assert build_config({}).respect_ignore_files is True


def test_normal_ignore_behaviour_is_unchanged():
    ignore = IgnoreSet.from_lines(["build/", "*.min.js", "/root_only.py", "!keep.min.js"])
    assert ignore.matches("build", True)
    assert ignore.matches("src/app.min.js", False)
    assert ignore.matches("root_only.py", False)
    assert not ignore.matches("src/root_only.py", False)
    assert not ignore.matches("keep.min.js", False)


def test_globstar_and_class_patterns_still_work():
    ignore = IgnoreSet.from_lines(["**/migrations/**", "docs/**", "*.[ch]", "a?c.py"])
    assert ignore.matches("app/migrations/0001.py", False)
    assert ignore.matches("docs/index.md", False)
    assert ignore.matches("main.c", False)
    assert ignore.matches("main.h", False)
    assert ignore.matches("abc.py", False)
    assert not ignore.matches("main.py", False)
    assert not ignore.matches("abcd.py", False)


def test_long_paths_are_not_truncated_before_matching():
    from fortress_scan.core.ignore import _MAX_PATH_LENGTH

    ignore = IgnoreSet.from_lines(["*.py"])
    segments = (_MAX_PATH_LENGTH - 100) // 201
    deep = "/".join("d" * 200 for _ in range(segments)) + "/ma_nguon.py"

    assert len(deep) < _MAX_PATH_LENGTH, "phep thu can duong dan NAM TRONG han muc"
    assert len(deep) > _MAX_PATH_LENGTH // 2, "duong dan phai du dai de phat hien viec cat"
    assert ignore.matches(deep, False), (
        "duong dan dai bi cat truoc khi khop nen mat duoi .py"
    )


def test_absurdly_long_paths_do_not_match_instead_of_being_guessed():
    ignore = IgnoreSet.from_lines(["*"])
    absurd = "a" * 5000
    assert not ignore.matches(absurd, False)


def test_long_path_decision_matches_the_short_path_decision():
    ignore = IgnoreSet.from_lines(["**/build/**", "*.log"])
    short = "src/build/out.log"
    long_prefix = "/".join("s" * 150 for _ in range(5))
    long_path = long_prefix + "/src/build/out.log"
    assert len(long_path) > 700
    assert ignore.matches(short, False) == ignore.matches(long_path, False)


def test_backslash_is_a_literal_character_not_an_escape():
    ignore = IgnoreSet.from_lines(["a\\*b"])
    assert ignore.matches("a\\xb", False)
    assert ignore.matches("a\\b", False)
    assert not ignore.matches("a*b", False)
    assert not ignore.matches("axb", False)


def test_wildcards_never_cross_a_path_separator():
    ignore = IgnoreSet.from_lines(["a*b"])
    assert ignore.matches("axxb", False)
    assert not ignore.matches("a/b", False)
    assert not ignore.matches("ax/xb", False)
