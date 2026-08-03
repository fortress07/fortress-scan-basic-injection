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
        except Exception as exc:
            box["error"] = repr(exc)
        box["elapsed"] = time.monotonic() - started

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout=seconds)
    return (not thread.is_alive()), box.get("elapsed")


@pytest.mark.parametrize("groups", [8, 16, 32, 64])
def test_star_heavy_pattern_matches_in_linear_time(groups: int):
    rule = compile_rule("a*" * groups + "b")
    assert rule is not None
    text = "a" * 120
    started = time.monotonic()
    rule.matcher.matches(text)
    elapsed = time.monotonic() - started
    assert elapsed < 0.5, "mau %d nhom mat %.3fs, co dau hieu backtracking mu" % (groups, elapsed)


def test_scan_is_not_hung_by_a_hostile_scanignore(tmp_path: Path):
    (tmp_path / ".fortress-scanignore").write_text("a*" * 30 + "b\n", encoding="utf-8")
    (tmp_path / ("a" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")

    finished, elapsed = run_with_timeout(lambda: scan(str(tmp_path), Config()))
    assert finished, "scan() bi treo boi .fortress-scanignore doc hai"
    assert elapsed < BUDGET_SECONDS


def test_scan_is_not_hung_by_a_hostile_gitignore(tmp_path: Path):
    (tmp_path / ".gitignore").write_text("x*" * 30 + "y\n", encoding="utf-8")
    (tmp_path / ("x" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")

    finished, elapsed = run_with_timeout(lambda: scan(str(tmp_path), Config()))
    assert finished, "scan() bi treo boi .gitignore doc hai"
    assert elapsed < BUDGET_SECONDS


def test_scan_is_not_hung_by_a_hostile_exclude_flag(tmp_path: Path):
    (tmp_path / ("a" * 80 + ".py")).write_text("x = 1\n", encoding="utf-8")
    config = Config(exclude_patterns=("a*" * 30 + "b",))

    finished, elapsed = run_with_timeout(lambda: scan(str(tmp_path), config))
    assert finished, "scan() bi treo boi mau --exclude doc hai"
    assert elapsed < BUDGET_SECONDS


def test_huge_ignore_file_stays_bounded():
    lines = [("a*" * 50) + "b" for _ in range(5000)]
    ignore = IgnoreSet.from_lines(lines)
    path = "/".join(["a" * 40] * 6)

    started = time.monotonic()
    ignore.matches(path, False)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, "tep ignore khong lo van ton %.2fs cho mot duong dan" % elapsed


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

    finished, elapsed = run_with_timeout(
        lambda: scan(str(tmp_path), Config(respect_ignore_files=False))
    )
    assert finished
    assert elapsed < BUDGET_SECONDS


def test_all_three_hardening_flags_together(tmp_path: Path):
    (tmp_path / ".fortress-scanignore").write_text("app.py\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("app.py\n", encoding="utf-8")
    (tmp_path / ".fortress-scan.json").write_text(
        '{"disabled_rules": ["FSB-CMD-001"]}', encoding="utf-8"
    )
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def h():\n    os.system(request.args.get('c'))  # fortress-scan: ignore-file\n",
        encoding="utf-8",
    )

    strict = Config(
        respect_ignore_files=False,
        respect_vcs_ignore=False,
        honor_inline_suppressions=False,
    )
    result = scan(str(tmp_path), strict)
    assert any(f.rule_id == "FSB-CMD-001" for f in result.findings), (
        "ba co cung bat phai vo hieu moi duong giau phat hien"
    )


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


def test_wildcards_never_cross_a_path_separator():
    ignore = IgnoreSet.from_lines(["a*b"])
    assert ignore.matches("axxb", False)
    assert not ignore.matches("a/b", False)
    assert not ignore.matches("ax/xb", False)
