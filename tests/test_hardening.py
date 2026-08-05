from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from fortress_scan.core import baseline
from fortress_scan.core.budget import Budget, BudgetExceeded
from fortress_scan.core.config import Config, ConfigError, build_config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.core.ignore import IgnoreSet
from fortress_scan.languages import PYTHON
from fortress_scan.security import paths as safe_paths
from fortress_scan.security import runtime as sandbox
from fortress_scan.security.redaction import PLACEHOLDER, redact
from fortress_scan.security.text import BIDI_CONTROLS, make_snippet, neutralize


def test_terminal_escape_sequences_are_neutralized():
    hostile = "os.system(x)  \x1b[2K\x1b[1A FAKE: scan clean"
    rendered = make_snippet(hostile)
    assert "\x1b" not in rendered
    assert "\\x1b" in rendered


def test_control_characters_are_escaped():
    assert neutralize("a\rb\x00c") == "a\\x0db\\x00c"
    assert neutralize("plain text") == "plain text"


def test_bidi_characters_are_escaped_in_output():
    hostile = "if amount < 100: %s return True" % BIDI_CONTROLS[4]
    rendered = make_snippet(hostile)
    assert BIDI_CONTROLS[4] not in rendered
    assert "\\u202e" in rendered


FAKE_AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
FAKE_GITHUB_TOKEN = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789"
FAKE_SHORT_TOKEN = "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz01"


def test_secrets_are_redacted_from_snippets():
    samples = (
        'password = "hunter2superSecret"',
        FAKE_AWS_KEY,
        FAKE_GITHUB_TOKEN,
        "postgres://user:sup3rs3cret@db.internal:5432/app",
    )
    for sample in samples:
        assert PLACEHOLDER in redact(sample), sample


def test_redaction_keeps_ordinary_code_intact():
    code = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
    assert redact(code) == code


def test_findings_carry_redacted_snippets():
    source = "import os\nos.system(\"curl -H 'token: %s' \" + x)\n" % FAKE_SHORT_TOKEN
    findings = scan_source(source, PYTHON, "sample.py", Config())
    for finding in findings:
        assert FAKE_SHORT_TOKEN not in finding.snippet


def test_sandbox_blocks_network_and_process_execution():
    import socket
    import subprocess

    sandbox.engage()
    try:
        assert sandbox.is_engaged()
        with pytest.raises(sandbox.SandboxViolation):
            socket.socket()
        with pytest.raises(sandbox.SandboxViolation):
            subprocess.Popen(["echo", "hi"])
        with pytest.raises(sandbox.SandboxViolation):
            os.system("echo hi")
    finally:
        sandbox.release()
    assert not sandbox.is_engaged()
    assert socket.socket is not None


def test_budget_stops_runaway_analysis():
    budget = Budget(units=10, seconds=5.0)
    with pytest.raises(BudgetExceeded):
        for _ in range(100):
            budget.spend()


def test_deeply_nested_source_does_not_crash():
    source = "x = " + "[" * 60 + "]" * 60 + "\n"
    assert scan_source(source, PYTHON, "deep.py", Config()) == []


def test_pathological_expression_is_bounded():
    source = "import os\nos.system(" + " + ".join(['"a"'] * 2000) + ")\n"
    findings = scan_source(source, PYTHON, "wide.py", Config())
    assert isinstance(findings, list)


def test_config_rejects_unknown_keys():
    with pytest.raises(ConfigError):
        build_config({"totally_unknown": 1})


def test_config_rejects_wrong_types():
    with pytest.raises(ConfigError):
        build_config({"max_files": "lots"})
    with pytest.raises(ConfigError):
        build_config({"follow_symlinks": "yes"})
    with pytest.raises(ConfigError):
        build_config({"exclude": "not-a-list"})


def test_config_rejects_non_positive_limits():
    with pytest.raises(ConfigError):
        build_config({"max_file_bytes": 0})


def test_config_accepts_known_keys():
    config = build_config({"min_severity": "high", "exclude": ["build/**"], "jobs": 4})
    assert config.min_severity.label == "high"
    assert config.exclude_patterns == ("build/**",)
    assert config.jobs == 4


def test_ignore_patterns_match_like_gitignore():
    ignore = IgnoreSet.from_lines(["build/", "*.min.js", "/root_only.py", "!keep.min.js"])
    assert ignore.matches("build", True)
    assert ignore.matches("src/app.min.js", False)
    assert ignore.matches("root_only.py", False)
    assert not ignore.matches("src/root_only.py", False)
    assert not ignore.matches("keep.min.js", False)


def test_output_path_rejects_missing_directory():
    with pytest.raises(safe_paths.PathConfinementError):
        safe_paths.validate_output_path("./no_such_directory_here/report.json")


def test_baseline_round_trip(tmp_path: Path):
    source = "import os\nfrom flask import request\ndef h():\n    os.system(request.args.get('c'))\n"
    findings = scan_source(source, PYTHON, "app.py", Config())
    assert findings
    target = tmp_path / "baseline.json"
    target.write_text(baseline.serialize(findings), encoding="utf-8")
    loaded = baseline.load(target)
    assert loaded == {finding.fingerprint for finding in findings}
    remaining, removed = baseline.apply(findings, loaded)
    assert remaining == []
    assert removed == len(findings)


def test_baseline_rejects_malformed_file(tmp_path: Path):
    target = tmp_path / "bad.json"
    target.write_text("[]", encoding="utf-8")
    with pytest.raises(baseline.BaselineError):
        baseline.load(target)


def test_fingerprint_is_stable_across_line_moves():
    body = "import os\nfrom flask import request\ndef h():\n    os.system(request.args.get('c'))\n"
    first = scan_source(body, PYTHON, "app.py", Config())
    second = scan_source("\n\n\n" + body, PYTHON, "app.py", Config())
    assert [f.fingerprint for f in first] == [f.fingerprint for f in second]


def test_scan_refuses_missing_target():
    with pytest.raises(safe_paths.PathConfinementError):
        scan("./definitely_missing_directory_xyz")


def test_scan_skips_oversized_files(tmp_path: Path):
    big = tmp_path / "big.py"
    big.write_text("import os\nos.system('ls')\n" + ("# padding\n" * 5000), encoding="utf-8")
    result = scan(str(tmp_path), Config(max_file_bytes=128))
    assert result.stats.files_analyzed == 0
    assert any(error.reason == "file-too-large" for error in result.errors)


def test_scan_skips_binary_files(tmp_path: Path):
    binary = tmp_path / "blob.py"
    binary.write_bytes(b"import os" + bytes(64) + b"os.system('ls')")
    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 0
    # Bỏ qua thì được, nhưng phải nói ra: im lặng thì người đọc báo cáo tưởng
    # tệp đó đã được soi và sạch.
    assert any(error.reason == "binary-skipped" for error in result.errors)


def test_a_stray_null_byte_does_not_hide_a_file(tmp_path: Path):
    """Một byte NUL lẻ không biến tệp thành nhị phân.

    Node và PHP vẫn chạy tệp có NUL trong chuỗi, nên nếu chỉ một byte đó đủ
    làm tệp biến mất khỏi lần quét thì đó là một đường né hoàn chỉnh.
    """
    payload = tmp_path / "app.js"
    payload.write_bytes(
        b"const cp = require('child_process');\n"
        b"const pad = '\x00';\n"
        b"function h(req){ const host = req.query.host; cp.exec('ping ' + host); }\n"
    )
    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 1
    assert any(f.rule_id == "FSB-CMD-001" for f in result.findings)


def test_symlink_outside_root_is_not_followed(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    try:
        (root / "link").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")
    result = scan(str(root), Config())
    assert result.stats.files_analyzed == 0
    result_following = scan(str(root), Config(follow_symlinks=True))
    assert result_following.stats.files_analyzed == 0


def test_excluded_directories_are_not_scanned(tmp_path: Path):
    vendored = tmp_path / "node_modules"
    vendored.mkdir()
    (vendored / "bad.py").write_text("import os\nos.system(input())\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("value = 1\n", encoding="utf-8")
    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 1


def test_project_config_from_scanned_tree_is_declarative_only(tmp_path: Path):
    (tmp_path / ".fortress-scan.json").write_text(
        json.dumps({"min_severity": "critical"}), encoding="utf-8"
    )
    from fortress_scan.core.config import find_config_file, load_config_file

    found = find_config_file(tmp_path)
    assert found is not None
    data = load_config_file(found)
    assert build_config(data).min_severity.label == "critical"


def test_serializer_round_trip_is_not_an_injection():
    source = """
import pickle
import requests

def check():
    response = requests.get("https://example.test")
    return pickle.loads(pickle.dumps(response))
"""
    assert scan_source(source, PYTHON, "roundtrip.py", Config()) == []


def test_non_confusable_scripts_are_not_reported():
    source = 'HOSTS = ["ジェーピー.jp", "中文网址.cn"]\n'
    ids = [finding.rule_id for finding in scan_source(source, PYTHON, "i18n.py", Config())]
    assert "FSB-UNI-003" not in ids


def test_latin_cyrillic_homoglyph_is_reported():
    cyrillic_a = chr(0x0430)
    source = "p" + cyrillic_a + "ssword = 'admin'\n"
    ids = [finding.rule_id for finding in scan_source(source, PYTHON, "homoglyph.py", Config())]
    assert "FSB-UNI-003" in ids


def test_invisible_character_is_reported_even_when_parsing_fails():
    zero_width_space = chr(0x200B)
    source = "def check%s_access(user):\n    return True\n" % zero_width_space
    ids = [finding.rule_id for finding in scan_source(source, PYTHON, "trojan.py", Config())]
    assert "FSB-UNI-002" in ids


def test_bidi_override_is_reported():
    override = chr(0x202E)
    isolate = chr(0x2069)
    source = "approved = False\n# %s return approved %s approved = True\n" % (override, isolate)
    ids = [finding.rule_id for finding in scan_source(source, PYTHON, "bidi.py", Config())]
    assert "FSB-UNI-001" in ids


def test_shell_wrapper_argument_is_detected():
    source = """
import subprocess
from flask import request

def handler():
    command = request.args.get("cmd")
    subprocess.run(["sh", "-c", command])
"""
    ids = [finding.rule_id for finding in scan_source(source, PYTHON, "app.py", Config())]
    assert "FSB-CMD-001" in ids
