from __future__ import annotations

import json
import random
import string
from pathlib import Path

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.languages import (
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    MANIFEST,
    PHP,
    PYTHON,
    RUBY,
    SHELL,
    TYPESCRIPT,
)

BIDI_OVERRIDE = chr(0x202E)
LEFT_TO_RIGHT_ISOLATE = chr(0x2066)
ZERO_WIDTH_SPACE = chr(0x200B)

ALL_LANGUAGES = (
    PYTHON,
    JAVASCRIPT,
    TYPESCRIPT,
    PHP,
    JAVA,
    RUBY,
    GO,
    CSHARP,
    SHELL,
    MANIFEST,
)

MALFORMED_INPUTS = (
    "",
    "\n\n\n",
    "\x00",
    "'''",
    '"""unterminated',
    "`" * 50,
    "${" * 200,
    "#{" * 200,
    "<<<EOT\nnever closed",
    "((((((((((((((((((((",
    "))))))))))))))))))))",
    "{" * 300,
    "}" * 300,
    "/*" + "a" * 500,
    "// " + "b" * 5000,
    "\\" * 500,
    "$" * 500,
    "'" + "x" * 3000,
    "a" * 20000,
    "\r\n\r\n\t\t  ",
    BIDI_OVERRIDE + LEFT_TO_RIGHT_ISOLATE + ZERO_WIDTH_SPACE,
    "def f(:\n  pass",
    "class {{{",
    "SELECT * FROM",
    "eval(",
    "eval(eval(eval(eval(",
    "x = " + "[" * 90 + "]" * 90,
    "x = " + "(1," * 400 + ")" * 400,
    "\ud800",
)


@pytest.mark.parametrize("language", ALL_LANGUAGES)
@pytest.mark.parametrize("payload", MALFORMED_INPUTS)
def test_malformed_input_never_raises(language: str, payload: str):
    findings = scan_source(payload, language, "fuzz-input", Config())
    assert isinstance(findings, list)


@pytest.mark.parametrize("language", ALL_LANGUAGES)
def test_random_bytes_never_raise(language: str):
    generator = random.Random(20260803)
    alphabet = string.printable + "é中" + BIDI_OVERRIDE + ZERO_WIDTH_SPACE
    for _ in range(25):
        payload = "".join(generator.choice(alphabet) for _ in range(400))
        assert isinstance(scan_source(payload, language, "fuzz", Config()), list)


def test_scan_is_deterministic(tmp_path: Path):
    for index in range(6):
        (tmp_path / ("module%d.py" % index)).write_text(
            "import os\nfrom flask import request\n"
            "def handler():\n    os.system('ping ' + request.args.get('h'))\n",
            encoding="utf-8",
        )
    first = scan(str(tmp_path), Config())
    second = scan(str(tmp_path), Config())
    assert json.dumps(first.to_dict()["findings"]) == json.dumps(second.to_dict()["findings"])
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


def test_parallel_and_serial_agree(tmp_path: Path):
    for index in range(12):
        (tmp_path / ("module%d.py" % index)).write_text(
            "import subprocess\nfrom flask import request\n"
            "def handler():\n"
            "    subprocess.check_output(request.args.get('c'), shell=True)\n",
            encoding="utf-8",
        )
    serial = scan(str(tmp_path), Config(jobs=1))
    parallel = scan(str(tmp_path), Config(jobs=8))
    assert [f.fingerprint for f in serial.findings] == [
        f.fingerprint for f in parallel.findings
    ]


def test_empty_directory_is_clean(tmp_path: Path):
    result = scan(str(tmp_path), Config())
    assert result.findings == []
    assert result.stats.files_analyzed == 0


def test_single_file_target(tmp_path: Path):
    target = tmp_path / "one.py"
    target.write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    result = scan(str(target), Config())
    assert result.stats.files_analyzed == 1
    assert any(finding.rule_id == "FSB-CMD-001" for finding in result.findings)


def test_unknown_extension_is_skipped(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("os.system(input())", encoding="utf-8")
    (tmp_path / "data.xml").write_text("<a>eval(x)</a>", encoding="utf-8")
    assert scan(str(tmp_path), Config()).stats.files_analyzed == 0


def test_latin1_and_utf16_files_do_not_crash(tmp_path: Path):
    (tmp_path / "latin.py").write_bytes("x = 'caf\xe9'\n".encode("latin-1"))
    (tmp_path / "utf16.py").write_bytes("x = 1\n".encode("utf-16"))
    result = scan(str(tmp_path), Config())
    assert isinstance(result.findings, list)


def test_bom_prefixed_file_is_parsed(tmp_path: Path):
    target = tmp_path / "bom.py"
    target.write_bytes(
        b"\xef\xbb\xbf" + b"import os\nos.system('ls ' + input())\n"
    )
    result = scan(str(tmp_path), Config(include_low_signal_sources=True))
    assert result.stats.files_analyzed == 1


def test_crlf_line_endings(tmp_path: Path):
    target = tmp_path / "crlf.py"
    target.write_bytes(
        b"import os\r\nfrom flask import request\r\n"
        b"def handler():\r\n    os.system(request.args.get('c'))\r\n"
    )
    result = scan(str(tmp_path), Config())
    assert any(finding.rule_id == "FSB-CMD-001" for finding in result.findings)


def test_very_long_single_line(tmp_path: Path):
    target = tmp_path / "long.py"
    target.write_text("x = " + " + ".join(['"a"'] * 8000) + "\n", encoding="utf-8")
    result = scan(str(tmp_path), Config())
    assert isinstance(result.findings, list)


def test_many_files_are_all_visited(tmp_path: Path):
    for index in range(150):
        (tmp_path / ("f%03d.py" % index)).write_text("value = %d\n" % index, encoding="utf-8")
    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 150


def test_nested_directories(tmp_path: Path):
    current = tmp_path
    for depth in range(20):
        current = current / ("level%d" % depth)
        current.mkdir()
        (current / "mod.py").write_text("value = 1\n", encoding="utf-8")
    result = scan(str(tmp_path), Config())
    assert result.stats.files_analyzed == 20


def test_all_report_formats_render(tmp_path: Path):
    from fortress_scan.report import to_json, to_markdown, to_sarif

    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    assert json.loads(to_json(result, "0.1.0"))["summary"]["total"] >= 1
    sarif = json.loads(to_sarif(result, "0.1.0"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
    assert "Fortress Scan" in to_markdown(result, "0.1.0")


def test_report_formats_handle_zero_findings(tmp_path: Path):
    from fortress_scan.report import to_json, to_markdown, to_sarif

    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    result = scan(str(tmp_path), Config())
    assert json.loads(to_json(result, "0.1.0"))["summary"]["total"] == 0
    assert json.loads(to_sarif(result, "0.1.0"))["runs"][0]["results"] == []
    assert isinstance(to_markdown(result, "0.1.0"), str)


def test_console_output_survives_a_restrictive_encoding(tmp_path: Path):
    import io

    from fortress_scan.report import ConsoleReporter

    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    assert result.findings

    for encoding in ("cp1258", "cp1252", "ascii"):
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding=encoding, errors="strict", newline="")
        ConsoleReporter(stream, color=False, verbose=True).render(result)
        stream.flush()
        assert buffer.getvalue()


def test_cli_writes_vietnamese_to_a_pipe(tmp_path: Path):
    import io
    import sys

    from fortress_scan.cli import main

    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    buffer = io.BytesIO()
    replacement = io.TextIOWrapper(buffer, encoding="cp1258", errors="strict", newline="")
    original = sys.stdout
    sys.stdout = replacement
    try:
        code = main([str(tmp_path), "--no-config", "--no-color"])
    finally:
        sys.stdout = original
    replacement.flush()
    assert code == 1
    assert buffer.getvalue()


def test_every_rule_in_registry_is_well_formed():
    from fortress_scan.core.registry import all_rules

    seen = set()
    for rule in all_rules():
        assert rule.id not in seen
        seen.add(rule.id)
        assert rule.id.startswith("FSB-")
        assert rule.title and rule.description and rule.remediation
        assert rule.cwe
        assert rule.owasp
    assert len(seen) >= 25


def test_min_severity_and_confidence_filters(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    assert scan(str(tmp_path), Config()).findings
    from fortress_scan.core.model import Severity

    filtered = scan(str(tmp_path), Config(min_severity=Severity.CRITICAL))
    assert all(f.severity >= Severity.CRITICAL for f in filtered.findings)


def test_disabled_rule_is_not_reported(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system(request.args.get('c'))\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config(disabled_rules=("FSB-CMD-001",)))
    assert all(finding.rule_id != "FSB-CMD-001" for finding in result.findings)
