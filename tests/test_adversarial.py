from __future__ import annotations

import io
import json
import os
import socket
import subprocess
from pathlib import Path

import pytest

from fortress_scan.core.config import Config, ConfigError, build_config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.languages import PYTHON
from fortress_scan.report import ConsoleReporter, to_json, to_sarif
from fortress_scan.security import runtime as sandbox

ESCAPE = chr(0x1B)
BIDI_OVERRIDE = chr(0x202E)
ZERO_WIDTH_SPACE = chr(0x200B)


def rule_ids(source: str, config: Config = None):
    return [f.rule_id for f in scan_source(source, PYTHON, "sample.py", config or Config())]


def render(result) -> str:
    buffer = io.StringIO()
    ConsoleReporter(buffer, color=False, verbose=True).render(result)
    return buffer.getvalue()


class TestAttacksOnTheScanner:
    def test_scanned_code_is_never_executed(self, tmp_path: Path):
        marker = tmp_path / "PWNED.txt"
        payload = tmp_path / "evil.py"
        payload.write_text(
            "import pathlib\n"
            "pathlib.Path(%r).write_text('pwned')\n"
            "import os\n"
            "os.system('echo pwned')\n" % str(marker),
            encoding="utf-8",
        )
        scan(str(tmp_path), Config())
        assert not marker.exists()

    def test_module_init_side_effects_never_run(self, tmp_path: Path):
        marker = tmp_path / "IMPORTED.txt"
        package = tmp_path / "pkg"
        package.mkdir()
        (package / "__init__.py").write_text(
            "import pathlib\npathlib.Path(%r).write_text('imported')\n" % str(marker),
            encoding="utf-8",
        )
        scan(str(tmp_path), Config())
        assert not marker.exists()

    def test_ansi_escapes_cannot_forge_the_report(self, tmp_path: Path):
        forged = "%s[2J%s[H  Khong phat hien lo hong nao." % (ESCAPE, ESCAPE)
        (tmp_path / "app.py").write_text(
            "import os\nfrom flask import request\n"
            "def handler():\n"
            "    os.system(request.args.get('c') + %r)\n" % forged,
            encoding="utf-8",
        )
        result = scan(str(tmp_path), Config())
        assert result.findings
        rendered = render(result)
        assert ESCAPE not in rendered
        assert "\\x1b" in rendered

    def test_ansi_escapes_cannot_reach_structured_reports(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "import os\nfrom flask import request\n"
            "def handler():\n"
            "    os.system(request.args.get('c') + %r)\n" % (ESCAPE + "[2J"),
            encoding="utf-8",
        )
        result = scan(str(tmp_path), Config())
        assert ESCAPE not in to_json(result, "0.1.0")
        assert ESCAPE not in to_sarif(result, "0.1.0")

    def test_bidi_characters_cannot_reach_the_terminal(self, tmp_path: Path):
        (tmp_path / "app.py").write_text(
            "approved = False\n# %s return approved\n" % BIDI_OVERRIDE, encoding="utf-8"
        )
        result = scan(str(tmp_path), Config())
        rendered = render(result)
        assert any(f.rule_id == "FSB-UNI-001" for f in result.findings)
        assert BIDI_OVERRIDE not in rendered

    def test_secrets_never_reach_structured_reports(self, tmp_path: Path):
        secret = "ghp_" + "a" * 36
        (tmp_path / "app.py").write_text(
            "import os\nfrom flask import request\n"
            "TOKEN = %r\n"
            "def handler():\n"
            "    os.system('curl -H ' + TOKEN + request.args.get('c'))\n" % secret,
            encoding="utf-8",
        )
        result = scan(str(tmp_path), Config())
        assert result.findings
        for payload in (to_json(result, "0.1.0"), to_sarif(result, "0.1.0"), render(result)):
            assert secret not in payload

    def test_control_characters_in_filenames_are_neutralized(self, tmp_path: Path):
        try:
            hostile = tmp_path / ("a%s[31mfake.py" % ESCAPE)
            hostile.write_text("import os\nos.system(input())\n", encoding="utf-8")
        except (OSError, ValueError):
            pytest.skip("he dieu hanh khong cho tao ten tep nay")
        result = scan(str(tmp_path), Config(include_low_signal_sources=True))
        assert ESCAPE not in render(result)
        assert ESCAPE not in to_json(result, "0.1.0")

    def test_project_config_cannot_smuggle_executable_settings(self, tmp_path: Path):
        (tmp_path / ".fortress-scan.json").write_text(
            json.dumps({"plugins": ["evil.py"], "hooks": {"post": "rm -rf /"}}),
            encoding="utf-8",
        )
        from fortress_scan.core.config import load_config_file

        data = load_config_file(tmp_path / ".fortress-scan.json")
        with pytest.raises(ConfigError):
            build_config(data)

    def test_project_config_cannot_be_a_yaml_or_pickle_payload(self, tmp_path: Path):
        from fortress_scan.core.config import load_config_file

        (tmp_path / ".fortress-scan.json").write_text(
            "!!python/object/apply:os.system ['echo pwned']", encoding="utf-8"
        )
        with pytest.raises(ConfigError):
            load_config_file(tmp_path / ".fortress-scan.json")

    def test_network_and_process_stay_blocked_during_a_scan(self, tmp_path: Path):
        (tmp_path / "app.py").write_text("import socket\nvalue = 1\n", encoding="utf-8")
        sandbox.engage()
        try:
            scan(str(tmp_path), Config())
            with pytest.raises(sandbox.SandboxViolation):
                socket.socket()
            with pytest.raises(sandbox.SandboxViolation):
                subprocess.Popen(["echo", "x"])
            with pytest.raises(sandbox.SandboxViolation):
                os.system("echo x")
        finally:
            sandbox.release()

    def test_output_refuses_to_write_through_a_symlink(self, tmp_path: Path):
        from fortress_scan.security.paths import PathConfinementError, validate_output_path

        outside = tmp_path / "real.json"
        outside.write_text("{}", encoding="utf-8")
        link = tmp_path / "link.json"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("moi truong khong cho tao symlink")
        with pytest.raises(PathConfinementError):
            validate_output_path(str(link))

    def test_budget_exhaustion_is_reported_not_silent(self, tmp_path: Path):
        padding = "\n".join("x%d = %d" % (i, i) for i in range(4000))
        (tmp_path / "huge.py").write_text(
            padding + "\nimport os\nos.system(input())\n", encoding="utf-8"
        )
        result = scan(str(tmp_path), Config(node_budget=500))
        assert any(error.reason == "budget-exceeded" for error in result.errors)

    def test_parse_failure_is_reported_and_unicode_checks_still_run(self, tmp_path: Path):
        (tmp_path / "broken.py").write_text(
            "def f(%s:\n    pass\n" % ZERO_WIDTH_SPACE, encoding="utf-8"
        )
        result = scan(str(tmp_path), Config())
        assert any(error.reason == "parse-error" for error in result.errors)
        assert any(f.rule_id == "FSB-UNI-002" for f in result.findings)


class TestEvasionAttempts:
    def test_aliased_module_import(self):
        source = (
            "import os as operating_system\n"
            "from flask import request\n"
            "def handler():\n"
            "    operating_system.system(request.args.get('c'))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_aliased_function_import(self):
        source = (
            "from os import system as run_it\n"
            "from flask import request\n"
            "def handler():\n"
            "    run_it(request.args.get('c'))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_hidden_behind_two_helper_functions(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def inner(value):\n"
            "    os.system(value)\n"
            "def outer(value):\n"
            "    inner(value)\n"
            "def handler():\n"
            "    outer(request.args.get('c'))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_taint_hidden_inside_a_container(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    payload = {'cmd': request.args.get('c')}\n"
            "    os.system(payload['cmd'])\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_taint_through_nested_fstring(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    part = f\"--flag={request.args.get('c')}\"\n"
            "    os.system(f'tool {part}')\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_taint_through_join_and_list(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    pieces = ['ping', request.args.get('h')]\n"
            "    os.system(' '.join(pieces))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_sink_reached_through_reflection_is_flagged(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    getattr(os, request.args.get('fn'))('ls')\n"
        )
        assert "FSB-REFL-001" in rule_ids(source)

    def test_shell_wrapper_disguised_as_argument_list(self):
        source = (
            "import subprocess\n"
            "from flask import request\n"
            "def handler():\n"
            "    subprocess.run(['/bin/bash', '-c', request.args.get('c')])\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_taint_surviving_a_loop_and_a_branch(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    result = ''\n"
            "    for item in request.args.getlist('x'):\n"
            "        if item:\n"
            "            result = result + item\n"
            "    os.system('echo ' + result)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_inline_suppression_abuse_is_defeatable(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    os.system(request.args.get('c'))  # fortress-scan: ignore-file\n"
        )
        assert rule_ids(source) == []
        strict = Config(honor_inline_suppressions=False)
        assert "FSB-CMD-001" in rule_ids(source, strict)

    def test_vcs_ignore_hiding_is_defeatable(self, tmp_path: Path):
        (tmp_path / ".gitignore").write_text("hidden.py\n", encoding="utf-8")
        (tmp_path / "hidden.py").write_text(
            "import os\nfrom flask import request\n"
            "def handler():\n    os.system(request.args.get('c'))\n",
            encoding="utf-8",
        )
        assert scan(str(tmp_path), Config()).findings == []
        exposed = scan(str(tmp_path), Config(respect_vcs_ignore=False))
        assert any(f.rule_id == "FSB-CMD-001" for f in exposed.findings)


class TestDocumentedGaps:
    def test_gap_taint_across_files_is_not_tracked(self, tmp_path: Path):
        (tmp_path / "helpers.py").write_text(
            "import os\ndef run(value):\n    os.system(value)\n", encoding="utf-8"
        )
        (tmp_path / "app.py").write_text(
            "from flask import request\nfrom helpers import run\n"
            "def handler():\n    run(request.args.get('c'))\n",
            encoding="utf-8",
        )
        result = scan(str(tmp_path), Config())
        assert not any(f.rule_id == "FSB-CMD-001" for f in result.findings)
        assert any(f.rule_id == "FSB-CMD-003" for f in result.findings)

    def test_gap_taint_stored_on_an_instance_attribute(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "class Runner:\n"
            "    def load(self):\n"
            "        self.command = request.args.get('c')\n"
            "    def go(self):\n"
            "        os.system(self.command)\n"
        )
        ids = rule_ids(source)
        assert "FSB-CMD-001" not in ids
        assert "FSB-CMD-003" in ids

    def test_gap_payload_decoded_at_runtime_is_only_a_dynamic_finding(self):
        source = (
            "import base64\n"
            "from flask import request\n"
            "def handler():\n"
            "    exec(base64.b64decode(request.args.get('p')))\n"
        )
        assert "FSB-EXEC-001" in rule_ids(source)

    def test_gap_second_order_injection_through_storage(self):
        source = (
            "import os\n"
            "def handler(database):\n"
            "    value = database.fetch_one('SELECT name FROM users')\n"
            "    os.system('echo ' + value)\n"
        )
        ids = rule_ids(source)
        assert "FSB-CMD-001" not in ids
        assert "FSB-CMD-003" in ids
