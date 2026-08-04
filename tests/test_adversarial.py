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


class TestSinkReachedThroughAnAlias:
    """A sink stays a sink when the call goes through a name that holds it.

    Sink matching is by API name, so storing the callable in a variable, a
    dispatch table or a getattr() used to make the call unrecognisable and the
    finding vanished silently.
    """

    def test_sink_assigned_to_a_local_variable(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    cmd = request.args.get('c')\n"
            "    func = os.system\n"
            "    func(cmd)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_sink_held_in_a_dispatch_table(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    cmd = request.args.get('c')\n"
            "    handlers = {'run': os.system}\n"
            "    handlers['run'](cmd)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_sink_held_in_a_list(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    cmd = request.args.get('c')\n"
            "    ops = [os.system]\n"
            "    ops[0](cmd)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_sink_reached_by_getattr_with_a_constant_name(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    getattr(os, 'system')(request.args.get('c'))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_dispatch_table_indexed_by_untrusted_input(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    handlers = {'run': os.system, 'show': print}\n"
            "    handlers[request.args.get('k')](request.args.get('c'))\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_dispatch_table_too_large_to_map_falls_back_to_the_union(self):
        """The per-key map is bounded; dropping it must lose precision, not the
        finding, or a padded table would be an evasion."""
        table = ", ".join("'k%d': os.system" % index for index in range(400))
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    cmd = request.args.get('c')\n"
            "    handlers = {%s}\n"
            "    handlers['k399'](cmd)\n" % table
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_method_sink_assigned_to_a_local_variable(self):
        source = (
            "from flask import request\n"
            "def handler(cursor):\n"
            "    name = request.args.get('n')\n"
            "    run = cursor.execute\n"
            "    run(f\"SELECT * FROM users WHERE name = '{name}'\")\n"
        )
        assert "FSB-SQL-001" in rule_ids(source)

    def test_builtin_sink_assigned_to_a_local_variable(self):
        source = (
            "from flask import request\n"
            "def handler():\n"
            "    run = eval\n"
            "    run(request.args.get('e'))\n"
        )
        assert "FSB-EXEC-001" in rule_ids(source)

    def test_template_sink_assigned_to_a_local_variable(self):
        source = (
            "from flask import request\n"
            "def handler(env):\n"
            "    render = env.from_string\n"
            "    render(request.args.get('t'))\n"
        )
        assert "FSB-TMPL-001" in rule_ids(source)

    def test_alias_of_a_local_wrapper_keeps_the_full_trace(self):
        """Aliasing a wrapper used to downgrade critical to medium and drop the
        data path, which reads as a code smell rather than an injection."""
        source = (
            "import os\n"
            "from flask import request\n"
            "def run_cmd(c):\n"
            "    os.system(c)\n"
            "def handler():\n"
            "    cmd = request.args.get('c')\n"
            "    f = run_cmd\n"
            "    f(cmd)\n"
        )
        findings = scan_source(source, PYTHON, "sample.py", Config())
        command = [f for f in findings if f.rule_id == "FSB-CMD-001"]
        assert command, "aliased wrapper must still report the injection"
        assert any(step.label.startswith("tham số truy vấn HTTP") for step in command[0].trace)

    def test_alias_through_a_branch_reports_both_targets(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler(flag):\n"
            "    cmd = request.args.get('c')\n"
            "    func = os.system if flag else eval\n"
            "    func(cmd)\n"
        )
        ids = rule_ids(source)
        assert "FSB-CMD-001" in ids
        assert "FSB-EXEC-001" in ids


class TestAliasTrackingStaysPrecise:
    """Alias resolution must not blame a callable the call cannot reach."""

    def test_constant_key_picks_only_that_dispatch_entry(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    handlers = {'safe': print, 'run': os.system}\n"
            "    handlers['safe'](request.args.get('v'))\n"
        )
        assert "FSB-CMD-001" not in rule_ids(source)

    def test_constant_index_picks_only_that_list_element(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    ops = [print, os.system]\n"
            "    ops[0](request.args.get('v'))\n"
        )
        assert "FSB-CMD-001" not in rule_ids(source)

    def test_a_sink_that_is_never_called_is_not_a_finding(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    runner = os.system\n"
            "    return str(runner) + request.args.get('v')\n"
        )
        assert "FSB-CMD-001" not in rule_ids(source)

    def test_alias_of_a_sanitizer_still_sanitizes(self):
        source = (
            "import shlex\n"
            "import subprocess\n"
            "from flask import request\n"
            "def handler():\n"
            "    quote = shlex.quote\n"
            "    run = subprocess.run\n"
            "    run('echo ' + quote(request.args.get('v')), shell=True)\n"
        )
        assert "FSB-CMD-001" not in rule_ids(source)

    def test_alias_matches_the_direct_call_exactly(self):
        """The alias path must add no finding the direct call would not make."""
        direct = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    os.system('echo ' + request.args.get('v'))\n"
        )
        aliased = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    run = os.system\n"
            "    run('echo ' + request.args.get('v'))\n"
        )
        assert sorted(rule_ids(direct)) == sorted(rule_ids(aliased))

    def test_getattr_still_carries_the_taint_of_its_receiver(self):
        """Naming a callable must not consume the data the call returns, or
        reflection would launder taint instead of tracking it."""
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    obj = request.args.get('o')\n"
            "    value = getattr(obj, 'name')\n"
            "    os.system('echo ' + value)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_getattr_still_carries_the_taint_of_its_default(self):
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler():\n"
            "    fallback = request.args.get('d')\n"
            "    value = getattr(object(), 'missing', fallback)\n"
            "    os.system('echo ' + value)\n"
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_merging_an_unmappable_table_keeps_the_finding(self):
        """One branch too large to map makes the other branch's key map
        non-authoritative; keeping it would read as 'key absent'."""
        table = ", ".join("'b%d': os.system" % index for index in range(400))
        source = (
            "import os\n"
            "from flask import request\n"
            "def handler(flag):\n"
            "    cmd = request.args.get('c')\n"
            "    if flag:\n"
            "        table = {'small': os.popen}\n"
            "    else:\n"
            "        table = {%s}\n"
            "    table['b399'](cmd)\n" % table
        )
        assert "FSB-CMD-001" in rule_ids(source)

    def test_a_plain_data_variable_is_not_treated_as_a_callable(self):
        source = (
            "from flask import request\n"
            "def handler():\n"
            "    system = request.args.get('v')\n"
            "    return system\n"
        )
        assert rule_ids(source) == []


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
