from __future__ import annotations

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import PYTHON


def rule_ids(source: str, config: Config = None):
    findings = scan_source(source, PYTHON, "sample.py", config or Config())
    return [finding.rule_id for finding in findings]


def test_command_injection_through_concatenation():
    source = """
import os
from flask import request

def handler():
    name = request.args.get("name")
    os.system("ping " + name)
"""
    assert "FSB-CMD-001" in rule_ids(source)


def test_argument_list_without_shell_is_clean():
    source = """
import subprocess
from flask import request

def handler():
    name = request.args.get("name")
    subprocess.run(["ping", "-c", "1", "--", name])
"""
    assert rule_ids(source) == []


def test_shlex_quote_neutralizes_command():
    source = """
import os
import shlex
from flask import request

def handler():
    name = request.args.get("name")
    os.system("ping " + shlex.quote(name))
"""
    assert rule_ids(source) == []


def test_allowlist_guard_with_early_return():
    source = """
import os
from flask import request

ALLOWED = {"nginx", "redis"}

def handler():
    unit = request.args.get("unit")
    if unit not in ALLOWED:
        raise ValueError("no")
    os.system("systemctl status " + unit)
"""
    assert rule_ids(source) == []


def test_positive_allowlist_guard():
    source = """
import os
from flask import request

ALLOWED = {"nginx", "redis"}

def handler():
    unit = request.args.get("unit")
    if unit in ALLOWED:
        os.system("systemctl status " + unit)
"""
    assert rule_ids(source) == []


def test_integer_coercion_neutralizes_eval():
    source = """
from flask import request

def handler():
    count = int(request.args.get("count"))
    return eval("1 + %d" % count)
"""
    assert rule_ids(source) == []


def test_sql_parameterized_is_clean():
    source = """
from flask import request

def handler(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
"""
    assert rule_ids(source) == []


def test_sql_fstring_is_injection():
    source = """
from flask import request

def handler(cursor):
    name = request.args.get("name")
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
"""
    assert "FSB-SQL-001" in rule_ids(source)


def test_interprocedural_flow_through_helper():
    source = """
import os
from flask import request

def run(command):
    os.system(command)

def handler():
    os.environ.setdefault("X", "1")
    run("echo " + request.args.get("message"))
"""
    ids = rule_ids(source)
    assert "FSB-CMD-001" in ids


def test_interprocedural_return_value_propagates():
    source = """
from flask import request

def build(identifier):
    return "SELECT * FROM users WHERE id = " + identifier

def handler(cursor):
    cursor.execute(build(request.args.get("id")))
"""
    assert "FSB-SQL-001" in rule_ids(source)


def test_route_handler_parameters_are_tainted():
    source = """
import os
from flask import Flask

app = Flask(__name__)

@app.route("/run/<command>")
def run(command):
    os.system(command)
"""
    assert "FSB-CMD-001" in rule_ids(source)


def test_yaml_safe_load_is_clean():
    source = """
import yaml
from flask import request

def handler():
    return yaml.safe_load(request.get_data())
"""
    assert rule_ids(source) == []


def test_yaml_load_without_safe_loader_is_flagged():
    source = """
import yaml
from flask import request

def handler():
    return yaml.load(request.get_data())
"""
    assert "FSB-DESER-001" in rule_ids(source)


def test_yaml_load_with_safe_loader_is_clean():
    source = """
import yaml
from flask import request

def handler():
    return yaml.load(request.get_data(), Loader=yaml.SafeLoader)
"""
    assert rule_ids(source) == []


def test_custom_sanitizer_wrapper_is_recognized():
    source = """
import os
import shlex
from flask import request

def lam_sach(gia_tri):
    return shlex.quote(gia_tri)

def handler():
    os.system("ping " + lam_sach(request.args.get("h")))
"""
    assert rule_ids(source) == []


def test_custom_validator_wrapper_is_recognized():
    source = """
import os
from flask import request

CHO_PHEP = {"nginx", "redis"}

def kiem_tra(gia_tri):
    if gia_tri not in CHO_PHEP:
        raise ValueError("khong hop le")
    return gia_tri

def handler():
    os.system("systemctl " + kiem_tra(request.args.get("u")))
"""
    assert rule_ids(source) == []


def test_custom_wrapper_that_does_not_sanitize_is_still_flagged():
    source = """
import os
from flask import request

def khong_lam_gi(gia_tri):
    return gia_tri.strip()

def handler():
    os.system("ping " + khong_lam_gi(request.args.get("h")))
"""
    assert "FSB-CMD-001" in rule_ids(source)


def test_local_function_shadows_builtin_sink():
    source = """
def compile(path, doraise=False):
    return path

def main(filename):
    compile(filename, doraise=True)
"""
    assert rule_ids(source) == []


def test_environment_source_requires_opt_in():
    source = """
import os

def handler():
    os.system("echo " + os.environ["MESSAGE"])
"""
    assert "FSB-CMD-001" not in rule_ids(source)
    opted_in = Config(include_low_signal_sources=True)
    assert "FSB-CMD-001" in rule_ids(source, opted_in)


def test_template_injection():
    source = """
from flask import request
from jinja2 import Template

def handler():
    return Template(request.args.get("body")).render()
"""
    assert "FSB-TMPL-001" in rule_ids(source)


def test_reflection_sink():
    source = """
from flask import request

def handler(target):
    return getattr(target, request.args.get("field"))
"""
    assert "FSB-REFL-001" in rule_ids(source)


def test_nosql_where_operator():
    source = """
from flask import request

def handler(collection):
    return collection.find({"$where": request.args.get("filter")})
"""
    assert "FSB-NOSQL-001" in rule_ids(source)


def test_loop_propagates_taint():
    source = """
import os
from flask import request

def handler():
    for item in request.args.getlist("items"):
        os.system("echo " + item)
"""
    assert "FSB-CMD-001" in rule_ids(source)


def test_inline_suppression_is_honored():
    source = """
import os
from flask import request

def handler():
    name = request.args.get("name")
    os.system("ping " + name)  # fortress-scan: ignore[FSB-CMD-001] -- reviewed
"""
    assert rule_ids(source) == []


def test_inline_suppression_is_rule_scoped():
    source = """
import os
from flask import request

def handler():
    name = request.args.get("name")
    os.system("ping " + name)  # fortress-scan: ignore[FSB-SQL-001]
"""
    assert "FSB-CMD-001" in rule_ids(source)


def test_syntax_error_is_reported_as_unparsable():
    from fortress_scan.analysis.base import AnalysisUnit
    from fortress_scan.analysis.python import PythonAnalyzer, UnparsableSource
    from fortress_scan.core.budget import Budget

    source = "def broken(:\n    pass\n"
    unit = AnalysisUnit(
        relative_path="broken.py",
        language=PYTHON,
        source=source,
        lines=tuple(source.splitlines()),
        config=Config(),
    )
    with pytest.raises(UnparsableSource):
        PythonAnalyzer().analyze(unit, Budget(10000, 5.0))
