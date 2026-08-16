"""Phân tích taint xuyên file: dữ liệu bẩn rời khỏi tệp nó đi vào.

Trước 0.2, mọi phân tích Python dừng ở ranh giới tệp -- sink nằm trong
helper ở tệp khác thì không bao giờ được báo. Các test ở đây chạy qua
engine.scan() với một dự án nhiều tệp thật sự trong tmp_path, vì đúng cấu
trúc hai pha ( thu thập -> báo cáo ) chỉ tồn tại ở tầng engine.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _ids(result) -> set:
    return {finding.rule_id for finding in result.findings}


def test_helper_sink_in_another_file_is_reported(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)
    finding = next(f for f in result.findings if f.rule_id == "FSB-CMD-001")
    # Phát hiện nằm ở lời gọi ( cùng tệp với nguồn ), đường đi chỉ rõ sink
    # nằm ở tệp helper.
    assert finding.path == "app.py"
    sink_step = finding.trace[-1]
    assert sink_step.path == "helpers.py"
    assert sink_step.line == 3


def test_chain_through_two_intermediate_files(tmp_path: Path):
    """web -> service -> runner: cần vòng tinh chỉnh của pha thu thập."""
    _write(
        tmp_path,
        "web.py",
        "from flask import request\n"
        "import service\n"
        "def handler():\n"
        "    return service.handle(request.args.get('q'))\n",
    )
    _write(
        tmp_path,
        "service.py",
        "import runner\n"
        "def handle(text):\n"
        "    return runner.execute(text)\n",
    )
    _write(
        tmp_path,
        "runner.py",
        "import subprocess\n"
        "def execute(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_taint_returning_from_another_file_flows_to_local_sink(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import echo\n"
        "import os\n"
        "def handler():\n"
        "    payload = echo(request.args.get('c'))\n"
        "    os.system('run ' + payload)\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "def echo(value):\n"
        "    return value\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_sanitizer_inside_helper_clears_taint_for_caller(tmp_path: Path):
    """Bộ khử độc nằm trong tệp helper vẫn phải vô hiệu hoá được cho caller."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import safe_run\n"
        "def handler():\n"
        "    return safe_run(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "import shlex\n"
        "def safe_run(value):\n"
        "    os.system('ping ' + shlex.quote(value))\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" not in _ids(result)


def test_constant_argument_to_dangerous_helper_stays_silent(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd('localhost')\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" not in _ids(result)


def test_no_cross_file_flag_restores_single_file_behavior(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config(cross_file_analysis=False))
    assert "FSB-CMD-001" not in _ids(result)


def test_package_import_resolves_across_directories(tmp_path: Path):
    _write(
        tmp_path,
        "routes.py",
        "from flask import request\n"
        "from services.commands import run\n"
        "def handler():\n"
        "    return run(request.args.get('c'))\n",
    )
    _write(tmp_path, "services/__init__.py", "")
    _write(
        tmp_path,
        "services/commands.py",
        "import os\n"
        "def run(value):\n"
        "    os.system(value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_same_helper_name_in_two_modules_is_not_confused(tmp_path: Path):
    """Hai module cùng định nghĩa run(): không được quy sink cho tệp sai."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "import first\n"
        "def handler():\n"
        "    return first.run(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "first.py",
        "def run(value):\n"
        "    return value.upper()\n",
    )
    _write(
        tmp_path,
        "second.py",
        "import os\n"
        "def run(value):\n"
        "    os.system(value)\n",
    )
    result = scan(str(tmp_path), Config())
    # first.run sạch: gọi nó với dữ liệu bẩn không được sinh ra phát hiện
    # commande nào cả ( second.run không hề được gọi ).
    assert not any(
        f.rule_id == "FSB-CMD-001" and f.path == "app.py" for f in result.findings
    )


def test_findings_are_deterministic_across_runs(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    first = scan(str(tmp_path), Config())
    second = scan(str(tmp_path), Config(jobs=4))
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


def test_scan_source_stays_single_file():
    """API một tệp ( scan_source ) không được âm thầm đổi hành vi."""
    from fortress_scan import scan_source
    from fortress_scan.languages import PYTHON

    source = (
        "import os\n"
        "def handler(value):\n"
        "    os.system('ping ' + value)\n"
    )
    findings = scan_source(source, PYTHON, "app.py", Config())
    # Không có nguồn nào ở đây, chỉ có dạng động; giữ nguyên kỳ vọng cũ.
    assert all(f.rule_id != "FSB-CMD-001" for f in findings)
