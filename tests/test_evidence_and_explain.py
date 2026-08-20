"""Bằng chứng đi kèm phát hiện, và `--explain` cho từng rule.

Một nhãn "high" trần trụi không kiểm chứng được. Phần bằng chứng nói ra vì
sao công cụ tin ( hoặc bớt tin ), và nó phải có mặt ở MỌI định dạng: người
đọc SARIF trong code scanning cần đúng những dòng lý do như người đọc console.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortress_scan.cli import main as cli_main
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.core.model import Confidence
from fortress_scan.core.registry import all_rules
from fortress_scan.languages import PYTHON
from fortress_scan.report import rule_explanation

VULN = (
    "import os\n"
    "from flask import request\n"
    "def h():\n"
    "    os.system('ping ' + request.args['a'])\n"
)

DYNAMIC = "import os\ndef h(muc_tieu):\n    os.system('ping ' + muc_tieu)\n"


def test_a_traced_finding_names_its_source():
    finding = scan_source(VULN, PYTHON, "app.py", Config())[0]
    joined = " ".join(finding.evidence)
    assert "nguồn dữ liệu không tin cậy" in joined
    assert "điểm nguy hiểm" in joined


def test_a_shape_only_finding_says_it_has_no_source():
    """FSB-CMD-003 là "chưa dựng được nguồn", và phải tự nói ra điều đó."""
    finding = scan_source(DYNAMIC, PYTHON, "app.py", Config())[0]
    assert finding.rule_id == "FSB-CMD-003"
    assert any("chưa dựng được nguồn" in item for item in finding.evidence)


def test_evidence_is_bounded():
    from fortress_scan.core.calibration import MAX_EVIDENCE

    for finding in scan_source(VULN, PYTHON, "app.py", Config()):
        assert len(finding.evidence) <= MAX_EVIDENCE
        assert all(len(item) <= 200 for item in finding.evidence)


def test_cross_file_findings_admit_their_approximation(tmp_path: Path):
    (tmp_path / "helpers.py").write_text(
        "import os\ndef chay(lenh):\n    os.system(lenh)\n", encoding="utf-8"
    )
    (tmp_path / "web.py").write_text(
        "from flask import request\nimport helpers\n"
        "def h():\n    helpers.chay(request.args['a'])\n",
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    cross = [f for f in result.findings if any(step.path for step in f.trace)]
    assert cross
    assert any("xuyên file" in item for item in cross[0].evidence)


def test_evidence_reaches_json(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    cli_main([str(tmp_path), "-f", "json"])
    payload = json.loads(capsys.readouterr().out)
    finding = payload["findings"][0]
    assert finding["evidence"]
    assert finding["context"] == "production"


def test_evidence_reaches_sarif(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    cli_main([str(tmp_path), "-f", "sarif"])
    payload = json.loads(capsys.readouterr().out)
    properties = payload["runs"][0]["results"][0]["properties"]
    assert properties["evidence"]
    assert properties["context"] == "production"


def test_evidence_reaches_markdown(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    cli_main([str(tmp_path), "-f", "markdown"])
    assert "Căn cứ:" in capsys.readouterr().out


def test_console_shows_evidence_only_with_verbose(tmp_path: Path, capsys):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    cli_main([str(tmp_path), "--no-color"])
    assert "căn cứ:" not in capsys.readouterr().out
    cli_main([str(tmp_path), "--no-color", "-v"])
    assert "căn cứ:" in capsys.readouterr().out


def test_console_always_shows_a_non_production_context(tmp_path: Path, capsys):
    """Ngữ cảnh không giấu sau -v: nó đổi hẳn cách đọc một dòng phát hiện."""
    target = tmp_path / "tests" / "test_api.py"
    target.parent.mkdir()
    target.write_text(VULN, encoding="utf-8")
    cli_main([str(tmp_path), "--no-color"])
    assert "trong phần kiểm thử" in capsys.readouterr().out


# --------------------------------------------------------------------- explain


@pytest.mark.parametrize("rule", [rule.id for rule in all_rules()])
def test_every_rule_can_be_explained(rule: str):
    text = rule_explanation(rule)
    assert rule in text
    assert "Vì sao đây là vấn đề" in text
    assert "Cách khắc phục" in text


def test_explain_is_multi_line_not_one_escaped_blob():
    """Trung hoà từng dòng, không trung hoà cả khối.

    Trung hoà cả khối thì chính dấu xuống dòng cũng bị escape, và tài liệu
    nhiều đoạn biến thành một dòng dài đặc \\x0a.
    """
    text = rule_explanation("FSB-CI-001")
    assert text.count("\n") > 10
    assert "\\x0a" not in text


def test_explain_accepts_lower_case(capsys):
    assert cli_main(["--explain", "fsb-exec-001"]) == 0
    assert "FSB-EXEC-001" in capsys.readouterr().out


def test_explain_refuses_an_unknown_rule():
    assert cli_main(["--explain", "FSB-KHONG-CO"]) == 2


# ---------------------------------------------------------------- cổng mã thoát


def test_confidence_gate_holds_the_exit_code(tmp_path: Path):
    (tmp_path / "app.py").write_text(VULN, encoding="utf-8")
    assert cli_main([str(tmp_path), "--quiet"]) == 1
    assert cli_main([str(tmp_path), "--quiet", "--fail-on-confidence", "high"]) == 1
    assert cli_main([str(tmp_path), "--quiet", "--fail-on-confidence", "certain"]) == 0


def test_confidence_gate_is_checked_per_finding(tmp_path: Path):
    """Ngưỡng soi TỪNG phát hiện, không phải mức cao nhất của từng chiều.

    Lấy mức độ cao nhất rồi so riêng với độ tin cậy cao nhất là trộn hai phát
    hiện khác nhau thành một cái không tồn tại: một phát hiện critical/low và
    một phát hiện low/high sẽ cùng nhau dựng ra một "critical + high" ảo.
    """
    (tmp_path / "nang.py").write_text(DYNAMIC, encoding="utf-8")
    target = tmp_path / "tests" / "test_api.py"
    target.parent.mkdir()
    target.write_text(VULN, encoding="utf-8")
    findings = scan(str(tmp_path), Config()).findings
    assert {f.confidence for f in findings} == {Confidence.MEDIUM}
    assert cli_main([str(tmp_path), "--quiet", "--fail-on-confidence", "high"]) == 0
