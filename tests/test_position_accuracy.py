"""Vị trí báo lỗi phải trỏ đúng vào mã nguồn thật.

Bộ phân tích Python đếm cột từ 0 ( ast.col_offset ) còn lexer generic từng
đếm từ 1, trong khi cả đường ra phía sau -- console, JSON, và SARIF với
startColumn = column + 1 -- đều giả định 0-based. Hệ quả là MỌI phát hiện
của mọi ngôn ngữ đi qua lexer generic lệch một cột, và nặng hơn: một chuỗi
đứng trước sink trên cùng dòng đặt lại cột về đầu dòng, nên `system` ở cột
17 bị báo ở cột 2.

Không test nào chạm tới cột của ngôn ngữ generic nên cả hai lỗi sống sót qua
mọi lượt xanh. Các test ở đây đối chiếu cột báo về với vị trí thật của ký
hiệu trong chính dòng mã.
"""

from __future__ import annotations

import json
from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.report.structured import to_sarif


def _scan(tmp_path: Path, name: str, source: str):
    (tmp_path / name).write_text(source, encoding="utf-8")
    return scan(str(tmp_path), Config())


def _finding_for(result, symbol_tail: str):
    for finding in result.findings:
        if finding.symbol.split(".")[-1] == symbol_tail:
            return finding
    raise AssertionError("khong tim thay phat hien cho %r" % symbol_tail)


def test_generic_column_is_zero_based_like_python(tmp_path: Path):
    source = '<?php\n$action = $_POST["action"];\nsystem("/bin/report " . $action);\n'
    result = _scan(tmp_path, "a.php", source)
    finding = _finding_for(result, "system")
    line = source.split("\n")[finding.line - 1]
    assert line[finding.column : finding.column + len("system")] == "system"
    assert finding.column == 0


def test_string_on_same_line_does_not_reset_the_column(tmp_path: Path):
    source = (
        "<?php\n"
        '$action = $_POST["action"];\n'
        '$log = "prefix"; system("/bin/report " . $action);\n'
    )
    result = _scan(tmp_path, "b.php", source)
    finding = _finding_for(result, "system")
    line = source.split("\n")[finding.line - 1]
    assert finding.column == line.index("system")
    assert line[finding.column : finding.column + len("system")] == "system"


def test_block_comment_on_same_line_does_not_reset_the_column(tmp_path: Path):
    source = (
        "<?php\n"
        '$action = $_POST["action"];\n'
        "/* ghi chu */ system(\"/bin/report \" . $action);\n"
    )
    result = _scan(tmp_path, "c.php", source)
    finding = _finding_for(result, "system")
    line = source.split("\n")[finding.line - 1]
    assert finding.column == line.index("system")


def test_column_survives_a_multiline_string_before_the_sink(tmp_path: Path):
    source = (
        "const cp = require('child_process');\n"
        "const banner = `line one\n"
        "line two`;\n"
        "cp.exec('ping ' + process.argv[2]);\n"
    )
    result = _scan(tmp_path, "d.js", source)
    finding = _finding_for(result, "exec")
    line = source.split("\n")[finding.line - 1]
    assert finding.column == line.index("cp.exec")


def test_sarif_region_spans_the_sink_call_not_one_character(tmp_path: Path):
    source = (
        "const cp = require('child_process');\n"
        "cp.exec('ping ' + process.argv[2]);\n"
    )
    result = _scan(tmp_path, "e.js", source)
    sarif = json.loads(to_sarif(result, "0.0.0-test"))
    regions = [
        r["locations"][0]["physicalLocation"]["region"] for r in sarif["runs"][0]["results"]
    ]
    assert regions, "khong co ket qua nao trong SARIF"
    region = regions[0]
    line = source.split("\n")[region["startLine"] - 1]
    # SARIF dung 1-based, endColumn loai tru.
    highlighted = line[region["startColumn"] - 1 : region["endColumn"] - 1]
    assert highlighted == "cp.exec"


def test_python_columns_stay_zero_based(tmp_path: Path):
    source = "import os\ndef f(x):\n    os.system('ping ' + x)\n"
    result = _scan(tmp_path, "f.py", source)
    finding = _finding_for(result, "system")
    line = source.split("\n")[finding.line - 1]
    assert line[finding.column : finding.column + len("os.system")] == "os.system"
