"""Kiểm tra kết cấu SARIF 2.1 - định dạng mà GitHub Code Scanning đọc.

SARIF từng chỉ được kiểm tra nông ( có version, có results ). Các test ở
đây giữ chặt phần GitHub thật sự dùng: region đầy đủ startColumn/endColumn,
fingerprints cho định danh cảnh báo xuyên các lần chạy, và codeFlows mang
đúng tệp của từng bước đường đi.
"""

from __future__ import annotations

import json
from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.report.structured import to_sarif


def _sarif_for(tmp_path: Path) -> dict:
    result = scan(str(tmp_path), Config())
    return json.loads(to_sarif(result, "test"))


def test_every_result_has_full_region_and_fingerprints(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "import os\n"
        "def handler():\n"
        "    os.system('ping ' + request.args.get('h'))\n",
        encoding="utf-8",
    )
    document = _sarif_for(tmp_path)
    results = document["runs"][0]["results"]
    assert results
    for entry in results:
        region = entry["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] >= 1
        assert region["startColumn"] >= 1
        assert region["endColumn"] > region["startColumn"]
        assert region["endLine"] >= region["startLine"]
        assert "fortress-scan/v1" in entry["fingerprints"]
        assert entry["fingerprints"] == entry["partialFingerprints"]


def test_cross_file_codeflow_points_at_both_files(tmp_path: Path):
    (tmp_path / "app.py").write_text(
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    run_cmd(request.args.get('c'))\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
        encoding="utf-8",
    )
    document = _sarif_for(tmp_path)
    results = document["runs"][0]["results"]
    cross = [r for r in results if r.get("codeFlows")]
    assert cross
    uris = set()
    for flow in cross[0]["codeFlows"]:
        for location in flow["threadFlows"][0]["locations"]:
            uris.add(location["location"]["physicalLocation"]["artifactLocation"]["uri"])
    assert {"app.py", "helpers.py"} <= uris
