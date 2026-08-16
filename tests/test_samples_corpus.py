"""Corpus mẫu thật - ba cổng mà CI chạy giờ chạy được cả khi chỉ gõ `pytest`.

Trước 0.2, ba kiểm tra này chỉ tồn tại dưới dạng bước workflow trong CI:
lượt `pytest` thường không đụng tới tests/samples, nên một hồi quy làm
hỏng corpus vẫn xanh ở máy local. Giữ nguyên kỳ vọng của CI: mẫu lỗi phải
bắn, mẫu an toàn phải im, tự quét nguồn phải sạch.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan import __version__
from fortress_scan.cli import main as cli_main
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.core.model import Severity

SAMPLES = Path(__file__).parent / "samples"
VULNERABLE = SAMPLES / "vulnerable"
SAFE = SAMPLES / "safe"
REPO_ROOT = Path(__file__).parent.parent


def test_vulnerable_corpus_fires_and_covers_every_family():
    result = scan(str(VULNERABLE), Config())
    ids = {finding.rule_id for finding in result.findings}
    assert result.findings, "corpus lỗi phải sinh phát hiện"
    # Mỗi họ quy ước có mặt trong corpus: các họ injection lõi + 4 họ mới của 0.2.
    for expected in (
        "FSB-CMD-001",
        "FSB-SQL-001",
        "FSB-EXEC-001",
        "FSB-DESER-001",
        "FSB-IMPORT-001",
        "FSB-REFL-001",
        "FSB-TMPL-001",
        "FSB-XSS-001",
        "FSB-PATH-001",
        "FSB-SSRF-001",
        "FSB-REDIR-001",
        "FSB-HDR-001",
    ):
        assert expected in ids, "thiếu %s trong corpus lỗi" % expected


def test_vulnerable_corpus_has_a_cross_file_finding():
    """db_helper.py chứa sink, web_app.py là nơi gọi: đường đi phải xuyên file."""
    result = scan(str(VULNERABLE), Config())
    cross = [f for f in result.findings if any(step.path for step in f.trace)]
    assert cross
    assert any(f.path == "web_app.py" for f in cross)


def test_safe_corpus_is_silent_at_the_strictest_threshold():
    result = scan(str(SAFE), Config(min_severity=Severity.INFO))
    assert result.findings == []
    assert result.errors == []


def test_cli_gates_match_ci():
    """Đúng hai lệnh CI chạy: corpus lỗi thoát khác 0, corpus sạch im ở mức info."""
    assert cli_main([str(VULNERABLE), "--no-config", "--quiet"]) != 0
    assert cli_main([str(SAFE), "--no-config", "--quiet", "--fail-on", "info"]) == 0


def test_self_scan_of_the_tool_source_is_clean():
    result = scan(str(REPO_ROOT / "src"), Config(min_severity=Severity.LOW))
    assert result.findings == [], [f.rule_id + " " + f.path for f in result.findings]


def test_version_is_0_2():
    assert __version__ == "0.2.0"
