"""Phòng thủ theo chiều sâu cho ký tự điều khiển trong mã nguồn.

Sửa được chỗ đếm dòng mới chỉ khiến công cụ này thôi bị lừa. Những ký tự gây ra
chuyện đó vẫn nằm nguyên trong tệp và vẫn đánh lừa được trình soạn thảo, trình
xem diff hay giao diện review mà người duyệt mã đang nhìn, nên bản thân chúng
phải được báo cáo.

Mọi ký tự thí nghiệm ở đây đều tạo bằng chr() hoặc escape, để chính tệp test
này không chứa ký tự điều khiển thô.
"""

from __future__ import annotations

import time

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import ScanResult, ScanStats
from fortress_scan.languages import PYTHON
from fortress_scan.report.structured import to_json, to_markdown, to_sarif

# Tách dòng với str.splitlines() nhưng không với trình biên dịch.
AMBIGUOUS = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")
# Ký tự điều khiển khác, không phải dấu tách dòng.
OTHER_CONTROLS = ("\x00", "\x1b", "\x7f", "\x01")

ALL_CONTROLS = AMBIGUOUS + OTHER_CONTROLS


def rule_ids(source: str):
    return [f.rule_id for f in scan_source(source, PYTHON, "mau.py", Config())]


@pytest.mark.parametrize("char", ALL_CONTROLS)
def test_control_character_is_reported(char: str):
    assert "FSB-UNI-004" in rule_ids("x = 1\n# ghi chu%sy = 2\n" % char)


@pytest.mark.parametrize("char", ("\t", "\n"))
def test_legitimate_whitespace_is_not_reported(char: str):
    assert "FSB-UNI-004" not in rule_ids("x = 1\ndef f():%s    return 2\n" % char)


def test_ordinary_source_stays_silent():
    source = "import os\n\n\ndef f(u):\n\treturn os.path.join('a', u)\n"
    assert "FSB-UNI-004" not in rule_ids(source)


@pytest.mark.parametrize("char", AMBIGUOUS)
def test_ascii_only_file_is_still_scanned(char: str):
    """Nhánh thoát sớm isascii() từng bỏ qua trọn vẹn các ký tự này."""
    source = "x = 1\n# ghi chu%sy = 2\n" % char
    if source.isascii():
        assert "FSB-UNI-004" in rule_ids(source), "tep thuan ASCII bi bo qua"


@pytest.mark.parametrize("char", AMBIGUOUS)
def test_message_names_the_line_splitting_risk(char: str):
    findings = [
        f
        for f in scan_source("x = 1\n# c%sy = 2\n" % char, PYTHON, "m.py", Config())
        if f.rule_id == "FSB-UNI-004"
    ]
    assert findings
    assert "xuống dòng" in findings[0].message
    assert "U+%04X" % ord(char) in findings[0].message


def test_reported_position_points_at_the_character():
    # "# c" chiếm cột 1-3 của dòng 2, nên ký tự điều khiển nằm ở cột 4.
    findings = [
        f
        for f in scan_source("x = 1\n# c\x0cy = 2\n", PYTHON, "m.py", Config())
        if f.rule_id == "FSB-UNI-004"
    ]
    assert [(f.line, f.column) for f in findings] == [(2, 4)]


@pytest.mark.parametrize("char", ALL_CONTROLS)
def test_no_raw_control_character_reaches_any_output(char: str):
    """Báo cáo không được in lại byte thô — nếu không chính nó thành nơi tiêm."""
    findings = scan_source("x = 1\n# c%sy = 2\n" % char, PYTHON, "m.py", Config())
    result = ScanResult(root=".", findings=findings, errors=[], stats=ScanStats())
    for rendered in (
        to_json(result, "test"),
        to_sarif(result, "test"),
        to_markdown(result, "test"),
    ):
        assert char not in rendered, "ky tu tho lot ra bao cao"


def test_report_count_is_bounded():
    """Một tệp nhồi ký tự điều khiển không được sinh ra hàng nghìn finding."""
    source = "x = 1\n" + ("# c\x0c" * 3000) + "\ny = 2\n"
    findings = [f for f in scan_source(source, PYTHON, "m.py", Config()) if f.rule_id == "FSB-UNI-004"]
    assert 0 < len(findings) <= 20


def test_padding_cannot_hide_a_trojan_source_file():
    """Chặn số lượng báo cáo còn vá một đường né có sẵn.

    Trước đây mỗi phát hiện đều kèm một lần dựng snippet, mà Budget chỉ soi
    đồng hồ mỗi 2048 lần gọi spend(). Nhồi vài nghìn ký tự vô hình là vượt
    file_timeout_seconds, BudgetExceeded được nuốt ở engine, và toàn bộ phát
    hiện unicode -- kể cả ký tự đảo chiều hiển thị -- biến mất khỏi báo cáo.
    """
    source = (
        "duyet = False\n"
        "# %s ghi chu\n" % chr(0x202E)
        + ("# %s" % chr(0x200B)) * 4000
        + "\nx = 1\n"
    )
    started = time.monotonic()
    found = set(rule_ids(source))
    elapsed = time.monotonic() - started

    assert "FSB-UNI-001" in found, "ky tu dao chieu bi giau bang cach nhoi ky tu vo hinh"
    assert elapsed < Config().file_timeout_seconds, "vuot moc thoi gian da cong bo"
