"""Ánh xạ bộ rule sang OWASP Top 10:2025 phải khớp với thứ công cụ thật sự quét.

Trước bản này cả 35 rule bị gộp vào đúng hai mục của bản 2021, mà gộp thô như
vậy là ánh xạ SAI chứ không phải ánh xạ gọn: người đọc báo cáo tra theo OWASP
sẽ không tìm ra rule nằm đúng chỗ của nó.

Nhãn 2021 được giữ nguyên đi kèm, vì mã rule và khoá JSON của bản 0.1.0 là giao
diện ổn định nên chỉ được THÊM vào chứ không được thay bằng thứ người dùng cũ
không tra ra.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def test_every_rule_carries_both_a_2025_and_a_2021_owasp_tag():
    """Nhãn 2021 là giao diện ổn định của bản 0.1.0 nên chỉ được THÊM vào."""
    from fortress_scan.core.registry import all_rules

    for rule in all_rules():
        tags = rule.owasp
        assert any(tag.startswith("A") and ":2025-" in tag for tag in tags), rule.id
        assert any(tag.startswith("A") and ":2021-" in tag for tag in tags), rule.id
        assert tags[0].endswith(tags[0].split("-", 1)[1]), rule.id


def test_owasp_2025_mapping_is_specific_not_lumped():
    """Gộp cả bộ rule vào một hai mục là ánh xạ sai, không phải ánh xạ gọn."""
    from fortress_scan.core.registry import all_rules, get_rule

    families = {rule.owasp[0] for rule in all_rules()}
    assert len(families) >= 5, "ánh xạ 2025 đang bị gộp quá thô: %s" % sorted(families)

    # Bốn chỗ bản 2025 xếp khác hẳn bản 2021, và đó là lý do phải cập nhật.
    assert get_rule("FSB-SSRF-001").owasp[0] == "A01:2025-Broken Access Control"
    assert get_rule("FSB-SUP-001").owasp[0] == "A03:2025-Software Supply Chain Failures"
    assert get_rule("FSB-PATH-001").owasp[0] == "A01:2025-Broken Access Control"
    assert get_rule("FSB-XML-001").owasp[0] == "A02:2025-Security Misconfiguration"
    assert get_rule("FSB-SQL-001").owasp[0] == "A05:2025-Injection"


def test_owasp_tags_reach_the_sarif_report(tmp_path):
    """CI đọc SARIF chứ không đọc màn hình, nên nhãn phải có mặt ở đó."""
    import json

    from fortress_scan.report import to_sarif

    (tmp_path / "app.py").write_text(
        "import os\nos.system(input())\n", encoding="utf-8"
    )
    result = scan(str(tmp_path), Config())
    assert result.findings, "mẫu này phải bắn thì mới kiểm được SARIF"

    document = json.loads(to_sarif(result, "0.1.0"))
    tags = document["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
    assert any(":2025-" in tag for tag in tags), tags
    assert any(":2021-" in tag for tag in tags), tags
