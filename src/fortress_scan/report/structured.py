from __future__ import annotations

import json
from typing import Any, Dict, List

from ..core.model import Finding, ScanResult, Severity
from ..core.registry import all_rules, get_rule, rules_digest
from ..security.text import display_path, neutralize

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def to_json(result: ScanResult, tool_version: str) -> str:
    payload = result.to_dict()
    payload["tool"] = {
        "name": "fortress-scan",
        "version": tool_version,
        "rules_digest": rules_digest(),
    }
    return json.dumps(payload, indent=2, sort_keys=False) + "\n"


def to_sarif(result: ScanResult, tool_version: str) -> str:
    used_rules = sorted({finding.rule_id for finding in result.findings})
    rules: List[Dict[str, Any]] = []
    for rule_id in used_rules:
        rule = get_rule(rule_id)
        rules.append(
            {
                "id": rule.id,
                "name": rule.id.replace("-", ""),
                "shortDescription": {"text": rule.title},
                "fullDescription": {"text": rule.description},
                "help": {"text": rule.remediation},
                "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
                "properties": {
                    "tags": ["security", rule.category.value] + list(rule.cwe) + list(rule.owasp),
                    "problem.severity": rule.severity.label,
                    "security-severity": _security_severity(rule.severity),
                },
            }
        )

    results: List[Dict[str, Any]] = []
    for finding in result.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": finding.message},
                "partialFingerprints": {"fortress-scan/v1": finding.fingerprint},
                "properties": {
                    "confidence": finding.confidence.label,
                    "category": finding.category.value,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": display_path(finding.path),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": max(1, finding.column + 1),
                                "endLine": max(finding.line, finding.end_line),
                                "snippet": {"text": finding.snippet},
                            },
                        }
                    }
                ],
                "codeFlows": _code_flows(finding),
            }
        )

    document = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Fortress Scan",
                        "version": tool_version,
                        "informationUri": (
                            "https://github.com/fortress07/fortress-scan-basic-injection"
                        ),
                        "rules": rules,
                    }
                },
                "originalUriBaseIds": {
                    "%SRCROOT%": {"uri": _root_uri(result.root)}
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": _notifications(result),
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"


def _notifications(result: ScanResult) -> List[Dict[str, Any]]:
    """Mọi thứ làm hẹp phạm vi quét, đặt vào đúng chỗ của SARIF.

    Không có phần này thì một lượt quét bị tệp cấu hình trong cây mục tiêu bóp
    còn một nửa vẫn xuất ra tệp SARIF trông y hệt một lượt quét sạch thật sự.
    """
    notifications: List[Dict[str, Any]] = []
    for notice in result.notices:
        text = "\n".join((notice.summary,) + tuple(notice.details))
        notifications.append(
            {
                "level": "warning",
                "message": {"text": text},
                "descriptor": {"id": notice.kind},
            }
        )
    for error in result.errors:
        detail = " ".join(part for part in (error.reason, error.detail) if part)
        notifications.append(
            {
                "level": "warning",
                "message": {"text": "%s: %s" % (display_path(error.path), detail)},
                "descriptor": {"id": error.reason},
            }
        )
    return notifications


def _code_flows(finding: Finding) -> List[Dict[str, Any]]:
    if not finding.trace:
        return []
    locations = []
    for step in finding.trace:
        locations.append(
            {
                "location": {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": display_path(finding.path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": max(1, step.line),
                            "startColumn": max(1, step.column + 1),
                        },
                    },
                    "message": {"text": step.label},
                }
            }
        )
    return [{"threadFlows": [{"locations": locations}]}]


def _security_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.3",
        Severity.HIGH: "7.5",
        Severity.MEDIUM: "5.0",
        Severity.LOW: "3.1",
        Severity.INFO: "1.0",
    }[severity]


def _root_uri(root: str) -> str:
    normalized = root.replace("\\", "/")
    if not normalized.endswith("/"):
        normalized += "/"
    if len(normalized) > 2 and normalized[1] == ":":
        return "file:///" + normalized
    return "file://" + normalized


def to_markdown(result: ScanResult, tool_version: str) -> str:
    lines: List[str] = []
    counts = result.counts_by_severity()
    lines.append("# Báo cáo Fortress Scan")
    lines.append("")
    lines.append("Đã quét `%s` bằng Fortress Scan %s." % (display_path(result.root), tool_version))
    lines.append("")
    lines.append("| Mức độ | Số lượng |")
    lines.append("| --- | --- |")
    for severity in sorted(Severity, reverse=True):
        lines.append("| %s | %d |" % (severity.label, counts.get(severity.label, 0)))
    lines.append("")
    lines.append(
        "Đã phân tích %d tệp trong %.2f giây."
        % (result.stats.files_analyzed, result.stats.duration_seconds)
    )
    if result.stats.files_skipped:
        lines.append("")
        lines.append("Bỏ qua %d tệp, không được phân tích." % result.stats.files_skipped)
    lines.append("")

    # Đặt trước phần phát hiện, và trước cả nhánh "không có phát hiện nào":
    # đây chính là lúc người đọc cần biết vì sao báo cáo lại sạch.
    if result.notices:
        lines.append("## ⚠️ Phạm vi quét đã bị thu hẹp")
        lines.append("")
        for notice in result.notices:
            lines.append("- %s" % _escape(notice.summary))
            for detail in notice.details:
                lines.append("  - %s" % _escape(detail))
        lines.append("")

    if not result.findings:
        lines.append("Không phát hiện lỗ hổng code injection nào.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Các phát hiện")
    lines.append("")
    for finding in result.findings:
        rule = get_rule(finding.rule_id)
        lines.append(
            "### %s - %s" % (finding.rule_id, _escape(finding.title))
        )
        lines.append("")
        lines.append(
            "- Vị trí: `%s:%d:%d`"
            % (display_path(finding.path), finding.line, finding.column)
        )
        lines.append(
            "- Mức độ: **%s** | Độ tin cậy: %s | Nhóm: %s"
            % (finding.severity.label, finding.confidence.label, finding.category.value)
        )
        if finding.cwe:
            lines.append("- Điểm yếu: %s" % ", ".join(finding.cwe))
        if finding.owasp:
            lines.append("- OWASP: %s" % ", ".join(finding.owasp))
        lines.append("- Vân tay: `%s`" % finding.fingerprint)
        lines.append("")
        lines.append(_escape(finding.message))
        lines.append("")
        if finding.snippet:
            lines.append("```")
            lines.append(finding.snippet)
            lines.append("```")
            lines.append("")
        if finding.trace:
            lines.append("Đường đi của dữ liệu:")
            lines.append("")
            for step in finding.trace:
                lines.append(
                    "1. dòng %d - %s (`%s`)"
                    % (step.line, _escape(step.label), _escape(step.code))
                )
            lines.append("")
        lines.append("**Cách khắc phục.** %s" % _escape(rule.remediation))
        lines.append("")
    return "\n".join(lines)


def rules_catalogue() -> str:
    lines = ["# Danh mục rule của Fortress Scan", ""]
    lines.append("| Mã | Mức độ | Nhóm | Tên |")
    lines.append("| --- | --- | --- | --- |")
    for rule in all_rules():
        lines.append(
            "| %s | %s | %s | %s |"
            % (rule.id, rule.severity.label, rule.category.value, _escape(rule.title))
        )
    lines.append("")
    return "\n".join(lines)


def _escape(text: str) -> str:
    # neutralize() trước cả escape cú pháp: | < > chỉ giữ cho bảng Markdown
    # không vỡ, còn escape sequence của terminal thì đi xuyên qua nguyên vẹn và
    # nổ ra khi ai đó cat tệp .md hoặc để CI in nó vào log. JSON và SARIF thoát
    # nạn này nhờ json.dumps, Markdown thì không có ai lo hộ.
    return neutralize(text).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")
