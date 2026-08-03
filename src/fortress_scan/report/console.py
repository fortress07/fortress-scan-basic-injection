from __future__ import annotations

import os
from typing import Dict, List, Sequence, TextIO

from ..core.model import Finding, ScanResult, Severity
from ..security.text import display_path, neutralize

_RESET = "\x1b[0m"
_STYLES: Dict[str, str] = {
    "critical": "\x1b[1;97;41m",
    "high": "\x1b[1;31m",
    "medium": "\x1b[1;33m",
    "low": "\x1b[1;36m",
    "info": "\x1b[1;90m",
    "dim": "\x1b[2m",
    "bold": "\x1b[1m",
    "path": "\x1b[1;36m",
    "good": "\x1b[1;32m",
}

_MARKS: Dict[str, str] = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}


class ConsoleReporter:
    def __init__(self, stream: TextIO, color: bool, verbose: bool = False) -> None:
        self._stream = stream
        self._color = color
        self._verbose = verbose

    def _paint(self, text: str, style: str) -> str:
        if not self._color or style not in _STYLES:
            return text
        return "%s%s%s" % (_STYLES[style], text, _RESET)

    def _write(self, text: str = "") -> None:
        try:
            self._stream.write(text + "\n")
        except UnicodeEncodeError:
            encoding = getattr(self._stream, "encoding", None) or "ascii"
            self._stream.write(text.encode(encoding, "replace").decode(encoding, "replace") + "\n")

    def render(self, result: ScanResult) -> None:
        self._write()
        if not result.findings:
            self._write(self._paint("  Không phát hiện lỗ hổng code injection nào.", "good"))
        else:
            grouped: Dict[str, List[Finding]] = {}
            for finding in result.findings:
                grouped.setdefault(finding.path, []).append(finding)
            for path in sorted(grouped):
                self._render_file(path, grouped[path])
        self._render_summary(result)

    def _render_file(self, path: str, findings: Sequence[Finding]) -> None:
        self._write(self._paint(display_path(path), "path"))
        for finding in findings:
            self._render_finding(finding)
        self._write()

    def _render_finding(self, finding: Finding) -> None:
        label = finding.severity.label
        badge = self._paint(" %s " % _MARKS.get(label, label.upper()), label)
        location = self._paint("%d:%d" % (finding.line, finding.column), "dim")
        self._write(
            "  %s %s  %s" % (badge, location, self._paint(finding.title, "bold"))
        )
        self._write("        %s" % neutralize(finding.message))
        meta = "%s | độ tin cậy %s | %s" % (
            finding.rule_id,
            finding.confidence.label,
            ", ".join(finding.cwe) if finding.cwe else "không có CWE",
        )
        self._write("        %s" % self._paint(meta, "dim"))
        if finding.snippet:
            self._write("        %s" % self._paint(finding.snippet, "dim"))
        if self._verbose and finding.trace:
            self._write("        %s" % self._paint("đường đi của dữ liệu:", "dim"))
            for step in finding.trace:
                self._write(
                    "          %s %s"
                    % (
                        self._paint("dòng %d" % step.line, "dim"),
                        neutralize(step.label),
                    )
                )
        if self._verbose and finding.remediation:
            self._write("        %s %s" % (self._paint("khắc phục:", "dim"), finding.remediation))

    def _render_summary(self, result: ScanResult) -> None:
        counts = result.counts_by_severity()
        parts = []
        for severity in sorted(Severity, reverse=True):
            count = counts.get(severity.label, 0)
            if count:
                parts.append(self._paint("%d %s" % (count, severity.label), severity.label))
        summary = "  ".join(parts) if parts else self._paint("sạch", "good")
        stats = result.stats
        self._write(self._paint("-" * 60, "dim"))
        self._write("  %s" % summary)
        self._write(
            self._paint(
                "  đã phân tích %d tệp trong %.2fs, thuộc %d ngôn ngữ"
                % (stats.files_analyzed, stats.duration_seconds, len(stats.languages)),
                "dim",
            )
        )
        if result.suppressed or result.baselined:
            self._write(
                self._paint(
                    "  %d bị ẩn bởi chú thích trong mã, %d trùng baseline"
                    % (result.suppressed, result.baselined),
                    "dim",
                )
            )
        if result.errors:
            self._write(
                self._paint("  %d tệp không phân tích được" % len(result.errors), "dim")
            )
            if self._verbose:
                for error in result.errors[:50]:
                    self._write(
                        self._paint(
                            "    %s: %s %s"
                            % (display_path(error.path), error.reason, neutralize(error.detail)),
                            "dim",
                        )
                    )
        self._write()


def supports_color(stream: TextIO) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    if not hasattr(stream, "isatty") or not stream.isatty():
        return False
    if os.name == "nt":
        return os.environ.get("WT_SESSION") is not None or os.environ.get("TERM") is not None
    return os.environ.get("TERM", "") != "dumb"
