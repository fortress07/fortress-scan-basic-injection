from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional, Sequence, Tuple

from .model import Finding

# Nhánh dài phải đứng trước: lựa chọn trong regex là "khớp cái đầu tiên", nên
# đặt "ignore" lên đầu sẽ nuốt luôn tiền tố của "ignore-file" và
# "ignore-next-line", khiến hai phạm vi đó âm thầm rơi về "ignore" một dòng.
_DIRECTIVE = re.compile(
    r"(?:#|//|/\*|--|<!--)\s*fortress-scan\s*:\s*(ignore-next-line|ignore-file|ignore)"
    r"(?:\s*\[([A-Za-z0-9\-, ]{0,200})\])?"
    r"(?:\s*(?:--|:)\s*(?P<reason>[^\n*]{0,200}))?"
)

_MAX_LINES = 200_000

# Chỉ thị nằm trong một chuỗi không phải là chỉ thị. Một dòng như
# HELP = "# fortress-scan: ignore-file" trông vô hại với người đọc nhưng lại
# tắt cả tệp, và im lặng -- nên nội dung chuỗi bị xoá trắng trước khi dò.
_COMMENT_MARKERS: Tuple[str, ...] = ("<!--", "/*", "//", "--", "#")
_TRIPLE_QUOTES: Tuple[str, ...] = ('"""', "'''")
_LINE_QUOTES: Tuple[str, ...] = ('"', "'", "`")
# Chuỗi một nháy không bắc qua dòng; chỉ ba nháy và backtick mới bắc được.
_SPANNING_QUOTES: Tuple[str, ...] = ("`",)
# Vùng nội suy bên trong chuỗi là mã, nên nó được phép chứa một chuỗi lồng
# dùng đúng dấu nháy đang mở -- `outer ${`inner`} end` là JavaScript hợp lệ.
# Không nhảy qua trọn vùng này thì dấu nháy mở của chuỗi lồng bị hiểu nhầm là
# dấu đóng của chuỗi ngoài, phần ruột rơi ra ngoài và một chỉ thị nằm trong
# dữ liệu lại được tính như chú thích thật.
_INTERPOLATION_MARKERS: Tuple[Tuple[str, str], ...] = (("${", "}"), ("#{", "}"), ("{$", "}"))


def _starts_with_any(text: str, index: int, options: Tuple[str, ...]) -> Optional[str]:
    for option in options:
        if text.startswith(option, index):
            return option
    return None


def _skip_nested_quote(raw: str, index: int) -> int:
    quote = raw[index]
    cursor = index + 1
    length = len(raw)
    while cursor < length:
        if raw[cursor] == "\\":
            cursor += 2
            continue
        if raw[cursor] == quote:
            return cursor + 1
        cursor += 1
    return cursor


def _interpolation_end(raw: str, index: int) -> int:
    """Chỉ số ngay sau dấu đóng khớp của vùng nội suy, hoặc -1 nếu không có."""
    for opener, closer in _INTERPOLATION_MARKERS:
        if raw.startswith(opener, index):
            return _scan_to_closer(raw, index + len(opener), opener, closer)
    return -1


def _scan_to_closer(raw: str, cursor: int, opener: str, closer: str) -> int:
    depth = 1
    length = len(raw)
    while cursor < length:
        char = raw[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char in ("'", '"', "`"):
            cursor = _skip_nested_quote(raw, cursor)
            continue
        if raw.startswith(opener, cursor):
            depth += 1
            cursor += len(opener)
            continue
        if char == closer:
            depth -= 1
            cursor += 1
            if depth == 0:
                return cursor
            continue
        cursor += 1
    return -1


def _close_open_string(raw: str, index: int, delimiter: str) -> Tuple[str, int, Optional[str]]:
    """Xoá phần thân của một chuỗi đang mở cho tới dấu đóng của nó."""
    end = raw.find(delimiter, index)
    if end < 0:
        return " " * (len(raw) - index), len(raw), delimiter
    return " " * (end - index) + delimiter, end + len(delimiter), None


def _consume_quoted(raw: str, index: int, quote: str) -> Tuple[str, int, Optional[str]]:
    """Xoá thân một chuỗi một nháy, tôn trọng dấu thoát."""
    pieces = [quote]
    index += 1
    length = len(raw)
    while index < length:
        char = raw[index]
        if char == "\\":
            pieces.append(" ")
            index += 1
            if index < length:
                pieces.append(" ")
                index += 1
            continue
        end = _interpolation_end(raw, index)
        if end != -1:
            # Cả vùng nội suy bị xoá trắng: bên trong là mã, nhưng ở đây ta chỉ
            # cần nó không sinh ra chỉ thị, và xoá là hướng an toàn.
            pieces.append(" " * (end - index))
            index = end
            continue
        if char == quote:
            pieces.append(quote)
            return "".join(pieces), index + 1, None
        pieces.append(" ")
        index += 1
    return "".join(pieces), length, quote if quote in _SPANNING_QUOTES else None


def _mask_line(raw: str, pending: Optional[str]) -> Tuple[str, Optional[str]]:
    pieces: List[str] = []
    index = 0
    length = len(raw)
    while index < length:
        if pending is not None:
            text, index, pending = _close_open_string(raw, index, pending)
            pieces.append(text)
            continue
        if _starts_with_any(raw, index, _COMMENT_MARKERS) is not None:
            pieces.append(raw[index:])
            break
        opener = _starts_with_any(raw, index, _TRIPLE_QUOTES)
        if opener is not None:
            pieces.append(opener)
            text, index, pending = _close_open_string(raw, index + len(opener), opener)
            pieces.append(text)
            continue
        quote = _starts_with_any(raw, index, _LINE_QUOTES)
        if quote is not None:
            text, index, pending = _consume_quoted(raw, index, quote)
            pieces.append(text)
            continue
        pieces.append(raw[index])
        index += 1
    return "".join(pieces), pending


def _mask_string_literals(lines: Sequence[str]) -> List[str]:
    """Thay nội dung chuỗi bằng khoảng trắng, giữ nguyên phần chú thích.

    Dấu mở chú thích được xét trước dấu nháy, nên dấu nháy đơn nằm trong chính
    chú thích (kiểu "don't") không bị hiểu nhầm là mở chuỗi.
    """
    masked: List[str] = []
    pending: Optional[str] = None
    for raw in lines:
        text, pending = _mask_line(raw, pending)
        masked.append(text)
    return masked


@dataclass(frozen=True)
class Suppression:
    line: int
    rules: Tuple[str, ...]
    scope: str
    reason: str

    def covers(self, finding: Finding) -> bool:
        if self.rules and finding.rule_id not in self.rules:
            return False
        if self.scope == "ignore-file":
            return True
        if self.scope == "ignore-next-line":
            return finding.line == self.line + 1
        return finding.line == self.line


class SuppressionIndex:
    def __init__(self, suppressions: Sequence[Suppression]) -> None:
        self._suppressions = tuple(suppressions)

    def __bool__(self) -> bool:
        return bool(self._suppressions)

    @classmethod
    def from_lines(cls, lines: Sequence[str]) -> "SuppressionIndex":
        window = lines[:_MAX_LINES]
        # Đa số tệp không nhắc tới công cụ này; khỏi cần xoá chuỗi làm gì.
        if not any("fortress-scan" in text for text in window):
            return cls(())
        found: List[Suppression] = []
        for index, text in enumerate(_mask_string_literals(window), start=1):
            if "fortress-scan" not in text:
                continue
            match = _DIRECTIVE.search(text)
            if match is None:
                continue
            raw_rules = match.group(2) or ""
            rules = tuple(
                item.strip().upper() for item in raw_rules.split(",") if item.strip()
            )
            found.append(
                Suppression(
                    line=index,
                    rules=rules,
                    scope=match.group(1),
                    reason=(match.group("reason") or "").strip(),
                )
            )
        return cls(found)

    def suppresses(self, finding: Finding) -> bool:
        for suppression in self._suppressions:
            if suppression.covers(finding):
                return True
        return False


def partition(
    findings: Sequence[Finding], index: SuppressionIndex
) -> Tuple[List[Finding], int]:
    if not index:
        return list(findings), 0
    kept: List[Finding] = []
    removed = 0
    for finding in findings:
        if index.suppresses(finding):
            removed += 1
        else:
            kept.append(finding)
    return kept, removed
