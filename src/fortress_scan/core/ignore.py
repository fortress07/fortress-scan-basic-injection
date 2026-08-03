from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Pattern, Sequence, Tuple

_MAX_PATTERN_LENGTH = 512
_MAX_PATTERNS = 5000


@dataclass(frozen=True)
class IgnoreRule:
    matcher: Pattern[str]
    negated: bool
    directory_only: bool
    anchored: bool


def _translate(pattern: str) -> str:
    result: List[str] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if index + 1 < length and pattern[index + 1] == "*":
                index += 2
                if index < length and pattern[index] == "/":
                    index += 1
                    result.append("(?:.*/)?")
                else:
                    result.append(".*")
                continue
            result.append("[^/]*")
        elif char == "?":
            result.append("[^/]")
        elif char == "[":
            end = index + 1
            if end < length and pattern[end] in ("!", "^"):
                end += 1
            if end < length and pattern[end] == "]":
                end += 1
            while end < length and pattern[end] != "]":
                end += 1
            if end >= length:
                result.append("\\[")
            else:
                body = pattern[index + 1 : end]
                if body.startswith(("!", "^")):
                    body = "^" + body[1:]
                result.append("[" + body.replace("\\", "\\\\") + "]")
                index = end + 1
                continue
        else:
            result.append(re.escape(char))
        index += 1
    return "".join(result)


def compile_rule(raw: str) -> Optional[IgnoreRule]:
    pattern = raw.rstrip("\r\n")
    if not pattern.strip() or pattern.lstrip().startswith("#"):
        return None
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:]
    pattern = pattern.strip()
    if not pattern:
        return None
    directory_only = pattern.endswith("/")
    if directory_only:
        pattern = pattern[:-1]
    anchored = "/" in pattern.rstrip("/")
    if pattern.startswith("/"):
        pattern = pattern[1:]
        anchored = True
    if not pattern:
        return None
    body = _translate(pattern)
    if anchored:
        expression = "^" + body + "(?:/.*)?$"
    else:
        expression = "^(?:.*/)?" + body + "(?:/.*)?$"
    try:
        matcher = re.compile(expression)
    except re.error:
        return None
    return IgnoreRule(matcher, negated, directory_only, anchored)


class IgnoreSet:
    def __init__(self, rules: Sequence[IgnoreRule] = ()) -> None:
        self._rules: Tuple[IgnoreRule, ...] = tuple(rules)

    def __bool__(self) -> bool:
        return bool(self._rules)

    @classmethod
    def from_lines(cls, lines: Sequence[str]) -> "IgnoreSet":
        rules: List[IgnoreRule] = []
        for raw in lines[:_MAX_PATTERNS]:
            rule = compile_rule(raw)
            if rule is not None:
                rules.append(rule)
        return cls(rules)

    @classmethod
    def from_file(cls, path: Path) -> "IgnoreSet":
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return cls(())
        return cls.from_lines(content.splitlines())

    def merged(self, other: "IgnoreSet") -> "IgnoreSet":
        return IgnoreSet(self._rules + other._rules)

    def matches(self, relative_path: str, is_directory: bool) -> bool:
        decision = False
        for rule in self._rules:
            if rule.directory_only and not is_directory:
                continue
            if rule.matcher.match(relative_path):
                decision = not rule.negated
        return decision
