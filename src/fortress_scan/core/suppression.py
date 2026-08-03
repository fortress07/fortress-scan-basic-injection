from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Sequence, Tuple

from .model import Finding

_DIRECTIVE = re.compile(
    r"(?:#|//|/\*|--|<!--)\s*fortress-scan\s*:\s*(ignore|ignore-next-line|ignore-file)"
    r"(?:\s*\[([A-Za-z0-9\-, ]{0,200})\])?"
    r"(?:\s*(?:--|:)\s*(?P<reason>[^\n*]{0,200}))?"
)

_MAX_LINES = 200_000


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
        found: List[Suppression] = []
        for index, text in enumerate(lines[:_MAX_LINES], start=1):
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
