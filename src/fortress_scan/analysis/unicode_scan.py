from __future__ import annotations

import re
from typing import List, Set

from ..core.budget import Budget
from ..core.model import Finding, StepKind
from ..security.text import (
    BIDI_CONTROLS,
    INVISIBLE_CHARS,
    code_point_name,
    find_code_points,
    script_of,
)
from .base import Analyzer, AnalysisUnit, FindingBuilder

_IDENTIFIER = re.compile(r"[^\W\d]\w{1,80}", re.UNICODE)
_MAX_IDENTIFIER_REPORTS = 20
_CONFUSABLE_SCRIPTS = frozenset({"LATIN", "CYRILLIC", "GREEK", "ARMENIAN"})


class UnicodeAnalyzer(Analyzer):
    name = "unicode-integrity"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        builder = FindingBuilder(unit)
        source = unit.source
        if source.isascii():
            return []

        for line, column, char in find_code_points(source, BIDI_CONTROLS):
            budget.spend()
            builder.add(
                rule_id="FSB-UNI-001",
                line=line,
                column=column,
                symbol=code_point_name(char),
                message=(
                    "%s (U+%04X) đảo thứ tự hiển thị của dòng này mà không đổi cách trình "
                    "biên dịch đọc nó" % (code_point_name(char), ord(char))
                ),
                trace=(
                    builder.step(
                        StepKind.SINK, line, column, "ký tự điều khiển hai chiều"
                    ),
                ),
            )

        for line, column, char in find_code_points(source, INVISIBLE_CHARS):
            budget.spend()
            builder.add(
                rule_id="FSB-UNI-002",
                line=line,
                column=column,
                symbol=code_point_name(char),
                message="%s (U+%04X) vô hình trong trình soạn thảo nhưng vẫn có ý nghĩa với trình biên dịch"
                % (code_point_name(char), ord(char)),
                trace=(
                    builder.step(StepKind.SINK, line, column, "ký tự vô hình"),
                ),
            )

        self._check_identifiers(unit, builder, budget)
        return builder.findings

    def _check_identifiers(
        self, unit: AnalysisUnit, builder: FindingBuilder, budget: Budget
    ) -> None:
        reported: Set[str] = set()
        for index, text in enumerate(unit.lines, start=1):
            if text.isascii():
                continue
            budget.spend()
            for match in _IDENTIFIER.finditer(text):
                token = match.group(0)
                if token.isascii() or token in reported:
                    continue
                scripts = {script_of(char) for char in token if char.isalpha()}
                scripts &= _CONFUSABLE_SCRIPTS
                if len(scripts) < 2:
                    continue
                reported.add(token)
                builder.add(
                    rule_id="FSB-UNI-003",
                    line=index,
                    column=match.start(),
                    symbol=token,
                    message="token %r trộn lẫn bảng chữ %s, các bảng này có những chữ trông giống hệt nhau"
                    % (token, " và ".join(sorted(scripts))),
                    trace=(
                        builder.step(
                            StepKind.SINK, index, match.start(), "token trộn nhiều hệ chữ"
                        ),
                    ),
                )
                if len(reported) >= _MAX_IDENTIFIER_REPORTS:
                    return
