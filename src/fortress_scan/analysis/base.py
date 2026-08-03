from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from ..core.budget import Budget
from ..core.config import Config
from ..core.model import Confidence, Finding, Severity, StepKind, TraceStep
from ..core.registry import get_rule
from ..security.redaction import redact
from ..security.text import make_snippet


@dataclass(frozen=True)
class AnalysisUnit:
    relative_path: str
    language: str
    source: str
    lines: Tuple[str, ...]
    config: Config
    degraded_encoding: bool = False


class FindingBuilder:
    def __init__(self, unit: AnalysisUnit) -> None:
        self._unit = unit
        self._findings: Dict[Tuple[str, int, int, str], Finding] = {}

    def snippet_for(self, line: int) -> str:
        if 1 <= line <= len(self._unit.lines):
            return make_snippet(redact(self._unit.lines[line - 1]))
        return ""

    def step(
        self,
        kind: StepKind,
        line: int,
        column: int,
        label: str,
        code: str = "",
    ) -> TraceStep:
        return TraceStep(
            kind=kind,
            line=line,
            column=column,
            label=make_snippet(label, 160),
            code=make_snippet(redact(code), 160) if code else self.snippet_for(line),
        )

    def add(
        self,
        rule_id: str,
        line: int,
        column: int,
        symbol: str,
        message: str,
        end_line: Optional[int] = None,
        end_column: Optional[int] = None,
        severity: Optional[Severity] = None,
        confidence: Optional[Confidence] = None,
        trace: Sequence[TraceStep] = (),
        tags: Sequence[str] = (),
    ) -> None:
        if not self._unit.config.rule_enabled(rule_id):
            return
        rule = get_rule(rule_id)
        resolved_severity = severity or rule.severity
        resolved_confidence = confidence or rule.confidence
        if resolved_severity < self._unit.config.min_severity:
            return
        if resolved_confidence < self._unit.config.min_confidence:
            return

        safe_line = max(1, line)
        key = (rule_id, safe_line, max(0, column), symbol)
        finding = Finding(
            rule_id=rule.id,
            title=rule.title,
            message=make_snippet(message, 400),
            severity=resolved_severity,
            confidence=resolved_confidence,
            category=rule.category,
            path=self._unit.relative_path,
            line=safe_line,
            column=max(0, column),
            end_line=max(safe_line, end_line or safe_line),
            end_column=max(0, end_column if end_column is not None else column),
            language=self._unit.language,
            snippet=self.snippet_for(safe_line),
            symbol=make_snippet(symbol, 120),
            cwe=rule.cwe,
            owasp=rule.owasp,
            remediation=rule.remediation,
            references=rule.references,
            trace=tuple(trace),
            tags=tuple(tags),
        )
        existing = self._findings.get(key)
        if existing is None or finding.sort_key < existing.sort_key:
            self._findings[key] = finding

    @property
    def findings(self) -> List[Finding]:
        best: Dict[Tuple[int, int, str], Finding] = {}
        for finding in self._findings.values():
            key = (finding.line, finding.column, finding.category.value)
            current = best.get(key)
            if current is None or finding.sort_key < current.sort_key:
                best[key] = finding
        return sorted(best.values(), key=lambda item: item.sort_key)


class Analyzer:
    name = "analyzer"
    languages: Tuple[str, ...] = ()

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        raise NotImplementedError
