from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Tuple

from ..core.budget import Budget
from ..core.model import Finding, StepKind
from .base import Analyzer, AnalysisUnit, FindingBuilder

_LIFECYCLE_KEYS = (
    "preinstall",
    "install",
    "postinstall",
    "preprepare",
    "prepare",
    "postprepare",
    "prepublish",
    "prepack",
    "postpack",
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "post-autoload-dump",
)

_FETCH = r"(?:curl|wget|iwr|Invoke-WebRequest|fetch)"
_INTERPRETER = r"(?:ba|z|k|da)?sh|python[23]?|perl|ruby|node|pwsh|powershell"

_FETCH_PIPE_EXECUTE = re.compile(
    r"(?is)\b%s\b[^|;&\n]{0,400}\|\s*(?:sudo\s+)?(?:%s)\b" % (_FETCH, _INTERPRETER)
)
_FETCH_THEN_EXECUTE = re.compile(
    r"(?is)\b%s\b[^;&\n]{0,400}(?:-o|-O|--output)\s*(\S+)[^\n]{0,200}[;&]{1,2}\s*"
    r"(?:sudo\s+)?(?:%s|\./)" % (_FETCH, _INTERPRETER)
)
_ENCODED_EXECUTE = re.compile(
    r"(?is)\b(?:base64\s+(?:-d|--decode)|atob|FromBase64String)\b[^\n]{0,200}\|\s*(?:%s)\b"
    % _INTERPRETER
)
_SHELL_INVOCATION = re.compile(
    r"(?is)\b(?:%s)\b\s+-c\b|\beval\b|\bnode\s+-e\b|\bpython[23]?\s+-c\b" % _INTERPRETER
)

_MAX_MANIFEST_BYTES = 2 * 1024 * 1024


class ManifestAnalyzer(Analyzer):
    name = "manifest-integrity"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        if len(unit.source) > _MAX_MANIFEST_BYTES:
            return []
        try:
            document = json.loads(unit.source)
        except (json.JSONDecodeError, RecursionError):
            return []
        if not isinstance(document, dict):
            return []

        builder = FindingBuilder(unit)
        for name, command in _lifecycle_commands(document):
            budget.spend()
            line = _locate(unit.lines, name)
            if _FETCH_PIPE_EXECUTE.search(command) or _ENCODED_EXECUTE.search(command):
                builder.add(
                    rule_id="FSB-SUP-001",
                    line=line,
                    column=0,
                    symbol=name,
                    message=(
                        "script vòng đời %s tải nội dung về rồi đẩy thẳng vào trình thông dịch" % name
                    ),
                    trace=(
                        builder.step(
                            StepKind.SINK, line, 0, "tải về và chạy trong %s" % name, command
                        ),
                    ),
                )
                continue
            if _FETCH_THEN_EXECUTE.search(command):
                builder.add(
                    rule_id="FSB-SUP-001",
                    line=line,
                    column=0,
                    symbol=name,
                    message=(
                        "script vòng đời %s tải một tệp về rồi thực thi nó" % name
                    ),
                    trace=(
                        builder.step(
                            StepKind.SINK, line, 0, "tải về rồi chạy trong %s" % name, command
                        ),
                    ),
                )
                continue
            if _SHELL_INVOCATION.search(command):
                builder.add(
                    rule_id="FSB-SUP-002",
                    line=line,
                    column=0,
                    symbol=name,
                    message="script vòng đời %s chạy một câu lệnh shell hoặc trình thông dịch nội dòng"
                    % name,
                    trace=(
                        builder.step(
                            StepKind.SINK, line, 0, "lệnh nội dòng trong %s" % name, command
                        ),
                    ),
                )
        return builder.findings


def _lifecycle_commands(document: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    scripts = document.get("scripts")
    if isinstance(scripts, dict):
        for name, command in scripts.items():
            if isinstance(name, str) and isinstance(command, str):
                if name in _LIFECYCLE_KEYS:
                    yield name, command[:4000]
    for key in _LIFECYCLE_KEYS:
        value = document.get(key)
        if isinstance(value, str):
            yield key, value[:4000]
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield key, item[:4000]


def _locate(lines: Tuple[str, ...], needle: str) -> int:
    marker = '"%s"' % needle
    for index, text in enumerate(lines, start=1):
        if marker in text:
            return index
    return 1
