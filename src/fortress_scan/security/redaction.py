from __future__ import annotations

import re
from typing import Pattern, Tuple

PLACEHOLDER = "[redacted]"

_PATTERNS: Tuple[Pattern[str], ...] = (
    re.compile(r"-----BEGIN[A-Z ]{0,40}PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,80}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,90}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,90}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,80}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,200}\.[A-Za-z0-9_\-]{10,200}\.[A-Za-z0-9_\-]{10,200}\b"),
    re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|"
        r"client[_-]?secret|auth)\b\s*[:=]\s*['\"]([^'\"\n]{4,120})['\"]"
    ),
    re.compile(
        r"(?i)\b(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*"
        r"([^\s'\";,)\]}]{8,120})"
    ),
    re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s/@]+:([^\s/@]{3,120})@"),
)


def redact(text: str) -> str:
    if not text:
        return ""
    result = text
    for pattern in _PATTERNS:
        result = _apply(pattern, result)
    return result


def _apply(pattern: Pattern[str], text: str) -> str:
    def _replace(match: "re.Match[str]") -> str:
        if pattern.groups == 0:
            return PLACEHOLDER
        whole = match.group(0)
        secret = match.group(1)
        if not secret:
            return whole
        start = match.start(1) - match.start(0)
        end = match.end(1) - match.start(0)
        return whole[:start] + PLACEHOLDER + whole[end:]

    return pattern.sub(_replace, text)
