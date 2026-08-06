from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any, Dict, List, Optional, Tuple


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()


class Confidence(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CERTAIN = 40

    @property
    def label(self) -> str:
        return self.name.lower()


class Category(str, Enum):
    CODE_EXECUTION = "code-execution"
    COMMAND = "os-command"
    SQL = "sql"
    NOSQL = "nosql"
    LDAP = "ldap"
    XPATH = "xpath"
    TEMPLATE = "template"
    DESERIALIZATION = "deserialization"
    DYNAMIC_IMPORT = "dynamic-import"
    REFLECTION = "reflection"
    EXPRESSION_LANGUAGE = "expression-language"
    MARKUP = "markup"
    XML = "xml"
    UNICODE = "unicode"
    SUPPLY_CHAIN = "supply-chain"


class StepKind(str, Enum):
    SOURCE = "source"
    PROPAGATION = "propagation"
    SANITIZER = "sanitizer"
    CALL = "call"
    SINK = "sink"


_SEVERITY_BY_NAME = {item.name.lower(): item for item in Severity}
_CONFIDENCE_BY_NAME = {item.name.lower(): item for item in Confidence}


def parse_severity(value: str) -> Severity:
    key = str(value).strip().lower()
    if key not in _SEVERITY_BY_NAME:
        raise ValueError(
            "mức độ %r không hợp lệ (phải là một trong: %s)"
            % (value, ", ".join(sorted(_SEVERITY_BY_NAME)))
        )
    return _SEVERITY_BY_NAME[key]


def parse_confidence(value: str) -> Confidence:
    key = str(value).strip().lower()
    if key not in _CONFIDENCE_BY_NAME:
        raise ValueError(
            "độ tin cậy %r không hợp lệ (phải là một trong: %s)"
            % (value, ", ".join(sorted(_CONFIDENCE_BY_NAME)))
        )
    return _CONFIDENCE_BY_NAME[key]


@dataclass(frozen=True)
class TraceStep:
    kind: StepKind
    line: int
    column: int
    label: str
    code: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind.value,
            "line": self.line,
            "column": self.column,
            "label": self.label,
            "code": self.code,
        }


_WHITESPACE = re.compile(r"\s+")


def _normalize(text: str) -> str:
    return _WHITESPACE.sub(" ", text).strip()


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    message: str
    severity: Severity
    confidence: Confidence
    category: Category
    path: str
    line: int
    column: int
    end_line: int
    end_column: int
    language: str
    snippet: str = ""
    symbol: str = ""
    cwe: Tuple[str, ...] = ()
    owasp: Tuple[str, ...] = ()
    remediation: str = ""
    references: Tuple[str, ...] = ()
    trace: Tuple[TraceStep, ...] = ()
    tags: Tuple[str, ...] = ()

    @property
    def fingerprint(self) -> str:
        material = "\x1f".join(
            (
                self.rule_id,
                self.path.replace("\\", "/"),
                self.symbol,
                _normalize(self.snippet),
            )
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]

    @property
    def sort_key(self) -> Tuple[Any, ...]:
        return (
            -int(self.severity),
            -int(self.confidence),
            self.path.replace("\\", "/"),
            self.line,
            self.column,
            self.rule_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "message": self.message,
            "severity": self.severity.label,
            "confidence": self.confidence.label,
            "category": self.category.value,
            "path": self.path.replace("\\", "/"),
            "line": self.line,
            "column": self.column,
            "end_line": self.end_line,
            "end_column": self.end_column,
            "language": self.language,
            "snippet": self.snippet,
            "symbol": self.symbol,
            "cwe": list(self.cwe),
            "owasp": list(self.owasp),
            "remediation": self.remediation,
            "references": list(self.references),
            "trace": [step.to_dict() for step in self.trace],
            "tags": list(self.tags),
            "fingerprint": self.fingerprint,
        }


@dataclass
class ScanError:
    path: str
    reason: str
    detail: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"path": self.path.replace("\\", "/"), "reason": self.reason, "detail": self.detail}


@dataclass
class ScanNotice:
    """Một thứ đã làm hẹp phạm vi quét so với mặc định.

    Khác `ScanError` ở chỗ không có gì hỏng cả: lượt quét chạy đúng như được
    yêu cầu, chỉ là nó đã nhìn ít hơn -- vì tệp cấu hình trong cây được quét,
    vì liên kết bị bỏ qua, vì ngưỡng bị nâng lên. Một báo cáo "sạch" sinh ra
    từ những thứ đó phải nói được vì sao nó sạch, và phải nói ở MỌI định dạng
    chứ không riêng màn hình -- người đọc JSON hay SARIF cũng cần biết.
    """

    kind: str
    summary: str
    details: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind, "summary": self.summary, "details": list(self.details)}


@dataclass
class ScanStats:
    files_discovered: int = 0
    files_analyzed: int = 0
    files_skipped: int = 0
    bytes_analyzed: int = 0
    duration_seconds: float = 0.0
    languages: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "files_analyzed": self.files_analyzed,
            "files_skipped": self.files_skipped,
            "bytes_analyzed": self.bytes_analyzed,
            "duration_seconds": round(self.duration_seconds, 4),
            "languages": dict(sorted(self.languages.items())),
        }


@dataclass
class ScanResult:
    root: str
    findings: List[Finding] = field(default_factory=list)
    errors: List[ScanError] = field(default_factory=list)
    notices: List[ScanNotice] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    suppressed: int = 0
    baselined: int = 0

    def counts_by_severity(self) -> Dict[str, int]:
        counts = {item.label: 0 for item in Severity}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(finding.severity for finding in self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root": self.root.replace("\\", "/"),
            "findings": [finding.to_dict() for finding in self.findings],
            "errors": [error.to_dict() for error in self.errors],
            "notices": [notice.to_dict() for notice in self.notices],
            "stats": self.stats.to_dict(),
            "summary": {
                "total": len(self.findings),
                "by_severity": self.counts_by_severity(),
                "suppressed": self.suppressed,
                "baselined": self.baselined,
            },
        }
