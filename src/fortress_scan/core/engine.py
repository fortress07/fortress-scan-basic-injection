from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Sequence, Set, Tuple

from ..analysis.base import AnalysisUnit
from ..analysis.generic.analyzer import GenericAnalyzer
from ..analysis.manifest import ManifestAnalyzer
from ..analysis.python.analyzer import PythonAnalyzer, UnparsableSource
from ..analysis.unicode_scan import UnicodeAnalyzer
from ..languages import MANIFEST, PYTHON
from ..security import paths as safe_paths
from . import baseline as baseline_module
from . import suppression as suppression_module
from .budget import Budget, BudgetExceeded
from .config import Config
from .discovery import Discovery, DiscoveredFile, FileChangedDuringScan, read_source
from .model import Finding, ScanError, ScanNotice, ScanResult, ScanStats

_PYTHON_ANALYZER = PythonAnalyzer()
_GENERIC_ANALYZER = GenericAnalyzer()
_UNICODE_ANALYZER = UnicodeAnalyzer()
_MANIFEST_ANALYZER = ManifestAnalyzer()

_MAX_FINDINGS = 20_000


def scan(
    target: str,
    config: Optional[Config] = None,
    baseline_fingerprints: Optional[Set[str]] = None,
    notices: Optional[Sequence[ScanNotice]] = None,
) -> ScanResult:
    settings = config or Config()
    root = safe_paths.resolve_root(target)
    started = time.monotonic()

    coverage_notices: List[ScanNotice] = list(notices or ())

    discovery = Discovery(root, settings)
    discovered = list(discovery.walk())

    stats = ScanStats(files_discovered=len(discovered))
    errors: List[ScanError] = list(discovery.errors)
    findings: List[Finding] = []
    suppressed = 0

    outcomes = _run(discovered, settings)
    for outcome in outcomes:
        if outcome.error is not None:
            errors.append(outcome.error)
        if outcome.analyzed:
            stats.files_analyzed += 1
            stats.bytes_analyzed += outcome.size
            stats.languages[outcome.language] = stats.languages.get(outcome.language, 0) + 1
        suppressed += outcome.suppressed
        findings.extend(outcome.findings)

    stats.files_skipped = discovery.skipped + (len(discovered) - stats.files_analyzed)

    # Bỏ qua liên kết là hành vi mặc định và đúng, nhưng nó vẫn là một mảng mã
    # chưa từng được soi. Nói ra, đừng để người đọc tự đoán từ một con số.
    if discovery.skipped_links:
        coverage_notices.append(
            ScanNotice(
                kind="links-skipped",
                summary=(
                    "đã bỏ qua %d liên kết; mã nằm sau chúng chưa được phân tích"
                    % discovery.skipped_links
                ),
                details=("bật --follow-symlinks để đi theo liên kết nằm trong thư mục quét",),
            )
        )

    findings.sort(key=lambda item: item.sort_key)
    if len(findings) > _MAX_FINDINGS:
        errors.append(
            ScanError(
                path=".",
                reason="finding-limit-reached",
                detail="đã cắt bớt còn %d phát hiện" % _MAX_FINDINGS,
            )
        )
        findings = findings[:_MAX_FINDINGS]

    baselined = 0
    if baseline_fingerprints:
        findings, baselined = baseline_module.apply(findings, baseline_fingerprints)

    stats.duration_seconds = time.monotonic() - started
    return ScanResult(
        root=str(root),
        findings=findings,
        errors=errors,
        notices=coverage_notices,
        stats=stats,
        suppressed=suppressed,
        baselined=baselined,
    )


def scan_source(
    source: str,
    language: str,
    relative_path: str = "<memory>",
    config: Optional[Config] = None,
) -> List[Finding]:
    settings = config or Config()
    unit = AnalysisUnit(
        relative_path=relative_path,
        language=language,
        source=source,
        config=settings,
    )
    findings, _ = _analyze_unit(unit, settings)
    if settings.honor_inline_suppressions:
        index = suppression_module.SuppressionIndex.from_lines(unit.lines)
        findings, _ = suppression_module.partition(findings, index)
    return sorted(findings, key=lambda item: item.sort_key)


class _Outcome:
    __slots__ = ("findings", "error", "analyzed", "size", "language", "suppressed")

    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.error: Optional[ScanError] = None
        self.analyzed = False
        self.size = 0
        self.language = ""
        self.suppressed = 0


def _run(discovered: Sequence[DiscoveredFile], config: Config) -> List[_Outcome]:
    if config.jobs <= 1 or len(discovered) < 4:
        return [_analyze_file(item, config) for item in discovered]
    workers = min(config.jobs, 32, len(discovered))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda item: _analyze_file(item, config), discovered))


def _analyze_file(discovered: DiscoveredFile, config: Config) -> _Outcome:
    outcome = _Outcome()
    outcome.language = discovered.language
    outcome.size = discovered.size
    try:
        source, degraded = read_source(
            discovered.path, discovered.language, discovered.identity
        )
    except FileChangedDuringScan:
        outcome.error = ScanError(
            path=discovered.relative,
            reason="file-changed-during-scan",
            detail="tệp bị thay thế sau khi được liệt kê nên không được phân tích",
        )
        return outcome
    except OSError as exc:
        outcome.error = ScanError(
            path=discovered.relative, reason="unreadable-file", detail=exc.strerror or ""
        )
        return outcome
    except MemoryError:
        outcome.error = ScanError(
            path=discovered.relative, reason="file-too-large", detail="không đủ bộ nhớ"
        )
        return outcome

    unit = AnalysisUnit(
        relative_path=discovered.relative,
        language=discovered.language,
        source=source,
        config=config,
        degraded_encoding=degraded,
    )
    try:
        findings, failure = _analyze_unit(unit, config)
    except RecursionError:
        outcome.error = ScanError(
            path=discovered.relative, reason="nesting-too-deep", detail="chạm giới hạn đệ quy"
        )
        return outcome

    if failure is not None:
        outcome.error = ScanError(
            path=discovered.relative, reason=failure[0], detail=failure[1][:200]
        )

    outcome.analyzed = True
    if config.honor_inline_suppressions:
        index = suppression_module.SuppressionIndex.from_lines(unit.lines)
        findings, outcome.suppressed = suppression_module.partition(findings, index)
    outcome.findings = findings
    return outcome


def _analyze_unit(
    unit: AnalysisUnit, config: Config
) -> Tuple[List[Finding], Optional[Tuple[str, str]]]:
    findings: List[Finding] = []
    failure: Optional[Tuple[str, str]] = None

    unicode_budget = Budget(config.node_budget, config.file_timeout_seconds)
    try:
        findings.extend(_UNICODE_ANALYZER.analyze(unit, unicode_budget))
    except BudgetExceeded:
        pass

    if unit.language == PYTHON:
        budget = Budget(config.node_budget, config.file_timeout_seconds)
        analyzer = _PYTHON_ANALYZER
    elif unit.language == MANIFEST:
        budget = Budget(config.node_budget, config.file_timeout_seconds)
        analyzer = _MANIFEST_ANALYZER
    else:
        budget = Budget(config.token_budget, config.file_timeout_seconds)
        analyzer = _GENERIC_ANALYZER

    try:
        findings.extend(analyzer.analyze(unit, budget))
    except UnparsableSource as exc:
        failure = ("parse-error", str(exc))
    except BudgetExceeded as exc:
        failure = ("budget-exceeded", str(exc))

    if failure is None and (budget.exhausted or unicode_budget.exhausted):
        failure = (
            "budget-exceeded",
            "tệp quá lớn hoặc quá phức tạp, phân tích chưa hoàn tất nên kết quả có thể thiếu",
        )

    return findings, failure
