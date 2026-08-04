from __future__ import annotations

from .core.model import (
    Category,
    Confidence,
    Finding,
    ScanError,
    ScanResult,
    ScanStats,
    Severity,
    StepKind,
    TraceStep,
)

__version__ = "0.1.0"
__author__ = "fortress07"
__license__ = "MIT"

__all__ = [
    "Category",
    "Confidence",
    "Finding",
    "ScanError",
    "ScanResult",
    "ScanStats",
    "Severity",
    "StepKind",
    "TraceStep",
    "scan",
    "scan_source",
    "__version__",
    "__author__",
    "__license__",
]


def scan(*args, **kwargs):
    from .core.engine import scan as _scan

    return _scan(*args, **kwargs)


def scan_source(*args, **kwargs):
    from .core.engine import scan_source as _scan_source

    return _scan_source(*args, **kwargs)
