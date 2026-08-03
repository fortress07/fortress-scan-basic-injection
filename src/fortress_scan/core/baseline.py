from __future__ import annotations

import json
from pathlib import Path
from typing import List, Sequence, Set, Tuple

from .model import Finding

BASELINE_VERSION = 1
_MAX_BASELINE_BYTES = 16 * 1024 * 1024


class BaselineError(Exception):
    pass


def load(path: Path) -> Set[str]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BaselineError("không đọc được tệp baseline %s" % path) from exc
    if size > _MAX_BASELINE_BYTES:
        raise BaselineError("tệp baseline lớn bất thường: %s" % path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BaselineError("tệp baseline %s không phải JSON hợp lệ" % path) from exc
    if not isinstance(document, dict):
        raise BaselineError("tệp baseline %s phải chứa một object JSON" % path)
    entries = document.get("fingerprints")
    if not isinstance(entries, list):
        raise BaselineError("tệp baseline %s thiếu mảng fingerprints" % path)
    return {item for item in entries if isinstance(item, str)}


def serialize(findings: Sequence[Finding]) -> str:
    payload = {
        "version": BASELINE_VERSION,
        "fingerprints": sorted({finding.fingerprint for finding in findings}),
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def apply(findings: Sequence[Finding], known: Set[str]) -> Tuple[List[Finding], int]:
    if not known:
        return list(findings), 0
    kept: List[Finding] = []
    removed = 0
    for finding in findings:
        if finding.fingerprint in known:
            removed += 1
        else:
            kept.append(finding)
    return kept, removed
