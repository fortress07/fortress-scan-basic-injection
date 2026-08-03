from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from .model import Confidence, Severity, parse_confidence, parse_severity

DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_FILES = 50_000
DEFAULT_NODE_BUDGET = 400_000
DEFAULT_TOKEN_BUDGET = 400_000
DEFAULT_FILE_SECONDS = 10.0

CONFIG_FILENAMES: Tuple[str, ...] = (".fortress-scan.json", "fortress-scan.json")

DEFAULT_EXCLUDED_DIRECTORIES: Tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    "virtualenv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
    "bower_components",
    "jspm_packages",
    "vendor",
    "site-packages",
    "dist-packages",
    "build",
    "dist",
    "out",
    "target",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".gradle",
    ".idea",
    ".vscode",
    "coverage",
    "htmlcov",
    "Pods",
    ".terraform",
    ".serverless",
    "bin",
    "obj",
)


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    min_severity: Severity = Severity.LOW
    min_confidence: Confidence = Confidence.LOW
    fail_on: Severity = Severity.MEDIUM
    excluded_directories: Tuple[str, ...] = DEFAULT_EXCLUDED_DIRECTORIES
    exclude_patterns: Tuple[str, ...] = ()
    include_patterns: Tuple[str, ...] = ()
    disabled_rules: Tuple[str, ...] = ()
    enabled_rules: Tuple[str, ...] = ()
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_files: int = DEFAULT_MAX_FILES
    node_budget: int = DEFAULT_NODE_BUDGET
    token_budget: int = DEFAULT_TOKEN_BUDGET
    file_timeout_seconds: float = DEFAULT_FILE_SECONDS
    follow_symlinks: bool = False
    honor_inline_suppressions: bool = True
    respect_ignore_files: bool = True
    respect_vcs_ignore: bool = True
    include_low_signal_sources: bool = False
    jobs: int = 1

    def with_overrides(self, **overrides: Any) -> "Config":
        cleaned = {key: value for key, value in overrides.items() if value is not None}
        return replace(self, **cleaned) if cleaned else self

    def rule_enabled(self, rule_id: str) -> bool:
        if self.enabled_rules and rule_id not in self.enabled_rules:
            return False
        return rule_id not in self.disabled_rules


_ALLOWED_KEYS = frozenset(
    (
        "min_severity",
        "min_confidence",
        "fail_on",
        "excluded_directories",
        "exclude",
        "include",
        "disabled_rules",
        "enabled_rules",
        "max_file_bytes",
        "max_total_bytes",
        "max_files",
        "node_budget",
        "token_budget",
        "file_timeout_seconds",
        "follow_symlinks",
        "honor_inline_suppressions",
        "respect_ignore_files",
        "respect_vcs_ignore",
        "include_low_signal_sources",
        "jobs",
    )
)

_INT_KEYS = frozenset(
    (
        "max_file_bytes",
        "max_total_bytes",
        "max_files",
        "node_budget",
        "token_budget",
        "jobs",
    )
)

_BOOL_KEYS = frozenset(
    (
        "follow_symlinks",
        "honor_inline_suppressions",
        "respect_ignore_files",
        "respect_vcs_ignore",
        "include_low_signal_sources",
    )
)

_LIST_KEYS = frozenset(
    (
        "excluded_directories",
        "exclude",
        "include",
        "disabled_rules",
        "enabled_rules",
    )
)

_MAX_CONFIG_BYTES = 256 * 1024


def find_config_file(start: Path) -> Optional[Path]:
    base = start if start.is_dir() else start.parent
    for name in CONFIG_FILENAMES:
        candidate = base / name
        if candidate.is_file():
            return candidate
    return None


def load_config_file(path: Path) -> Dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ConfigError("không đọc được thông tin tệp cấu hình %s" % path) from exc
    if size > _MAX_CONFIG_BYTES:
        raise ConfigError("tệp cấu hình lớn bất thường: %s" % path)
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError("không đọc được tệp cấu hình %s" % path) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ConfigError("tệp cấu hình %s không phải JSON hợp lệ: %s" % (path, exc.msg)) from exc
    if not isinstance(data, dict):
        raise ConfigError("tệp cấu hình %s phải chứa một object JSON" % path)
    return data


def build_config(data: Dict[str, Any], base: Optional[Config] = None) -> Config:
    config = base or Config()
    unknown = sorted(set(data) - _ALLOWED_KEYS)
    if unknown:
        raise ConfigError("khóa cấu hình không hợp lệ: %s" % ", ".join(unknown))

    overrides: Dict[str, Any] = {}
    for key, value in data.items():
        if key in _INT_KEYS:
            overrides[key] = _coerce_int(key, value)
        elif key in _BOOL_KEYS:
            overrides[key] = _coerce_bool(key, value)
        elif key in _LIST_KEYS:
            items = _coerce_str_list(key, value)
            if key == "exclude":
                overrides["exclude_patterns"] = items
            elif key == "include":
                overrides["include_patterns"] = items
            else:
                overrides[key] = items
        elif key == "file_timeout_seconds":
            overrides[key] = _coerce_float(key, value)
        elif key in ("min_severity", "fail_on"):
            overrides[key] = parse_severity(_coerce_str(key, value))
        elif key == "min_confidence":
            overrides[key] = parse_confidence(_coerce_str(key, value))

    return config.with_overrides(**overrides)


def _coerce_int(key: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("khóa cấu hình %r phải là số nguyên" % key)
    if value <= 0:
        raise ConfigError("khóa cấu hình %r phải là số dương" % key)
    return value


def _coerce_float(key: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError("khóa cấu hình %r phải là một số" % key)
    if value <= 0:
        raise ConfigError("khóa cấu hình %r phải là số dương" % key)
    return float(value)


def _coerce_bool(key: str, value: Any) -> bool:
    if not isinstance(value, bool):
        raise ConfigError("khóa cấu hình %r phải là true hoặc false" % key)
    return value


def _coerce_str(key: str, value: Any) -> str:
    if not isinstance(value, str):
        raise ConfigError("khóa cấu hình %r phải là chuỗi" % key)
    return value


def _coerce_str_list(key: str, value: Any) -> Tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError("khóa cấu hình %r phải là danh sách chuỗi" % key)
    if len(value) > 5000:
        raise ConfigError("khóa cấu hình %r có quá nhiều phần tử" % key)
    return tuple(value)
