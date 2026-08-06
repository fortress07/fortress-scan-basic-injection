from __future__ import annotations

from pathlib import Path, PurePath
from typing import Dict, Optional, Tuple

PYTHON = "python"
JAVASCRIPT = "javascript"
TYPESCRIPT = "typescript"
PHP = "php"
JAVA = "java"
RUBY = "ruby"
GO = "go"
CSHARP = "csharp"
SHELL = "shell"
MANIFEST = "manifest"

_EXTENSION_MAP: Dict[str, str] = {
    ".py": PYTHON,
    ".pyw": PYTHON,
    ".pyi": PYTHON,
    ".js": JAVASCRIPT,
    ".mjs": JAVASCRIPT,
    ".cjs": JAVASCRIPT,
    ".jsx": JAVASCRIPT,
    ".ts": TYPESCRIPT,
    ".tsx": TYPESCRIPT,
    ".mts": TYPESCRIPT,
    ".cts": TYPESCRIPT,
    ".vue": JAVASCRIPT,
    ".svelte": JAVASCRIPT,
    ".php": PHP,
    ".php3": PHP,
    ".php4": PHP,
    ".php5": PHP,
    ".php7": PHP,
    ".phtml": PHP,
    ".inc": PHP,
    ".java": JAVA,
    ".jsp": JAVA,
    ".jspx": JAVA,
    ".kt": JAVA,
    ".kts": JAVA,
    ".groovy": JAVA,
    ".scala": JAVA,
    ".rb": RUBY,
    ".rake": RUBY,
    ".erb": RUBY,
    ".go": GO,
    ".cs": CSHARP,
    ".cshtml": CSHARP,
    ".aspx": CSHARP,
    ".ashx": CSHARP,
    ".sh": SHELL,
    ".bash": SHELL,
    ".zsh": SHELL,
    ".ksh": SHELL,
}

_FILENAME_MAP: Dict[str, str] = {
    "package.json": MANIFEST,
    "composer.json": MANIFEST,
    "Gemfile": RUBY,
    "Rakefile": RUBY,
    "Dockerfile": SHELL,
    "Makefile": SHELL,
}

_SHEBANG_MAP: Tuple[Tuple[str, str], ...] = (
    ("python", PYTHON),
    ("node", JAVASCRIPT),
    ("php", PHP),
    ("ruby", RUBY),
    ("bash", SHELL),
    ("zsh", SHELL),
    ("sh", SHELL),
)

_MAX_FILENAME_LENGTH = 255


def is_scannable_name(name: str) -> bool:
    if not name or len(name) > _MAX_FILENAME_LENGTH:
        return False
    return not name.startswith(".") or name in _FILENAME_MAP


def detect_language(path: Path, name: Optional[str] = None) -> Optional[str]:
    """`name` tách tên hiển thị khỏi tệp thật trên đĩa.

    Khi đi theo một liên kết, cái tên nằm trong cây được quét là tên của
    liên kết, còn nội dung nằm ở đích -- nên ngôn ngữ đoán theo tên liên kết
    nhưng shebang phải đọc từ đích.
    """
    label = name or path.name
    mapped = _FILENAME_MAP.get(label)
    if mapped is not None:
        return mapped
    suffix = PurePath(label).suffix.lower()
    mapped = _EXTENSION_MAP.get(suffix)
    if mapped is not None:
        return mapped
    if suffix == "":
        return _detect_by_shebang(path)
    return None


def _detect_by_shebang(path: Path) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            first = handle.readline(256)
    except OSError:
        return None
    if not first.startswith(b"#!"):
        return None
    try:
        header = first.decode("utf-8", errors="replace").lower()
    except Exception:
        return None
    for token, language in _SHEBANG_MAP:
        if token in header:
            return language
    return None


def display_name(language: str) -> str:
    return {
        PYTHON: "Python",
        JAVASCRIPT: "JavaScript",
        TYPESCRIPT: "TypeScript",
        PHP: "PHP",
        JAVA: "Java/JVM",
        RUBY: "Ruby",
        GO: "Go",
        CSHARP: "C#",
        SHELL: "Shell",
        MANIFEST: "Package manifest",
    }.get(language, language)
