from __future__ import annotations

import unicodedata
from typing import Iterable, Tuple

BIDI_CODE_POINTS: Tuple[int, ...] = (
    0x202A,
    0x202B,
    0x202C,
    0x202D,
    0x202E,
    0x2066,
    0x2067,
    0x2068,
    0x2069,
    0x200E,
    0x200F,
    0x061C,
)

INVISIBLE_CODE_POINTS: Tuple[int, ...] = (
    0x00AD,
    0x180E,
    0x200B,
    0x200C,
    0x200D,
    0x2060,
    0x2061,
    0x2062,
    0x2063,
    0x2064,
    0xFEFF,
    0x115F,
    0x1160,
    0x3164,
    0xFFA0,
)

BIDI_CONTROLS: Tuple[str, ...] = tuple(chr(point) for point in BIDI_CODE_POINTS)
INVISIBLE_CHARS: Tuple[str, ...] = tuple(chr(point) for point in INVISIBLE_CODE_POINTS)

_BIDI_SET = frozenset(BIDI_CONTROLS)
_INVISIBLE_SET = frozenset(INVISIBLE_CHARS)

_SAFE_WHITESPACE = frozenset("\t")

MAX_SNIPPET_LENGTH = 240


def _is_unsafe(char: str) -> bool:
    code = ord(char)
    if char in _SAFE_WHITESPACE:
        return False
    if code < 0x20 or code == 0x7F:
        return True
    if 0x80 <= code <= 0x9F:
        return True
    if char in _BIDI_SET or char in _INVISIBLE_SET:
        return True
    if unicodedata.category(char) in ("Cf", "Co", "Cs", "Cn"):
        return True
    return False


def _escape(char: str) -> str:
    code = ord(char)
    if code <= 0xFF:
        return "\\x%02x" % code
    if code <= 0xFFFF:
        return "\\u%04x" % code
    return "\\U%08x" % code


def neutralize(value: str) -> str:
    if not value:
        return ""
    if not any(_is_unsafe(char) for char in value):
        return value
    return "".join(_escape(char) if _is_unsafe(char) else char for char in value)


def make_snippet(value: str, max_length: int = MAX_SNIPPET_LENGTH) -> str:
    collapsed = value.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").strip()
    safe = neutralize(collapsed)
    if len(safe) > max_length:
        return safe[: max_length - 3].rstrip() + "..."
    return safe


def display_path(value: str) -> str:
    return neutralize(value.replace("\\", "/"))


def find_code_points(text: str, wanted: Iterable[str]) -> Tuple[Tuple[int, int, str], ...]:
    targets = frozenset(wanted)
    if not targets:
        return ()
    hits = []
    line = 1
    column = 1
    for char in text:
        if char in targets:
            hits.append((line, column, char))
        if char == "\n":
            line += 1
            column = 1
        else:
            column += 1
    return tuple(hits)


def code_point_name(char: str) -> str:
    try:
        return unicodedata.name(char)
    except ValueError:
        return "U+%04X" % ord(char)


def script_of(char: str) -> str:
    if char.isascii():
        return "LATIN"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return ""
    return name.split(" ", 1)[0]
