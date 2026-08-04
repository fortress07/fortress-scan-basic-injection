from __future__ import annotations

import re
import unicodedata
from typing import FrozenSet, Iterable, List, Tuple

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

# str.splitlines() và nhiều trình soạn thảo, trình xem diff coi những ký tự này
# là xuống dòng; ast.parse và các lexer ở đây thì không. Chính khoảng chênh đó
# là thứ làm số dòng của hai bên lệch nhau.
AMBIGUOUS_LINE_BREAKS: FrozenSet[str] = frozenset(
    "\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
)

# C0 và C1 trừ tab, xuống dòng, về đầu dòng; cộng DEL và hai dấu tách dòng
# Unicode. Không ký tự nào ở đây có lý do chính đáng để nằm trong mã nguồn.
_CONTROL_PATTERN = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u2028\u2029]")

# unicodedata không đặt tên cho ký tự điều khiển C0/C1, nên tự đặt cho dễ đọc.
_CONTROL_NAMES = {
    "\x00": "NULL",
    "\x08": "BACKSPACE",
    "\x0b": "VERTICAL TAB",
    "\x0c": "FORM FEED",
    "\x1b": "ESCAPE",
    "\x1c": "FILE SEPARATOR",
    "\x1d": "GROUP SEPARATOR",
    "\x1e": "RECORD SEPARATOR",
    "\x1f": "UNIT SEPARATOR",
    "\x7f": "DELETE",
    "\x85": "NEXT LINE",
}

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
    # Zl/Zp là U+2028 và U+2029. Chúng không thuộc nhóm C nào nên từng lọt
    # nguyên vẹn ra báo cáo, dù JavaScript coi đây là ký tự kết thúc dòng thật
    # và nhiều trình kết xuất Markdown cũng ngắt dòng ở đó.
    if unicodedata.category(char) in ("Cf", "Co", "Cs", "Cn", "Zl", "Zp"):
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
    # Cắt trước khi escape. neutralize() ánh xạ từng ký tự và không bỏ ký tự
    # nào, nên max_length ký tự đầu vào chắc chắn dựng đủ max_length ký tự đầu
    # ra: kết quả không đổi, nhưng một dòng dài hàng chục nghìn ký tự không còn
    # bị escape trọn vẹn chỉ để vứt gần hết ngay sau đó.
    truncated = len(collapsed) > max_length
    safe = neutralize(collapsed[:max_length])
    if truncated or len(safe) > max_length:
        return safe[: max_length - 3].rstrip() + "..."
    return safe


def display_path(value: str) -> str:
    return neutralize(value.replace("\\", "/"))


def normalize_newlines(text: str) -> str:
    if "\r" not in text:
        return text
    return text.replace("\r\n", "\n").replace("\r", "\n")


def split_lines(text: str) -> Tuple[str, ...]:
    """Tách dòng chỉ theo "\\n", sau khi quy CRLF/CR về LF.

    Không dùng str.splitlines(): nó còn tách ở \\v, \\f, \\x1c-\\x1e, \\x85,
    U+2028 và U+2029, mà không bộ phân tích nào ở đây coi là xuống dòng --
    ast.parse, Tokenizer._line và find_code_points đều chỉ đếm "\\n". Một ký
    tự như vậy nhét trong comment sẽ làm lệch số phần tử của mảng dòng so với
    số dòng mà rule engine báo, khiến snippet hiển thị sai đoạn mã.
    """
    lines = normalize_newlines(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return tuple(lines)


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


def find_control_points(text: str, limit: int) -> Tuple[Tuple[int, int, str], ...]:
    """Định vị ký tự điều khiển, đếm dòng theo cùng quy ước "\\n" của find_code_points.

    Dừng ở `limit` kết quả để một tệp dày đặc ký tự điều khiển không tự biến
    thành hàng nghìn finding.
    """
    hits: List[Tuple[int, int, str]] = []
    line = 1
    line_start = 0
    cursor = 0
    for match in _CONTROL_PATTERN.finditer(text):
        position = match.start()
        crossed = text.count("\n", cursor, position)
        if crossed:
            line += crossed
            line_start = text.rindex("\n", cursor, position) + 1
        cursor = position
        hits.append((line, position - line_start + 1, match.group()))
        if len(hits) >= limit:
            break
    return tuple(hits)


def code_point_name(char: str) -> str:
    try:
        return unicodedata.name(char)
    except ValueError:
        return _CONTROL_NAMES.get(char) or "U+%04X" % ord(char)


def script_of(char: str) -> str:
    if char.isascii():
        return "LATIN"
    try:
        name = unicodedata.name(char)
    except ValueError:
        return ""
    return name.split(" ", 1)[0]
