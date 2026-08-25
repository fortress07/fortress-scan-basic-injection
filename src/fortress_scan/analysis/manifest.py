from __future__ import annotations

import json
import re
from itertools import islice
from typing import Any, Dict, Iterable, List, Optional, Tuple

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

_INTERPRETER = r"(?:ba|z|k|da)?sh|python[23]?|perl|ruby|node|pwsh|powershell"

# Ba phép dò dưới đây từng là ba regex, kiểu
# `\bcurl\b[^;&\n]{0,400}(?:-o|--output)...[;&]{1,2}`. Khi không khớp thì mỗi
# vị trí bắt đầu phải thử lại 400 x 200 tổ hợp độ dài: đo được 23 giây cho một
# chuỗi 200 KB toàn "curl -o ", nhân tiếp theo từng script vòng đời trong tệp.
#
# Chữa giống cách đã chữa looks_like_sql(): tìm từ khoá bằng alternation của
# chuỗi cố định, rồi soi một cửa sổ có chặn trên phía sau bằng str.find. Cả hai
# đều tuyến tính, và kết quả nhận dạng không đổi.
_FETCH_KEYWORD = re.compile(r"(?i)\b(?:curl|wget|iwr|Invoke-WebRequest|fetch)\b")
_DECODE_KEYWORD = re.compile(
    r"(?i)\b(?:base64\s{1,8}(?:-d|--decode)|atob|FromBase64String)\b"
)
# Neo vào đầu cửa sổ: chỗ gọi đã tự cắt cửa sổ nên không cần regex đi tìm.
_PIPED_INTERPRETER = re.compile(r"(?is)^\s{0,80}(?:sudo\s{1,8})?(?:%s)\b" % _INTERPRETER)
_CHAINED_INTERPRETER = re.compile(
    r"(?is)^\s{0,80}(?:sudo\s{1,8})?(?:%s|\./)" % _INTERPRETER
)
# Cờ (?i) đã bật nên `-o` phủ luôn `-O`; viết cả hai chỉ là một nhánh chết.
_OUTPUT_FLAG = re.compile(r"(?i)(?:^|\s)(?:-o|--output)(?=\s|$)")

# `python -c` và `node -e` không được viết lại ở đây: _INTERPRETER đã chứa cả
# hai cái tên, nên nhánh `<trình thông dịch> -c` phủ sẵn `python -c`. Nhắc lại
# chúng tạo ra nhánh không bao giờ được chọn -- đọc thì tưởng là thêm phạm vi,
# chạy thì chỉ thêm việc cho bộ máy regex.
_SHELL_INVOCATION = re.compile(
    r"(?is)\b(?:%s)\b\s{1,8}(?:-c|-e)\b|\beval\b" % _INTERPRETER
)

# Bao xa sau từ khoá tải về thì vẫn coi là "cùng một câu lệnh".
_PIPE_WINDOW = 400
_CHAIN_WINDOW = 400
_AFTER_OUTPUT_WINDOW = 200
_DECODE_WINDOW = 200


def _window(text: str, start: int, size: int, stop_at: str) -> str:
    """Đoạn ngay sau `start`, cắt ở ký tự phân tách câu lệnh đầu tiên."""
    chunk = text[start : start + size]
    cut = len(chunk)
    for char in stop_at:
        found = chunk.find(char)
        if found != -1 and found < cut:
            cut = found
    return chunk[:cut]


def fetch_pipes_into_interpreter(command: str) -> bool:
    """`curl ... | sh` -- tải về rồi đẩy thẳng vào trình thông dịch."""
    for match in _FETCH_KEYWORD.finditer(command):
        chunk = command[match.end() : match.end() + _PIPE_WINDOW]
        pipe = chunk.find("|")
        if pipe == -1:
            continue
        # Dấu ; & \n trước dấu ống dẫn nghĩa là đã sang câu lệnh khác.
        if any(char in chunk[:pipe] for char in ";&\n"):
            continue
        if _PIPED_INTERPRETER.match(chunk[pipe + 1 :]):
            return True
    return False


def fetch_then_executes(command: str) -> bool:
    """`curl -o x.sh ... ; sh x.sh` -- tải xuống tệp rồi chạy nó ở lệnh sau."""
    for match in _FETCH_KEYWORD.finditer(command):
        chunk = _window(command, match.end(), _CHAIN_WINDOW, ";&\n")
        flag = _OUTPUT_FLAG.search(chunk)
        if flag is None:
            continue
        tail = command[match.end() + flag.end() :][:_AFTER_OUTPUT_WINDOW]
        line = tail.split("\n", 1)[0]
        separator = _first_separator(line)
        if separator is None:
            continue
        if _CHAINED_INTERPRETER.match(line[separator:]):
            return True
    return False


def _first_separator(line: str) -> Optional[int]:
    """Vị trí ngay sau chuỗi `;` hoặc `&` đầu tiên ( tối đa hai ký tự )."""
    for index, char in enumerate(line):
        if char not in ";&":
            continue
        end = index + 1
        if end < len(line) and line[end] in ";&":
            end += 1
        return end
    return None


def decoded_pipes_into_interpreter(command: str) -> bool:
    """`base64 -d ... | sh` -- giải mã rồi đẩy thẳng vào trình thông dịch."""
    for match in _DECODE_KEYWORD.finditer(command):
        chunk = _window(command, match.end(), _DECODE_WINDOW, "\n")
        pipe = chunk.find("|")
        if pipe == -1:
            continue
        if _PIPED_INTERPRETER.match(chunk[pipe + 1 :]):
            return True
    return False


_MAX_MANIFEST_BYTES = 2 * 1024 * 1024

# Manifest thật có dưới hai chục script vòng đời và không script nào dài tới
# 4000 ký tự. Hai chặn trên này là thứ giữ cho chi phí phân tích một tệp
# không phụ thuộc vào việc người viết tệp đó muốn nó tốn bao nhiêu.
MAX_LIFECYCLE_COMMANDS = 200
MAX_COMMAND_LENGTH = 4000


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
            if fetch_pipes_into_interpreter(command) or decoded_pipes_into_interpreter(command):
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
            if fetch_then_executes(command):
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
    """Từng câu lệnh vòng đời, có chặn trên cả về độ dài lẫn SỐ LƯỢNG.

    Chặn độ dài ( 4000 ký tự ) đã có từ trước. Chặn số lượng thì chưa, và
    thiếu nó là một chỗ khuếch đại thật: một khoá vòng đời nhận được cả một
    danh sách, nên `{"postinstall": ["...4000 ký tự...", x500]}` gói gọn trong
    2 MB mà bắt bộ dò làm việc gấp 500 lần. Đo được 3,2 giây cho một tệp -- và
    con số đó nhân tiếp với số package.json trong một kho monorepo.

    Manifest thật có dưới hai chục script vòng đời; vượt xa mức này thì phần
    dư không còn là thứ ai đó vô tình viết ra.
    """
    # islice trên một generator là lười: nó ngừng KÉO chứ không lọc sau khi
    # đã tính, nên phần dư của một danh sách khổng lồ không bao giờ được chạm
    # tới. Tách chặn trên ra khỏi phần đi tìm cũng giữ cho mỗi hàm chỉ làm
    # đúng một việc.
    return islice(_declared_lifecycle_commands(document), MAX_LIFECYCLE_COMMANDS)


def _declared_lifecycle_commands(document: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """Hai chỗ khai báo script vòng đời, và chúng có hình dạng khác hẳn nhau.

    npm gom tất cả vào một object `scripts`; Composer đặt thẳng ở cấp gốc và
    cho phép một khoá mang cả một danh sách. Tách làm hai hàm vì gộp lại thì
    một vòng lặp phải mang cả hai hình dạng cùng lúc, và chỗ rẽ nhánh dày đặc
    đó chính là nơi hạn mức số lệnh từng bị bỏ quên.
    """
    for item in _script_object_commands(document):
        yield item
    for item in _top_level_commands(document):
        yield item


def _script_object_commands(document: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """Kiểu npm: `{"scripts": {"postinstall": "..."}}`."""
    scripts = document.get("scripts")
    if not isinstance(scripts, dict):
        return
    for name, command in scripts.items():
        if not isinstance(name, str) or not isinstance(command, str):
            continue
        if name in _LIFECYCLE_KEYS:
            yield name, command[:MAX_COMMAND_LENGTH]


def _top_level_commands(document: Dict[str, Any]) -> Iterable[Tuple[str, str]]:
    """Kiểu Composer: khoá ở cấp gốc, giá trị là chuỗi hoặc cả một danh sách."""
    for key in _LIFECYCLE_KEYS:
        value = document.get(key)
        if isinstance(value, str):
            yield key, value[:MAX_COMMAND_LENGTH]
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    yield key, item[:MAX_COMMAND_LENGTH]


def _locate(lines: Tuple[str, ...], needle: str) -> int:
    marker = '"%s"' % needle
    for index, text in enumerate(lines, start=1):
        if marker in text:
            return index
    return 1
