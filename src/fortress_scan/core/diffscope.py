"""Giới hạn báo cáo về đúng những dòng vừa thay đổi, đọc từ một unified diff.

Đây là thứ quyết định một bộ dò tĩnh có sống được trong CI hay không. Bật nó
trên một repo có sẵn 400 phát hiện cũ thì mọi pull request đều đỏ vì nợ của
người khác, và cả đội tắt luôn cái cổng. Cái cần biết là: pull request NÀY có
thêm lỗ hổng nào không.

Công cụ không tự chạy git. Nó đọc một patch mà người dùng đưa vào::

    git diff --unified=0 origin/main... > changes.patch
    fortress-scan . --diff changes.patch

Cách này giữ đúng lời hứa của công cụ -- không sinh tiến trình con, không
chạm vào mạng, không có đường nào để tên nhánh hay tên tệp trong repo bị quét
biến thành đối số của một lệnh. Patch chỉ là văn bản, và mọi hạn mức ở đây
coi nó là văn bản KHÔNG TIN CẬY.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

MAX_PATCH_BYTES = 8 * 1024 * 1024
MAX_PATHS = 20_000
MAX_RANGES_PER_PATH = 20_000
# Tổng số dòng thay đổi được giữ lại, tính trên toàn bộ patch. Hạn mức này là
# thứ chặn bộ nhớ thật: MAX_PATHS nhân MAX_RANGES_PER_PATH cho một con số
# không ai muốn cấp phát, còn đây là trần cứng cho cả hai. Một pull request
# đổi 200.000 dòng đã là ngoài mọi thực tế, và vượt qua nó thì công cụ nói ra
# chứ không im lặng coi phần còn lại là "không đổi".
MAX_LINES = 200_000

# Thân hunk phải đếm theo CẢ HAI phía: dòng bị xoá chỉ tiêu tốn hạn mức của
# bản cũ, dòng thêm mới chỉ tiêu tốn hạn mức của bản mới. Đếm một phía thôi
# thì `@@ -30,2 +33,1 @@` ( xoá hai dòng, thêm một ) kết thúc ngay sau hai
# dòng `-`, và đúng cái dòng `+` cần bắt bị bỏ lại ngoài hunk.
_HUNK = re.compile(r"^@@+ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MAX_LINE_NUMBER = 1 << 31

_PATH_PREFIXES: Tuple[str, ...] = ("a/", "b/", "i/", "w/", "c/", "o/")


class DiffError(Exception):
    pass


def _strip_prefix(raw: str) -> Optional[str]:
    """Bỏ tiền tố kiểu git khỏi đường dẫn trong patch; None nếu không dùng được.

    Đường dẫn trong patch do người khác viết. Một mục trỏ tới /dev/null là tệp
    bị xoá ( không còn gì để quét ), còn ".." hay đường dẫn tuyệt đối thì không
    có nghĩa nào trong hệ toạ độ "tương đối so với gốc quét" -- nhận chúng vào
    chỉ tạo ra một bảng khoá không bao giờ khớp, hoặc tệ hơn là khớp nhầm.
    """
    text = raw.strip()
    if not text or text == "/dev/null":
        return None
    # Một số bộ sinh diff gắn thêm dấu thời gian sau một dấu tab.
    text = text.split("\t", 1)[0].strip()
    if text.startswith(chr(34)):
        # Git trích dẫn tên tệp có ký tự đặc biệt. Không giải mã escape ở đây:
        # đoán sai một dấu chéo ngược là khớp nhầm sang tệp khác, còn bỏ qua
        # thì chỉ mất phần lọc cho riêng tệp đó -- hướng an toàn là bỏ qua.
        return None
    for prefix in _PATH_PREFIXES:
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    text = _normalize(text)
    if not text or text.startswith("/") or ".." in text.split("/"):
        return None
    if len(text) > 1 and text[1] == ":":
        # Đường dẫn tuyệt đối kiểu Windows.
        return None
    return text


def _merge(ranges: Sequence[Tuple[int, int]]) -> Tuple[Tuple[int, int], ...]:
    if not ranges:
        return ()
    ordered = sorted(ranges)
    merged: List[Tuple[int, int]] = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            if end > last_end:
                merged[-1] = (last_start, end)
        else:
            merged.append((start, end))
    return tuple(merged)


def _normalize(path: str) -> str:
    text = path.replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


class ChangedLines:
    """Bảng "tệp -> khoảng dòng đã đổi", tra theo khoảng chứ không theo từng dòng."""

    __slots__ = ("_by_path", "_starts", "paths", "line_count", "truncated")

    def __init__(
        self, by_path: Dict[str, Tuple[Tuple[int, int], ...]], truncated: bool = False
    ) -> None:
        self._by_path = by_path
        # Mốc đầu của từng khoảng, tách riêng để tra bằng bisect. Quét tuyến
        # tính thì mỗi phát hiện phải duyệt hết bảng khoảng của tệp nó thuộc
        # về, và với một patch lớn thì chính công cụ tự làm mình chậm lại theo
        # cấp số nhân trên đúng dữ liệu mà người ngoài đưa vào.
        self._starts: Dict[str, Tuple[int, ...]] = {
            path: tuple(start for start, _ in ranges) for path, ranges in by_path.items()
        }
        self.paths: FrozenSet[str] = frozenset(by_path)
        self.line_count = sum(
            end - start + 1 for ranges in by_path.values() for start, end in ranges
        )
        self.truncated = truncated

    def __bool__(self) -> bool:
        # Một patch không đổi dòng nào vẫn là một bộ lọc CÓ HIỆU LỰC ( kết quả
        # phải rỗng ), nên đối tượng này không bao giờ được rơi vào falsy: chỗ
        # gọi hay viết `if config.changed_lines:` để hỏi "có dùng patch không".
        return True

    def touches(self, path: str, lines: Iterable[int]) -> bool:
        key = _normalize(path)
        ranges = self._by_path.get(key)
        if not ranges:
            return False
        starts = self._starts[key]
        for line in lines:
            # Khoảng đã gộp và đã sắp xếp nên chỉ có đúng một ứng viên: khoảng
            # cuối cùng bắt đầu trước hoặc đúng tại `line`.
            index = bisect_right(starts, line) - 1
            if index >= 0 and line <= ranges[index][1]:
                return True
        return False

    def ranges_for(self, path: str) -> Tuple[Tuple[int, int], ...]:
        return self._by_path.get(_normalize(path), ())


def parse_patch(text: str) -> ChangedLines:
    """Đọc unified diff, giữ những dòng CÓ MẶT trong bản mới.

    Chỉ dòng thêm mới được ghi nhận: dòng ngữ cảnh không đổi, còn dòng bị xoá
    không tồn tại trong bản mới nên không có toạ độ để một phát hiện trỏ tới.
    Với --unified=0 thì hai tập này trùng nhau; với -U3 mặc định thì cách làm
    này vẫn đúng, chỉ hẹp hơn -- và hẹp là hướng đúng cho một cổng CI.
    """
    if len(text) > MAX_PATCH_BYTES:
        raise DiffError("tệp patch lớn bất thường (giới hạn %d byte)" % MAX_PATCH_BYTES)
    reader = _PatchReader()
    for raw in text.splitlines():
        reader.feed(raw)
    return reader.result()


class _PatchReader:
    """Máy trạng thái đọc unified diff, mỗi lần một dòng.

    Tách khỏi `parse_patch` vì cùng một vòng lặp trước đây phải mang bốn biến
    trạng thái ( tệp hiện tại, số dòng bản mới, hạn mức còn lại của hai phía )
    xuyên qua chín nhánh rẽ. Đọc thì rối, mà sửa thì dễ chạm nhầm nhánh khác:
    chính chỗ này từng có lỗi đếm hunk chỉ theo một phía, và nó nấp được lâu
    đúng vì không nhìn ra được ranh giới giữa "dòng tiêu đề" và "dòng thân".

    Cắt theo đúng ranh giới đó: `feed` phân loại dòng, ba phương thức còn lại
    lo ba loại. Hành vi giữ nguyên từng chi tiết -- bộ 23 kiểm tra của
    tests/test_diff_scope.py là thứ chứng minh điều đó.
    """

    __slots__ = ("_collected", "_current", "_new_line", "_old_left", "_new_left",
                 "_truncated", "_total")

    def __init__(self) -> None:
        self._collected: Dict[str, List[Tuple[int, int]]] = {}
        self._current: Optional[str] = None
        self._new_line = 0
        self._old_left = 0
        self._new_left = 0
        self._truncated = False
        self._total = 0

    def result(self) -> ChangedLines:
        merged = {path: _merge(ranges) for path, ranges in self._collected.items()}
        return ChangedLines(merged, self._truncated)

    def feed(self, raw: str) -> None:
        if raw.startswith("diff "):
            self._current = None
            self._close_hunk()
        elif raw.startswith("+++ "):
            self._current = _strip_prefix(raw[4:])
            self._close_hunk()
        elif raw.startswith(("--- ", "index ")):
            return
        else:
            match = _HUNK.match(raw)
            if match is not None:
                self._open_hunk(match)
            elif self._inside_hunk():
                self._body(raw)

    def _inside_hunk(self) -> bool:
        return self._current is not None and (self._old_left > 0 or self._new_left > 0)

    def _close_hunk(self) -> None:
        self._old_left = self._new_left = 0

    def _open_hunk(self, match: "re.Match[str]") -> None:
        self._close_hunk()
        try:
            old_length = int(match.group(2)) if match.group(2) is not None else 1
            start = int(match.group(3))
            new_length = int(match.group(4)) if match.group(4) is not None else 1
        except ValueError:
            return
        if start < 0 or start > _MAX_LINE_NUMBER or new_length < 0 or old_length < 0:
            return
        self._new_line = start
        self._old_left = old_length
        self._new_left = new_length

    def _body(self, raw: str) -> None:
        # Dòng trống trong thân hunk là một dòng ngữ cảnh rỗng.
        marker = raw[0] if raw else " "
        if marker == "+":
            self._record()
            self._new_line += 1
            self._new_left -= 1
        elif marker == " ":
            self._new_line += 1
            self._old_left -= 1
            self._new_left -= 1
        elif marker == "-":
            self._old_left -= 1
        elif marker == "\\":
            # "No newline at end of file" -- không phải một dòng nội dung.
            return
        else:
            # Ra khỏi thân hunk ( ví dụ dòng phân cách của định dạng email patch ).
            self._close_hunk()

    def _record(self) -> None:
        """Ghi nhận một dòng thêm mới, trong khuôn khổ ba hạn mức bộ nhớ."""
        if self._total >= MAX_LINES:
            self._truncated = True
            return
        current = self._current
        if current is None:
            return
        if current not in self._collected and len(self._collected) >= MAX_PATHS:
            self._truncated = True
            return
        bucket = self._collected.setdefault(current, [])
        if len(bucket) >= MAX_RANGES_PER_PATH:
            self._truncated = True
            return
        bucket.append((self._new_line, self._new_line))
        self._total += 1


def finding_lines(finding) -> Tuple[Tuple[str, Tuple[int, ...]], ...]:
    """Mọi cặp (tệp, dòng) mà một phát hiện chạm tới, kể cả bước xuyên file.

    Một phát hiện "mới" không chỉ là phát hiện nằm trên dòng mới: sửa một
    handler ở tệp A để nó bắt đầu gọi một sink cũ ở tệp B cũng là lỗ hổng do
    chính pull request này tạo ra. Nên mọi bước trên đường đi đều được tính.
    """
    own = [finding.line]
    if finding.end_line and finding.end_line > finding.line:
        own.extend(range(finding.line, min(finding.end_line, finding.line + 200) + 1))
    grouped: Dict[str, List[int]] = {_normalize(finding.path): own}
    for step in finding.trace:
        key = _normalize(step.path or finding.path)
        grouped.setdefault(key, []).append(step.line)
    return tuple((path, tuple(lines)) for path, lines in grouped.items())


def touches_change(finding, changed: ChangedLines) -> bool:
    for path, lines in finding_lines(finding):
        if changed.touches(path, lines):
            return True
    return False
