from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, List, Optional, Sequence, Tuple

from ..security.text import split_lines

_MAX_PATTERN_LENGTH = 512
_MAX_PATTERNS = 1000
_MAX_TOTAL_TOKENS = 10000
_MAX_PATH_LENGTH = 4096

# Tệp ignore nằm TRONG cây được quét, nên nó là dữ liệu không tin cậy y như
# .fortress-scan.json và tệp patch. Hai thứ đó có trần kích thước từ lâu, còn
# chỗ này thì chưa: read_text() nuốt trọn tệp trước khi bất kỳ hạn mức nào kịp
# đếm, nên một .gitignore 2 GB gồm toàn dòng chú thích ( tức là KHÔNG sinh ra
# lấy một quy tắc nào ) vẫn đủ giết lượt quét bằng bộ nhớ. Trần này đứng TRƯỚC
# phép đọc, và một .gitignore thật chưa bao giờ tới nổi một phần trăm của nó.
_MAX_IGNORE_BYTES = 1024 * 1024

# Hạn mức CHUNG cho cả lượt quét, tiêu theo số ô mà phép quy hoạch động thật
# sự phải tính.
#
# _MAX_TOTAL_TOKENS chặn được độ phức tạp của MỘT lần so, nhưng walk() gọi
# matches() một lần cho MỖI entry trong cây, nên chi phí thật là
# tokens x độ_dài_đường_dẫn x số_entry, và hai thừa số sau không có trần nào.
# Đo được: một .gitignore 15 KB hợp lệ ( 30 dòng ) trên 200 tệp nằm sâu 20 cấp
# kéo lượt quét từ 0,7 giây lên 96 giây, và nhân theo trần 50.000 tệp mặc định
# thì thành hàng giờ. Cạn hạn mức thì BỎ HẾT quy tắc thay vì so tiếp, cùng
# hướng an toàn với overflowed: không tệp nào bị giấu, và engine nói ra.
#
# Con số lấy từ đo đạc chứ không phải đoán: quét chính kho này tốn 175 ô cho
# mỗi tệp, tức là một kho 50.000 tệp tiêu khoảng 8,8 triệu ô. Trần dưới đây
# rộng gấp hơn mười lần mức đó, mà vẫn giữ trường hợp thù địch nhất ở mức vài
# giây thay vì vài giờ. Kho nào thật sự chạm trần thì hỏng theo hướng an toàn:
# quét NHIỀU hơn dự định, kèm một dòng cảnh báo, chứ không phải quét thiếu.
_MAX_MATCH_CELLS = 100_000_000

LITERAL = 0
ANY_CHAR = 1
STAR = 2
GLOBSTAR = 3
GLOBSTAR_SLASH = 4
CLASS = 5

ClassPayload = Tuple[bool, FrozenSet[str], Tuple[Tuple[str, str], ...]]


class MatchBudget:
    """Hạn mức so khớp dùng chung cho cả một lượt quét.

    Là đối tượng chứ không phải biến toàn cục vì engine có thể chạy nhiều cây
    song song, và mỗi lượt quét phải mang hạn mức riêng của nó.
    """

    __slots__ = ("_remaining", "exhausted")

    def __init__(self, cells: int = _MAX_MATCH_CELLS) -> None:
        self._remaining = cells
        self.exhausted = False

    def spend(self, cells: int) -> bool:
        """Trừ phần vừa tiêu; False nghĩa là đã cạn và không được so nữa."""
        if self.exhausted:
            return False
        self._remaining -= cells
        if self._remaining <= 0:
            self.exhausted = True
            return False
        return True
Token = Tuple[int, object]


def _parse_class(pattern: str, index: int) -> Tuple[Optional[Token], int]:
    end = index + 1
    negated = False
    if end < len(pattern) and pattern[end] in ("!", "^"):
        negated = True
        end += 1
    if end < len(pattern) and pattern[end] == "]":
        end += 1
    while end < len(pattern) and pattern[end] != "]":
        end += 1
    if end >= len(pattern):
        return None, index
    body = pattern[index + 1 : end]
    if body.startswith(("!", "^")):
        body = body[1:]
    members: List[str] = []
    ranges: List[Tuple[str, str]] = []
    position = 0
    while position < len(body):
        if position + 2 < len(body) and body[position + 1] == "-":
            ranges.append((body[position], body[position + 2]))
            position += 3
        else:
            members.append(body[position])
            position += 1
    payload: ClassPayload = (negated, frozenset(members), tuple(ranges))
    return (CLASS, payload), end + 1


def _tokenize(pattern: str) -> List[Token]:
    tokens: List[Token] = []
    index = 0
    length = len(pattern)
    while index < length:
        char = pattern[index]
        if char == "*":
            if index + 1 < length and pattern[index + 1] == "*":
                index += 2
                if index < length and pattern[index] == "/":
                    index += 1
                    tokens.append((GLOBSTAR_SLASH, None))
                else:
                    tokens.append((GLOBSTAR, None))
                continue
            tokens.append((STAR, None))
        elif char == "?":
            tokens.append((ANY_CHAR, None))
        elif char == "[":
            token, next_index = _parse_class(pattern, index)
            if token is None:
                tokens.append((LITERAL, "["))
            else:
                tokens.append(token)
                index = next_index
                continue
        else:
            tokens.append((LITERAL, char))
        index += 1
    return tokens


def _class_matches(payload: ClassPayload, char: str) -> bool:
    negated, members, ranges = payload
    inside = char in members
    if not inside:
        for low, high in ranges:
            if low <= char <= high:
                inside = True
                break
    return inside != negated


def _longest_literal_run(tokens: Sequence[Token]) -> str:
    """Chuỗi ký tự dài nhất mà MỌI đường dẫn khớp đều bắt buộc phải chứa.

    Token LITERAL nằm liền nhau thì phải xuất hiện liền nhau và đúng thứ tự
    trong đường dẫn, nên đoạn dài nhất trong số đó là một điều kiện CẦN. Phép
    thử `run not in text` chạy ở tốc độ C và loại được gần hết số quy tắc
    trước khi phải dựng bảng quy hoạch động.

    Đây là phép lọc CHÍNH XÁC, không phải phỏng đoán: nó chỉ loại những đường
    dẫn mà bảng kia chắc chắn cũng trả lời "không", nên kết quả không đổi một
    trường hợp nào.
    """
    best = ""
    current: list = []
    for kind, payload in tokens:
        if kind == LITERAL:
            current.append(payload)
            continue
        if len(current) > len(best):
            best = "".join(current)
        current = []
    if len(current) > len(best):
        best = "".join(current)
    return best


class GlobMatcher:
    __slots__ = ("_tokens", "_required")

    def __init__(self, tokens: Sequence[Token], anchored: bool) -> None:
        prefix: Tuple[Token, ...] = () if anchored else ((GLOBSTAR_SLASH, None),)
        self._tokens = prefix + tuple(tokens)
        self._required = _longest_literal_run(self._tokens)

    @property
    def token_count(self) -> int:
        return len(self._tokens)

    def matches(self, text: str, budget: Optional[MatchBudget] = None) -> bool:
        if len(text) > _MAX_PATH_LENGTH:
            return False
        # Lọc trước khi tiêu hạn mức: đây là phần giữ cho một .gitignore thật
        # ( `node_modules/`, `__pycache__/`, `*.py[cod]`... ) gần như không tốn
        # gì, vì đường dẫn bình thường không chứa những chuỗi đó.
        if self._required and self._required not in text:
            return False
        if budget is not None and not budget.spend(len(self._tokens) * (len(text) + 1)):
            return False

        tokens = self._tokens
        total_text = len(text)
        following = [index == total_text or text[index] == "/" for index in range(total_text + 1)]

        for token_index in range(len(tokens) - 1, -1, -1):
            kind, payload = tokens[token_index]
            current = [False] * (total_text + 1)

            if kind == LITERAL:
                for position in range(total_text):
                    if text[position] == payload:
                        current[position] = following[position + 1]
            elif kind == ANY_CHAR:
                for position in range(total_text):
                    if text[position] != "/":
                        current[position] = following[position + 1]
            elif kind == CLASS:
                for position in range(total_text):
                    char = text[position]
                    if char != "/" and _class_matches(payload, char):
                        current[position] = following[position + 1]
            elif kind == STAR:
                carried = False
                for position in range(total_text, -1, -1):
                    if position == total_text:
                        carried = False
                    elif text[position] == "/":
                        carried = False
                    else:
                        carried = current[position + 1]
                    current[position] = following[position] or carried
            elif kind == GLOBSTAR:
                carried = False
                for position in range(total_text, -1, -1):
                    if position < total_text:
                        carried = current[position + 1]
                    current[position] = following[position] or carried
            elif kind == GLOBSTAR_SLASH:
                after_slash = False
                for position in range(total_text, -1, -1):
                    if position < total_text:
                        landed = following[position + 1] if text[position] == "/" else False
                        after_slash = landed or after_slash
                    else:
                        after_slash = False
                    current[position] = following[position] or after_slash

            following = current

        return following[0]


@dataclass(frozen=True)
class IgnoreRule:
    matcher: GlobMatcher
    negated: bool
    directory_only: bool
    anchored: bool


def compile_rule(raw: str) -> Optional[IgnoreRule]:
    pattern = raw.rstrip("\r\n")
    if not pattern.strip() or pattern.lstrip().startswith("#"):
        return None
    if len(pattern) > _MAX_PATTERN_LENGTH:
        return None
    negated = pattern.startswith("!")
    if negated:
        pattern = pattern[1:]
    pattern = pattern.strip()
    if not pattern:
        return None
    directory_only = pattern.endswith("/")
    if directory_only:
        pattern = pattern[:-1]
    anchored = "/" in pattern.rstrip("/")
    if pattern.startswith("/"):
        pattern = pattern[1:]
        anchored = True
    if not pattern:
        return None
    tokens = _tokenize(pattern)
    if not tokens:
        return None
    return IgnoreRule(GlobMatcher(tokens, anchored), negated, directory_only, anchored)


class IgnoreSet:
    def __init__(
        self,
        rules: Sequence[IgnoreRule] = (),
        overflowed: bool = False,
        budget: Optional[MatchBudget] = None,
    ) -> None:
        self._rules: Tuple[IgnoreRule, ...] = tuple(rules)
        self._overflowed = overflowed
        # Hạn mức đi theo TẬP quy tắc chứ không theo từng lần so, và merged()
        # chuyền tiếp đúng đối tượng đó, nên mọi thư mục trong một lượt quét
        # cùng tiêu chung một túi.
        self._budget = budget if budget is not None else MatchBudget()

    def __bool__(self) -> bool:
        return bool(self._rules)

    @property
    def overflowed(self) -> bool:
        return self._overflowed

    @property
    def budget(self) -> MatchBudget:
        return self._budget

    @property
    def budget_exhausted(self) -> bool:
        return self._budget.exhausted

    @classmethod
    def from_lines(
        cls, lines: Sequence[str], budget: Optional[MatchBudget] = None
    ) -> "IgnoreSet":
        rules: List[IgnoreRule] = []
        remaining = _MAX_TOTAL_TOKENS
        if len(lines) > _MAX_PATTERNS:
            return cls((), overflowed=True, budget=budget)
        for raw in lines:
            rule = compile_rule(raw)
            if rule is None:
                continue
            remaining -= rule.matcher.token_count
            if remaining < 0:
                return cls((), overflowed=True, budget=budget)
            rules.append(rule)
        return cls(rules, budget=budget)

    @classmethod
    def from_file(
        cls, path: Path, budget: Optional[MatchBudget] = None
    ) -> "IgnoreSet":
        # Trần kích thước đứng trước phép đọc, không phải sau: đếm dòng sau khi
        # đã nuốt trọn tệp vào RAM thì hạn mức đếm cho một thứ đã xảy ra rồi.
        try:
            if path.stat().st_size > _MAX_IGNORE_BYTES:
                return cls((), overflowed=True, budget=budget)
        except OSError:
            return cls((), budget=budget)
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, MemoryError):
            return cls((), budget=budget)
        # Chỉ tách theo "\n" như git. str.splitlines() còn cắt ở \v, \f,
        # \x1c-\x1e, \x85, U+2028, U+2029 -- một dòng comment như
        # "# ghi chú\x0csecret/" sẽ bị tách làm đôi, biến phần đuôi thành
        # pattern thật và lặng lẽ loại thư mục đó khỏi phạm vi quét.
        return cls.from_lines(split_lines(content), budget=budget)

    def merged(self, other: "IgnoreSet") -> "IgnoreSet":
        return IgnoreSet(
            self._rules + other._rules,
            self._overflowed or other._overflowed,
            budget=self._budget,
        )

    def matches(self, relative_path: str, is_directory: bool) -> bool:
        # Cạn hạn mức thì không quy tắc nào còn hiệu lực. Ngả về phía KHÔNG
        # giấu gì cả, y như khi một tệp ignore vượt hạn mức mẫu.
        if self._budget.exhausted:
            return False
        decision = False
        for rule in self._rules:
            if rule.directory_only and not is_directory:
                continue
            if rule.matcher.matches(relative_path, self._budget):
                decision = not rule.negated
        return decision
