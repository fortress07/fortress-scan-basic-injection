from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

from ...core.budget import Budget

IDENT = "ident"
STRING = "string"
NUMBER = "number"
OP = "op"
NEWLINE = "newline"

_MAX_INTERPOLATION_DEPTH = 4
_MAX_STRING_LENGTH = 4096


@dataclass(frozen=True)
class Token:
    kind: str
    text: str
    line: int
    column: int
    in_string: bool = False
    interpolated: bool = False
    quote: str = ""


@dataclass(frozen=True)
class LexerProfile:
    line_comments: Tuple[str, ...] = ("//",)
    block_comments: Tuple[Tuple[str, str], ...] = (("/*", "*/"),)
    plain_quotes: Tuple[str, ...] = ("'",)
    interpolating_quotes: Tuple[str, ...] = ('"',)
    interpolation_markers: Tuple[Tuple[str, str], ...] = (("${", "}"),)
    dollar_interpolation: bool = False
    identifier_extra: str = "_$"
    heredoc_markers: Tuple[str, ...] = ()
    escape_character: str = "\\"
    raw_quotes: Tuple[str, ...] = ()
    multichar_operators: Tuple[str, ...] = (
        "===",
        "!==",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "=>",
        "->",
        "::",
        "+=",
        "-=",
        "*=",
        "/=",
        ".=",
        "??",
        "?.",
        "**",
        "<<",
        ">>",
    )


def _is_identifier_start(char: str, profile: LexerProfile) -> bool:
    return char.isalpha() or char in profile.identifier_extra or ord(char) > 127


def _is_identifier_part(char: str, profile: LexerProfile) -> bool:
    return char.isalnum() or char in profile.identifier_extra or ord(char) > 127


class Tokenizer:
    def __init__(
        self, source: str, profile: LexerProfile, budget: Budget, depth: int = 0
    ) -> None:
        self._source = source
        self._profile = profile
        self._budget = budget
        self._depth = depth
        self._length = len(source)
        self._index = 0
        self._line = 1
        self._column = 1
        self._tokens: List[Token] = []

    def run(self) -> List[Token]:
        while self._index < self._length:
            self._budget.spend()
            char = self._source[self._index]
            if char == "\n":
                self._emit(NEWLINE, "\n")
                self._advance(1)
                self._line += 1
                self._column = 1
                continue
            if char in " \t\r\f\v":
                self._advance(1)
                continue
            if self._skip_comment():
                continue
            if self._read_heredoc():
                continue
            if self._read_string():
                continue
            if char.isdigit():
                self._read_number()
                continue
            if _is_identifier_start(char, self._profile):
                self._read_identifier()
                continue
            self._read_operator()
        return self._tokens

    def _emit(self, kind: str, text: str, in_string: bool = False, quote: str = "") -> None:
        self._tokens.append(
            Token(
                kind=kind,
                text=text,
                line=self._line,
                column=self._column,
                in_string=in_string,
                quote=quote,
            )
        )

    def _advance(self, count: int) -> None:
        self._index += count
        self._column += count

    def _skip_comment(self) -> bool:
        for marker in self._profile.line_comments:
            if self._source.startswith(marker, self._index):
                end = self._source.find("\n", self._index)
                if end == -1:
                    self._index = self._length
                else:
                    self._advance(end - self._index)
                return True
        for opener, closer in self._profile.block_comments:
            if self._source.startswith(opener, self._index):
                end = self._source.find(closer, self._index + len(opener))
                segment_end = self._length if end == -1 else end + len(closer)
                segment = self._source[self._index : segment_end]
                self._line += segment.count("\n")
                self._index = segment_end
                self._column = 1
                return True
        return False

    def _read_heredoc(self) -> bool:
        for marker in self._profile.heredoc_markers:
            if not self._source.startswith(marker, self._index):
                continue
            cursor = self._index + len(marker)
            while cursor < self._length and self._source[cursor] in " \t~-":
                cursor += 1
            quote = ""
            if cursor < self._length and self._source[cursor] in "\"'":
                quote = self._source[cursor]
                cursor += 1
            start = cursor
            while cursor < self._length and (
                self._source[cursor].isalnum() or self._source[cursor] == "_"
            ):
                cursor += 1
            label = self._source[start:cursor]
            if not label:
                return False
            if quote and cursor < self._length and self._source[cursor] == quote:
                cursor += 1
            body_start = self._source.find("\n", cursor)
            if body_start == -1:
                return False
            body_start += 1
            terminator = self._find_heredoc_end(label, body_start)
            body = self._source[body_start:terminator][:_MAX_STRING_LENGTH]
            segment = self._source[self._index : terminator]
            self._emit(STRING, body, in_string=False)
            if quote != "'":
                self._scan_interpolations(body)
            self._line += segment.count("\n")
            self._index = terminator
            self._column = 1
            return True
        return False

    def _find_heredoc_end(self, label: str, start: int) -> int:
        cursor = start
        while cursor < self._length:
            end_of_line = self._source.find("\n", cursor)
            if end_of_line == -1:
                end_of_line = self._length
            if self._source[cursor:end_of_line].strip().rstrip(";") == label:
                return cursor
            cursor = end_of_line + 1
        return self._length

    def _read_string(self) -> bool:
        char = self._source[self._index]
        profile = self._profile
        if char not in profile.plain_quotes and char not in profile.interpolating_quotes:
            if char not in profile.raw_quotes:
                return False
        interpolating = char in profile.interpolating_quotes
        raw = char in profile.raw_quotes
        cursor = self._index + 1
        pieces: List[str] = []
        while cursor < self._length:
            current = self._source[cursor]
            if not raw and current == profile.escape_character and cursor + 1 < self._length:
                pieces.append(self._source[cursor + 1])
                cursor += 2
                continue
            if current == char:
                cursor += 1
                break
            pieces.append(current)
            cursor += 1
        body = "".join(pieces)[:_MAX_STRING_LENGTH]
        segment = self._source[self._index : cursor]
        self._emit(STRING, body, quote=char)
        if interpolating and not raw:
            self._scan_interpolations(body)
        self._line += segment.count("\n")
        self._index = cursor
        self._column = 1
        return True

    def _scan_interpolations(self, body: str) -> None:
        if self._depth >= _MAX_INTERPOLATION_DEPTH:
            return
        profile = self._profile
        for opener, closer in profile.interpolation_markers:
            start = 0
            while True:
                position = body.find(opener, start)
                if position == -1:
                    break
                end = _matching_index(body, position + len(opener), opener[-1], closer)
                if end == -1:
                    break
                inner = body[position + len(opener) : end]
                self._emit_inner(inner)
                start = end + len(closer)
        if profile.dollar_interpolation:
            self._scan_dollar(body)

    def _scan_dollar(self, body: str) -> None:
        index = 0
        length = len(body)
        while index < length:
            position = body.find("$", index)
            if position == -1 or position + 1 >= length:
                return
            following = body[position + 1]
            if following == "{":
                end = body.find("}", position + 2)
                if end == -1:
                    return
                self._emit_inner(body[position + 2 : end])
                index = end + 1
                continue
            if following == "(":
                end = _matching_index(body, position + 2, "(", ")")
                if end == -1:
                    return
                self._emit_inner(body[position + 2 : end])
                index = end + 1
                continue
            if following.isdigit() or following in "@*#?":
                self._emit_expansion(body[position : position + 2])
                index = position + 2
                continue
            if _is_identifier_start(following, self._profile):
                cursor = position + 1
                while cursor < length and _is_identifier_part(body[cursor], self._profile):
                    cursor += 1
                self._emit_expansion(body[position:cursor])
                index = cursor
                continue
            index = position + 1

    def _emit_expansion(self, text: str) -> None:
        self._tokens.append(
            Token(
                kind=IDENT,
                text=text,
                line=self._line,
                column=self._column,
                in_string=True,
                interpolated=True,
            )
        )

    def _emit_inner(self, inner: str) -> None:
        if not inner.strip():
            return
        nested = Tokenizer(inner, self._profile, self._budget, self._depth + 1)
        nested._line = self._line
        nested._column = self._column
        for token in nested.run():
            if token.kind == NEWLINE:
                continue
            self._tokens.append(
                Token(
                    kind=token.kind,
                    text=token.text,
                    line=self._line,
                    column=self._column,
                    in_string=True,
                    interpolated=True,
                )
            )

    def _read_number(self) -> None:
        cursor = self._index
        while cursor < self._length and (
            self._source[cursor].isalnum() or self._source[cursor] in "._"
        ):
            cursor += 1
        self._emit(NUMBER, self._source[self._index : cursor])
        self._advance(cursor - self._index)

    def _read_identifier(self) -> None:
        cursor = self._index
        while cursor < self._length and _is_identifier_part(self._source[cursor], self._profile):
            cursor += 1
        self._emit(IDENT, self._source[self._index : cursor])
        self._advance(cursor - self._index)

    def _read_operator(self) -> None:
        for operator in self._profile.multichar_operators:
            if self._source.startswith(operator, self._index):
                self._emit(OP, operator)
                self._advance(len(operator))
                return
        self._emit(OP, self._source[self._index])
        self._advance(1)


def _matching_index(text: str, start: int, opener: str, closer: str) -> int:
    depth = 1
    index = start
    length = len(text)
    while index < length:
        char = text[index]
        if char == opener and opener != closer:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def tokenize(source: str, profile: LexerProfile, budget: Budget) -> List[Token]:
    return Tokenizer(source, profile, budget).run()
