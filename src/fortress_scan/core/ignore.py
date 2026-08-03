from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, List, Optional, Sequence, Tuple

_MAX_PATTERN_LENGTH = 512
_MAX_PATTERNS = 1000
_MAX_TOTAL_TOKENS = 10000
_MAX_PATH_LENGTH = 4096

LITERAL = 0
ANY_CHAR = 1
STAR = 2
GLOBSTAR = 3
GLOBSTAR_SLASH = 4
CLASS = 5

ClassPayload = Tuple[bool, FrozenSet[str], Tuple[Tuple[str, str], ...]]
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


class GlobMatcher:
    __slots__ = ("_tokens",)

    def __init__(self, tokens: Sequence[Token], anchored: bool) -> None:
        prefix: Tuple[Token, ...] = () if anchored else ((GLOBSTAR_SLASH, None),)
        self._tokens = prefix + tuple(tokens)

    @property
    def token_count(self) -> int:
        return len(self._tokens)

    def matches(self, text: str) -> bool:
        if len(text) > _MAX_PATH_LENGTH:
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
    def __init__(self, rules: Sequence[IgnoreRule] = ()) -> None:
        self._rules: Tuple[IgnoreRule, ...] = tuple(rules)

    def __bool__(self) -> bool:
        return bool(self._rules)

    @classmethod
    def from_lines(cls, lines: Sequence[str]) -> "IgnoreSet":
        rules: List[IgnoreRule] = []
        budget = _MAX_TOTAL_TOKENS
        for raw in lines[:_MAX_PATTERNS]:
            rule = compile_rule(raw)
            if rule is None:
                continue
            budget -= rule.matcher.token_count
            if budget < 0:
                break
            rules.append(rule)
        return cls(rules)

    @classmethod
    def from_file(cls, path: Path) -> "IgnoreSet":
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return cls(())
        return cls.from_lines(content.splitlines())

    def merged(self, other: "IgnoreSet") -> "IgnoreSet":
        return IgnoreSet(self._rules + other._rules)

    def matches(self, relative_path: str, is_directory: bool) -> bool:
        decision = False
        for rule in self._rules:
            if rule.directory_only and not is_directory:
                continue
            if rule.matcher.matches(relative_path):
                decision = not rule.negated
        return decision
