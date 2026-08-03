from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Confidence, Finding, StepKind
from ..base import Analyzer, AnalysisUnit, FindingBuilder
from ..python.specs import SQL_STATEMENT
from .lexer import IDENT, NEWLINE, OP, STRING, Token, tokenize
from .profiles import GenericSink, LanguageSpec, spec_for

_MAX_STATEMENTS = 20000
_MAX_STATEMENT_TOKENS = 600
_CONTINUATION_OPERATORS = frozenset(
    {"+", "-", "*", "/", ",", "=", "(", "[", "{", "&&", "||", ".", "?", ":", "|", "\\", "+="}
)
_STATEMENT_BREAKS = frozenset({";", "{", "}"})
_SHELL_QUIET_COMMANDS = frozenset({"echo", "printf", "return", "local", "export", "declare"})


@dataclass(frozen=True)
class TaintMark:
    label: str
    line: int
    confidence: Confidence = Confidence.MEDIUM


class GenericAnalyzer(Analyzer):
    name = "generic-dataflow"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        spec = spec_for(unit.language)
        if spec is None:
            return []
        try:
            tokens = tokenize(unit.source, spec.lexer, budget)
            return _Analysis(unit, spec, budget).run(tokens)
        except BudgetExceeded:
            return []


class _Analysis:
    def __init__(self, unit: AnalysisUnit, spec: LanguageSpec, budget: Budget) -> None:
        self.unit = unit
        self.spec = spec
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.tainted: Dict[str, TaintMark] = {}
        self.sanitized: Set[str] = set()

    def run(self, tokens: Sequence[Token]) -> List[Finding]:
        self._seed_annotations(tokens)
        statements = _split_statements(tokens)
        for statement in statements[:_MAX_STATEMENTS]:
            self.budget.spend()
            if not statement:
                continue
            self._analyze_statement(statement)
        return self.builder.findings

    def _seed_annotations(self, tokens: Sequence[Token]) -> None:
        if not self.spec.annotation_sources:
            return
        index = 0
        limit = len(tokens)
        while index < limit - 2:
            token = tokens[index]
            if token.kind == OP and token.text == "@":
                label = self.spec.annotation_sources.get(tokens[index + 1].text)
                if label is not None:
                    name = _next_declared_name(tokens, index + 2)
                    if name is not None:
                        self.tainted[name] = TaintMark(label, token.line, Confidence.HIGH)
            index += 1

    def _analyze_statement(self, statement: Sequence[Token]) -> None:
        if len(statement) > _MAX_STATEMENT_TOKENS:
            statement = statement[:_MAX_STATEMENT_TOKENS]
        if self.spec.language == "shell":
            self._analyze_shell_statement(statement)
            return
        self._analyze_assignment(statement)
        self._analyze_calls(statement)
        self._analyze_backticks(statement)

    def _analyze_assignment(self, statement: Sequence[Token]) -> None:
        position = _assignment_position(statement, self.spec)
        if position is None:
            return
        left = statement[:position]
        right = statement[position + 1 :]
        if not right:
            return
        target = _assignment_target(left, self.spec)
        mark = self._taint_of(right)

        if target is not None:
            member = target.rsplit(".", 1)[-1]
            sink = self.spec.assignment_sinks.get(member)
            if sink is not None:
                self._report_expression(
                    rule_id=sink[0],
                    dynamic_rule=None,
                    description=sink[2],
                    symbol=member,
                    tokens=right,
                    mark=mark,
                )
            if mark is not None:
                self.tainted[target] = mark
                self.sanitized.discard(target)
                simple = target.rsplit(".", 1)[-1]
                if simple != target:
                    self.tainted.setdefault(simple, mark)
            else:
                self.tainted.pop(target, None)
                if self._is_neutralized(right):
                    self.sanitized.add(target)
                else:
                    self.sanitized.discard(target)

    def _analyze_calls(self, statement: Sequence[Token]) -> None:
        index = 0
        limit = len(statement)
        while index < limit:
            self.budget.spend()
            chain, next_index = _read_chain(statement, index, self.spec)
            if chain is None:
                index += 1
                continue
            opens_call = (
                next_index < limit
                and statement[next_index].kind == OP
                and statement[next_index].text == "("
            )
            if opens_call:
                arguments, _ = _read_arguments(statement, next_index)
                self._check_call(chain, statement[index], arguments)
            elif chain in self.spec.bare_call_names:
                self._check_call(chain, statement[index], [list(statement[next_index:])])
            index = max(next_index, index + 1)

    def _check_call(
        self, chain: str, anchor: Token, arguments: Sequence[Sequence[Token]]
    ) -> None:
        sink = _match_sink(chain, self.spec)
        if sink is None:
            return
        if sink.require_sql:
            selected = _select_sql_argument(arguments, sink, chain)
        elif sink.program_position:
            wrapped = _shell_wrapper_argument(arguments)
            if wrapped is not None:
                self._report_expression(
                    rule_id="FSB-CMD-001",
                    dynamic_rule="FSB-CMD-003",
                    description="một lệnh shell truyền qua cờ thông dịch",
                    symbol=chain,
                    tokens=wrapped,
                    mark=self._taint_of(wrapped),
                    anchor=anchor,
                    confidence=Confidence.HIGH,
                )
                return
            selected = arguments[0] if arguments else ()
        else:
            position = min(sink.argument_index, max(0, len(arguments) - 1))
            selected = arguments[position] if arguments else ()
        if not selected:
            return
        mark = self._taint_of(selected)
        self._report_expression(
            rule_id=sink.tainted_rule,
            dynamic_rule=sink.dynamic_rule,
            description=sink.description,
            symbol=chain,
            tokens=selected,
            mark=mark,
            anchor=anchor,
            confidence=sink.confidence,
        )

    def _analyze_backticks(self, statement: Sequence[Token]) -> None:
        if not self.spec.backtick_command:
            return
        for index, token in enumerate(statement):
            if token.kind != STRING or token.quote != "`":
                continue
            embedded = _following_interpolations(statement, index)
            if not embedded:
                continue
            mark = self._taint_of(embedded)
            self._report_expression(
                rule_id="FSB-CMD-001",
                dynamic_rule="FSB-CMD-003",
                description="một lệnh shell trong dấu backtick",
                symbol="`",
                tokens=embedded,
                mark=mark,
                anchor=token,
            )

    def _analyze_shell_statement(self, statement: Sequence[Token]) -> None:
        position = _assignment_position(statement, self.spec)
        if position == 1 and statement[0].kind == IDENT:
            mark = self._taint_of(statement[position + 1 :])
            name = statement[0].text
            if mark is not None:
                self.tainted["$" + name] = mark
            else:
                self.tainted.pop("$" + name, None)
            return
        command = statement[0]
        if command.kind != IDENT:
            return
        if command.text == "read":
            for token in statement[1:]:
                if token.kind == IDENT and not token.text.startswith("-"):
                    self.tainted["$" + token.text] = TaintMark("luồng nhập chuẩn", token.line)
            return
        if command.text in ("eval", "source", "."):
            arguments = statement[1:]
            mark = self._taint_of(arguments)
            sink = _match_sink(command.text, self.spec)
            if sink is not None:
                self._report_expression(
                    rule_id=sink.tainted_rule,
                    dynamic_rule=sink.dynamic_rule,
                    description=sink.description,
                    symbol=command.text,
                    tokens=arguments,
                    mark=mark,
                    anchor=command,
                )
            return
        if command.text in _SHELL_QUIET_COMMANDS:
            return
        for token in statement[1:]:
            if token.kind != IDENT or token.in_string or not token.text.startswith("$"):
                continue
            mark = self.tainted.get(token.text) or self._source_mark(token.text, token.line)
            if mark is None:
                continue
            self.builder.add(
                rule_id="FSB-CMD-004",
                line=token.line,
                column=token.column,
                symbol=token.text,
                message="%s được khai triển không có nháy kép trong câu lệnh; hãy viết \"%s\""
                % (mark.label, token.text),
                trace=(
                    self.builder.step(StepKind.SOURCE, mark.line, 0, mark.label),
                    self.builder.step(
                        StepKind.SINK, token.line, token.column, "khai triển không có nháy kép"
                    ),
                ),
            )

    def _report_expression(
        self,
        rule_id: str,
        dynamic_rule: Optional[str],
        description: str,
        symbol: str,
        tokens: Sequence[Token],
        mark: Optional[TaintMark],
        anchor: Optional[Token] = None,
        confidence: Confidence = Confidence.MEDIUM,
    ) -> None:
        target = anchor or (tokens[0] if tokens else None)
        if target is None:
            return
        if mark is not None:
            self.builder.add(
                rule_id=rule_id,
                line=target.line,
                column=target.column,
                symbol=symbol,
                message="%s chạy tới %s mà chưa được vô hiệu hóa" % (mark.label, description),
                confidence=min(confidence, mark.confidence),
                trace=(
                    self.builder.step(StepKind.SOURCE, mark.line, 0, "%s đi vào từ đây" % mark.label),
                    self.builder.step(
                        StepKind.SINK, target.line, target.column, "chạy tới %s" % description
                    ),
                ),
            )
            return
        if dynamic_rule is None or _is_literal(tokens) or self._is_neutralized(tokens):
            return
        self.builder.add(
            rule_id=dynamic_rule,
            line=target.line,
            column=target.column,
            symbol=symbol,
            message="%s nhận một giá trị không phải hằng" % description,
            trace=(
                self.builder.step(StepKind.SINK, target.line, target.column, description),
            ),
        )

    def _taint_of(self, tokens: Sequence[Token]) -> Optional[TaintMark]:
        hits: List[Tuple[int, TaintMark]] = []
        index = 0
        limit = len(tokens)
        while index < limit:
            chain, next_index = _read_chain(tokens, index, self.spec)
            if chain is None:
                index += 1
                continue
            mark = self.tainted.get(chain) or self._source_mark(chain, tokens[index].line)
            if mark is not None:
                hits.append((index, mark))
            index = max(next_index, index + 1)
        if not hits:
            return None
        protected = _sanitizer_ranges(tokens, self.spec)
        for position, mark in hits:
            if not any(start <= position < end for start, end in protected):
                return mark
        return None

    def _source_mark(self, chain: str, line: int) -> Optional[TaintMark]:
        label = self.spec.sources.get(chain)
        if label is not None:
            return TaintMark(label, line, Confidence.HIGH)
        prefix = chain
        while "." in prefix:
            prefix = prefix.rsplit(".", 1)[0]
            label = self.spec.sources.get(prefix)
            if label is not None:
                return TaintMark(label, line, Confidence.HIGH)
        return None

    def _is_sanitized(self, tokens: Sequence[Token]) -> bool:
        for chain in self._chains(tokens):
            if chain in self.spec.sanitizers:
                return True
        return False

    def _is_neutralized(self, tokens: Sequence[Token]) -> bool:
        if self._is_sanitized(tokens):
            return True
        chains = self._chains(tokens)
        if not chains:
            return False
        return all(chain in self.sanitized for chain in chains)

    def _chains(self, tokens: Sequence[Token]) -> List[str]:
        found: List[str] = []
        index = 0
        limit = len(tokens)
        while index < limit:
            chain, next_index = _read_chain(tokens, index, self.spec)
            if chain is not None:
                found.append(chain)
            index = max(next_index if chain else index + 1, index + 1)
        return found


def _split_statements(tokens: Sequence[Token]) -> List[List[Token]]:
    statements: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    for token in tokens:
        if token.kind == NEWLINE:
            if depth == 0 and current and not _continues(current[-1]):
                statements.append(current)
                current = []
            continue
        if token.kind == OP and not token.in_string:
            if token.text in "([":
                depth += 1
            elif token.text in ")]":
                depth = max(0, depth - 1)
            elif token.text in _STATEMENT_BREAKS:
                if current:
                    statements.append(current)
                current = []
                depth = 0
                continue
        current.append(token)
        if len(current) > _MAX_STATEMENT_TOKENS:
            statements.append(current)
            current = []
    if current:
        statements.append(current)
    return statements


def _continues(token: Token) -> bool:
    return token.kind == OP and token.text in _CONTINUATION_OPERATORS


def _assignment_position(statement: Sequence[Token], spec: LanguageSpec) -> Optional[int]:
    depth = 0
    for index, token in enumerate(statement):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([":
            depth += 1
        elif token.text in ")]":
            depth = max(0, depth - 1)
        elif depth == 0 and token.text in spec.assignment_operators:
            return index
    return None


def _assignment_target(left: Sequence[Token], spec: LanguageSpec) -> Optional[str]:
    filtered = [token for token in left if token.kind in (IDENT, OP)]
    if not filtered:
        return None
    end = len(filtered)
    start = end - 1
    while start > 0:
        previous = filtered[start - 1]
        if previous.kind == OP and previous.text in spec.chain_separators:
            start -= 2
            continue
        break
    if start < 0:
        start = 0
    chain, _ = _read_chain(filtered, start, spec)
    if chain is None:
        return None
    if chain in spec.declaration_keywords:
        return None
    return chain


def _read_chain(
    tokens: Sequence[Token], index: int, spec: LanguageSpec
) -> Tuple[Optional[str], int]:
    limit = len(tokens)
    if index >= limit or tokens[index].kind != IDENT:
        return None, index
    parts = [tokens[index].text]
    cursor = index + 1
    while cursor + 1 < limit:
        separator = tokens[cursor]
        if separator.kind == OP and separator.text == "(" and cursor + 1 < limit:
            if tokens[cursor + 1].kind == OP and tokens[cursor + 1].text == ")":
                if (
                    cursor + 3 < limit
                    and tokens[cursor + 2].kind == OP
                    and tokens[cursor + 2].text in spec.chain_separators
                    and tokens[cursor + 3].kind == IDENT
                ):
                    parts.append(tokens[cursor + 3].text)
                    cursor += 4
                    continue
            break
        if separator.kind != OP or separator.text not in spec.chain_separators:
            break
        following = tokens[cursor + 1]
        if following.kind != IDENT:
            break
        parts.append(following.text)
        cursor += 2
    return ".".join(parts), cursor


def _read_arguments(
    tokens: Sequence[Token], open_index: int
) -> Tuple[List[List[Token]], int]:
    arguments: List[List[Token]] = []
    current: List[Token] = []
    depth = 0
    index = open_index
    limit = len(tokens)
    while index < limit:
        token = tokens[index]
        if token.kind == OP and not token.in_string:
            if token.text in "([{":
                depth += 1
                if depth == 1 and index == open_index:
                    index += 1
                    continue
            elif token.text in ")]}":
                depth -= 1
                if depth == 0:
                    if current:
                        arguments.append(current)
                    return arguments, index + 1
            elif token.text == "," and depth == 1:
                arguments.append(current)
                current = []
                index += 1
                continue
        current.append(token)
        index += 1
    if current:
        arguments.append(current)
    return arguments, limit


_SHELL_BINARIES = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "cmd", "cmd.exe", "powershell", "pwsh", "busybox"}
)
_SHELL_FLAGS = frozenset({"-c", "/c", "/C", "-Command", "-command"})


def _shell_wrapper_argument(
    arguments: Sequence[Sequence[Token]],
) -> Optional[Sequence[Token]]:
    if len(arguments) < 3:
        return None
    program = _sole_string(arguments[0])
    if program is None:
        return None
    if program.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower() not in _SHELL_BINARIES:
        return None
    for index in range(1, len(arguments) - 1):
        flag = _sole_string(arguments[index])
        if flag is not None and flag in _SHELL_FLAGS:
            return arguments[index + 1]
    return None


def _sole_string(argument: Sequence[Token]) -> Optional[str]:
    meaningful = [token for token in argument if not token.in_string]
    if len(meaningful) == 1 and meaningful[0].kind == STRING:
        return meaningful[0].text
    return None


_ALWAYS_SQL = frozenset(
    {
        "mysqli_query",
        "mysqli_multi_query",
        "mysql_query",
        "pg_query",
        "sqlite_query",
        "find_by_sql",
        "exec_query",
        "select_all",
        "knex.raw",
        "sequelize.query",
        "FromSqlRaw",
        "ExecuteSqlRaw",
        "createNativeQuery",
        "createSQLQuery",
    }
)


def _select_sql_argument(
    arguments: Sequence[Sequence[Token]], sink: GenericSink, chain: str
) -> Sequence[Token]:
    for argument in arguments:
        text = " ".join(token.text for token in argument if token.kind == STRING)
        if SQL_STATEMENT.search(text):
            return argument
    tail = chain.rsplit(".", 1)[-1]
    if chain in _ALWAYS_SQL or tail in _ALWAYS_SQL:
        position = min(sink.argument_index, max(0, len(arguments) - 1))
        if arguments:
            return arguments[position]
    return ()


def _match_sink(chain: str, spec: LanguageSpec) -> Optional[GenericSink]:
    best: Optional[GenericSink] = None
    best_length = -1
    for sink in spec.sinks:
        for name in sink.names:
            if chain == name or chain.endswith("." + name):
                if len(name) > best_length:
                    best = sink
                    best_length = len(name)
    return best


def _sanitizer_ranges(
    tokens: Sequence[Token], spec: LanguageSpec
) -> List[Tuple[int, int]]:
    ranges: List[Tuple[int, int]] = []
    index = 0
    limit = len(tokens)
    while index < limit:
        chain, next_index = _read_chain(tokens, index, spec)
        if chain is not None and chain in spec.sanitizers:
            if next_index < limit and tokens[next_index].kind == OP:
                if tokens[next_index].text == "(":
                    _, after = _read_arguments(tokens, next_index)
                    ranges.append((index, after))
                    index = after
                    continue
        index = max(next_index if chain else index + 1, index + 1)
    return ranges


def _is_literal(tokens: Sequence[Token]) -> bool:
    for token in tokens:
        if token.interpolated:
            return False
        if token.kind in (IDENT,):
            return False
    return True


def _following_interpolations(statement: Sequence[Token], index: int) -> List[Token]:
    collected: List[Token] = []
    cursor = index + 1
    while cursor < len(statement) and statement[cursor].in_string:
        collected.append(statement[cursor])
        cursor += 1
    return collected


def _next_declared_name(tokens: Sequence[Token], index: int) -> Optional[str]:
    cursor = index
    limit = min(len(tokens), index + 12)
    last: Optional[str] = None
    while cursor < limit:
        token = tokens[cursor]
        if token.kind == IDENT:
            last = token.text
        elif token.kind == OP and token.text in (",", ")"):
            break
        cursor += 1
    return last
