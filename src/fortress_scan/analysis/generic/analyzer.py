from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from ...core.budget import Budget, BudgetExceeded
from ...core.model import Category, Confidence, Finding, StepKind
from ...core.registry import get_rule
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
_EVERY_CATEGORY: FrozenSet[Category] = frozenset(Category)

# Từ khoá khai báo hàm của các ngôn ngữ ở đây. Dùng để nhận ra tệp được quét tự
# định nghĩa một cái tên trùng với bộ khử độc trong bảng.
_FUNCTION_KEYWORDS = frozenset({"function", "func", "def", "sub", "fn"})

# `const escapeHtml = require("escape-html")` là nạp thư viện thật, không phải
# chiếm tên. Trong JavaScript thì require/import mới là phép nhập, còn dấu `=`
# chỉ là cú pháp -- nên phải nhìn vế phải mới phân biệt được hai chuyện.
_IMPORT_CALLS = frozenset({"require", "import", "await"})


@dataclass(frozen=True)
class TaintMark:
    label: str
    line: int
    confidence: Confidence = Confidence.MEDIUM
    # Những nhóm đã thật sự được khử trên đường đi tới đây. Đi kèm giá trị chứ
    # không quyết định ngay tại chỗ gặp bộ khử độc, vì lúc gán thì chưa biết
    # giá trị này rồi sẽ chảy vào sink thuộc nhóm nào:
    #     $safe = htmlspecialchars($_GET['d']);   // khử MARKUP
    #     system("ls " . $safe);                  // sink COMMAND -> vẫn thủng
    cleared: FrozenSet[Category] = frozenset()

    def active_for(self, category: Category) -> bool:
        return category not in self.cleared


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
        self.declared: Set[str] = set()

    def run(self, tokens: Sequence[Token]) -> List[Finding]:
        self._collect_declarations(tokens)
        self._seed_annotations(tokens)
        statements = _split_statements(tokens)
        for statement in statements[:_MAX_STATEMENTS]:
            self.budget.spend()
            if not statement:
                continue
            self._analyze_statement(statement)
        return self.builder.findings

    def _collect_declarations(self, tokens: Sequence[Token]) -> None:
        """Tên khử độc mà chính tệp này định nghĩa lại.

        Chỉ quan tâm những tên có trong bảng khử độc -- số còn lại không đổi
        được kết quả, nên không cần dựng bảng ký hiệu đầy đủ cho tám ngôn ngữ.
        Bắt hai dạng: khai báo hàm (`function escapeHtml`, `func`, `def`...) và
        gán vào chính cái tên đó (`escapeHtml = s => s`), vì cả hai đều đủ để
        cướp lấy quyền miễn trừ của bảng.

        Hai thứ KHÔNG phải là chiếm tên, và tính nhầm chúng thì bộ khử độc thật
        mất tác dụng -- tức là báo bừa đúng vào cách viết đúng nhất:

            const escapeHtml = require("escape-html");  // nạp thư viện THẬT
            utils.escapeHtml = fn;                      // gán vào thuộc tính

        Đây cũng là ranh giới mà dccc9b8 đã vạch cho phía Python: `import`
        không ghi vào môi trường, còn phép gán thì có.
        """
        limit = len(tokens)
        for index, token in enumerate(tokens):
            if token.kind != IDENT or token.in_string:
                continue
            if token.text not in self.spec.sanitizers:
                continue
            previous = tokens[index - 1] if index else None
            if previous is not None and previous.kind == OP:
                if previous.text in self.spec.chain_separators:
                    # `utils.escapeHtml` -- thuộc tính, không phải tên trần.
                    continue
            if (
                previous is not None
                and previous.kind == IDENT
                and previous.text in _FUNCTION_KEYWORDS
            ):
                self.declared.add(token.text)
                continue
            following = tokens[index + 1] if index + 1 < limit else None
            if (
                following is not None
                and following.kind == OP
                and following.text in self.spec.assignment_operators
            ):
                initializer = tokens[index + 2] if index + 2 < limit else None
                if (
                    initializer is not None
                    and initializer.kind == IDENT
                    and initializer.text in _IMPORT_CALLS
                ):
                    continue
                self.declared.add(token.text)

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
        # Bộ khử độc đã chạy trên đường đi chỉ có giá trị cho ĐÚNG nhóm của nó.
        # htmlspecialchars() rồi đem vào system() thì vết nhiễm vẫn còn sống,
        # nên chỗ này hỏi lại theo nhóm của chính rule sắp báo.
        #
        # Khử đúng nhóm thì im hẳn, không rơi xuống rule "giá trị không phải
        # hằng" bên dưới: đã có người khử đúng chỗ rồi thì nhắc nữa là báo bừa.
        # Đây chính là điều kiện _is_neutralized() ở nhánh dưới vẫn luôn kiểm,
        # chỉ là nói được chính xác theo từng nhóm.
        if mark is not None and not mark.active_for(_category_of(rule_id)):
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
        """Vết nhiễm còn sống trong biểu thức này, kèm những nhóm đã được khử.

        Một nhóm chỉ coi là an toàn khi MỌI vết nhiễm trong biểu thức đều đã
        được khử cho nhóm đó -- nên phần `cleared` trả về là phần giao. Chỉ cần
        một toán hạng chưa được khử là cả biểu thức vẫn thủng ở nhóm ấy.
        """
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

        protected = _sanitizer_ranges(tokens, self.spec, self.declared)
        surviving: Optional[TaintMark] = None
        cleared: Optional[FrozenSet[Category]] = None
        for position, mark in hits:
            here = mark.cleared
            for start, end, categories in protected:
                if start <= position < end:
                    here = here | categories
            cleared = here if cleared is None else (cleared & here)
            if surviving is None and here != _EVERY_CATEGORY:
                surviving = mark
        if surviving is None or cleared is None or cleared == _EVERY_CATEGORY:
            return None
        return replace(surviving, cleared=cleared)

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
        # Cùng lý do với _sanitizer_ranges: một cái tên do chính tệp này định
        # nghĩa thì không được hưởng quyền miễn trừ của bảng.
        for chain in self._chains(tokens):
            if chain in self.spec.sanitizers and chain not in self.declared:
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


def _category_of(rule_id: str) -> Category:
    return get_rule(rule_id).category


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


def _strip_type_annotation(left: Sequence[Token], spec: LanguageSpec) -> Sequence[Token]:
    """Drop ``: T`` from ``const x: T = ...`` so the target stays ``x``.

    Only the first separator at bracket depth zero counts; a colon inside an
    object literal, a generic argument or an index type belongs to the type, not
    to the declaration.
    """
    separator = spec.annotation_separator
    if separator is None:
        return left
    depth = 0
    for index, token in enumerate(left):
        if token.kind != OP or token.in_string:
            continue
        if token.text in "([{":
            depth += 1
        elif token.text in ")]}":
            depth = max(0, depth - 1)
        elif depth == 0 and token.text == separator:
            trimmed = list(left[:index])
            while trimmed and trimmed[-1].kind == OP and trimmed[-1].text == "?":
                trimmed.pop()
            return trimmed
    return left


def _assignment_target(left: Sequence[Token], spec: LanguageSpec) -> Optional[str]:
    left = _strip_type_annotation(left, spec)
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
    tokens: Sequence[Token], spec: LanguageSpec, declared: Set[str]
) -> List[Tuple[int, int, FrozenSet[Category]]]:
    """Khoảng token nằm trong một lời gọi khử độc, kèm nhóm mà nó khử.

    `declared` là những cái tên chính tệp được quét tự định nghĩa. Bảng khử độc
    tra theo TÊN, nên không loại chúng ra thì bốn dòng dưới đây đủ để tắt một
    phát hiện critical, và tắt trong im lặng:

        function escapeHtml(s) { return s; }
        cp.exec("ping " + escapeHtml(req.query.host));

    Đây đúng lập luận đã dùng cho phía Python ở dccc9b8: bỏ sót một cái tên bị
    che ở phía sink chỉ tốn thêm một phát hiện, còn bỏ sót ở đây thì xoá mất
    một phát hiện thật.
    """
    ranges: List[Tuple[int, int, FrozenSet[Category]]] = []
    index = 0
    limit = len(tokens)
    while index < limit:
        chain, next_index = _read_chain(tokens, index, spec)
        categories = spec.sanitizers.get(chain) if chain is not None else None
        if categories is not None and chain not in declared:
            if next_index < limit and tokens[next_index].kind == OP:
                if tokens[next_index].text == "(":
                    _, after = _read_arguments(tokens, next_index)
                    ranges.append((index, after, categories))
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
