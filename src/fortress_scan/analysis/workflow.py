"""Phân tích workflow CI theo cú pháp GitHub Actions.

Workflow là mã nguồn, và là mã nguồn chạy ở chỗ đắt nhất: trên runner đang
cầm GITHUB_TOKEN, secret ký release và quyền đẩy lên registry. Nó cũng có một
lớp lỗ hổng mà không bộ dò ngôn ngữ nào ở đây bắt được, vì nó xảy ra TRƯỚC
khi shell chạy: GitHub thay thế biểu thức ``${{ ... }}`` bằng phép ghép chuỗi
thô vào thân script, nên một tiêu đề issue chứa dấu nháy là một câu lệnh mới.

Bộ đọc ở đây là bộ quét theo dòng có chặn trên, KHÔNG phải một bộ phân tích
YAML đầy đủ, và điều đó là cố ý: dự án không có phụ thuộc ngoài, còn một bộ
phân tích YAML tự viết lại chính là một mặt tấn công mới ( alias bung ra vô
hạn, neo đệ quy ) nằm ngay trong công cụ đọc tệp của người lạ. Cái giá là
những chỗ nó không nhìn thấy, và chúng được nói thẳng ở đây:

* luồng chảy trong YAML dạng JSON ( ``run: {a: b}`` ) không được lần theo;
* neo và alias ( ``*ref`` ) không được mở, nên giá trị đi qua chúng không
  được xét;
* ``${{ }}`` nằm trong một action tự viết ( ``action.yml`` của chính repo )
  chỉ được xét ở chính tệp đó, không lần qua ranh giới action.

Những gì nó CÓ nhìn thấy thì nhìn chính xác: vị trí dòng/cột của từng biểu
thức, phạm vi của từng khối scalar, và trigger nào đang cấp quyền cho job.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

from ..core.budget import Budget
from ..core.model import Confidence, Finding, StepKind
from .base import Analyzer, AnalysisUnit, FindingBuilder

# Một workflow thật dài vài trăm dòng. Chặn trên rộng gấp nhiều lần mức đó,
# đủ cho tệp sinh tự động, nhưng vẫn hữu hạn trước một tệp cố tình phình to.
MAX_LINES = 20_000
MAX_EXPRESSIONS_PER_FILE = 2_000
MAX_BLOCK_LINES = 2_000
# Số ký tự tối đa của MỘT dòng được đem đi dò biểu thức. Mẫu ${{ ... }} có
# lượng từ lười và có chặn trên, nên trên một dòng dài vài megabyte rải đầy
# "${{" không bao giờ đóng, bộ máy regex thử lại ở từng vị trí và tự biến
# công cụ thành nạn nhân của chính tệp nó đang đọc. Dòng workflow thật dài
# vài trăm ký tự; hạn mức này rộng gấp nhiều lần mức đó.
MAX_LINE_SCAN = 16_384

_EXPRESSION = re.compile(r"\$\{\{(.{0,2000}?)\}\}", re.DOTALL)
_KEY = re.compile(r"^(\s*)(?:-\s+)?([A-Za-z_][\w.-]*)\s*:(.*)$")
_LIST_ITEM = re.compile(r"^(\s*)-\s+(.*)$")
_BLOCK_SCALAR = re.compile(r"^[|>][+-]?\d*\s*$")

# Trigger nào chạy với quyền của kho ( token ghi được, secret đọc được ) trên
# nội dung do người ngoài gửi tới. Đây là điều kiện biến một injection từ
# "chạy mã trong hộp cát của chính pull request" thành "chạy mã có token".
PRIVILEGED_TRIGGERS: FrozenSet[str] = frozenset(
    {
        "pull_request_target",
        "workflow_run",
        "issue_comment",
        "issues",
        "discussion",
        "discussion_comment",
        "pull_request_review",
        "pull_request_review_comment",
        "fork",
        "watch",
    }
)

# Đường dẫn context mà người ngoài đặt được nội dung. Danh sách này bám theo
# tài liệu hardening của GitHub; mỗi mục là một tiền tố đã chuẩn hoá.
_UNTRUSTED_EXACT: FrozenSet[str] = frozenset(
    {
        "github.head_ref",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.pull_request.head.label",
        "github.event.pull_request.head.repo.default_branch",
        "github.event.pull_request.head.repo.description",
        "github.event.pull_request.head.repo.homepage",
        "github.event.pull_request.head.repo.name",
        "github.event.pull_request.head.repo.full_name",
        "github.event.pull_request.head.repo.owner.login",
        "github.event.pull_request.head.repo.owner.email",
        "github.event.comment.body",
        "github.event.review.body",
        "github.event.review_comment.body",
        "github.event.discussion.title",
        "github.event.discussion.body",
        "github.event.head_commit.message",
        "github.event.head_commit.author.name",
        "github.event.head_commit.author.email",
        "github.event.workflow_run.head_branch",
        "github.event.workflow_run.head_commit.message",
        "github.event.workflow_run.head_repository.description",
        "github.event.workflow_run.display_title",
        "github.event.milestone.title",
        "github.event.milestone.description",
        "github.event.project_card.note",
        "github.event.release.body",
        "github.event.release.name",
    }
)

# Những đường dẫn có phần chỉ số ở giữa: `github.event.commits[0].message`,
# `github.event.pages[3].page_name`.
_UNTRUSTED_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"^github\.event\.commits\[\d{0,6}\]\.(?:message|author\.(?:name|email))$"),
    re.compile(r"^github\.event\.pages\[\d{0,6}\]\.(?:page_name|title)$"),
    re.compile(r"^github\.event\.(?:issue|pull_request)\.user\.login$"),
    re.compile(r"^github\.event\.pull_request\.head\.repo\.owner\.(?:login|email|name)$"),
)

# Nhóm thứ hai: người gửi phải có quyền trong kho mới đặt được, nên nó là điểm
# yếu cần siết chứ chưa phải lỗ hổng bất kỳ ai khai thác được.
_SEMI_TRUSTED_PATTERNS: Tuple[re.Pattern, ...] = (
    re.compile(r"^github\.event\.inputs\.[\w.-]{0,200}$"),
    re.compile(r"^inputs\.[\w.-]{0,200}$"),
    re.compile(r"^github\.event\.client_payload(?:\.[\w.-]{0,200})?$"),
    re.compile(r"^steps\.[\w.-]{1,100}\.outputs\.[\w.-]{1,100}$"),
    re.compile(r"^needs\.[\w.-]{1,100}\.outputs\.[\w.-]{1,100}$"),
    re.compile(r"^env\.[\w-]{1,100}$"),
)

_LABELS: Dict[str, str] = {
    "github.head_ref": "tên nhánh của pull request",
    "github.event.issue.title": "tiêu đề issue",
    "github.event.issue.body": "nội dung issue",
    "github.event.pull_request.title": "tiêu đề pull request",
    "github.event.pull_request.body": "nội dung pull request",
    "github.event.comment.body": "nội dung comment",
    "github.event.review.body": "nội dung review",
    "github.event.discussion.title": "tiêu đề discussion",
    "github.event.discussion.body": "nội dung discussion",
    "github.event.head_commit.message": "thông điệp commit",
}

# Bước checkout, và khoá `ref:` trỏ về đúng mã của pull request. Cặp này cộng
# với một trigger đặc quyền là hình dạng kinh điển của "pwn request".
_CHECKOUT_ACTIONS = ("actions/checkout",)
_PR_REF_MARKERS: Tuple[str, ...] = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.merge_commit_sha",
    "github.head_ref",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "refs/pull/",
)

# Action do chính GitHub phát hành: chúng nằm dưới quyền kiểm soát của cùng
# một bên đang chạy runner, nên nhãn di động ở đây không thêm bên tin cậy mới.
_FIRST_PARTY_OWNERS: FrozenSet[str] = frozenset({"actions", "github"})

_SHA_PIN = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")

_SCRIPT_ACTIONS: Tuple[str, ...] = ("actions/github-script",)


@dataclass(frozen=True)
class _Expression:
    text: str
    line: int
    column: int


def _normalize_expression(raw: str) -> str:
    """Bỏ khoảng trắng và hạ chữ, giữ nguyên cấu trúc dấu chấm và chỉ số.

    Biểu thức trong workflow được viết rất tự do -- `${{github.event.issue.title}}`,
    `${{ GitHub.Event.Issue.Title }}` và `${{ github.event .issue.title }}` là
    cùng một thứ với bộ chạy của GitHub, nên chúng phải là cùng một chuỗi ở đây.
    """
    return re.sub(r"\s+", "", raw).lower()


def _mentioned_paths(expression: str) -> Tuple[str, ...]:
    """Mọi đường dẫn context xuất hiện trong một biểu thức.

    Biểu thức không chỉ là một tên trần: `format('{0}', github.head_ref)` hay
    `toJSON(github.event.issue)` cũng đưa đúng chuỗi đó vào script. Tách theo
    ranh giới token thay vì so cả biểu thức, nếu không thì mọi lời gọi hàm bọc
    ngoài đều là một đường lách.
    """
    return tuple(re.findall(r"[a-z_][\w.]*(?:\[\d{0,6}\][\w.]*)*", expression))


def classify_expression(raw: str) -> Optional[Tuple[str, Confidence, str]]:
    """(đường dẫn, độ tin cậy, nhãn) của phần không tin cậy nhất trong biểu thức."""
    normalized = _normalize_expression(raw)
    if not normalized:
        return None
    best: Optional[Tuple[str, Confidence, str]] = None
    for path in _mentioned_paths(normalized):
        if path in _UNTRUSTED_EXACT or any(
            pattern.match(path) for pattern in _UNTRUSTED_PATTERNS
        ):
            label = _LABELS.get(path, "dữ liệu do người ngoài đặt (%s)" % path)
            return (path, Confidence.HIGH, label)
        if best is None and any(pattern.match(path) for pattern in _SEMI_TRUSTED_PATTERNS):
            best = (
                path,
                Confidence.LOW,
                "giá trị do người có quyền trong kho đặt (%s)" % path,
            )
    return best


class _Document:
    """Bảng dòng đã tách sẵn khoá, thụt lề và khối scalar.

    Đây là toàn bộ phần "hiểu YAML" của module: mỗi dòng biết mình thụt vào
    bao nhiêu, có phải khoá không, và nếu là khoá mở khối thì khối kéo dài
    tới đâu. Không có neo, không có alias, không có luồng JSON -- đúng tập
    con mà workflow thật dùng.
    """

    def __init__(self, lines: Sequence[str]) -> None:
        self.lines = list(lines[:MAX_LINES])
        self.truncated = len(lines) > MAX_LINES

    def indent_of(self, index: int) -> int:
        line = self.lines[index]
        return len(line) - len(line.lstrip(" "))

    def key_at(self, index: int) -> Optional[Tuple[int, str, str]]:
        """(thụt lề, tên khoá, phần giá trị) nếu dòng này là một khoá ánh xạ."""
        raw = self.lines[index]
        match = _KEY.match(raw)
        if match is None:
            return None
        indent = len(match.group(1))
        # `- run: echo` -- mục danh sách vẫn là một khoá, nhưng thụt lề thật
        # của nó tính từ sau dấu gạch đầu dòng.
        item = _LIST_ITEM.match(raw)
        if item is not None and _KEY.match(item.group(2)) is not None:
            indent = len(item.group(1)) + 2
        return indent, match.group(2), match.group(3).strip()

    def block_range(self, index: int, indent: int) -> Tuple[int, int]:
        """Nửa khoảng [đầu, cuối) của khối thuộc về khoá ở dòng `index`."""
        end = index + 1
        limit = min(len(self.lines), index + 1 + MAX_BLOCK_LINES)
        while end < limit:
            line = self.lines[end]
            if line.strip():
                if self.indent_of(end) <= indent:
                    break
            end += 1
        return index + 1, end


def _inline_sequence(value: str) -> List[str]:
    """`[push, pull_request]` hoặc `push` viết ngay sau dấu hai chấm."""
    cleaned = value.strip()
    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    return [part.strip().strip("'\"") for part in cleaned.split(",")]


def _expressions_in(text: str, line: int, base_column: int) -> List[_Expression]:
    # Phép kiểm chuỗi con này chạy trên mọi dòng của mọi workflow, và tuyệt
    # đại đa số dòng không có biểu thức nào -- nó giữ bộ máy regex khỏi phải
    # khởi động cho chúng.
    if "${{" not in text:
        return []
    found: List[_Expression] = []
    for match in _EXPRESSION.finditer(text[:MAX_LINE_SCAN]):
        found.append(
            _Expression(text=match.group(1), line=line, column=base_column + match.start())
        )
    return found


class WorkflowAnalyzer(Analyzer):
    name = "ci-workflow"

    def analyze(self, unit: AnalysisUnit, budget: Budget) -> List[Finding]:
        document = _Document(unit.lines)
        return _Scan(unit, document, budget).run()


class _Scan:
    def __init__(self, unit: AnalysisUnit, document: _Document, budget: Budget) -> None:
        self.unit = unit
        self.document = document
        self.budget = budget
        self.builder = FindingBuilder(unit)
        self.triggers: FrozenSet[str] = frozenset()
        self._expressions_seen = 0

    def run(self) -> List[Finding]:
        self.triggers = self._collect_triggers()
        self._scan_script_keys()
        self._scan_uses()
        self._scan_pwn_request()
        return self.builder.findings

    # ------------------------------------------------------------------ trigger

    def _collect_triggers(self) -> FrozenSet[str]:
        """Tên các sự kiện kích hoạt workflow.

        Khoá `on:` ở YAML có một cái bẫy riêng: `on` cũng là một giá trị
        boolean trong YAML 1.1, nên vài bộ ghi tự động xuất nó thành `"on":`
        hoặc `True:`. Nhận cả ba dạng, vì đoán sai chỗ này thì mọi phép nâng
        mức theo trigger đặc quyền im lặng biến mất.
        """
        names: List[str] = []
        for index in range(len(self.document.lines)):
            self.budget.spend()
            parsed = self.document.key_at(index)
            if parsed is None:
                continue
            indent, key, value = parsed
            if indent != 0 or key.strip().strip('"').lower() not in ("on", "true"):
                continue
            if value:
                names.extend(_inline_sequence(value))
            else:
                names.extend(self._trigger_block(index, indent))
        return frozenset(name.lower() for name in names if name and name.isascii())

    def _trigger_block(self, index: int, indent: int) -> List[str]:
        """Tên sự kiện là con TRỰC TIẾP của `on:`.

        Khoá sâu hơn một cấp là bộ lọc của chính sự kiện ( `branches:`,
        `types:`, `paths:` ). Nhặt chúng vào thì workflow nào lọc theo nhánh
        cũng mọc thêm một trigger tên "branches" -- vô hại về mặt tên, nhưng
        nó làm phép so với PRIVILEGED_TRIGGERS mất ý nghĩa.
        """
        start, end = self.document.block_range(index, indent)
        names: List[str] = []
        base: Optional[int] = None
        for inner in range(start, end):
            self.budget.spend()
            text = self.document.lines[inner].strip()
            if not text or text.startswith("#"):
                continue
            depth = self.document.indent_of(inner)
            if base is None:
                base = depth
            elif depth > base:
                continue
            item = _LIST_ITEM.match(self.document.lines[inner])
            if item is not None:
                names.append(item.group(2).strip().strip("'\"").rstrip(":"))
                continue
            nested = self.document.key_at(inner)
            if nested is not None:
                names.append(nested[1])
        return names

    @property
    def _privileged(self) -> bool:
        return bool(self.triggers & PRIVILEGED_TRIGGERS)

    # ------------------------------------------------------------------- script

    def _scan_script_keys(self) -> None:
        """Mọi khối `run:` và `script:`, kể cả dạng scalar nhiều dòng."""
        for index in range(len(self.document.lines)):
            self.budget.spend()
            parsed = self.document.key_at(index)
            if parsed is None:
                continue
            indent, key, value = parsed
            lowered = key.lower()
            if lowered == "run":
                rule = "FSB-CI-001"
                what = "khối run: của workflow"
            elif lowered == "script" and self._script_key_is_code(index, indent):
                rule = "FSB-CI-002"
                what = "script inline của action"
            else:
                continue
            for expression in self._expressions_for(index, indent, value):
                self._report_expression(expression, rule, what)

    def _script_key_is_code(self, index: int, indent: int) -> bool:
        """`script:` chỉ là mã khi bước đó dùng một action biết eval nó.

        Nhiều action khác cũng có đầu vào tên `script` mà chỉ coi nó là dữ
        liệu. Bắn cho mọi `script:` là đúng kiểu báo bừa mà công cụ này phải
        tránh, nên phải tìm được `uses:` cùng bước và đối chiếu tên action.
        """
        for neighbour in self._step_keys(index, indent):
            parsed = self.document.key_at(neighbour)
            if parsed is None:
                continue
            if parsed[1].lower() != "uses":
                continue
            target = parsed[2].strip().strip("'\"").lower()
            if target.startswith(_SCRIPT_ACTIONS):
                return True
        return False

    def _step_keys(self, index: int, indent: int) -> List[int]:
        """Các dòng khoá anh em cùng một bước với dòng `index`.

        Một bước trong workflow là một mục danh sách; mọi khoá của nó thụt vào
        đúng bằng nhau. Đi lên tới mục danh sách gần nhất rồi đi xuống hết
        khối của nó là bắt được cả `uses:` đứng trước lẫn đứng sau `script:`.
        """
        start = index
        while start > 0:
            self.budget.spend()
            line = self.document.lines[start]
            if (
                line.strip()
                and _LIST_ITEM.match(line) is not None
                and self.document.indent_of(start) < indent
            ):
                break
            start -= 1
        # Dừng ở chính mục danh sách, không dừng ở khoá cha gần nhất: `uses:`
        # và `with:` là anh em của nhau, còn `script:` nằm TRONG `with:`. Đi
        # lên đúng một cấp thì từ `script:` chỉ thấy `with:` và bước này mãi
        # mãi không biết mình đang chạy action nào.
        item_indent = self.document.indent_of(start)
        end = start + 1
        limit = min(len(self.document.lines), start + 1 + MAX_BLOCK_LINES)
        while end < limit:
            self.budget.spend()
            line = self.document.lines[end]
            if line.strip() and self.document.indent_of(end) <= item_indent:
                break
            end += 1
        return [item for item in range(start, end) if item != index]

    def _expressions_for(self, index: int, indent: int, value: str) -> List[_Expression]:
        """Biểu thức trong giá trị inline, hoặc trong khối scalar theo sau."""
        line_number = index + 1
        if value and not _BLOCK_SCALAR.match(value):
            column = self.document.lines[index].find(value)
            return self._budgeted(_expressions_in(value, line_number, max(column, 0)))
        start, end = self.document.block_range(index, indent)
        collected: List[_Expression] = []
        for inner in range(start, end):
            self.budget.spend()
            collected.extend(_expressions_in(self.document.lines[inner], inner + 1, 0))
        return self._budgeted(collected)

    def _budgeted(self, expressions: List[_Expression]) -> List[_Expression]:
        room = MAX_EXPRESSIONS_PER_FILE - self._expressions_seen
        if room <= 0:
            return []
        self._expressions_seen += len(expressions[:room])
        return expressions[:room]

    def _report_expression(self, expression: _Expression, rule: str, what: str) -> None:
        verdict = classify_expression(expression.text)
        if verdict is None:
            return
        path, confidence, label = verdict
        if confidence >= Confidence.HIGH and not self._privileged:
            # Trigger không đặc quyền vẫn là injection thật -- kẻ tấn công chạy
            # được lệnh trên runner -- nhưng token của job chỉ đọc, nên thiệt
            # hại dừng ở đó. Hạ một nấc, đừng bỏ qua.
            confidence = Confidence.MEDIUM
        evidence = [
            "biểu thức ${{ %s }} được thay bằng phép ghép chuỗi thô trước khi %s chạy"
            % (_normalize_expression(expression.text)[:120], what),
            "trigger của workflow: %s"
            % (", ".join(sorted(self.triggers)) if self.triggers else "không đọc được"),
        ]
        if self._privileged:
            evidence.append(
                "trigger đặc quyền nên job chạy với token ghi được và secret của kho"
            )
        step = self.builder.step(
            StepKind.SINK,
            expression.line,
            expression.column,
            "được dán vào %s" % what,
        )
        source_step = self.builder.step(
            StepKind.SOURCE, expression.line, expression.column, label
        )
        self.builder.add(
            rule_id=rule,
            line=expression.line,
            column=expression.column,
            symbol=path,
            message="%s được nội suy thẳng vào %s" % (label, what),
            confidence=confidence,
            trace=(source_step, step),
            tags=("ci-workflow",),
            evidence=tuple(evidence),
        )

    # --------------------------------------------------------------- uses / pin

    def _scan_uses(self) -> None:
        for index in range(len(self.document.lines)):
            self.budget.spend()
            parsed = self.document.key_at(index)
            if parsed is None or parsed[1].lower() != "uses":
                continue
            reference = parsed[2].strip().strip("'\"")
            problem = _pin_problem(reference)
            if problem is None:
                continue
            self.builder.add(
                rule_id="FSB-CI-004",
                line=index + 1,
                column=max(self.document.lines[index].find(reference), 0),
                symbol=reference[:120],
                message="action %s được ghim bằng %s" % (reference.split("@")[0][:80], problem),
                trace=(
                    self.builder.step(
                        StepKind.SINK, index + 1, 0, "action chạy trên runner của bạn"
                    ),
                ),
                tags=("ci-workflow", "supply-chain"),
                evidence=(
                    "tham chiếu %s không phải digest commit nên nội dung sau nó đổi được"
                    % problem,
                    "chủ sở hữu kho action, hoặc bất kỳ ai chiếm được kho đó, di chuyển "
                    "được nhãn này mà không cần bạn sửa workflow",
                ),
            )

    # ------------------------------------------------------------- pwn request

    def _scan_pwn_request(self) -> None:
        """Trigger đặc quyền + checkout đúng mã của pull request."""
        if not self._privileged:
            return
        checkout_lines = []
        for index in range(len(self.document.lines)):
            self.budget.spend()
            if self._is_checkout(index):
                checkout_lines.append(index)
        if not checkout_lines:
            return
        for index in checkout_lines:
            self.budget.spend()
            ref_line = self._checked_out_pr_ref(index)
            if ref_line is None:
                continue
            self.builder.add(
                rule_id="FSB-CI-003",
                line=ref_line + 1,
                column=0,
                symbol="actions/checkout",
                message=(
                    "workflow chạy bằng trigger đặc quyền (%s) nhưng checkout đúng mã "
                    "của pull request" % ", ".join(sorted(self.triggers & PRIVILEGED_TRIGGERS))
                ),
                trace=(
                    self.builder.step(
                        StepKind.SOURCE, index + 1, 0, "bước checkout mã đóng góp"
                    ),
                    self.builder.step(
                        StepKind.SINK, ref_line + 1, 0, "ref trỏ về nhánh của người gửi"
                    ),
                ),
                tags=("ci-workflow", "pwn-request"),
                evidence=(
                    "trigger %s cấp cho job token ghi được và quyền đọc secret"
                    % ", ".join(sorted(self.triggers & PRIVILEGED_TRIGGERS)),
                    "mã được checkout là mã của người gửi pull request, chưa qua review",
                ),
            )

    def _is_checkout(self, index: int) -> bool:
        parsed = self.document.key_at(index)
        if parsed is None or parsed[1].lower() != "uses":
            return False
        return parsed[2].strip().strip("'\"").lower().startswith(_CHECKOUT_ACTIONS)

    def _checked_out_pr_ref(self, index: int) -> Optional[int]:
        parsed = self.document.key_at(index)
        if parsed is None:
            return None
        for neighbour in self._step_keys(index, parsed[0]):
            self.budget.spend()
            inner = self.document.key_at(neighbour)
            if inner is None or inner[1].lower() != "ref":
                continue
            value = _normalize_expression(inner[2])
            if any(marker in value for marker in _PR_REF_MARKERS):
                return neighbour
        return None


def _pin_problem(reference: str) -> Optional[str]:
    """Mô tả cách ghim yếu của một `uses:`, hoặc None nếu đã ghim chắc.

    Ba dạng KHÔNG phải bên thứ ba và không bị tính: action cục bộ (`./...`),
    container Docker cục bộ, và action do chính GitHub phát hành. Đưa chúng
    vào chỉ tạo ra tiếng ồn trên mọi workflow từng viết.
    """
    text = reference.strip()
    if not text or text.startswith((".", "/")) or text.startswith("docker://"):
        return None
    if "${{" in text:
        return None
    owner, _, rest = text.partition("/")
    if not rest:
        return None
    if owner.lower() in _FIRST_PARTY_OWNERS:
        return None
    name, separator, version = rest.partition("@")
    if not separator or not version:
        return "không có phần @phiên bản nào"
    del name
    if _SHA_PIN.match(version.strip().lower()):
        return None
    label = version.strip()[:60]
    if label.startswith("v") or label[:1].isdigit():
        return "tag %s ( tag di chuyển được )" % label
    return "nhánh %s ( nội dung nhánh đổi bất cứ lúc nào )" % label
