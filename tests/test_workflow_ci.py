"""Workflow CI: injection biểu thức, pwn request và ghim action.

Workflow chạy trên máy giữ token đẩy release, nên một injection ở đây đắt hơn
hẳn cùng loại lỗi trong mã ứng dụng. Đổi lại, phần lớn workflow trên đời viết
đúng, nên cái giá của báo nhầm cũng cao tương ứng: mỗi kiểm tra dưới đây đi
theo cặp -- một bản thủng và bản đã sửa theo đúng hướng dẫn của GitHub.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from fortress_scan.analysis.workflow import classify_expression
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.core.model import Confidence, Severity
from fortress_scan.languages import WORKFLOW, language_from_relative


def rules(source: str):
    return [f.rule_id for f in scan_source(source, WORKFLOW, ".github/workflows/ci.yml", Config())]


def findings(source: str):
    return scan_source(source, WORKFLOW, ".github/workflows/ci.yml", Config())


HEADER = "jobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"


# ------------------------------------------------------------------ nhận diện


@pytest.mark.parametrize(
    "relative,expected",
    [
        (".github/workflows/ci.yml", WORKFLOW),
        (".github/workflows/nested/deploy.yaml", WORKFLOW),
        (".gitea/workflows/b.yml", WORKFLOW),
        (".forgejo/workflows/b.yml", WORKFLOW),
        ("docs/ci.yml", None),
        (".github/dependabot.yml", None),
        ("workflows/ci.yml", None),
    ],
)
def test_only_workflow_directories_count(relative: str, expected):
    assert language_from_relative(relative) is expected


def test_workflow_file_is_picked_up_by_a_real_scan(tmp_path: Path):
    target = tmp_path / ".github" / "workflows" / "ci.yml"
    target.parent.mkdir(parents=True)
    target.write_text(
        "on: issue_comment\n" + HEADER + '      - run: echo "${{ github.event.issue.title }}"\n',
        encoding="utf-8",
    )
    result = scan(str(tmp_path), Config())
    assert [f.rule_id for f in result.findings] == ["FSB-CI-001"]
    assert result.stats.languages == {"workflow": 1}


# --------------------------------------------------------------- run: và script:


def test_untrusted_expression_in_run_block():
    source = "on: issue_comment\n" + HEADER + '      - run: echo "${{ github.event.issue.title }}"\n'
    assert "FSB-CI-001" in rules(source)


def test_untrusted_expression_in_a_multiline_run_block():
    source = (
        "on: issue_comment\n"
        + HEADER
        + "      - name: greet\n"
        "        run: |\n"
        "          set -e\n"
        '          echo "xin chao ${{ github.event.comment.body }}"\n'
        "          make build\n"
    )
    found = findings(source)
    assert [f.rule_id for f in found] == ["FSB-CI-001"]
    # Vị trí phải trỏ vào ĐÚNG dòng chứa biểu thức trong khối, không phải dòng
    # của khoá run: -- người đọc nhảy tới đó để sửa.
    assert found[0].line == 9


def test_environment_variable_pattern_is_silent():
    """Đúng cách GitHub khuyến nghị: giá trị đi qua môi trường, không qua script."""
    source = (
        "on: issue_comment\n"
        + HEADER
        + "      - env:\n"
        "          TIEU_DE: ${{ github.event.issue.title }}\n"
        '        run: echo "$TIEU_DE"\n'
    )
    assert rules(source) == []


def test_trusted_context_values_are_silent():
    source = (
        "on: push\n"
        + HEADER
        + '      - run: echo "${{ github.repository }} tai ${{ github.sha }}"\n'
    )
    assert rules(source) == []


def test_github_script_body_is_code():
    source = (
        "on: issue_comment\n"
        + HEADER
        + "      - uses: actions/github-script@v7\n"
        "        with:\n"
        "          script: |\n"
        '            console.log("${{ github.event.comment.body }}")\n'
    )
    assert "FSB-CI-002" in rules(source)


def test_script_input_of_an_unrelated_action_is_not_code():
    """`script:` chỉ là mã khi bước đó dùng một action biết eval nó.

    Rất nhiều action có đầu vào tên `script` mà chỉ coi nó là dữ liệu; bắn cho
    mọi `script:` là đúng kiểu báo bừa mà công cụ này phải tránh.
    """
    source = (
        "on: issue_comment\n"
        + HEADER
        + "      - uses: ben-khac/dan-nhan@abcdef0123456789abcdef0123456789abcdef01\n"
        "        with:\n"
        "          script: ${{ github.event.comment.body }}\n"
    )
    assert "FSB-CI-002" not in rules(source)


def test_expression_wrapped_in_a_function_still_counts():
    """`format()` hay `toJSON()` bọc ngoài không làm chuỗi bớt nguy hiểm."""
    source = (
        "on: issue_comment\n"
        + HEADER
        + "      - run: echo ${{ format('{0}', github.event.issue.title) }}\n"
    )
    assert "FSB-CI-001" in rules(source)


def test_non_privileged_trigger_lowers_confidence_but_still_reports():
    privileged = (
        "on: issue_comment\n" + HEADER + '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    plain = (
        "on: pull_request\n" + HEADER + '      - run: echo "${{ github.event.issue.title }}"\n'
    )
    assert findings(privileged)[0].confidence is Confidence.HIGH
    assert findings(plain)[0].confidence is Confidence.MEDIUM


def test_workflow_dispatch_input_is_only_a_weak_signal():
    source = (
        "on: workflow_dispatch\n" + HEADER + '      - run: echo "${{ github.event.inputs.ten }}"\n'
    )
    found = findings(source)
    assert [f.rule_id for f in found] == ["FSB-CI-001"]
    assert found[0].confidence is Confidence.LOW


# ------------------------------------------------------------------ pwn request


def test_privileged_checkout_of_pull_request_code():
    source = (
        "on: pull_request_target\n"
        + HEADER
        + "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "FSB-CI-003" in rules(source)


def test_plain_pull_request_checkout_is_fine():
    """pull_request thường chạy trong hộp cát: không token ghi, không secret."""
    source = (
        "on: pull_request\n"
        + HEADER
        + "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.sha }}\n"
    )
    assert "FSB-CI-003" not in rules(source)


def test_privileged_checkout_of_the_base_branch_is_fine():
    source = "on: pull_request_target\n" + HEADER + "      - uses: actions/checkout@v4\n"
    assert "FSB-CI-003" not in rules(source)


# ------------------------------------------------------------------- ghim action


@pytest.mark.parametrize(
    "reference,flagged",
    [
        ("ben-thu-ba/setup@v3", True),
        ("ben-thu-ba/setup@main", True),
        ("ben-thu-ba/setup", True),
        ("ben-thu-ba/setup@abcdef0123456789abcdef0123456789abcdef01", False),
        # Action của chính GitHub: cùng một bên đang chạy runner, nhãn di động
        # ở đây không thêm bên tin cậy mới.
        ("actions/checkout@v4", False),
        ("github/codeql-action/analyze@v3", False),
        # Action cục bộ và container Docker cục bộ không phải bên thứ ba.
        ("./.github/actions/build", False),
        ("docker://alpine:3", False),
    ],
)
def test_action_pinning(reference: str, flagged: bool):
    source = "on: push\n" + HEADER + "      - uses: %s\n" % reference
    assert ("FSB-CI-004" in rules(source)) is flagged


# ------------------------------------------------------------- phân loại biểu thức


@pytest.mark.parametrize(
    "expression",
    [
        "github.event.issue.title",
        " github.event.pull_request.body ",
        "GitHub.Head_Ref",
        "github.event.commits[0].message",
        "github.event.pages[12].page_name",
    ],
)
def test_untrusted_expressions_are_recognised(expression: str):
    verdict = classify_expression(expression)
    assert verdict is not None and verdict[1] is Confidence.HIGH


@pytest.mark.parametrize(
    "expression",
    [
        "github.repository",
        "github.sha",
        "secrets.GITHUB_TOKEN",
        "matrix.python-version",
        "runner.os",
        "",
    ],
)
def test_trusted_expressions_are_not_flagged(expression: str):
    assert classify_expression(expression) is None


# ------------------------------------------------------------------- độ bền


@pytest.mark.parametrize(
    "source",
    [
        "",
        "khong phai yaml\n",
        ":\n",
        "- - - - -\n",
        "run: ${{ chua dong\n",
        "on:\n  push:\n    branches:\n      - main\n",
    ],
)
def test_malformed_workflows_do_not_raise(source: str):
    scan_source(source, WORKFLOW, ".github/workflows/ci.yml", Config(min_severity=Severity.INFO))


def test_pathological_input_stays_bounded():
    """Tệp cố tình phá phải dừng theo hạn mức, không được kéo dài vô hạn.

    Bốn hình dạng ở đây nhắm đúng vào những chỗ có thể nổ: mở biểu thức mà
    không bao giờ đóng ( bộ máy regex thử lại ở từng vị trí ), một dòng dài
    vài trăm nghìn ký tự, thụt lề sâu bất thường, và rất nhiều biểu thức thật.

    Dựng trong thân hàm chứ không qua parametrize: pytest đưa tham số vào tên
    test, và tên test lại đi vào biến môi trường PYTEST_CURRENT_TEST -- Windows
    chặn ở 32767 ký tự nên cả tệp test hỏng chứ không riêng một kiểm tra.
    """
    for source in (
        "${{" * 20000,
        "on: push\njobs:\n  b:\n    steps:\n      - run: " + "x" * 200000 + "\n",
        "on:\n" + "  " * 500 + "push:\n",
        "on: issue_comment\n" + "      - run: ${{ github.event.issue.title }}\n" * 3000,
    ):
        scan_source(
            source, WORKFLOW, ".github/workflows/ci.yml", Config(min_severity=Severity.INFO)
        )
