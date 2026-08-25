"""Chỉ thị `ignore` giấu trong chuỗi nhiều dòng của các ngôn ngữ mới.

Mô hình đe doạ: kẻ tấn công gửi một pull request. Dòng họ viết phải trông như
dữ liệu với người review, nhưng nếu bộ mặt nạ đọc nó như mã thì dấu `#` hay
`--` ở đầu dòng mở ra một "chú thích", và cả tệp tắt tiếng.

Đây đúng là họ lỗ hổng đã được vá cho heredoc của PHP, Ruby và shell. Bản
0.1.0 thêm bốn ngôn ngữ cùng một bộ phân tích workflow mà chưa mở rộng bộ mặt
nạ theo, nên mở lại năm cửa: chuỗi ngoặc của Lua, here-string của PowerShell,
heredoc của Perl, chuỗi nhiều dòng của Rust, và scalar của YAML.

Mỗi kiểm tra đi theo cặp. Một mình vế "không tắt được" thì cách sửa dễ nhất là
bỏ luôn tính năng chú thích, và bộ test vẫn xanh trong khi người dùng mất một
thứ họ cần. Vế "chỉ thị thật vẫn chạy" đứng ngay cạnh để chặn đường đó.
"""

from __future__ import annotations

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import LUA, PERL, POWERSHELL, RUST, WORKFLOW


def rules(source: str, language: str):
    return [item.rule_id for item in scan_source(source, language, "mau", Config())]


WORKFLOW_TAIL = (
    "jobs:\n  b:\n    steps:\n"
    '      - run: echo "${{ github.event.issue.title }}"\n'
)

# (ngôn ngữ, mã thủng, mã thủng kèm chỉ thị GIẤU trong chuỗi nhiều dòng)
HIDDEN_CASES = {
    "lua-chuoi-ngoac": (
        LUA,
        "local args = ngx.req.get_uri_args()\nos.execute('ping ' .. args.host)\n",
        "local tai_lieu = [[\n"
        "-- fortress-scan: ignore-file\n"
        "]]\n"
        "local args = ngx.req.get_uri_args()\n"
        "os.execute('ping ' .. args.host)\n",
    ),
    "powershell-here-string": (
        POWERSHELL,
        '$t = $args[0]\nInvoke-Expression "ping $t"\n',
        '$tai_lieu = @"\n'
        "# fortress-scan: ignore-file\n"
        '"@\n'
        "$t = $args[0]\n"
        'Invoke-Expression "ping $t"\n',
    ),
    "perl-heredoc": (
        PERL,
        "my $host = $q->param('host');\nsystem(\"ping $host\");\n",
        'my $tai_lieu = <<"EOT";\n'
        "# fortress-scan: ignore-file\n"
        "EOT\n"
        "my $host = $q->param('host');\n"
        'system("ping $host");\n',
    ),
    "rust-chuoi-nhieu-dong": (
        RUST,
        "use std::process::Command;\n"
        "fn h(req: &HttpRequest) {\n"
        '    let host = req.match_info().query("host");\n'
        "    Command::new(host).status().unwrap();\n}\n",
        "use std::process::Command;\n"
        'const TAI_LIEU: &str = "\n'
        "// fortress-scan: ignore-file\n"
        '";\n'
        "fn h(req: &HttpRequest) {\n"
        '    let host = req.match_info().query("host");\n'
        "    Command::new(host).status().unwrap();\n}\n",
    ),
    "yaml-scalar-nhay-kep": (
        WORKFLOW,
        "on: issue_comment\n" + WORKFLOW_TAIL,
        "on: issue_comment\n"
        "env:\n"
        '  MO_TA: "tai lieu\n'
        '# fortress-scan: ignore-file"\n' + WORKFLOW_TAIL,
    ),
    "yaml-scalar-nhay-don": (
        WORKFLOW,
        "on: issue_comment\n" + WORKFLOW_TAIL,
        "on: issue_comment\n"
        "env:\n"
        "  MO_TA: 'tai lieu\n"
        "# fortress-scan: ignore-file'\n" + WORKFLOW_TAIL,
    ),
    "yaml-block-scalar": (
        WORKFLOW,
        "on: issue_comment\n" + WORKFLOW_TAIL,
        "on: issue_comment\n"
        "env:\n"
        "  MO_TA: |\n"
        "    # fortress-scan: ignore-file\n" + WORKFLOW_TAIL,
    ),
    "yaml-block-scalar-gap": (
        WORKFLOW,
        "on: issue_comment\n" + WORKFLOW_TAIL,
        "on: issue_comment\n"
        "env:\n"
        "  MO_TA: >-\n"
        "    # fortress-scan: ignore-file\n" + WORKFLOW_TAIL,
    ),
}


@pytest.mark.parametrize("name", sorted(HIDDEN_CASES))
def test_a_directive_hidden_in_data_cannot_silence_the_file(name: str):
    language, plain, hidden = HIDDEN_CASES[name]
    assert rules(plain, language), "mẫu gốc phải sinh phát hiện"
    assert rules(hidden, language) == rules(plain, language)


# (ngôn ngữ, mã thủng, cùng mã đó kèm chỉ thị THẬT ở đúng chỗ chú thích)
REAL_CASES = {
    "lua": (
        LUA,
        "local args = ngx.req.get_uri_args()\nos.execute('ping ' .. args.host)\n",
        "local args = ngx.req.get_uri_args()\n"
        "-- fortress-scan: ignore-next-line\n"
        "os.execute('ping ' .. args.host)\n",
    ),
    "perl": (
        PERL,
        "my $host = $q->param('host');\nsystem(\"ping $host\");\n",
        "my $host = $q->param('host');\n"
        "# fortress-scan: ignore-next-line\n"
        'system("ping $host");\n',
    ),
    "powershell": (
        POWERSHELL,
        '$t = $args[0]\nInvoke-Expression "ping $t"\n',
        "$t = $args[0]\n"
        "# fortress-scan: ignore-next-line\n"
        'Invoke-Expression "ping $t"\n',
    ),
    "rust": (
        RUST,
        "use std::process::Command;\n"
        "fn h(req: &HttpRequest) {\n"
        '    let host = req.match_info().query("host");\n'
        "    Command::new(host).status().unwrap();\n}\n",
        "use std::process::Command;\n"
        "fn h(req: &HttpRequest) {\n"
        '    let host = req.match_info().query("host");\n'
        "    // fortress-scan: ignore-next-line\n"
        "    Command::new(host).status().unwrap();\n}\n",
    ),
    "workflow": (
        WORKFLOW,
        "on: issue_comment\n" + WORKFLOW_TAIL,
        "on: issue_comment\njobs:\n  b:\n    steps:\n"
        "      # fortress-scan: ignore-next-line\n"
        '      - run: echo "${{ github.event.issue.title }}"\n',
    ),
}


@pytest.mark.parametrize("name", sorted(REAL_CASES))
def test_a_real_directive_still_works(name: str):
    language, plain, suppressed = REAL_CASES[name]
    assert rules(plain, language), "mẫu gốc phải sinh phát hiện"
    assert rules(suppressed, language) == []


def test_lua_long_bracket_levels_are_recognised():
    """`[=[` và `[==[` là cùng một dạng chuỗi, chỉ khác số dấu bằng."""
    for opener, closer in (("[=[", "]=]"), ("[==[", "]==]")):
        source = (
            "local tai_lieu = %s\n"
            "-- fortress-scan: ignore-file\n"
            "%s\n"
            "local args = ngx.req.get_uri_args()\n"
            "os.execute('ping ' .. args.host)\n" % (opener, closer)
        )
        assert rules(source, LUA) == ["FSB-CMD-001"]


def test_yaml_block_scalar_closes_when_indentation_drops():
    """Khối đóng lại thì phát hiện phía sau phải hiện ra bình thường."""
    source = (
        "on: issue_comment\n"
        "env:\n"
        "  MO_TA: |\n"
        "    chi la van ban\n" + WORKFLOW_TAIL
    )
    assert rules(source, WORKFLOW) == ["FSB-CI-001"]
