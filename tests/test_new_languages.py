"""Bốn ngôn ngữ mới của 0.1.0: Rust, PowerShell, Perl, Lua.

Mỗi ngôn ngữ được kiểm theo cặp -- một bản thủng và một bản viết đúng -- vì
thêm một ngôn ngữ mà chỉ đo "có bắn không" thì rất dễ ra một bộ luật bắn vào
mọi thứ. Kèm theo là những cái bẫy riêng của từng bộ đọc: lifetime của Rust,
cmdlet không dấu ngoặc của PowerShell, sigil của Perl, chuỗi ngoặc vuông của
Lua.
"""

from __future__ import annotations

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.model import Severity
from fortress_scan.languages import LUA, PERL, POWERSHELL, RUST, detect_language


def rules(source: str, language: str):
    return [f.rule_id for f in scan_source(source, language, "mau", Config())]


# ------------------------------------------------------------------------ Rust


def test_rust_command_takes_a_tainted_program_name():
    source = (
        "use std::process::Command;\n"
        "fn handle(req: &HttpRequest) {\n"
        '    let host = req.match_info().query("host");\n'
        "    Command::new(host).status().unwrap();\n"
        "}\n"
    )
    assert "FSB-CMD-002" in rules(source, RUST)


def test_rust_parsed_integer_is_clean():
    source = (
        "use std::process::Command;\n"
        "fn handle(req: &HttpRequest) {\n"
        '    let port: u16 = req.match_info().query("p").parse().unwrap();\n'
        '    Command::new("ping").arg(port.to_string()).status().unwrap();\n'
        "}\n"
    )
    assert rules(source, RUST) == []


def test_rust_lifetimes_do_not_swallow_the_file():
    """Dấu nháy đơn trong Rust là lifetime, không phải mở chuỗi.

    Coi nó là chuỗi thì `&'a str` nuốt trọn phần còn lại của tệp vào trong
    một chuỗi không bao giờ đóng, và mọi sink phía sau biến mất trong im lặng.
    """
    source = (
        "use std::process::Command;\n"
        "struct Ngu<'a> { ten: &'a str }\n"
        "impl<'a> Ngu<'a> {\n"
        "    fn chay(&self, req: &HttpRequest) {\n"
        '        let host = req.match_info().query("host");\n'
        "        Command::new(host).status().unwrap();\n"
        "    }\n"
        "}\n"
    )
    assert "FSB-CMD-002" in rules(source, RUST)


# ------------------------------------------------------------------ PowerShell


def test_powershell_invoke_expression_with_argument():
    source = "$target = $args[0]\nInvoke-Expression \"ping $target\"\n"
    assert "FSB-EXEC-001" in rules(source, POWERSHELL)


def test_powershell_typed_cast_and_argument_list_are_clean():
    source = (
        "$target = [int]$args[0]\n"
        "Start-Process -FilePath ping -ArgumentList @('-n', '1')\n"
    )
    assert rules(source, POWERSHELL) == []


def test_powershell_plain_cmdlet_lines_stay_quiet():
    """Cmdlet gọi không dấu ngoặc nên bộ đọc không tách được đối số thật.

    Vì vậy các sink của PowerShell chỉ báo khi có vết nhiễm thật; nếu chúng
    còn giữ rule "giá trị không phải hằng" thì mọi dòng đúng chuẩn nhất --
    `Start-Process -FilePath ping` -- đều bị kêu.
    """
    source = (
        "Import-Module Az.Accounts\n"
        "Get-Content -Path .\\ghichu.txt\n"
        "Start-Process -FilePath dotnet -ArgumentList build\n"
    )
    assert rules(source, POWERSHELL) == []


# ------------------------------------------------------------------------ Perl


def test_perl_system_with_cgi_parameter():
    source = "my $host = $q->param('host');\nsystem(\"ping $host\");\n"
    assert "FSB-CMD-001" in rules(source, PERL)


def test_perl_shell_quote_clears_the_command_category():
    source = (
        "use String::ShellQuote;\n"
        "my $host = shell_quote($q->param('host'));\n"
        'system("ping $host");\n'
    )
    assert rules(source, PERL) == []


def test_perl_quotemeta_does_not_clear_a_shell_command():
    """quotemeta() thoát ký tự đặc biệt của REGEX, không phải của shell.

    Dấu chấm phẩy và ống dẫn đi qua nó nguyên vẹn -- cùng một cái bẫy mà
    preg_quote() của PHP đã bị vạch ra từ trước.
    """
    source = "my $host = quotemeta($q->param('host'));\nsystem(\"ping $host\");\n"
    assert "FSB-CMD-001" in rules(source, PERL)


# ------------------------------------------------------------------------- Lua


def test_lua_openresty_arguments_reach_os_execute():
    source = "local args = ngx.req.get_uri_args()\nos.execute('ping ' .. args.host)\n"
    assert "FSB-CMD-001" in rules(source, LUA)


def test_lua_tonumber_clears_it():
    source = (
        "local args = ngx.req.get_uri_args()\n"
        "local host = tonumber(args.host)\n"
        "os.execute('sleep ' .. host)\n"
    )
    assert rules(source, LUA) == []


def test_lua_loadstring_of_request_data():
    source = "local args = ngx.req.get_uri_args()\nloadstring(args.code)()\n"
    assert "FSB-EXEC-001" in rules(source, LUA)


# ------------------------------------------------- vết nhiễm đi qua thuộc tính


def test_field_of_a_tainted_value_stays_tainted():
    """`args` bẩn thì `args.host` cũng bẩn.

    Đây là cách viết phổ biến nhất của mọi framework -- gom tham số vào một
    biến rồi lấy từng trường. Trước 0.1.0 chỉ tên đầy đủ mới được tra, nên cả
    họ cách viết này rơi thẳng qua lưới.
    """
    source = (
        "function h(req) {\n"
        "  const q = req.query;\n"
        "  child_process.exec('ping ' + q.host);\n"
        "}\n"
    )
    assert "FSB-CMD-001" in rules(source, "javascript")


# ------------------------------------------------------------- nhận diện tệp


@pytest.mark.parametrize(
    "name,expected",
    [
        ("main.rs", RUST),
        ("build.ps1", POWERSHELL),
        ("module.psm1", POWERSHELL),
        ("cgi-bin/handler.pl", PERL),
        ("Lib.pm", PERL),
        ("init.lua", LUA),
    ],
)
def test_extensions_map_to_the_new_languages(tmp_path, name: str, expected: str):
    target = tmp_path / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("-- x\n", encoding="utf-8")
    assert detect_language(target) == expected


@pytest.mark.parametrize("language", [RUST, POWERSHELL, PERL, LUA])
@pytest.mark.parametrize(
    "source",
    ["", "\x00\x01\x02", "'" * 500, '"' * 500, "((((((((((", "#" * 2000],
)
def test_broken_sources_do_not_raise(language: str, source: str):
    scan_source(source, language, "mau", Config(min_severity=Severity.INFO))
