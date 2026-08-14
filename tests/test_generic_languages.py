from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import (
    CSHARP,
    GO,
    JAVA,
    JAVASCRIPT,
    PHP,
    RUBY,
    SHELL,
    TYPESCRIPT,
)


def rule_ids(source: str, language: str):
    return [finding.rule_id for finding in scan_source(source, language, "sample", Config())]


def test_javascript_command_injection():
    source = """
const child_process = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  child_process.exec("ping -c 1 " + host, (error, stdout) => res.send(stdout));
});
"""
    assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)


def test_javascript_template_literal_sql():
    source = """
app.get("/user", (req, res) => {
  const name = req.query.name;
  db.query(`SELECT * FROM users WHERE name = '${name}'`, (e, rows) => res.json(rows));
});
"""
    assert "FSB-SQL-001" in rule_ids(source, JAVASCRIPT)


def test_javascript_parameterized_sql_is_clean():
    source = """
app.get("/user", (req, res) => {
  const name = req.query.name;
  db.query("SELECT * FROM users WHERE name = ?", [name], (e, rows) => res.json(rows));
});
"""
    assert "FSB-SQL-001" not in rule_ids(source, JAVASCRIPT)


def test_javascript_inner_html():
    source = """
function render(container, req) {
  const bio = req.body.bio;
  container.innerHTML = bio;
}
"""
    assert "FSB-XSS-001" in rule_ids(source, JAVASCRIPT)


def test_javascript_eval_of_query_parameter():
    source = """
app.get("/calc", (req, res) => {
  const expression = req.query.expr;
  res.send(String(eval(expression)));
});
"""
    assert "FSB-EXEC-001" in rule_ids(source, JAVASCRIPT)


def test_javascript_comment_does_not_trigger():
    source = """
// child_process.exec("rm -rf " + req.query.path)
/* eval(req.query.expr) */
const safe = 1;
"""
    assert rule_ids(source, JAVASCRIPT) == []


def test_php_sql_injection():
    source = """<?php
$id = $_GET["id"];
$result = mysqli_query($connection, "SELECT * FROM products WHERE id = " . $id);
"""
    assert "FSB-SQL-001" in rule_ids(source, PHP)


def test_php_escapeshellarg_is_clean():
    source = """<?php
$safe = escapeshellarg($_GET["name"]);
system("/usr/bin/greet " . $safe);
"""
    assert rule_ids(source, PHP) == []


def test_php_intval_is_clean():
    source = """<?php
$limit = intval($_GET["limit"]);
mysqli_query($connection, "SELECT * FROM products LIMIT " . $limit);
"""
    assert rule_ids(source, PHP) == []


def test_php_unserialize_of_cookie():
    source = """<?php
$state = unserialize($_COOKIE["state"]);
"""
    assert "FSB-DESER-001" in rule_ids(source, PHP)


def test_php_file_inclusion():
    source = """<?php
$page = $_REQUEST["page"];
include $page . ".php";
"""
    assert "FSB-IMPORT-001" in rule_ids(source, PHP)


def test_php_single_quoted_string_has_no_interpolation():
    source = """<?php
$command = 'echo $_GET';
system('echo hello');
"""
    assert rule_ids(source, PHP) == []


def test_java_runtime_exec():
    source = """
public class Handler {
  public void run(HttpServletRequest request) throws Exception {
    String name = request.getParameter("name");
    Runtime.getRuntime().exec("ping " + name);
  }
}
"""
    assert "FSB-CMD-001" in rule_ids(source, JAVA)


def test_java_annotation_source_reaches_sql():
    source = """
@GetMapping("/user")
public List<User> find(@RequestParam String name) throws Exception {
  return jdbc.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
}
"""
    assert "FSB-SQL-001" in rule_ids(source, JAVA)


def test_ruby_command_injection():
    source = """
def run
  name = params[:name]
  system("ping " + name)
end
"""
    assert "FSB-CMD-001" in rule_ids(source, RUBY)


def test_ruby_marshal_load():
    source = """
def restore
  Marshal.load(request.body)
end
"""
    assert "FSB-DESER-001" in rule_ids(source, RUBY)


def test_go_command_injection():
    source = """
func handler(w http.ResponseWriter, r *http.Request) {
    host := r.FormValue("host")
    cmd := exec.Command(host, "-c", "1")
    cmd.Run()
}
"""
    assert "FSB-CMD-002" in rule_ids(source, GO)


def test_csharp_sql_injection():
    source = """
public void Find(string unused) {
    var name = Request.QueryString["name"];
    var command = new SqlCommand("SELECT * FROM Users WHERE Name = '" + name + "'", connection);
    command.ExecuteReader();
}
"""
    assert "FSB-SQL-001" in rule_ids(source, CSHARP)


def test_shell_eval_of_positional_argument():
    source = """#!/bin/bash
BRANCH=$1
eval "git checkout $BRANCH"
"""
    assert "FSB-EXEC-001" in rule_ids(source, SHELL)


def test_shell_unquoted_expansion():
    source = """#!/bin/bash
TARGET="$1"
rsync -a ./dist/ $TARGET
"""
    assert "FSB-CMD-004" in rule_ids(source, SHELL)


def test_shell_quoted_expansion_is_clean():
    source = """#!/bin/bash
TARGET="$1"
rsync -a ./dist/ "$TARGET"
"""
    assert "FSB-CMD-004" not in rule_ids(source, SHELL)


class TestNestedTemplateLiterals:
    """`outer ${`inner`} end` -- vùng nội suy chứa chuỗi lồng cùng dấu nháy.

    Đóng chuỗi ở dấu backtick thứ hai làm phần ruột rơi ra ngoài thành mã, gây
    cả hai chiều: bỏ sót taint đi xuyên qua nó, và báo nhầm khi phần ruột chỉ
    là văn bản mô tả.
    """

    def test_taint_survives_a_nested_template_literal(self):
        source = """
const cp = require("child_process");
function h(req) {
  const host = req.query.host;
  cp.exec(`ping ${`${host}`}`);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)

    def test_text_inside_a_nested_template_literal_is_not_code(self):
        source = 'const label = `doc ${`use exec("ping " + req.query.host) here`} end`;\n'
        assert rule_ids(source, JAVASCRIPT) == []

    def test_code_after_a_nested_template_literal_is_still_analysed(self):
        source = """
const cp = require("child_process");
const msg = `a ${`b`} c`;
function h(req) {
  cp.exec("ping " + req.query.host);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)

    def test_plain_interpolation_is_unaffected(self):
        source = """
const cp = require("child_process");
function h(req) {
  const host = req.query.host;
  cp.exec(`ping ${host}`);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)


class TestTypescriptTypeAnnotations:
    """A type annotation must not become the assignment target.

    ``const dir: string = req.query.dir`` used to bind the taint to ``string``
    instead of ``dir``, so the sink downgraded from critical to medium — silent
    and easy to triage away.
    """

    def test_annotated_declaration_still_tracks_taint(self):
        source = """
import { exec } from "child_process";
export function h(req: any): void {
  const dir: string = req.query.dir;
  exec("ls " + dir);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, TYPESCRIPT)

    def test_annotated_and_bare_declarations_agree(self):
        bare = """
import { exec } from "child_process";
export function h(req: any): void {
  const dir = req.query.dir;
  exec("ls " + dir);
}
"""
        annotated = """
import { exec } from "child_process";
export function h(req: any): void {
  const dir: string = req.query.dir;
  exec("ls " + dir);
}
"""
        assert sorted(rule_ids(bare, TYPESCRIPT)) == sorted(rule_ids(annotated, TYPESCRIPT))

    def test_generic_type_argument_is_not_the_target(self):
        source = """
import { exec } from "child_process";
export function h(req: any): void {
  const m: Map<string, number> = req.query.m;
  exec("ls " + m);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, TYPESCRIPT)

    def test_array_type_is_not_the_target(self):
        source = """
import { exec } from "child_process";
export function h(req: any): void {
  const a: string[] = req.query.a;
  exec("ls " + a);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, TYPESCRIPT)

    def test_optional_annotated_property_is_not_the_target(self):
        source = """
import { exec } from "child_process";
export function h(req: any): void {
  const v?: string = req.query.v;
  exec("ls " + v);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, TYPESCRIPT)

    def test_annotated_sanitizer_result_stays_clean(self):
        source = """
import { exec } from "child_process";
export function h(req: any): void {
  const raw: string = req.query.d;
  const safe: string = encodeURIComponent(raw);
  exec("ls " + safe);
}
"""
        assert rule_ids(source, TYPESCRIPT) == []

    def test_annotated_constant_is_not_reported(self):
        source = """
import { exec } from "child_process";
export function h(): void {
  const dir: string = "/tmp";
  exec("ls " + dir);
}
"""
        assert "FSB-CMD-001" not in rule_ids(source, TYPESCRIPT)

    def test_javascript_ternary_colon_is_untouched(self):
        source = """
const child_process = require("child_process");
function h(req, flag) {
  const t = flag ? req.query.a : req.query.b;
  child_process.exec("ls " + t);
}
"""
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)


class TestSanitizerCategoriesAreNotInterchangeable:
    """Một bộ khử độc chỉ khử được đúng nhóm của nó.

    Bảng khử độc từng là một tập tên phẳng, không nhóm, nên bất kỳ tên nào
    trong đó cũng tắt được MỌI nhóm. Đó là cách viết sai phổ biến nhất ngoài
    đời -- lập trình viên dùng nhầm bộ thoát -- và công cụ lại im lặng đúng
    ngay ở chỗ nó cần lên tiếng nhất.
    """

    def test_html_escape_does_not_clear_a_shell_command(self):
        # htmlspecialchars() không đụng tới ; | & $ hay dấu nháy ngược.
        source = '<?php\nsystem("ls " . htmlspecialchars($_GET["d"]));\n'
        assert "FSB-CMD-001" in rule_ids(source, PHP)

    def test_html_escape_does_not_clear_sql(self):
        source = (
            '<?php\nmysqli_query($c, "SELECT * FROM u WHERE n=\'"'
            ' . htmlspecialchars($_GET["n"]) . "\'");\n'
        )
        assert "FSB-SQL-001" in rule_ids(source, PHP)

    def test_shell_quoting_does_not_clear_sql(self):
        # escapeshellarg() bọc chuỗi trong nháy đơn -- trong một câu SQL thì
        # chính dấu nháy đó là ký tự phá cú pháp.
        source = (
            '<?php\nmysqli_query($c, "SELECT * FROM u WHERE n=\'"'
            ' . escapeshellarg($_GET["n"]) . "\'");\n'
        )
        assert "FSB-SQL-001" in rule_ids(source, PHP)

    def test_basename_does_not_clear_a_shell_command(self):
        # basename("a;id") vẫn trả về "a;id".
        source = '<?php\nsystem("ls " . basename($_GET["d"]));\n'
        assert "FSB-CMD-001" in rule_ids(source, PHP)

    def test_uri_encoding_does_not_clear_sql(self):
        # encodeURIComponent() không mã hoá dấu nháy đơn.
        source = (
            'function h(req, db) {\n'
            '  db.query("SELECT * FROM u WHERE n=\'" + encodeURIComponent(req.query.n) + "\'");\n'
            '}\n'
        )
        assert "FSB-SQL-001" in rule_ids(source, JAVASCRIPT)

    def test_html_escape_does_not_clear_a_java_command(self):
        source = (
            "class A {\n"
            "  void f(javax.servlet.http.HttpServletRequest req) throws Exception {\n"
            '    Runtime.getRuntime().exec("ping "'
            ' + StringEscapeUtils.escapeHtml4(req.getParameter("h")));\n'
            "  }\n"
            "}\n"
        )
        assert "FSB-CMD-001" in rule_ids(source, JAVA)

    def test_html_escape_does_not_clear_a_ruby_command(self):
        source = 'def h\n  system("ping " + CGI.escapeHTML(params[:host]))\nend\n'
        assert "FSB-CMD-001" in rule_ids(source, RUBY)

    def test_html_encode_does_not_clear_csharp_sql(self):
        source = (
            "class A { void F() {\n"
            '  db.ExecuteSqlRaw("SELECT * FROM u WHERE n=\'"'
            ' + HttpUtility.HtmlEncode(Request.Query["n"]) + "\'");\n'
            "} }\n"
        )
        assert "FSB-SQL-001" in rule_ids(source, CSHARP)

    def test_the_category_survives_an_intermediate_variable(self):
        source = (
            '<?php\n$s = htmlspecialchars($_GET["d"]);\nsystem("ls " . $s);\n'
        )
        assert "FSB-CMD-001" in rule_ids(source, PHP)

    def test_the_right_sanitizer_still_silences_its_own_category(self):
        """Mặt kia: dùng đúng bộ khử độc thì phải im hẳn, kể cả rule mức trung
        bình "giá trị không phải hằng"."""
        assert rule_ids('<?php\nsystem("ls " . escapeshellarg($_GET["d"]));\n', PHP) == []
        assert rule_ids('<?php\ninclude(basename($_GET["p"]));\n', PHP) == []
        assert rule_ids('<?php\necho htmlspecialchars($_GET["n"]);\n', PHP) == []
        assert rule_ids(
            'function h(req, el) { el.innerHTML = DOMPurify.sanitize(req.query.x); }\n',
            JAVASCRIPT,
        ) == []
        assert rule_ids('def h\n  system("ping " + Shellwords.escape(params[:host]))\nend\n', RUBY) == []

    def test_numeric_coercion_still_clears_everything(self):
        assert rule_ids('<?php\nsystem("ls " . intval($_GET["d"]));\n', PHP) == []
        assert rule_ids(
            'const cp = require("child_process");\n'
            'function h(req) { cp.exec("ping " + parseInt(req.query.host)); }\n',
            JAVASCRIPT,
        ) == []


class TestSanitizerNameShadowing:
    """Bảng khử độc tra theo TÊN, mà cái tên thì tệp được quét tự đặt được.

    Cùng lập luận đã áp cho phía Python: bỏ sót một cái tên bị che ở phía sink
    chỉ tốn thêm một phát hiện, còn bỏ sót ở đây thì xoá mất một phát hiện thật.
    """

    def test_a_local_function_cannot_hand_out_a_sanitizer_clearance(self):
        source = (
            'const cp = require("child_process");\n'
            "function escapeHtml(s) { return s; }\n"
            'function h(req) { cp.exec("ping " + escapeHtml(req.query.host)); }\n'
        )
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)

    def test_a_rebound_name_cannot_either(self):
        source = (
            'const cp = require("child_process");\n'
            "const encodeURIComponent = s => s;\n"
            'function h(req) { cp.exec("ping " + encodeURIComponent(req.query.host)); }\n'
        )
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)

    def test_shadowing_survives_an_intermediate_variable(self):
        source = (
            'const cp = require("child_process");\n'
            "function escapeHtml(s) { return s; }\n"
            "function h(req) {\n"
            "  const s = escapeHtml(req.query.host);\n"
            '  cp.exec("ping " + s);\n'
            "}\n"
        )
        assert "FSB-CMD-001" in rule_ids(source, JAVASCRIPT)

    def test_a_php_function_shadowing_escapeshellarg(self):
        source = (
            "<?php\n"
            "function escapeshellarg($s) { return $s; }\n"
            'system("ls " . escapeshellarg($_GET["d"]));\n'
        )
        assert "FSB-CMD-001" in rule_ids(source, PHP)

    def test_an_untouched_sanitizer_keeps_working(self):
        source = (
            'const cp = require("child_process");\n'
            "function otherHelper(s) { return s; }\n"
            'function h(req) { cp.exec("ping " + encodeURIComponent(req.query.host)); }\n'
        )
        assert rule_ids(source, JAVASCRIPT) == []
