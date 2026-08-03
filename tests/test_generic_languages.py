from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, RUBY, SHELL


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
