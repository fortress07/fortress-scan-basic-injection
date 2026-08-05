from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Optional, Tuple

from ...core.model import Category, Confidence
from ...languages import CSHARP, GO, JAVA, JAVASCRIPT, PHP, RUBY, SHELL, TYPESCRIPT
from .lexer import LexerProfile


@dataclass(frozen=True)
class GenericSink:
    names: Tuple[str, ...]
    category: Category
    tainted_rule: str
    dynamic_rule: Optional[str]
    description: str
    argument_index: int = 0
    require_sql: bool = False
    program_position: bool = False
    confidence: Confidence = Confidence.MEDIUM


@dataclass(frozen=True)
class LanguageSpec:
    language: str
    lexer: LexerProfile
    sources: Dict[str, str]
    sinks: Tuple[GenericSink, ...]
    assignment_sinks: Dict[str, Tuple[str, Category, str]] = field(default_factory=dict)
    sanitizers: FrozenSet[str] = frozenset()
    weak_sanitizers: FrozenSet[str] = frozenset()
    declaration_keywords: FrozenSet[str] = frozenset()
    chain_separators: Tuple[str, ...] = (".",)
    # Languages that write the type after the name (``const x: T = ...``) need
    # it stripped, or the type name gets bound as the assignment target.
    annotation_separator: Optional[str] = None
    annotation_sources: Dict[str, str] = field(default_factory=dict)
    backtick_command: bool = False
    bare_call_names: FrozenSet[str] = frozenset()
    assignment_operators: Tuple[str, ...] = ("=", "+=", ".=")


_JS_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"', "`"),
    interpolation_markers=(("${", "}"),),
    identifier_extra="_$",
)

_PHP_LEXER = LexerProfile(
    line_comments=("//", "#"),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("{$", "}"),),
    dollar_interpolation=True,
    identifier_extra="_$",
    heredoc_markers=("<<<",),
    multichar_operators=("===", "!==", "==", "!=", "<=", ">=", "&&", "||", "->", "::", ".=", "=>"),
)

_JAVA_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    identifier_extra="_$",
)

_RUBY_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(("=begin", "=end"),),
    plain_quotes=("'",),
    interpolating_quotes=('"', "`"),
    interpolation_markers=(("#{", "}"),),
    identifier_extra="_@$?!",
    heredoc_markers=("<<~", "<<-"),
)

_GO_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    raw_quotes=("`",),
    identifier_extra="_",
    multichar_operators=(
        ":=",
        "==",
        "!=",
        "<=",
        ">=",
        "&&",
        "||",
        "+=",
        "-=",
        "*=",
        "/=",
        "<-",
        "...",
    ),
)

_CSHARP_LEXER = LexerProfile(
    line_comments=("//",),
    block_comments=(("/*", "*/"),),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(("{", "}"),),
    identifier_extra="_@",
)

_SHELL_LEXER = LexerProfile(
    line_comments=("#",),
    block_comments=(),
    plain_quotes=("'",),
    interpolating_quotes=('"',),
    interpolation_markers=(),
    dollar_interpolation=True,
    identifier_extra="_$-./",
    heredoc_markers=("<<",),
    multichar_operators=("&&", "||", ">>", "<<", "|&"),
)


_JS_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "globalEval", "window.eval", "geval"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "eval()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("Function", "vm.compileFunction"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "hàm khởi tạo Function",
    ),
    GenericSink(
        ("vm.runInThisContext", "vm.runInNewContext", "vm.runInContext", "vm.Script"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "module vm",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("setTimeout", "setInterval", "setImmediate"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "callback của timer bị thực thi như mã",
    ),
    GenericSink(
        ("exec", "execSync", "child_process.exec", "child_process.execSync", "shelljs.exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "một lệnh shell",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("spawn", "spawnSync", "execFile", "execFileSync", "fork"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "việc tạo tiến trình",
        program_position=True,
    ),
    GenericSink(
        ("query", "raw", "unsafe", "sequelize.query", "knex.raw", "db.query", "client.query"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL",
        require_sql=True,
    ),
    GenericSink(
        ("require", "import"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp module",
    ),
    GenericSink(
        ("write", "writeln", "document.write", "document.writeln", "insertAdjacentHTML", "html"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "nơi xuất HTML thô",
    ),
    GenericSink(
        ("unserialize", "node_serialize.unserialize", "serialize.unserialize"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự đối tượng",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("yaml.load", "jsyaml.load", "safeLoadAll"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự YAML",
    ),
)

# Nhãn nguồn dữ liệu hiện thẳng trong báo cáo, và cùng một nhãn được dùng lại
# cho hàng chục API khác nhau. Gõ tay mỗi lần thì chỉ cần sai một bản là báo
# cáo mô tả cùng một loại nguồn theo hai kiểu khác nhau.
QUERY_PARAM = "tham số truy vấn HTTP"
REQUEST_BODY = "body của request HTTP"
PATH_PARAM = "tham số đường dẫn HTTP"
HTTP_HEADER = "header HTTP"
HTTP_COOKIE = "cookie HTTP"
REQUEST_PARAM = "tham số của request HTTP"
FORM_FIELD = "trường form HTTP"
URL_QUERY_FRAGMENT = "fragment hoặc query của URL"
DOCUMENT_URL = "URL của tài liệu"
COMMAND_LINE_ARG = "tham số dòng lệnh"
ENVIRONMENT_VARIABLE = "biến môi trường"
QUERY_STRING = "query string HTTP"
STANDARD_INPUT = "luồng nhập chuẩn"

_JS_SOURCES: Dict[str, str] = {
    "req.query": QUERY_PARAM,
    "req.body": REQUEST_BODY,
    "req.params": PATH_PARAM,
    "req.headers": HTTP_HEADER,
    "req.cookies": HTTP_COOKIE,
    "req.rawBody": REQUEST_BODY,
    "req.param": REQUEST_PARAM,
    "req.get": HTTP_HEADER,
    "request.query": QUERY_PARAM,
    "request.body": REQUEST_BODY,
    "request.params": PATH_PARAM,
    "request.headers": HTTP_HEADER,
    "ctx.query": QUERY_PARAM,
    "ctx.request": "request HTTP",
    "ctx.params": PATH_PARAM,
    "location.search": URL_QUERY_FRAGMENT,
    "location.hash": URL_QUERY_FRAGMENT,
    "location.href": URL_QUERY_FRAGMENT,
    "location.pathname": "đường dẫn URL",
    "window.location": URL_QUERY_FRAGMENT,
    "window.name": "tên cửa sổ",
    "document.URL": DOCUMENT_URL,
    "document.documentURI": DOCUMENT_URL,
    "document.referrer": "referrer của tài liệu",
    "document.location": DOCUMENT_URL,
    "localStorage.getItem": "kho lưu trữ trình duyệt",
    "sessionStorage.getItem": "kho lưu trữ trình duyệt",
    "event.data": "dữ liệu sự kiện message",
    "event.body": "dữ liệu sự kiện",
    "event.queryStringParameters": "dữ liệu sự kiện",
    "process.argv": COMMAND_LINE_ARG,
}

_PHP_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "assert", "create_function"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "eval()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("preg_replace", "preg_replace_callback"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        None,
        "một phép thay thế bằng biểu thức chính quy",
        argument_index=1,
    ),
    GenericSink(
        ("system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "một lệnh shell",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("mysqli_query", "mysqli_multi_query", "pg_query", "sqlite_query", "mysqli_prepare"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL",
        argument_index=1,
        require_sql=True,
    ),
    GenericSink(
        ("mysql_query", "query", "exec", "prepare"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL",
        require_sql=True,
    ),
    GenericSink(
        ("unserialize",),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "unserialize()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("include", "include_once", "require", "require_once"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "một lệnh nạp tệp",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("call_user_func", "call_user_func_array", "array_map", "usort"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "một callable động",
    ),
    GenericSink(
        ("extract", "parse_str"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "việc chèn biến vào phạm vi cục bộ",
    ),
    GenericSink(
        ("ldap_search", "ldap_list", "ldap_read"),
        Category.LDAP,
        "FSB-LDAP-001",
        None,
        "một bộ lọc LDAP",
        argument_index=2,
    ),
    GenericSink(
        ("simplexml_load_string", "DOMDocument.loadXML"),
        Category.XML,
        "FSB-XML-001",
        None,
        "một bộ phân tích XML",
    ),
)

_PHP_SOURCES: Dict[str, str] = {
    "$_GET": QUERY_PARAM,
    "$_POST": FORM_FIELD,
    "$_REQUEST": REQUEST_PARAM,
    "$_COOKIE": HTTP_COOKIE,
    "$_SERVER": "biến server HTTP",
    "$_FILES": "tệp tải lên qua HTTP",
    "$_ENV": ENVIRONMENT_VARIABLE,
    "$HTTP_RAW_POST_DATA": REQUEST_BODY,
    "$argv": COMMAND_LINE_ARG,
    "getenv": ENVIRONMENT_VARIABLE,
    "filter_input": REQUEST_PARAM,
    "apache_request_headers": HTTP_HEADER,
    "getallheaders": HTTP_HEADER,
}

_JAVA_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Runtime.exec", "getRuntime.exec", "Runtime.getRuntime.exec"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "Runtime.exec()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("ProcessBuilder", "ProcessBuilder.command"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "ProcessBuilder",
        program_position=True,
    ),
    GenericSink(
        ("ScriptEngine.eval", "engine.eval", "GroovyShell.evaluate", "shell.evaluate"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "một script engine",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        (
            "executeQuery",
            "executeUpdate",
            "execute",
            "createQuery",
            "createNativeQuery",
            "createSQLQuery",
            "queryForObject",
            "queryForList",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL hoặc JPQL",
        require_sql=True,
    ),
    GenericSink(
        ("readObject", "XMLDecoder", "readUnshared"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "việc giải tuần tự đối tượng Java",
    ),
    GenericSink(
        (
            "parseExpression",
            "Ognl.getValue",
            "MVEL.eval",
            "ExpressionParser.parseExpression",
            "getValue",
        ),
        Category.EXPRESSION_LANGUAGE,
        "FSB-EL-001",
        None,
        "một bộ đánh giá expression language",
    ),
    GenericSink(
        ("Class.forName", "loadClass", "Assembly.load"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp class động",
    ),
    GenericSink(
        ("XPathExpression.evaluate", "xpath.evaluate", "compile"),
        Category.XPATH,
        "FSB-XPATH-001",
        None,
        "một biểu thức XPath",
    ),
)

_JAVA_SOURCES: Dict[str, str] = {
    "request.getParameter": QUERY_PARAM,
    "request.getParameterValues": QUERY_PARAM,
    "request.getHeader": HTTP_HEADER,
    "request.getHeaders": HTTP_HEADER,
    "request.getQueryString": QUERY_STRING,
    "request.getCookies": HTTP_COOKIE,
    "request.getInputStream": REQUEST_BODY,
    "request.getReader": REQUEST_BODY,
    "request.getRequestURI": "đường dẫn của request HTTP",
    "request.getPathInfo": "đường dẫn của request HTTP",
    "req.getParameter": QUERY_PARAM,
    "req.getHeader": HTTP_HEADER,
    "System.getenv": ENVIRONMENT_VARIABLE,
    "System.getProperty": "thuộc tính hệ thống",
}

_JAVA_ANNOTATIONS: Dict[str, str] = {
    "RequestParam": QUERY_PARAM,
    "PathVariable": PATH_PARAM,
    "RequestBody": REQUEST_BODY,
    "RequestHeader": HTTP_HEADER,
    "CookieValue": HTTP_COOKIE,
    "QueryParam": QUERY_PARAM,
    "PathParam": PATH_PARAM,
    "FormParam": FORM_FIELD,
    "HeaderParam": HTTP_HEADER,
}

_RUBY_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval", "instance_eval", "class_eval", "module_eval", "binding.eval"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "eval()",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("system", "exec", "spawn", "IO.popen", "Open3.capture2", "Open3.capture3"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "một lệnh shell",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("send", "public_send", "__send__", "const_get", "method"),
        Category.REFLECTION,
        "FSB-REFL-001",
        None,
        "việc điều phối phương thức động",
    ),
    GenericSink(
        ("find_by_sql", "execute", "where", "order", "select_all", "exec_query"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL",
        require_sql=True,
    ),
    GenericSink(
        ("Marshal.load", "YAML.load", "Psych.load", "Marshal.restore"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự đối tượng",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("ERB.new", "Erubi.new", "Liquid.Template.parse"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        "FSB-TMPL-002",
        "một trình biên dịch template",
    ),
)

_RUBY_SOURCES: Dict[str, str] = {
    "params": REQUEST_PARAM,
    "request.params": REQUEST_PARAM,
    "request.body": REQUEST_BODY,
    "request.query_string": QUERY_STRING,
    "request.env": HTTP_HEADER,
    "cookies": HTTP_COOKIE,
    "session": "giá trị session",
    "ENV": ENVIRONMENT_VARIABLE,
    "ARGV": COMMAND_LINE_ARG,
    "gets": STANDARD_INPUT,
    "STDIN.gets": STANDARD_INPUT,
}

_GO_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("exec.Command", "exec.CommandContext"),
        Category.COMMAND,
        "FSB-CMD-002",
        None,
        "os/exec",
        program_position=True,
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("db.Query", "db.Exec", "db.QueryRow", "Query", "Exec", "QueryRow", "QueryContext"),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một truy vấn SQL",
        require_sql=True,
    ),
    GenericSink(
        ("template.HTML", "template.JS", "template.URL", "template.HTMLAttr"),
        Category.MARKUP,
        "FSB-XSS-001",
        None,
        "một giá trị template không được escape",
    ),
    GenericSink(
        ("Parse", "template.New", "ParseGlob"),
        Category.TEMPLATE,
        "FSB-TMPL-001",
        None,
        "một trình biên dịch template",
    ),
    GenericSink(
        ("gob.NewDecoder", "Decode"),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        None,
        "một bộ giải mã",
    ),
)

_GO_SOURCES: Dict[str, str] = {
    "r.URL.Query": QUERY_PARAM,
    "r.FormValue": FORM_FIELD,
    "r.PostFormValue": FORM_FIELD,
    "r.Header.Get": HTTP_HEADER,
    "r.Body": REQUEST_BODY,
    "req.URL.Query": QUERY_PARAM,
    "req.FormValue": FORM_FIELD,
    "mux.Vars": PATH_PARAM,
    "c.Param": PATH_PARAM,
    "c.Query": QUERY_PARAM,
    "os.Args": COMMAND_LINE_ARG,
    "os.Getenv": ENVIRONMENT_VARIABLE,
}

_CSHARP_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("Process.Start", "ProcessStartInfo"),
        Category.COMMAND,
        "FSB-CMD-001",
        "FSB-CMD-003",
        "việc tạo tiến trình",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        (
            "SqlCommand",
            "OleDbCommand",
            "MySqlCommand",
            "NpgsqlCommand",
            "ExecuteReader",
            "ExecuteNonQuery",
            "ExecuteScalar",
            "FromSqlRaw",
            "ExecuteSqlRaw",
        ),
        Category.SQL,
        "FSB-SQL-001",
        "FSB-SQL-002",
        "một câu lệnh SQL",
        require_sql=True,
    ),
    GenericSink(
        (
            "BinaryFormatter.Deserialize",
            "Deserialize",
            "LosFormatter.Deserialize",
            "NetDataContractSerializer.Deserialize",
            "ObjectStateFormatter.Deserialize",
        ),
        Category.DESERIALIZATION,
        "FSB-DESER-001",
        "FSB-DESER-002",
        "một bộ giải tuần tự .NET",
    ),
    GenericSink(
        ("Assembly.Load", "Assembly.LoadFrom", "Type.GetType", "Activator.CreateInstance"),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc nạp assembly hoặc kiểu động",
    ),
    GenericSink(
        ("CompileAssemblyFromSource", "CSharpScript.EvaluateAsync", "CSharpScript.RunAsync"),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "việc biên dịch lúc chạy",
        confidence=Confidence.HIGH,
    ),
)

_CSHARP_SOURCES: Dict[str, str] = {
    "Request.QueryString": QUERY_PARAM,
    "Request.Form": FORM_FIELD,
    "Request.Params": REQUEST_PARAM,
    "Request.Headers": HTTP_HEADER,
    "Request.Cookies": HTTP_COOKIE,
    "Request.Body": REQUEST_BODY,
    "Request.Query": QUERY_PARAM,
    "Environment.GetEnvironmentVariable": ENVIRONMENT_VARIABLE,
}

_SHELL_SINKS: Tuple[GenericSink, ...] = (
    GenericSink(
        ("eval",),
        Category.CODE_EXECUTION,
        "FSB-EXEC-001",
        "FSB-EXEC-002",
        "eval",
        confidence=Confidence.HIGH,
    ),
    GenericSink(
        ("source", "."),
        Category.DYNAMIC_IMPORT,
        "FSB-IMPORT-001",
        "FSB-IMPORT-002",
        "việc source một script",
    ),
)

_SHELL_SOURCES: Dict[str, str] = {
    "$1": COMMAND_LINE_ARG,
    "$2": COMMAND_LINE_ARG,
    "$3": COMMAND_LINE_ARG,
    "$4": COMMAND_LINE_ARG,
    "$5": COMMAND_LINE_ARG,
    "$@": COMMAND_LINE_ARG,
    "$*": COMMAND_LINE_ARG,
    "$REPLY": STANDARD_INPUT,
    "$QUERY_STRING": QUERY_STRING,
    "$HTTP_USER_AGENT": HTTP_HEADER,
    "$GITHUB_HEAD_REF": "tham chiếu CI không tin cậy",
    "$GITHUB_EVENT_NAME": "đầu vào CI không tin cậy",
}


SPECS: Dict[str, LanguageSpec] = {
    JAVASCRIPT: LanguageSpec(
        language=JAVASCRIPT,
        lexer=_JS_LEXER,
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        assignment_sinks={
            "innerHTML": ("FSB-XSS-001", Category.MARKUP, "innerHTML"),
            "outerHTML": ("FSB-XSS-001", Category.MARKUP, "outerHTML"),
            "srcdoc": ("FSB-XSS-001", Category.MARKUP, "srcdoc"),
            "dangerouslySetInnerHTML": (
                "FSB-XSS-001",
                Category.MARKUP,
                "dangerouslySetInnerHTML",
            ),
        },
        sanitizers=frozenset(
            {
                "encodeURIComponent",
                "encodeURI",
                "parseInt",
                "parseFloat",
                "Number",
                "DOMPurify.sanitize",
                "sanitizeHtml",
                "validator.escape",
                "shellQuote.quote",
                "escapeHtml",
            }
        ),
        declaration_keywords=frozenset({"var", "let", "const"}),
    ),
    TYPESCRIPT: LanguageSpec(
        language=TYPESCRIPT,
        lexer=_JS_LEXER,
        sources=_JS_SOURCES,
        sinks=_JS_SINKS,
        assignment_sinks={
            "innerHTML": ("FSB-XSS-001", Category.MARKUP, "innerHTML"),
            "outerHTML": ("FSB-XSS-001", Category.MARKUP, "outerHTML"),
            "dangerouslySetInnerHTML": (
                "FSB-XSS-001",
                Category.MARKUP,
                "dangerouslySetInnerHTML",
            ),
        },
        sanitizers=frozenset(
            {
                "encodeURIComponent",
                "encodeURI",
                "parseInt",
                "parseFloat",
                "Number",
                "DOMPurify.sanitize",
                "sanitizeHtml",
                "escapeHtml",
            }
        ),
        declaration_keywords=frozenset({"var", "let", "const"}),
        annotation_separator=":",
    ),
    PHP: LanguageSpec(
        language=PHP,
        lexer=_PHP_LEXER,
        sources=_PHP_SOURCES,
        sinks=_PHP_SINKS,
        sanitizers=frozenset(
            {
                "escapeshellarg",
                "escapeshellcmd",
                "intval",
                "floatval",
                "htmlspecialchars",
                "htmlentities",
                "preg_quote",
                "filter_var",
                "basename",
                "urlencode",
                "rawurlencode",
            }
        ),
        weak_sanitizers=frozenset(
            {"addslashes", "mysql_real_escape_string", "mysqli_real_escape_string", "quote"}
        ),
        chain_separators=("->", "::"),
        backtick_command=True,
        bare_call_names=frozenset(
            {"include", "include_once", "require", "require_once", "echo", "print"}
        ),
    ),
    JAVA: LanguageSpec(
        language=JAVA,
        lexer=_JAVA_LEXER,
        sources=_JAVA_SOURCES,
        sinks=_JAVA_SINKS,
        sanitizers=frozenset(
            {
                "Integer.parseInt",
                "Long.parseLong",
                "Double.parseDouble",
                "UUID.fromString",
                "Encode.forHtml",
                "StringEscapeUtils.escapeHtml4",
                "ESAPI.encoder",
            }
        ),
        annotation_sources=_JAVA_ANNOTATIONS,
    ),
    RUBY: LanguageSpec(
        language=RUBY,
        lexer=_RUBY_LEXER,
        sources=_RUBY_SOURCES,
        sinks=_RUBY_SINKS,
        sanitizers=frozenset(
            {
                "Integer",
                "Float",
                "to_i",
                "to_f",
                "Shellwords.escape",
                "Shellwords.shellescape",
                "ERB::Util.html_escape",
                "CGI.escapeHTML",
            }
        ),
        backtick_command=True,
    ),
    GO: LanguageSpec(
        language=GO,
        lexer=_GO_LEXER,
        sources=_GO_SOURCES,
        sinks=_GO_SINKS,
        sanitizers=frozenset(
            {
                "strconv.Atoi",
                "strconv.ParseInt",
                "strconv.ParseFloat",
                "html.EscapeString",
                "url.QueryEscape",
                "template.HTMLEscapeString",
            }
        ),
        declaration_keywords=frozenset({"var", "const"}),
        assignment_operators=("=", ":=", "+="),
    ),
    CSHARP: LanguageSpec(
        language=CSHARP,
        lexer=_CSHARP_LEXER,
        sources=_CSHARP_SOURCES,
        sinks=_CSHARP_SINKS,
        sanitizers=frozenset(
            {
                "int.Parse",
                "Int32.Parse",
                "Int64.Parse",
                "Convert.ToInt32",
                "Guid.Parse",
                "HttpUtility.HtmlEncode",
                "AntiXss.HtmlEncode",
            }
        ),
        declaration_keywords=frozenset({"var", "string", "int", "object"}),
    ),
    SHELL: LanguageSpec(
        language=SHELL,
        lexer=_SHELL_LEXER,
        sources=_SHELL_SOURCES,
        sinks=_SHELL_SINKS,
        sanitizers=frozenset({"printf"}),
        backtick_command=True,
    ),
}


def spec_for(language: str) -> Optional[LanguageSpec]:
    return SPECS.get(language)
