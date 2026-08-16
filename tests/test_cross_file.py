"""Phân tích taint xuyên file: dữ liệu bẩn rời khỏi tệp nó đi vào.

Trước 0.2, mọi phân tích Python dừng ở ranh giới tệp -- sink nằm trong
helper ở tệp khác thì không bao giờ được báo. Các test ở đây chạy qua
engine.scan() với một dự án nhiều tệp thật sự trong tmp_path, vì đúng cấu
trúc hai pha ( thu thập -> báo cáo ) chỉ tồn tại ở tầng engine.
"""

from __future__ import annotations

from pathlib import Path

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan


def _write(root: Path, name: str, source: str) -> None:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _ids(result) -> set:
    return {finding.rule_id for finding in result.findings}


def test_helper_sink_in_another_file_is_reported(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)
    finding = next(f for f in result.findings if f.rule_id == "FSB-CMD-001")
    # Phát hiện nằm ở lời gọi ( cùng tệp với nguồn ), đường đi chỉ rõ sink
    # nằm ở tệp helper.
    assert finding.path == "app.py"
    sink_step = finding.trace[-1]
    assert sink_step.path == "helpers.py"
    assert sink_step.line == 3


def test_chain_through_two_intermediate_files(tmp_path: Path):
    """web -> service -> runner: cần vòng tinh chỉnh của pha thu thập."""
    _write(
        tmp_path,
        "web.py",
        "from flask import request\n"
        "import service\n"
        "def handler():\n"
        "    return service.handle(request.args.get('q'))\n",
    )
    _write(
        tmp_path,
        "service.py",
        "import runner\n"
        "def handle(text):\n"
        "    return runner.execute(text)\n",
    )
    _write(
        tmp_path,
        "runner.py",
        "import subprocess\n"
        "def execute(cmd):\n"
        "    subprocess.call(cmd, shell=True)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_taint_returning_from_another_file_flows_to_local_sink(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import echo\n"
        "import os\n"
        "def handler():\n"
        "    payload = echo(request.args.get('c'))\n"
        "    os.system('run ' + payload)\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "def echo(value):\n"
        "    return value\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_sanitizer_inside_helper_clears_taint_for_caller(tmp_path: Path):
    """Bộ khử độc nằm trong tệp helper vẫn phải vô hiệu hoá được cho caller."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import safe_run\n"
        "def handler():\n"
        "    return safe_run(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "import shlex\n"
        "def safe_run(value):\n"
        "    os.system('ping ' + shlex.quote(value))\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" not in _ids(result)


def test_constant_argument_to_dangerous_helper_stays_silent(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd('localhost')\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" not in _ids(result)


def test_no_cross_file_flag_restores_single_file_behavior(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config(cross_file_analysis=False))
    assert "FSB-CMD-001" not in _ids(result)


def test_package_import_resolves_across_directories(tmp_path: Path):
    _write(
        tmp_path,
        "routes.py",
        "from flask import request\n"
        "from services.commands import run\n"
        "def handler():\n"
        "    return run(request.args.get('c'))\n",
    )
    _write(tmp_path, "services/__init__.py", "")
    _write(
        tmp_path,
        "services/commands.py",
        "import os\n"
        "def run(value):\n"
        "    os.system(value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_same_helper_name_in_two_modules_is_not_confused(tmp_path: Path):
    """Hai module cùng định nghĩa run(): không được quy sink cho tệp sai."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "import first\n"
        "def handler():\n"
        "    return first.run(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "first.py",
        "def run(value):\n"
        "    return value.upper()\n",
    )
    _write(
        tmp_path,
        "second.py",
        "import os\n"
        "def run(value):\n"
        "    os.system(value)\n",
    )
    result = scan(str(tmp_path), Config())
    # first.run sạch: gọi nó với dữ liệu bẩn không được sinh ra phát hiện
    # commande nào cả ( second.run không hề được gọi ).
    assert not any(
        f.rule_id == "FSB-CMD-001" and f.path == "app.py" for f in result.findings
    )


def test_findings_are_deterministic_across_runs(tmp_path: Path):
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import run_cmd\n"
        "def handler():\n"
        "    return run_cmd(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def run_cmd(value):\n"
        "    os.system('ping ' + value)\n",
    )
    first = scan(str(tmp_path), Config())
    second = scan(str(tmp_path), Config(jobs=4))
    assert [f.fingerprint for f in first.findings] == [f.fingerprint for f in second.findings]


def test_scan_source_stays_single_file():
    """API một tệp ( scan_source ) không được âm thầm đổi hành vi."""
    from fortress_scan import scan_source
    from fortress_scan.languages import PYTHON

    source = (
        "import os\n"
        "def handler(value):\n"
        "    os.system('ping ' + value)\n"
    )
    findings = scan_source(source, PYTHON, "app.py", Config())
    # Không có nguồn nào ở đây, chỉ có dạng động; giữ nguyên kỳ vọng cũ.
    assert all(f.rule_id != "FSB-CMD-001" for f in findings)


def test_method_call_never_binds_to_foreign_same_name_function(tmp_path: Path):
    """`cp.read(x)` là lời gọi phương thức, không được nhận summary của
    `def read(x)` ở module khác.

    Bug thật bắt được khi đối chiếu stdlib: fallback tên-trần từng áp cho cả
    attribute call, khiến chuỗi taint socket -> fileConfig -> eval trong
    logging/config.py bị cắt oan chỉ vì một module khác có hàm trùng tên
    `read` với summary 'tham số không sống qua return'.
    """
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "import os\n"
        "def handler(cp):\n"
        "    data = cp.read(request.args.get('q'))\n"
        "    os.system('run ' + data)\n",
    )
    _write(
        tmp_path,
        "reader.py",
        "def read(value):\n"
        "    return 'hằng an toàn'\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_ambiguous_simple_name_stays_ambiguous_for_any_module_count(tmp_path: Path):
    """Tên đụng độ phải mất liên kết VĨNH VIỄN, không theo tính chẵn lẻ.

    Chỉ mục từng xử lý đụng độ bằng cách xóa khóa ở cuối mỗi lần register.
    Module thứ ba dùng lại tên đó tạo lại khóa với đúng một phần tử và giành
    được liên kết, nên 3 module cùng định nghĩa `run_cmd` thì `run_cmd` trỏ
    về module cuối còn 4 module thì lại sạch. Hệ quả: taint xuyên file quy
    sink về NHẦM tệp tùy số lượng module - và tên phổ biến ( run, query,
    execute, handle ) đụng nhau khắp mọi repo thật.
    """
    from fortress_scan.analysis.python.analyzer import FunctionInfo, SinkHit, Summary
    from fortress_scan.analysis.python.project import ProjectIndex
    from fortress_scan.core.model import Category

    def info(path: str) -> FunctionInfo:
        hit = SinkHit(
            parameter="value",
            rule_id="FSB-CMD-001",
            category=Category.COMMAND,
            line=1,
            column=0,
            symbol="os.system",
            description="sink",
        )
        return FunctionInfo(
            node=object(),
            qualname="run_cmd",
            simple_name="run_cmd",
            parameters=("value",),
            handler_sources={},
            summary=Summary(sinks=frozenset({hit})),
            origin_path=path,
        )

    for module_count in range(2, 8):
        index = ProjectIndex()
        for number in range(module_count):
            path = "pkg/mod%d.py" % number
            entry = info(path)
            index.register(path, {"run_cmd": entry}, {"run_cmd": entry.summary})
        assert index.lookup("run_cmd") is None, (
            "%d module cùng tên vẫn trả về một liên kết" % module_count
        )


def test_unique_name_still_resolves_across_files(tmp_path: Path):
    """Bảo vệ chiều ngược lại: chống đụng độ không được làm câm tên duy nhất."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from only_helper import uniquely_named_runner\n"
        "def handler():\n"
        "    return uniquely_named_runner(request.args.get('c'))\n",
    )
    _write(
        tmp_path,
        "only_helper.py",
        "import os\n"
        "def uniquely_named_runner(value):\n"
        "    os.system('ping ' + value)\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_three_way_name_collision_does_not_invent_a_cross_file_trace(tmp_path: Path):
    """Đầu-đến-cuối cho cùng lỗi: 3 module định nghĩa `handle`, và chỉ một
    trong số đó có sink. Không có import nào nối tới nó, nên không được có
    phát hiện xuyên file nào trỏ sang tệp khác."""
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "def view(obj):\n"
        "    return obj.handle(request.args.get('q'))\n",
    )
    for number, body in enumerate(
        (
            "    return 'an toan'\n",
            "    return value.strip()\n",
            "    import os\n    os.system('ping ' + value)\n",
        )
    ):
        _write(tmp_path, "mod%d.py" % number, "def handle(value):\n%s" % body)
    result = scan(str(tmp_path), Config())
    cross = [f for f in result.findings if f.path == "app.py" and f.rule_id == "FSB-CMD-001"]
    assert not cross, "gán nhầm summary của một module trùng tên cho obj.handle()"


def test_bare_builtin_name_never_binds_to_a_foreign_function(tmp_path: Path):
    """`map(...)` trong tệp không import `map` là builtin, không phải hàm
    trùng tên ở module khác.

    Chỉ mục từng nối hai thứ đó, và vì summary của hàm lạ nói giá trị trả về
    chỉ sinh từ THAM SỐ CỦA NÓ, taint thật mang theo đối số bị vứt - phát
    hiện tụt từ "có vết nhiễm" xuống "giá trị không phải hằng". Đối chiếu cả
    stdlib bắt được đúng dạng này: socket -> fileConfig -> eval trong
    logging/config.py bị hạ cấp chỉ vì tkinter/ttk.py có `Style.map`.
    """
    # `query_opt` mới là thứ được trả về, còn `style` - chỗ mà đối số nhiễm
    # rơi vào khi lời gọi trần bị nối nhầm sang đây - thì không. Đó chính là
    # cách vết nhiễm bị vứt âm thầm.
    _write(
        tmp_path,
        "widget.py",
        "class Style:\n"
        "    def map(self, style, query_opt='mac dinh'):\n"
        "        return query_opt\n",
    )
    # Đúng hình dạng của logging/config.py: một helper trả thẳng kết quả
    # map() rồi giá trị đó chạy tiếp tới sink.
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "import os\n"
        "def _strip_spaces(alist):\n"
        "    return map(str.strip, alist)\n"
        "def handler():\n"
        "    data = _strip_spaces(request.args.get('q'))\n"
        "    os.system('ping ' + str(data))\n",
    )
    result = scan(str(tmp_path), Config())
    ids = _ids(result)
    # FSB-CMD-001 = có vết nhiễm ( kèm đường đi ); FSB-CMD-003 = chỉ "giá trị
    # không phải hằng". Nối nhầm builtin làm phát hiện tụt xuống loại yếu.
    assert "FSB-CMD-001" in ids, (
        "builtin bi nham voi ham cung ten o module khac nen vet nhiem bi vut: %s" % sorted(ids)
    )


def test_project_index_never_hands_out_a_builtin_name(tmp_path: Path):
    """Chốt thẳng ở tầng chỉ mục: tên trần trùng builtin không bao giờ được
    trả về, dù module kia có định nghĩa hàm trùng tên."""
    from fortress_scan.analysis.python.analyzer import FunctionInfo, SinkHit, Summary
    from fortress_scan.analysis.python.project import ProjectIndex
    from fortress_scan.core.model import Category

    hit = SinkHit(
        parameter="value",
        rule_id="FSB-CMD-001",
        category=Category.COMMAND,
        line=1,
        column=0,
        symbol="os.system",
        description="sink",
    )
    index = ProjectIndex()
    for name in ("map", "filter", "str", "set", "__import__", "open"):
        entry = FunctionInfo(
            node=object(),
            qualname="Style.%s" % name,
            simple_name=name,
            parameters=("value",),
            handler_sources={},
            summary=Summary(sinks=frozenset({hit})),
            origin_path="widget.py",
        )
        index.register("widget.py", {entry.qualname: entry}, {entry.qualname: entry.summary})
    for name in ("map", "filter", "str", "set", "__import__", "open"):
        assert index.lookup(name) is None, "ten trung builtin %r van duoc noi" % name


def test_user_function_named_like_a_builtin_still_resolves_when_imported(tmp_path: Path):
    """Chiều ngược lại: import tường minh thì vẫn phải nối được.

    Lời gọi đã import đi đường dotted nên việc chặn tên trần trùng builtin
    không được đụng tới nó.
    """
    _write(
        tmp_path,
        "helpers.py",
        "import os\n"
        "def filter(value):\n"
        "    os.system('ping ' + value)\n",
    )
    _write(
        tmp_path,
        "app.py",
        "from flask import request\n"
        "from helpers import filter\n"
        "def handler():\n"
        "    return filter(request.args.get('c'))\n",
    )
    result = scan(str(tmp_path), Config())
    assert "FSB-CMD-001" in _ids(result)


def test_foreign_sink_line_is_never_reported_in_the_caller_file(tmp_path: Path):
    """Dòng của sink ở tệp khác không được báo theo tọa độ của tệp gọi.

    SinkHit chép `line` vào summary mà không nhớ tệp gốc, nên khi một hàm
    CÙNG TỆP mang theo sink của tệp khác, phát hiện được báo ở dòng ấy trong
    tệp gọi. Đối chiếu stdlib ra một phát hiện ở logging/config.py dòng 1339
    trong khi tệp đó chỉ có 1066 dòng - vị trí không tồn tại.
    """
    padding = "\n".join("# dong dem %d" % index for index in range(40))
    _write(
        tmp_path,
        "deep.py",
        "import os\n%s\ndef deep_sink(value):\n    os.system('ping ' + value)\n" % padding,
    )
    app_source = (
        "from flask import request\n"
        "from deep import deep_sink\n"
        "def local_wrapper(value):\n"
        "    return deep_sink(value)\n"
        "def handler():\n"
        "    return local_wrapper(request.args.get('q'))\n"
    )
    _write(tmp_path, "app.py", app_source)
    app_lines = len(app_source.split("\n"))
    result = scan(str(tmp_path), Config())
    for finding in result.findings:
        if finding.path == "app.py":
            assert finding.line <= app_lines, (
                "bao o dong %d trong app.py chi co %d dong" % (finding.line, app_lines)
            )
        for step in finding.trace:
            if (step.path or finding.path) == "app.py":
                assert step.line <= app_lines, (
                    "buoc trace tro toi dong %d trong app.py" % step.line
                )
