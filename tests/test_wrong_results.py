"""Những chỗ công cụ có thể cho kết quả SAI NGHIÊM TRỌNG.

Sai ở đây không phải là báo thừa một dòng. Sai ở đây là bỏ sót một lỗ hổng
thật, hoặc che mất một lỗ hổng vừa được thêm vào, trong khi vẫn in ra chữ
"sạch". Đó là kiểu hỏng duy nhất khiến một công cụ bảo mật trở nên nguy hiểm
hơn là không dùng nó, vì người ta đã thôi tự kiểm dựa trên câu trả lời của nó.

Hai lỗi dưới đây đều có thật và đều do chính bản 0.1.0 tạo ra.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fortress_scan.cli import main as cli_main
from fortress_scan.core import baseline as baseline_module
from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan, scan_source
from fortress_scan.languages import PYTHON


def rules(source: str):
    return [f.rule_id for f in scan_source(source, PYTHON, "app.py", Config())]


# ------------------------------------------- chú thích kiểu không phải lời hứa


def test_flask_ignores_type_annotations_on_route_parameters():
    """Python không ép kiểu theo chú thích, và Flask cũng không.

    `@app.route('/x/<so>')` luôn giao vào một chuỗi. Coi `so: int` là bằng
    chứng đã ép kiểu là bỏ sót thẳng một command injection còn nguyên.
    """
    source = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x/<so>')\n"
        "def h(so: int):\n"
        "    os.system('ping ' + str(so))\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_flask_route_converter_is_enforced_and_stays_silent():
    """`<int:so>` thì Flask có thi hành thật: sai kiểu là 404 trước khi vào hàm."""
    source = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x/<int:so>')\n"
        "def h(so):\n"
        "    os.system('sleep %d' % so)\n"
    )
    assert rules(source) == []


@pytest.mark.parametrize("framework", ["fastapi", "litestar", "blacksheep", "ninja"])
def test_frameworks_that_do_enforce_annotations_stay_silent(framework: str):
    source = (
        "import os\n"
        "from %s import App\n"
        "app = App()\n"
        "@app.get('/x')\n"
        "def h(so: int):\n"
        "    os.system('sleep %%d' %% so)\n" % framework
    )
    assert rules(source) == []


def test_a_framework_that_is_not_imported_promises_nothing():
    """Không thấy framework nào ép kiểu thì chú thích chỉ là chú thích."""
    source = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x')\n"
        "def h(ten: int):\n"
        "    os.system('ping ' + str(ten))\n"
    )
    assert "FSB-CMD-001" in rules(source)


# ------------------------------------------- vân tay không được trùng nhau


DUPLICATED = (
    "import os\n"
    "from flask import request\n"
    "def a():\n"
    "    os.system('ping ' + request.args['h'])\n"
    "def b():\n"
    "    os.system('ping ' + request.args['h'])\n"
    "def c():\n"
    "    os.system('ping ' + request.args['h'])\n"
)


def test_identical_findings_get_distinct_fingerprints():
    found = scan_source(DUPLICATED, PYTHON, "app.py", Config())
    assert len(found) == 3
    assert len({item.fingerprint for item in found}) == 3


def test_the_first_occurrence_keeps_the_plain_fingerprint():
    """Đánh số mà đổi luôn vân tay của cái đầu tiên thì mọi baseline đã ghi
    trước đây hỏng hết trong im lặng."""
    single = (
        "import os\n"
        "from flask import request\n"
        "def a():\n"
        "    os.system('ping ' + request.args['h'])\n"
    )
    alone = scan_source(single, PYTHON, "app.py", Config())[0]
    first_of_many = scan_source(DUPLICATED, PYTHON, "app.py", Config())[0]
    assert alone.fingerprint == first_of_many.fingerprint
    assert alone.occurrence == 0


def test_a_baseline_does_not_hide_a_newly_added_identical_finding():
    """Đây là lỗi nặng nhất trong nhóm này.

    Baseline ghi lúc tệp mới có một dòng thủng. Người ta thêm một dòng thủng
    thứ hai y hệt. Trước khi vá, cả hai cùng một vân tay nên baseline che sạch
    và cổng CI vẫn xanh: người ta vừa thêm một lỗ hổng mà công cụ báo an toàn.
    """
    single = (
        "import os\n"
        "from flask import request\n"
        "def a():\n"
        "    os.system('ping ' + request.args['h'])\n"
    )
    known = {item.fingerprint for item in scan_source(single, PYTHON, "app.py", Config())}
    later = scan_source(DUPLICATED, PYTHON, "app.py", Config())
    kept, hidden = baseline_module.apply(later, known)
    assert hidden == 1
    assert len(kept) == 2


def test_baseline_round_trip_still_hides_everything(tmp_path: Path, capsys):
    """Vá xong mà baseline hết tác dụng thì lại là đổi lỗi lấy lỗi."""
    (tmp_path / "app.py").write_text(DUPLICATED, encoding="utf-8")
    stored = tmp_path / "baseline.json"
    cli_main([str(tmp_path), "--quiet", "--no-config", "--write-baseline", str(stored)])
    capsys.readouterr()
    cli_main([str(tmp_path), "-f", "json", "--no-config", "--baseline", str(stored)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total"] == 0
    assert payload["summary"]["baselined"] == 3


def test_numbering_is_stable_across_runs(tmp_path: Path):
    (tmp_path / "app.py").write_text(DUPLICATED, encoding="utf-8")
    first = [item.fingerprint for item in scan(str(tmp_path), Config()).findings]
    second = [item.fingerprint for item in scan(str(tmp_path), Config()).findings]
    assert first == second


# ---------------------------- `<<` là toán tử dịch trái, không phải heredoc


def test_perl_left_shift_does_not_swallow_the_rest_of_the_file():
    """`my $mask = 1 << 8;` từng nuốt trọn phần đuôi tệp.

    Bộ tách token nhận `<< 8` là mở heredoc, và vì không có dòng kết thúc nào
    nên mọi thứ phía sau rơi vào một chuỗi. Mọi phát hiện trong phần đó biến
    mất: không lỗi, không cảnh báo, chỉ là một báo cáo sạch không đúng sự thật.
    """
    source = (
        "my $mask = 1 << 8;\n"
        "my $host = $q->param('host');\n"
        'system("ping $host");\n'
    )
    assert "FSB-CMD-001" in [
        item.rule_id for item in scan_source(source, "perl", "x.pl", Config())
    ]


def test_perl_shift_by_a_constant_name_is_not_a_heredoc():
    """Nhãn trần của Perl phải dính liền `<<`; có khoảng trắng là phép dịch."""
    source = (
        "my $mask = 1 << BITS;\n"
        "my $host = $q->param('host');\n"
        'system("ping $host");\n'
    )
    assert "FSB-CMD-001" in [
        item.rule_id for item in scan_source(source, "perl", "x.pl", Config())
    ]


def test_shell_arithmetic_shift_does_not_swallow_the_rest_of_the_file():
    source = "V=$(( 1 << 8 ))\nTARGET=$1\nrsync -a ./dist/ $TARGET\n"
    assert "FSB-CMD-004" in [
        item.rule_id for item in scan_source(source, "shell", "x.sh", Config())
    ]


@pytest.mark.parametrize(
    "language,source",
    [
        ("perl", 'my $t = <<EOT;\nxin chao\nEOT\nmy $h = $q->param(\'h\');\nsystem("ping $h");\n'),
        (
            "perl",
            'my $t = << "EOT";\nxin chao\nEOT\nmy $h = $q->param(\'h\');\nsystem("ping $h");\n',
        ),
        ("shell", "cat << EOF\nxin chao\nEOF\nTARGET=$1\nrsync -a ./dist/ $TARGET\n"),
    ],
)
def test_real_heredocs_still_close_properly(language: str, source: str):
    """Siết lại mà làm hỏng heredoc thật thì phần thân lại lọt ra làm mã."""
    assert [item.rule_id for item in scan_source(source, language, "x", Config())]


def test_numbering_does_not_depend_on_thread_count(tmp_path: Path):
    """Số thứ tự gán sau khi đã sắp xếp, nên --jobs không được đổi nó."""
    for index in range(6):
        (tmp_path / ("m%d.py" % index)).write_text(DUPLICATED, encoding="utf-8")
    one = [item.fingerprint for item in scan(str(tmp_path), Config(jobs=1)).findings]
    many = [item.fingerprint for item in scan(str(tmp_path), Config(jobs=8)).findings]
    assert one == many
    assert len(set(one)) == len(one)
