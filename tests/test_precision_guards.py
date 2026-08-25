"""Độ chính xác: cách viết ĐÚNG phải im lặng, cách viết thủng vẫn phải bắn.

Mỗi kiểm tra ở đây là một cặp. Một mình vế "phải im lặng" thì cách sửa dễ
nhất luôn là tắt bớt rule, và bộ test vẫn xanh trong khi công cụ mù thêm một
chút. Vế "phải bắn" đứng ngay cạnh để chặn đúng đường đó.
"""

from __future__ import annotations

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.languages import PYTHON


def rules(source: str):
    return [f.rule_id for f in scan_source(source, PYTHON, "app.py", Config())]


def test_assert_guard_clears_the_value():
    """`assert x in CHO_PHEP` nói đúng điều mà `if x not in ...: raise` nói.

    Đây là cách viết kiểm tra rất phổ biến trong mã nội bộ; không đọc nó thì
    công cụ báo nhầm đúng vào chỗ tác giả đã cẩn thận.
    """
    source = (
        "import os\n"
        "from flask import request\n"
        "CHO_PHEP = ('a', 'b')\n"
        "def h():\n"
        "    a = request.args['a']\n"
        "    assert a in CHO_PHEP\n"
        "    os.system('echo ' + a)\n"
    )
    assert rules(source) == []


def test_assert_guard_only_covers_the_name_it_names():
    source = (
        "import os\n"
        "from flask import request\n"
        "CHO_PHEP = ('a',)\n"
        "def h():\n"
        "    a = request.args['a']\n"
        "    b = request.args['b']\n"
        "    assert a in CHO_PHEP\n"
        "    os.system('echo ' + b)\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_enum_construction_is_an_allowlist():
    """`Lenh(gia_tri)` hoặc khớp một thành viên, hoặc ném ValueError.

    Không có nhánh thứ ba, nên giá trị đi ra khỏi đó luôn là hằng viết sẵn
    trong thân lớp -- đúng định nghĩa của một phép kiểm danh sách cho phép.
    """
    source = (
        "import os\n"
        "import enum\n"
        "from flask import request\n"
        "class Lenh(enum.Enum):\n"
        "    A = 'ls'\n"
        "    B = 'pwd'\n"
        "def h():\n"
        "    os.system(Lenh(request.args['a']).value)\n"
    )
    assert rules(source) == []


def test_enum_imported_by_name_is_recognised_too():
    source = (
        "import os\n"
        "from enum import Enum\n"
        "from flask import request\n"
        "class Lenh(Enum):\n"
        "    A = 'ls'\n"
        "def h():\n"
        "    os.system(Lenh(request.args['a']).value)\n"
    )
    assert rules(source) == []


def test_a_type_annotation_outside_a_handler_promises_nothing():
    """Chú thích kiểu của Python không được ép lúc chạy.

    Với route handler thì framework kiểm trước khi thân hàm chạy, nên phép ép
    kiểu là thật. Với một hàm thường thì `def f(x: int)` chỉ là lời hứa của
    tác giả, và tin nó là tự tạo ra điểm mù.
    """
    source = (
        "import os\n"
        "def chay(muc_tieu: int):\n"
        "    os.system('ping ' + muc_tieu)\n"
    )
    assert "FSB-CMD-003" in rules(source)


def test_a_plain_class_is_not_an_enum():
    source = (
        "import os\n"
        "from flask import request\n"
        "class K:\n"
        "    def __init__(self, v):\n"
        "        self.v = v\n"
        "def h():\n"
        "    os.system('echo ' + K(request.args['a']).v)\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_mapping_get_does_not_carry_the_key():
    """`bang.get(khoa)` trả về GIÁ TRỊ trong bảng, không trả về khoá.

    Tra bảng ánh xạ là cách khử độc được khuyên dùng nhiều nhất; gộp cả khoá
    vào kết quả là báo nhầm đúng vào lời khuyên của chính công cụ. Phép tra
    bằng ngoặc vuông đã tính đúng từ trước.
    """
    source = (
        "import os\n"
        "from flask import request\n"
        "LENH = {'a': 'ls'}\n"
        "def h():\n"
        "    os.system(LENH.get(request.args['a'], 'true'))\n"
    )
    assert rules(source) == []


def test_mapping_get_still_carries_a_tainted_default():
    source = (
        "import os\n"
        "from flask import request\n"
        "LENH = {'a': 'ls'}\n"
        "def h():\n"
        "    os.system(LENH.get('a', request.args['b']))\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_mapping_get_on_a_tainted_container_still_flows():
    source = (
        "import os\n"
        "from flask import request\n"
        "def h():\n"
        "    os.system(request.args.get('a'))\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_route_converter_guarantees_the_type():
    source = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x/<int:so>')\n"
        "def h(so):\n"
        "    os.system('sleep %d' % so)\n"
    )
    assert rules(source) == []


def test_string_route_converter_guarantees_nothing():
    source = (
        "import os\n"
        "from flask import Flask\n"
        "app = Flask(__name__)\n"
        "@app.route('/x/<path:duong_dan>')\n"
        "def h(duong_dan):\n"
        "    os.system('cat ' + duong_dan)\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_annotated_integer_parameter_is_clean():
    source = (
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/x')\n"
        "def h(so: int):\n"
        "    os.system('sleep %d' % so)\n"
    )
    assert rules(source) == []


def test_annotated_string_parameter_is_not_clean():
    source = (
        "import os\n"
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "@app.get('/x')\n"
        "def h(ten: str):\n"
        "    os.system('echo ' + ten)\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_sqlalchemy_text_with_bound_parameters_is_silent():
    """Dạng tham số hoá đúng chuẩn không được bị gọi là "câu lệnh không phải hằng"."""
    source = (
        "from sqlalchemy import text\n"
        "from flask import request\n"
        "def h(conn):\n"
        "    stmt = text('SELECT * FROM t WHERE id = :id')\n"
        "    return conn.execute(stmt, {'id': request.args['i']})\n"
    )
    assert rules(source) == []


def test_sqlalchemy_text_built_by_concatenation_still_fires():
    source = (
        "from sqlalchemy import text\n"
        "from flask import request\n"
        "def h(conn):\n"
        "    stmt = text('SELECT * FROM t WHERE id = ' + request.args['i'])\n"
        "    return conn.execute(stmt)\n"
    )
    assert "FSB-SQL-001" in rules(source)


def test_validating_helper_clears_its_return_value():
    source = (
        "import os\n"
        "from flask import request\n"
        "CHO_PHEP = {'stop', 'start'}\n"
        "def chon(ten):\n"
        "    if ten not in CHO_PHEP:\n"
        "        raise ValueError('khong hop le')\n"
        "    return ten\n"
        "def h():\n"
        "    os.system('systemctl ' + chon(request.args['a']))\n"
    )
    assert rules(source) == []


def test_a_helper_that_validates_nothing_does_not_clear():
    source = (
        "import os\n"
        "from flask import request\n"
        "def chay(ten):\n"
        "    return ten\n"
        "def h():\n"
        "    os.system('systemctl ' + chay(request.args['a']))\n"
    )
    assert "FSB-CMD-001" in rules(source)


def test_validation_survives_two_hops_of_helpers():
    source = (
        "import os\n"
        "from flask import request\n"
        "CHO_PHEP = ('a',)\n"
        "def kiem(v):\n"
        "    if v not in CHO_PHEP:\n"
        "        raise ValueError\n"
        "    return v\n"
        "def boc(v):\n"
        "    return kiem(v)\n"
        "def h():\n"
        "    os.system('echo ' + boc(request.args['a']))\n"
    )
    assert rules(source) == []


def test_a_sanitizer_for_the_wrong_category_does_not_clear():
    """html.escape() không đụng tới một ký tự đặc biệt nào của shell."""
    source = (
        "import os\n"
        "import html\n"
        "from flask import request\n"
        "def h():\n"
        "    os.system('echo ' + html.escape(request.args['a']))\n"
    )
    assert "FSB-CMD-001" in rules(source)
