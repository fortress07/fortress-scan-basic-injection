from __future__ import annotations

import builtins
import io
import os
import socket
import subprocess
from pathlib import Path
from typing import List, Tuple

import pytest

from fortress_scan.core.config import Config
from fortress_scan.core.engine import scan
from fortress_scan.security import runtime as sandbox

WRITE_MODES = ("w", "a", "x", "+")


def build_project(root: Path) -> None:
    (root / "app").mkdir(parents=True)
    (root / "app" / "routes.py").write_text(
        "import os\nfrom flask import request\n"
        "def handler():\n    os.system('ping ' + request.args.get('h'))\n",
        encoding="utf-8",
    )
    (root / "app" / "db.py").write_text(
        "def tim(cursor, ma):\n"
        "    cursor.execute('SELECT * FROM users WHERE id = ' + ma)\n",
        encoding="utf-8",
    )
    (root / "server.js").write_text(
        "app.get('/x', (req, res) => { eval(req.query.e); });\n", encoding="utf-8"
    )
    (root / ".gitignore").write_text("*.log\n", encoding="utf-8")


def snapshot(root: Path):
    entries = {}
    for path in sorted(root.rglob("*")):
        status = path.stat()
        entries[str(path.relative_to(root))] = (
            path.is_dir(),
            status.st_size if path.is_file() else 0,
            status.st_mtime_ns,
        )
    return entries


class WriteRecorder:
    def __init__(self) -> None:
        self.writes: List[Tuple[str, str]] = []
        self.reads: List[str] = []
        self._original_builtins = builtins.open
        self._original_io = io.open

    def _wrapper(self, original):
        def opener(file, mode="r", *args, **kwargs):
            try:
                name = os.fspath(file)
            except TypeError:
                name = repr(file)
            if any(flag in mode for flag in WRITE_MODES):
                self.writes.append((str(name), mode))
            else:
                self.reads.append(str(name))
            return original(file, mode, *args, **kwargs)

        return opener

    def __enter__(self) -> "WriteRecorder":
        builtins.open = self._wrapper(self._original_builtins)
        io.open = self._wrapper(self._original_io)
        return self

    def __exit__(self, *_exc: object) -> None:
        builtins.open = self._original_builtins
        io.open = self._original_io


def test_scan_does_not_touch_the_scanned_tree(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)

    before = snapshot(project)
    result = scan(str(project), Config())
    after = snapshot(project)

    assert result.findings, "phai co phat hien de phep thu co y nghia"
    assert before == after, "quet da lam thay doi cay thu muc duoc quet"


def test_scan_performs_no_write_operation(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)

    with WriteRecorder() as recorder:
        result = scan(str(project), Config())

    assert result.findings
    assert recorder.writes == [], "quet da mo tep o che do ghi: %s" % recorder.writes


def test_scan_reads_nothing_outside_the_scan_root(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)
    (tmp_path / "bi_mat.txt").write_text("khong duoc doc", encoding="utf-8")

    with WriteRecorder() as recorder:
        scan(str(project), Config())

    root = str(project.resolve()).lower()
    outside = [
        path
        for path in recorder.reads
        if not str(Path(path).resolve()).lower().startswith(root)
    ]
    assert outside == [], "quet da doc tep ngoai thu muc chi dinh: %s" % outside


def test_scan_creates_no_pycache_in_the_scanned_project(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)

    scan(str(project), Config())

    caches = [str(p) for p in project.rglob("__pycache__")]
    pyc = [str(p) for p in project.rglob("*.pyc")]
    assert caches == [], "da tao __pycache__ trong du an duoc quet: %s" % caches
    assert pyc == [], "da tao tep .pyc trong du an duoc quet: %s" % pyc


def test_scan_opens_no_network_connection(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)

    attempts: List[str] = []
    original = socket.socket

    def spy(*args, **kwargs):
        attempts.append("socket")
        return original(*args, **kwargs)

    socket.socket = spy
    try:
        scan(str(project), Config())
    finally:
        socket.socket = original

    assert attempts == [], "quet da tao socket mang"


def test_sandbox_blocks_network_and_process_during_a_scan(tmp_path: Path):
    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)

    sandbox.engage()
    try:
        result = scan(str(project), Config())
        assert result.findings
        with pytest.raises(sandbox.SandboxViolation):
            socket.socket()
        with pytest.raises(sandbox.SandboxViolation):
            subprocess.Popen(["echo", "x"])
        with pytest.raises(sandbox.SandboxViolation):
            os.system("echo x")
    finally:
        sandbox.release()


def test_writes_happen_only_when_the_user_asks_for_a_file(tmp_path: Path):
    from fortress_scan.report import to_json

    project = tmp_path / "du_an"
    project.mkdir()
    build_project(project)
    destination = tmp_path / "bao_cao.json"

    result = scan(str(project), Config())
    with WriteRecorder() as recorder:
        destination.write_text(to_json(result, "0.1.0"), encoding="utf-8")

    written = [path for path, _ in recorder.writes]
    assert written == [str(destination)], "chi duoc ghi dung tep nguoi dung yeu cau: %s" % written


NETWORK_MODULES = frozenset(
    {
        "urllib",
        "http",
        "httplib",
        "requests",
        "httpx",
        "aiohttp",
        "smtplib",
        "ftplib",
        "telnetlib",
        "poplib",
        "imaplib",
        "nntplib",
        "webbrowser",
        "xmlrpc",
        "socketserver",
        "ssl",
        "ctypes",
    }
)

NEUTRALIZED_MODULES = frozenset({"socket", "subprocess"})


def collect_imports():
    import ast

    root = Path(__file__).resolve().parent.parent / "src" / "fortress_scan"
    found = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.setdefault(alias.name.split(".")[0], set()).add(path.name)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                found.setdefault(node.module.split(".")[0], set()).add(path.name)
    return found


def test_tool_imports_no_network_library():
    imports = collect_imports()
    offenders = {
        module: sorted(files)
        for module, files in imports.items()
        if module in NETWORK_MODULES and files != {"runtime.py"}
    }
    assert offenders == {}, "cong cu import thu vien mang: %s" % offenders


def test_socket_and_subprocess_appear_only_where_they_are_blocked():
    imports = collect_imports()
    for module in NEUTRALIZED_MODULES:
        files = imports.get(module, set())
        assert files <= {"runtime.py"}, (
            "%s chi duoc phep xuat hien trong security/runtime.py (noi vo hieu hoa no), "
            "nhung tim thay o: %s" % (module, sorted(files))
        )
