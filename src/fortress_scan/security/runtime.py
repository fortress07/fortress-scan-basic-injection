from __future__ import annotations

import os
import socket
import subprocess
import sys
from typing import Any, Callable, Dict, List, Tuple


class SandboxViolation(RuntimeError):
    pass


_PATCHED = False
_ORIGINALS: Dict[str, Any] = {}


def _blocked_network(*_args: Any, **_kwargs: Any) -> Any:
    raise SandboxViolation(
        "đã chặn truy cập mạng: Fortress Scan không bao giờ gửi đi mã nguồn hay dữ liệu thống kê"
    )


def _blocked_process(*_args: Any, **_kwargs: Any) -> Any:
    raise SandboxViolation(
        "đã chặn tạo tiến trình: Fortress Scan phân tích mã nguồn mà không chạy nó"
    )


_NETWORK_TARGETS: Tuple[Tuple[Any, str], ...] = (
    (socket, "socket"),
    (socket, "create_connection"),
    (socket, "create_server"),
)

_PROCESS_TARGETS: Tuple[Tuple[Any, str], ...] = (
    (subprocess, "Popen"),
    (subprocess, "run"),
    (subprocess, "call"),
    (subprocess, "check_call"),
    (subprocess, "check_output"),
    (os, "system"),
    (os, "popen"),
    (os, "execv"),
    (os, "execve"),
    (os, "execvp"),
    (os, "execvpe"),
    (os, "spawnv"),
    (os, "spawnve"),
    (os, "posix_spawn"),
    (os, "fork"),
    (os, "forkpty"),
)


def engage() -> None:
    global _PATCHED
    if _PATCHED:
        return
    for module, attribute in _NETWORK_TARGETS:
        _replace(module, attribute, _blocked_network)
    for module, attribute in _PROCESS_TARGETS:
        _replace(module, attribute, _blocked_process)
    _PATCHED = True


def release() -> None:
    global _PATCHED
    if not _PATCHED:
        return
    for key, original in _ORIGINALS.items():
        module_name, attribute = key.split(":", 1)
        module = sys.modules.get(module_name)
        if module is not None:
            setattr(module, attribute, original)
    _ORIGINALS.clear()
    _PATCHED = False


def _replace(module: Any, attribute: str, replacement: Callable[..., Any]) -> None:
    original = getattr(module, attribute, None)
    if original is None:
        return
    key = "%s:%s" % (module.__name__, attribute)
    _ORIGINALS[key] = original
    try:
        setattr(module, attribute, replacement)
    except (AttributeError, TypeError):
        _ORIGINALS.pop(key, None)


def is_engaged() -> bool:
    return _PATCHED


def elevated_privilege_warnings() -> List[str]:
    warnings: List[str] = []
    getuid = getattr(os, "geteuid", None)
    if getuid is not None and getuid() == 0:
        warnings.append(
            "đang chạy bằng quyền root; hãy quét mã không tin cậy bằng tài khoản thường"
        )
    if os.name == "nt":
        try:
            import ctypes

            if ctypes.windll.shell32.IsUserAnAdmin():
                warnings.append(
                    "đang chạy bằng quyền Administrator; hãy quét mã không tin cậy bằng tài khoản thường"
                )
        except Exception:
            pass
    return warnings
