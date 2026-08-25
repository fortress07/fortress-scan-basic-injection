from __future__ import annotations

import os
import socket
# Module này NHẬP subprocess chỉ để vá chặn nó ( xem _PROCESS_TARGETS bên
# dưới ); công cụ không bao giờ chạy tiến trình nào.
import subprocess  # nosec B404
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

# Đây là dây chuyền cảnh báo chứ không phải rào cản: mã bị quét không bao giờ
# được chạy, nên list này tồn tại để một lỗi tương lai nào đó chạm vào primitive
# tạo tiến trình sẽ bị phát hiện ngay. Nhớ phủ cả các biến thể ``l`` của họ
# exec*/spawn* -- trên nền tảng nào đó chúng tồn tại độc lập với họ ``v``.
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
    (os, "execl"),
    (os, "execle"),
    (os, "execlp"),
    (os, "spawnv"),
    (os, "spawnve"),
    (os, "spawnvp"),
    (os, "spawnvpe"),
    (os, "spawnl"),
    (os, "spawnle"),
    (os, "spawnlp"),
    (os, "spawnlpe"),
    (os, "posix_spawn"),
    (os, "posix_spawnp"),
    (os, "fork"),
    (os, "forkpty"),
    (os, "startfile"),
)

# pty chỉ tồn tại trên POSIX; bỏ qua nếu nền tảng không có.
try:
    import pty
except ImportError:
    pty = None  # type: ignore[assignment]
if pty is not None:
    _PROCESS_TARGETS = _PROCESS_TARGETS + ((pty, "spawn"),)


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


def _running_as_windows_admin() -> bool:
    """Kểm tra quyền Administrator trên Windows; sai nền tảng hoặc lỗi probe
    thì coi như không ( chỉ thiếu một dòng cảnh báo, không đáng ném lỗi )."""
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevated_privilege_warnings() -> List[str]:
    warnings: List[str] = []
    getuid = getattr(os, "geteuid", None)
    if getuid is not None and getuid() == 0:
        warnings.append(
            "đang chạy bằng quyền root; hãy quét mã không tin cậy bằng tài khoản thường"
        )
    if os.name == "nt" and _running_as_windows_admin():
        warnings.append(
            "đang chạy bằng quyền Administrator; hãy quét mã không tin cậy bằng tài khoản thường"
        )
    return warnings
