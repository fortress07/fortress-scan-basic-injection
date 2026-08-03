from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


class PathConfinementError(Exception):
    pass


def resolve_root(candidate: str) -> Path:
    path = Path(candidate).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathConfinementError("không phân giải được đường dẫn cần quét: %s" % candidate) from exc
    if not resolved.is_dir() and not resolved.is_file():
        raise PathConfinementError("đường dẫn cần quét không phải tệp cũng không phải thư mục: %s" % candidate)
    return resolved


def is_within(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def safe_resolve(root: Path, candidate: Path) -> Optional[Path]:
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    if resolved == root:
        return resolved
    if not is_within(root, resolved):
        return None
    return resolved


def is_link_like(path: Path) -> bool:
    try:
        if path.is_symlink():
            return True
    except OSError:
        return True
    junction_check = getattr(path, "is_junction", None)
    if junction_check is not None:
        try:
            if junction_check():
                return True
        except OSError:
            return True
    return False


def is_regular_file(path: Path) -> bool:
    try:
        status = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    import stat as stat_module

    return stat_module.S_ISREG(status.st_mode)


def relative_display(root: Path, path: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def validate_output_path(candidate: str) -> Path:
    path = Path(candidate).expanduser()
    parent = path.parent if str(path.parent) else Path(".")
    try:
        resolved_parent = parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PathConfinementError("thư mục xuất kết quả không tồn tại: %s" % parent) from exc
    if not resolved_parent.is_dir():
        raise PathConfinementError("đường dẫn cha của tệp xuất không phải thư mục: %s" % parent)
    target = resolved_parent / path.name
    if is_link_like(target):
        raise PathConfinementError("từ chối ghi xuyên qua một liên kết: %s" % candidate)
    return target
