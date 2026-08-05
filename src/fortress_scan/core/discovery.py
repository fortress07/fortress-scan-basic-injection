from __future__ import annotations

import io
import os
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, List, Optional, Set, Tuple

from ..languages import PYTHON, detect_language, is_scannable_name
from ..security import paths as safe_paths
from .config import Config
from .ignore import IgnoreSet
from .model import ScanError

IGNORE_FILENAMES: Tuple[str, ...] = (".fortress-scanignore",)
VCS_IGNORE_FILENAMES: Tuple[str, ...] = (".gitignore",)

_BINARY_PROBE_BYTES = 8192
_MAX_STRAY_NULL_BYTES = 4


@dataclass(frozen=True)
class DiscoveredFile:
    path: Path
    relative: str
    language: str
    size: int


class Discovery:
    def __init__(self, root: Path, config: Config) -> None:
        self._root = root
        self._config = config
        self._excluded = frozenset(config.excluded_directories)
        self._explicit = IgnoreSet.from_lines(config.exclude_patterns)
        self._include = IgnoreSet.from_lines(config.include_patterns)
        self._visited_directories: Set[Tuple[int, int]] = set()
        self.errors: List[ScanError] = []
        self.skipped = 0

    def walk(self) -> Iterator[DiscoveredFile]:
        if self._root.is_file():
            candidate = self._consider(self._root, self._root.name)
            if candidate is not None:
                yield candidate
            return
        base_ignore = self._load_ignore_files(self._root)
        yielded = 0
        total_bytes = 0
        for discovered in self._walk_directory(self._root, base_ignore, 0):
            if yielded >= self._config.max_files:
                self.errors.append(
                    ScanError(
                        path=".",
                        reason="file-limit-reached",
                        detail="dừng sau %d tệp" % self._config.max_files,
                    )
                )
                return
            total_bytes += discovered.size
            if total_bytes > self._config.max_total_bytes:
                self.errors.append(
                    ScanError(
                        path=".",
                        reason="byte-limit-reached",
                        detail="dừng sau %d byte" % self._config.max_total_bytes,
                    )
                )
                return
            yielded += 1
            yield discovered

    def _load_ignore_files(self, directory: Path) -> IgnoreSet:
        ignore = self._explicit
        names: List[str] = []
        if self._config.respect_ignore_files:
            names.extend(IGNORE_FILENAMES)
        if self._config.respect_vcs_ignore:
            names.extend(VCS_IGNORE_FILENAMES)
        for name in names:
            candidate = directory / name
            if candidate.is_file() and not safe_paths.is_link_like(candidate):
                loaded = IgnoreSet.from_file(candidate)
                if loaded.overflowed:
                    self.errors.append(
                        ScanError(
                            path=safe_paths.relative_display(self._root, candidate),
                            reason="ignore-file-too-complex",
                            detail=(
                                "vượt hạn mức mẫu nên toàn bộ quy tắc trong tệp này bị bỏ; "
                                "không tệp nào bị ẩn khỏi lượt quét"
                            ),
                        )
                    )
                ignore = ignore.merged(loaded)
        return ignore

    def _walk_directory(
        self, directory: Path, inherited: IgnoreSet, depth: int
    ) -> Iterator[DiscoveredFile]:
        if depth > 64:
            self.errors.append(
                ScanError(
                    path=safe_paths.relative_display(self._root, directory),
                    reason="depth-limit",
                    detail="thư mục lồng nhau vượt quá 64 cấp",
                )
            )
            return
        try:
            key = self._directory_key(directory)
        except OSError:
            return
        if key is not None:
            if key in self._visited_directories:
                return
            self._visited_directories.add(key)

        ignore = inherited if depth == 0 else inherited.merged(self._load_ignore_files(directory))

        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as exc:
            self.errors.append(
                ScanError(
                    path=safe_paths.relative_display(self._root, directory),
                    reason="unreadable-directory",
                    detail=exc.strerror or "",
                )
            )
            return

        subdirectories: List[Path] = []
        for entry in entries:
            entry_path = Path(entry.path)
            relative = safe_paths.relative_display(self._root, entry_path)
            try:
                is_directory = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue

            if self._is_link(entry, entry_path):
                if not self._config.follow_symlinks:
                    self.skipped += 1
                    continue
                if safe_paths.safe_resolve(self._root, entry_path) is None:
                    self.skipped += 1
                    self.errors.append(
                        ScanError(
                            path=relative,
                            reason="link-escapes-root",
                            detail="liên kết trỏ ra ngoài thư mục đang quét",
                        )
                    )
                    continue

            if is_directory:
                if entry.name in self._excluded:
                    continue
                if ignore.matches(relative, True):
                    continue
                subdirectories.append(entry_path)
                continue

            if ignore.matches(relative, False):
                continue
            if self._include and not self._include.matches(relative, False):
                continue
            candidate = self._consider(entry_path, relative)
            if candidate is not None:
                yield candidate

        for subdirectory in subdirectories:
            for discovered in self._walk_directory(subdirectory, ignore, depth + 1):
                yield discovered

    def _is_link(self, entry: "os.DirEntry[str]", entry_path: Path) -> bool:
        try:
            if entry.is_symlink():
                return True
        except OSError:
            return True
        junction_check = getattr(entry, "is_junction", None)
        if junction_check is not None:
            try:
                if junction_check():
                    return True
            except OSError:
                return True
        return safe_paths.is_link_like(entry_path)

    def _directory_key(self, directory: Path) -> Optional[Tuple[int, int]]:
        status = os.stat(directory)
        if status.st_dev == 0 and status.st_ino == 0:
            return None
        return (status.st_dev, status.st_ino)

    def _consider(self, path: Path, relative: str) -> Optional[DiscoveredFile]:
        if not is_scannable_name(path.name):
            return None
        language = detect_language(path)
        if language is None:
            return None
        if not safe_paths.is_regular_file(path):
            self.skipped += 1
            return None
        try:
            size = path.stat().st_size
        except OSError:
            self.skipped += 1
            return None
        if size == 0:
            return None
        if size > self._config.max_file_bytes:
            self.skipped += 1
            self.errors.append(
                ScanError(
                    path=relative,
                    reason="file-too-large",
                    detail="%d byte vượt giới hạn %d byte"
                    % (size, self._config.max_file_bytes),
                )
            )
            return None
        if _looks_binary(path):
            self.skipped += 1
            # Bỏ qua thì được, nhưng bỏ qua trong im lặng thì không: tệp này
            # mang phần mở rộng của một ngôn ngữ được hỗ trợ, nên người đọc
            # báo cáo phải biết là nó chưa từng được soi.
            self.errors.append(
                ScanError(
                    path=relative,
                    reason="binary-skipped",
                    detail="tệp %s chứa dữ liệu nhị phân nên không được phân tích" % language,
                )
            )
            return None
        return DiscoveredFile(path=path, relative=relative, language=language, size=size)


def _looks_binary(path: Path) -> bool:
    """Chỉ tệp có phần mở rộng của một ngôn ngữ mới đi tới đây, nên "nhị phân"
    ở đây nghĩa là UTF-16 hoặc một khối dữ liệu bị đặt nhầm tên.

    Một byte NUL lẻ thì không đủ để kết luận: nhét đúng một byte đó vào chuỗi
    là đủ khiến cả tệp biến mất khỏi lần quét, trong khi Node, PHP hay trình
    thông dịch vẫn chạy tệp bình thường. Những thứ thật sự nhị phân có NUL
    dày đặc chứ không phải một hai byte.
    """
    try:
        with open(path, "rb") as handle:
            probe = handle.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True
    return probe.count(b"\x00") > _MAX_STRAY_NULL_BYTES


def declared_python_encoding(raw: bytes) -> Optional[str]:
    """Cách CPython chọn bảng mã cho một tệp .py (PEP 263), hoặc None nếu tệp
    khai báo một bảng mã mà chính CPython cũng từ chối."""
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    except SyntaxError:
        return None
    return encoding


def read_source(path: Path, language: Optional[str] = None) -> Tuple[str, bool]:
    with open(path, "rb") as handle:
        raw = handle.read()
    if language == PYTHON:
        return _decode_python(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    try:
        return raw.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), True


def _decode_python(raw: bytes) -> Tuple[str, bool]:
    """Giải mã đúng như CPython sẽ làm khi chạy tệp này.

    Đọc cứng UTF-8 là một lỗ hổng thật: một tệp khai báo `# coding: utf-7` bị
    CPython đọc ra mã hoàn toàn khác với những gì đọc theo UTF-8 -- `+AAo-`
    trong UTF-7 là một dấu xuống dòng, nên thứ trông như một dòng chú thích
    lại là mã chạy được. Phân tích sai bản giải mã thì sink thật không bao giờ
    lọt vào AST.
    """
    encoding = declared_python_encoding(raw)
    if encoding is not None:
        try:
            return raw.decode(encoding), False
        except (LookupError, ValueError):  # ValueError bao cả UnicodeDecodeError
            pass
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="replace"), True
