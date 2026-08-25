"""Chỉ mục hàm dùng chung giữa các tệp Python của cùng một lượt quét.

Phân tích taint từng tệp ( 0.1 ) không thấy dữ liệu bẩn rời khỏi tệp nó đi
vào: một handler gọi helper ở tệp khác thì sink nằm trong helper không bao
giờ được báo. Module này giữ phần "summary" của mọi hàm trong dự án -- tham
số nào chảy tới sink nào, tham số nào sống sót qua lời return -- để lượt
phân tích của tệp gọi áp được summary đó như áp summary của hàm cùng tệp.

Vì summary được tính riêng cho từng tệp rồi ghép lại nên đây là xấp xỉ có
chặn trên, không phải fixpoint toàn cục: engine chạy thêm một vòng tinh
chỉnh ( tính lại summary với chỉ mục vòng một ) để bắt chuỗi gọi qua hai
tệp trung gian, rồi dừng.
"""

from __future__ import annotations

import builtins
from typing import Dict, FrozenSet, Optional, Set, Tuple

from .analyzer import FunctionInfo, Summary

# Dấu nhận diện cho node của hàm ở tệp khác: không bao giờ trùng với một
# ast.AST thật cũng như None, để bộ chống đệ quy ( "đừng áp summary của
# chính hàm đang xét" ) không nhầm nó với hàm cục bộ.
FOREIGN_NODE = object()

MAX_INDEX_MODULES = 5000
MAX_INDEX_FUNCTIONS = 20000

# Tên trần trùng một builtin thì không bao giờ được tra qua chỉ mục dự án.
# `map(...)` trong tệp không import `map` là builtin, chứ không phải `Style.map`
# của tkinter. Nối nhầm hai thứ đó làm taint thật bị vứt, và phát hiện tụt từ
# FSB-EXEC-001 xuống FSB-EXEC-002: bật phân tích xuyên file lại làm kết quả yếu
# đi. Hàm người dùng tự đặt trùng tên builtin vẫn chạy bình thường, vì
# `from helpers import map` được phân giải thành `helpers.map` nên đi đường
# dotted.
_BUILTIN_NAMES: FrozenSet[str] = frozenset(dir(builtins))


def module_names(relative_path: str) -> Tuple[str, ...]:
    """Những tên module mà một tệp có thể được import dưới, từ dài nhất.

    ``app/services/helpers.py`` import được dưới dạng ``app.services.helpers``,
    ``services.helpers`` hay ``helpers`` tùy sys.path của dự án, nên đăng ký
    cả ba; xung đột tên sẽ bị loại ở ``register`` theo hướng bảo toàn.
    """
    parts = relative_path.replace("\\", "/").strip("/").split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        return ()
    stem = parts[-1]
    if stem == "__init__.py":
        stem_parts = parts[:-1]
    elif stem.endswith(".py"):
        stem_parts = parts[:-1] + [stem[: -len(".py")]]
    else:
        return ()
    if not stem_parts or any(not part.isidentifier() for part in stem_parts):
        return ()
    return tuple(
        ".".join(stem_parts[index:]) for index in range(len(stem_parts))
    )


class ProjectIndex:
    """Bảng summary hàm của toàn dự án, tra theo tên import hoặc tên đơn."""

    def __init__(self) -> None:
        self._dotted: Dict[str, FunctionInfo] = {}
        self._simple: Dict[str, FunctionInfo] = {}
        # Tên đã từng đụng độ phải ở lại "mập mờ" VĨNH VIỄN. Trước đây đụng độ
        # chỉ được xử lý bằng cách xóa khóa cuối mỗi lần register, nên module
        # thứ ba dùng lại tên đó tạo lại khóa với đúng một phần tử và giành
        # được liên kết: 3 module cùng định nghĩa `run` thì `run` trỏ về module
        # cuối, 4 module thì lại sạch - sai theo tính chẵn lẻ. Tên phổ biến
        # ( run, query, execute, handle ) đụng nhau khắp mọi repo thật, và cái
        # giá là taint xuyên file quy sink về NHẦM tệp.
        self._ambiguous_dotted: Set[str] = set()
        self._ambiguous_simple: Set[str] = set()
        self.functions_registered = 0
        self.modules_registered = 0
        self.full = False

    @staticmethod
    def _bind(
        table: Dict[str, FunctionInfo],
        ambiguous: Set[str],
        key: str,
        info: FunctionInfo,
    ) -> None:
        """Giữ liên kết chỉ khi tên còn trỏ về đúng một hàm."""
        if key in ambiguous:
            return
        current = table.get(key)
        if current is None:
            table[key] = info
        elif current is not info:
            # Một tên trỏ về nhiều hàm khác nhau thì mọi liên kết theo tên đó
            # đều mất giá trị: bỏ hẳn thay vì đoán mò một bên.
            del table[key]
            ambiguous.add(key)

    def register(
        self,
        relative_path: str,
        functions: Dict[str, FunctionInfo],
        summaries: Dict[str, Summary],
    ) -> None:
        names = module_names(relative_path)
        if not names or not functions:
            return
        if (
            self.modules_registered >= MAX_INDEX_MODULES
            or self.functions_registered >= MAX_INDEX_FUNCTIONS
        ):
            self.full = True
            return
        self.modules_registered += 1
        for qualname, info in sorted(functions.items()):
            if self.functions_registered >= MAX_INDEX_FUNCTIONS:
                self.full = True
                break
            summary = summaries.get(qualname)
            if summary is None or not summary.sinks and not summary.returns:
                # Hàm không chạm sink nào cũng không trả về taint thì áp
                # summary hay không cũng vậy -- đừng nhét vào chỉ mục.
                continue
            foreign = FunctionInfo(
                node=FOREIGN_NODE,
                qualname=qualname,
                simple_name=info.simple_name,
                parameters=info.parameters,
                handler_sources={},
                summary=summary,
                origin_path=relative_path.replace("\\", "/"),
            )
            if info.simple_name not in _BUILTIN_NAMES:
                self._bind(self._simple, self._ambiguous_simple, info.simple_name, foreign)
            for module_name in names:
                self._bind(
                    self._dotted,
                    self._ambiguous_dotted,
                    "%s.%s" % (module_name, qualname),
                    foreign,
                )
            self.functions_registered += 1

    def lookup(
        self, qualname: Optional[str], *, allow_simple: bool = True
    ) -> Optional[FunctionInfo]:
        """Tra hàm theo tên import; `allow_simple` bật tra thêm theo tên trần.

        Đường dotted ( `helpers.run_cmd` ) là liên kết có căn cứ import nên
        luôn được tra. Tên trần thì chỉ dành cho lời gọi `run_cmd(...)` không
        qua attribute: áp nó cho `cp.read(...)` là gán nguồn gốc sai cho một
        lời gọi phương thức trên đối tượng vô danh.
        """
        if not qualname:
            return None
        exact = self._dotted.get(qualname)
        if exact is not None:
            return exact
        if not allow_simple:
            return None
        return self._simple.get(qualname.rsplit(".", 1)[-1])
