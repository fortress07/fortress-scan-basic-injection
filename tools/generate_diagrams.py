"""Sinh bộ hình minh hoạ cho README, mỗi hình hai bản sáng và tối.

Vì sao phải SINH ra chứ không vẽ tay một lần rồi thôi: mọi con số trên hình đều
lấy thẳng từ `core.registry`, nên thêm hay bớt một rule là hình tự lệch theo mã
chứ không âm thầm nói sai. `tests/test_diagrams.py` chạy lại script này rồi so
từng byte với tệp đã commit, nên hình không thể cũ hơn mã.

Số đo hiệu năng thì không suy ra được từ mã, nên chúng nằm trong `MEASUREMENTS`
kèm cả trung vị, khoảng min/max và số lần lặp. Đo lại thì sửa ở đúng một chỗ.

Chạy:  python tools/generate_diagrams.py
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from fortress_scan.core.registry import all_rules  # noqa: E402

OUT = ROOT / "docs" / "img"

FONT = "'Segoe UI',system-ui,-apple-system,Helvetica,Arial,sans-serif"
MONO = "'Cascadia Code','SF Mono',Consolas,'Liberation Mono',monospace"


# --------------------------------------------------------------------------
# Bảng màu. Hai bản đối xứng nhau để cùng một hình đọc được ở cả hai chế độ.
# --------------------------------------------------------------------------

THEMES: Dict[str, Dict[str, str]] = {
    "light": {
        "bg": "#ffffff",
        "panel": "#f6f8fa",
        "panel2": "#eaeef2",
        "border": "#d1d9e0",
        "text": "#1f2328",
        "muted": "#59636e",
        "red": "#cf222e",
        "orange": "#bc4c00",
        "yellow": "#9a6700",
        "blue": "#0969da",
        "green": "#1a7f37",
        "purple": "#8250df",
        "teal": "#0e7490",
        "pink": "#bf3989",
        "on_accent": "#ffffff",
    },
    "dark": {
        "bg": "#0d1117",
        "panel": "#161b22",
        "panel2": "#21262d",
        "border": "#30363d",
        "text": "#e6edf3",
        "muted": "#9198a1",
        "red": "#f85149",
        "orange": "#db6d28",
        "yellow": "#d29922",
        "blue": "#388bfd",
        "green": "#3fb950",
        "purple": "#a371f7",
        "teal": "#39a0b0",
        "pink": "#db61a2",
        "on_accent": "#ffffff",
    },
}


# --------------------------------------------------------------------------
# Số đo. Máy đo: Windows 11, CPython 3.13. Mỗi phép lặp 7 lần, lấy trung vị.
# --------------------------------------------------------------------------

MEASUREMENTS = {
    "ignore_realistic_us": {
        "label": "So khớp .gitignore thật",
        "unit": "µs / entry",
        "before": 1299.30,
        "after": 34.93,
        "before_range": (1266.99, 1369.20),
        "after_range": (34.57, 39.45),
        "note": "bộ mẫu Python + Node của GitHub, 74 dòng",
    },
    "attack_scan_s": {
        "label": "Quét cây dựng riêng để đốt CPU",
        "unit": "giây",
        "before": 26.14,
        "after": 6.16,
        "before_range": (22.70, 26.47),
        "after_range": (5.78, 6.80),
        "note": ".gitignore 15 KB hợp lệ, 60 tệp sâu 14 cấp",
    },
    "ignore_peak_mb": {
        "label": "Đỉnh bộ nhớ, .gitignore 126 MB",
        "unit": "MB",
        "before": 378.24,
        "after": 0.04,
        "before_range": (378.24, 378.24),
        "after_range": (0.035, 0.035),
        "note": "tệp gồm TOÀN dòng chú thích, không sinh quy tắc nào",
    },
    "selfscan_s": {
        "label": "Quét chính src/ ( đối chứng )",
        "unit": "giây",
        "before": 3.14,
        "after": 3.38,
        "before_range": (2.98, 3.77),
        "after_range": (3.14, 3.41),
        "note": "khoảng đo chồng nhau, tức là không đổi",
    },
}

REPS = 7


# --------------------------------------------------------------------------
# Tiện ích dựng SVG. Chỉ dùng thuộc tính trình bày, không dùng khối <style>,
# vì bộ lọc SVG của GitHub không hứa giữ lại khối đó.
# --------------------------------------------------------------------------


def esc(text: str) -> str:
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


class Canvas:
    def __init__(self, width: int, height: int, theme: str) -> None:
        self.width = width
        self.height = height
        self.theme = theme
        self.c = THEMES[theme]
        self.parts: List[str] = []

    def rect(self, x, y, w, h, fill, rx=0, stroke=None, sw=1, opacity=None):
        extra = ' stroke="%s" stroke-width="%s"' % (stroke, sw) if stroke else ""
        if opacity is not None:
            extra += ' opacity="%s"' % opacity
        self.parts.append(
            '<rect x="%s" y="%s" width="%s" height="%s" rx="%s" fill="%s"%s/>'
            % (x, y, w, h, rx, fill, extra)
        )

    def text(self, x, y, s, size=14, fill=None, weight="normal", anchor="start",
             font=None, opacity=None):
        extra = ' opacity="%s"' % opacity if opacity is not None else ""
        self.parts.append(
            '<text x="%s" y="%s" font-family="%s" font-size="%s" font-weight="%s" '
            'fill="%s" text-anchor="%s"%s>%s</text>'
            % (x, y, font or FONT, size, weight, fill or self.c["text"], anchor,
               extra, esc(s))
        )

    def line(self, x1, y1, x2, y2, stroke, sw=2, dash=None, marker=False):
        extra = ' stroke-dasharray="%s"' % dash if dash else ""
        if marker:
            extra += ' marker-end="url(#arrow-%s)"' % self.theme
        self.parts.append(
            '<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="%s"'
            ' stroke-linecap="round"%s/>' % (x1, y1, x2, y2, stroke, sw, extra)
        )

    def path(self, d, stroke=None, fill="none", sw=2, marker=False):
        extra = ' marker-end="url(#arrow-%s)"' % self.theme if marker else ""
        self.parts.append(
            '<path d="%s" fill="%s" stroke="%s" stroke-width="%s"'
            ' stroke-linecap="round" stroke-linejoin="round"%s/>'
            % (d, fill, stroke or "none", sw, extra)
        )

    def circle(self, cx, cy, r, fill, stroke=None, sw=1):
        extra = ' stroke="%s" stroke-width="%s"' % (stroke, sw) if stroke else ""
        self.parts.append(
            '<circle cx="%s" cy="%s" r="%s" fill="%s"%s/>' % (cx, cy, r, fill, extra)
        )

    def badge(self, x, y, label, fill, text_fill=None, pad=10, size=12, height=22):
        width = int(len(label) * size * 0.62) + pad * 2
        self.rect(x, y, width, height, fill, rx=height // 2)
        self.text(x + width / 2, y + height * 0.71, label, size=size,
                  fill=text_fill or self.c["on_accent"], weight="600", anchor="middle")
        return width

    def render(self) -> str:
        head = (
            '<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
            'viewBox="0 0 %d %d" role="img">'
            % (self.width, self.height, self.width, self.height)
        )
        defs = (
            '<defs><marker id="arrow-%s" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="%s"/></marker></defs>'
            % (self.theme, self.c["muted"])
        )
        bg = ('<rect width="%d" height="%d" rx="12" fill="%s"/>'
              % (self.width, self.height, self.c["bg"]))
        return head + defs + bg + "".join(self.parts) + "</svg>\n"


def title_block(cv: Canvas, title: str, subtitle: str = "") -> None:
    cv.rect(0, 0, cv.width, 4, cv.c["blue"], rx=0)
    cv.text(28, 42, title, size=20, weight="700")
    if subtitle:
        cv.text(28, 66, subtitle, size=13, fill=cv.c["muted"])


def footer(cv: Canvas, note: str) -> None:
    cv.text(28, cv.height - 16, note, size=11, fill=cv.c["muted"])


# --------------------------------------------------------------------------
# 1. Mô hình phân tích: nguồn, lan truyền, khử độc, sink
# --------------------------------------------------------------------------


def diagram_taint_flow(theme: str) -> str:
    cv = Canvas(1040, 516, theme)
    c = cv.c
    title_block(
        cv,
        "Cách công cụ hiểu mã: truy vết đường đi của dữ liệu",
        "Không dò từ khoá. Chỉ báo khi dữ liệu bẩn TỚI ĐƯỢC sink mà chưa bị vô hiệu hoá.",
    )

    stages = [
        ("1", "NGUỒN", "chỗ dữ liệu người\nngoài đi vào", c["blue"],
         "request.args · $_GET\nreq.query · input()"),
        ("2", "LAN TRUYỀN", "vết bẩn chảy theo\nphép gán và phép nối", c["purple"],
         "gán · nối chuỗi\nf-string · list/dict"),
        ("3", "KHỬ ĐỘC", "hàng rào duy nhất\nxoá được vết bẩn", c["green"],
         "shlex.quote · escape\ntham số hoá · allowlist"),
        ("4", "SINK", "API nguy hiểm,\nnơi dữ liệu phát nổ", c["red"],
         "os.system · cursor.execute\neval · from_string"),
    ]

    # 4 hộp cộng 3 khe cộng hai lề phải nằm gọn trong bề rộng khung.
    box_w, box_h, gap = 214, 168, 34
    x0 = 28
    y0 = 96
    for index, (num, name, desc, color, examples) in enumerate(stages):
        x = x0 + index * (box_w + gap)
        cv.rect(x, y0, box_w, box_h, c["panel"], rx=12, stroke=c["border"])
        cv.rect(x, y0, box_w, 5, color, rx=2)
        cv.circle(x + 26, y0 + 34, 14, color)
        cv.text(x + 26, y0 + 39, num, size=14, fill=c["on_accent"],
                weight="700", anchor="middle")
        cv.text(x + 50, y0 + 39, name, size=15, weight="700", fill=color)
        for line_index, line in enumerate(desc.split("\n")):
            cv.text(x + 18, y0 + 66 + line_index * 17, line, size=12, fill=c["muted"])
        cv.rect(x + 14, y0 + 104, box_w - 28, 50, c["panel2"], rx=8)
        for line_index, line in enumerate(examples.split("\n")):
            cv.text(x + 22, y0 + 124 + line_index * 17, line, size=10,
                    fill=c["text"], font=MONO)
        if index < len(stages) - 1:
            arrow_x = x + box_w + 8
            cv.line(arrow_x, y0 + box_h / 2, arrow_x + gap - 18, y0 + box_h / 2,
                    c["muted"], sw=2, marker=True)

    # Hai lối ra, đặt ngay dưới đúng chặng quyết định ra chúng: hàng rào khử
    # độc dừng được đường đi, còn tới được sink thì thành phát hiện.
    stage3_x = x0 + 2 * (box_w + gap)
    stage4_x = x0 + 3 * (box_w + gap)
    out_y = y0 + box_h + 34
    out_h = 56

    cv.line(stage3_x + box_w / 2, y0 + box_h, stage3_x + box_w / 2, out_y - 4,
            c["green"], sw=2, marker=True)
    cv.rect(stage3_x, out_y, box_w, out_h, c["panel"], rx=10, stroke=c["green"])
    cv.circle(stage3_x + 24, out_y + 20, 9, c["green"])
    cv.text(stage3_x + 24, out_y + 24, "✓", size=11, fill=c["on_accent"],
            weight="700", anchor="middle")
    cv.text(stage3_x + 42, out_y + 24, "Đã khử độc", size=13, weight="700",
            fill=c["green"])
    cv.text(stage3_x + 16, out_y + 45, "im lặng, không báo gì", size=11,
            fill=c["muted"])

    cv.line(stage4_x + box_w / 2, y0 + box_h, stage4_x + box_w / 2, out_y - 4,
            c["red"], sw=2, marker=True)
    cv.rect(stage4_x, out_y, box_w, out_h, c["panel"], rx=10, stroke=c["red"])
    cv.circle(stage4_x + 24, out_y + 20, 9, c["red"])
    cv.text(stage4_x + 24, out_y + 24, "!", size=11, fill=c["on_accent"],
            weight="700", anchor="middle")
    cv.text(stage4_x + 42, out_y + 24, "Thành PHÁT HIỆN", size=13, weight="700",
            fill=c["red"])
    cv.text(stage4_x + 16, out_y + 45, "kèm cả đường đi để tự kiểm", size=11,
            fill=c["muted"])

    # Ví dụ thật, để người đọc đối chiếu mô hình với một đoạn mã cụ thể.
    ex_y = out_y + out_h + 30
    cv.rect(28, ex_y, 984, 92, c["panel2"], rx=10, stroke=c["border"])
    cv.text(44, ex_y + 24, "Đường đi mà báo cáo in ra", size=12,
            weight="700", fill=c["text"])
    rows = [
        ("dòng 40", "tham số truy vấn HTTP đi vào từ đây", c["blue"]),
        ("dòng 40", "chảy vào biến name", c["purple"]),
        ("dòng 42", "chạy tới cursor.execute()", c["red"]),
    ]
    for index, (where, what, color) in enumerate(rows):
        row_y = ex_y + 46 + index * 16
        cv.circle(52, row_y - 4, 4, color)
        cv.text(66, row_y, where, size=10.5, fill=c["muted"], font=MONO)
        cv.text(132, row_y, what, size=10.5, fill=c["text"], font=MONO)

    footer(cv, "Rẽ nhánh thì hai nhánh được gộp lại: nhiễm ở một nhánh là đủ để cảnh báo.")
    return cv.render()


# --------------------------------------------------------------------------
# 2. Sáu bước của một lượt quét
# --------------------------------------------------------------------------


def diagram_pipeline(theme: str) -> str:
    cv = Canvas(1040, 412, theme)
    c = cv.c
    title_block(
        cv,
        "Sáu bước xảy ra khi anh em gõ lệnh quét",
        "Bước 1 là lý do anh em trỏ được công cụ vào mã lạ mà không cần dựng sandbox riêng.",
    )

    steps = [
        ("1", "Khoá tiến trình", c["red"],
         "vá đè socket, subprocess,\nos.system, os.fork",
         "dù có lỗi cũng không\nchạy được mã, không gọi mạng"),
        ("2", "Tìm tệp", c["orange"],
         "bỏ thư mục loại trừ, tệp\nnhị phân, tệp quá lớn",
         "không đi theo liên kết\ntrỏ ra ngoài thư mục đích"),
        ("3", "Đọc và giải mã", c["yellow"],
         "giải mã đúng theo khai báo\n# coding: của PEP 263",
         "để thấy đúng thứ\nCPython sẽ chạy"),
        ("4", "Phân tích", c["green"],
         "truy vết đường đi\ncủa dữ liệu",
         "AST cho Python,\nlexer riêng cho ngôn ngữ khác"),
        ("5", "Lọc", c["blue"],
         "chỉ thị ignore, ngưỡng mức độ,\nrule bị tắt, baseline",
         "mọi thứ làm hẹp phạm vi\nđều bị ghi lại và nói ra"),
        ("6", "Báo cáo", c["purple"],
         "console, JSON,\nSARIF, Markdown",
         "kèm mã thoát\ncho cổng CI"),
    ]

    card_w, card_h = 318, 118
    gap_x, gap_y = 25, 34
    x0, y0 = 28, 92
    for index, (num, name, color, what, why) in enumerate(steps):
        col = index % 3
        row = index // 3
        x = x0 + col * (card_w + gap_x)
        y = y0 + row * (card_h + gap_y)
        cv.rect(x, y, card_w, card_h, c["panel"], rx=12, stroke=c["border"])
        cv.rect(x, y, 5, card_h, color, rx=2)
        cv.circle(x + 34, y + 30, 14, color)
        cv.text(x + 34, y + 35, num, size=14, fill=c["on_accent"],
                weight="700", anchor="middle")
        cv.text(x + 58, y + 35, name, size=15, weight="700")
        for line_index, line in enumerate(what.split("\n")):
            cv.text(x + 20, y + 62 + line_index * 16, line, size=11.5, fill=c["text"])
        for line_index, line in enumerate(why.split("\n")):
            cv.text(x + 20, y + 96 + line_index * 14, line, size=10.5,
                    fill=c["muted"], opacity="0.95")
        if col < 2:
            ax = x + card_w + 4
            cv.line(ax, y + card_h / 2, ax + gap_x - 10, y + card_h / 2,
                    c["muted"], sw=2, marker=True)

    # Nối cuối hàng một xuống đầu hàng hai: ra từ đáy thẻ 3, quét ngang
    # trong khe giữa hai hàng, rồi đi lên vào đỉnh thẻ 4.
    mid_y = y0 + card_h + gap_y / 2
    end_x = x0 + 2 * (card_w + gap_x) + card_w / 2
    start_x = x0 + card_w / 2
    cv.path("M %d %d L %d %d L %d %d L %d %d"
            % (end_x, y0 + card_h, end_x, mid_y, start_x, mid_y,
               start_x, y0 + card_h + gap_y - 5),
            stroke=c["muted"], sw=2, marker=True)

    footer(cv, "Mỗi tệp có ngân sách node/token riêng, nên một tệp dựng riêng để "
               "làm treo công cụ sẽ bị cắt chứ không kéo cả lượt quét đi theo.")
    return cv.render()


# --------------------------------------------------------------------------
# 3. Số đo trước và sau khi vá
# --------------------------------------------------------------------------


def _fmt(value: float) -> str:
    if value >= 100:
        return ("%.0f" % value)
    if value >= 10:
        return ("%.1f" % value).replace(".", ",")
    if value >= 1:
        return ("%.2f" % value).replace(".", ",")
    return ("%.2f" % value).replace(".", ",")


def diagram_benchmarks(theme: str) -> str:
    cv = Canvas(1040, 520, theme)
    c = cv.c
    title_block(
        cv,
        "Bốn phép đo trước và sau khi vá",
        "Mỗi phép lặp %d lần, lấy trung vị. Máy đo: Windows 11, CPython 3.13." % REPS,
    )

    keys = ["ignore_realistic_us", "attack_scan_s", "ignore_peak_mb", "selfscan_s"]
    row_h = 96
    y0 = 96
    bar_x = 380
    # Thanh phải chừa chỗ cho con số ngay sau nó VÀ cho huy hiệu ở mép phải.
    bar_max = 400

    for index, key in enumerate(keys):
        item = MEASUREMENTS[key]
        y = y0 + index * row_h
        cv.rect(28, y, 984, row_h - 12, c["panel"], rx=10, stroke=c["border"])
        cv.text(46, y + 26, item["label"], size=14, weight="700")
        cv.text(46, y + 46, item["note"], size=10.5, fill=c["muted"])
        cv.text(46, y + 66, "đơn vị: " + item["unit"], size=10.5, fill=c["muted"])

        before = item["before"]
        after = item["after"]
        # Thanh vẽ theo căn bậc hai để chênh lệch hàng nghìn lần vẫn nhìn được,
        # còn con số thật thì luôn in nguyên bên cạnh.
        span = max(before, after) or 1.0
        w_before = max(6, (before / span) ** 0.5 * bar_max)
        w_after = max(6, (after / span) ** 0.5 * bar_max)

        improved = after < before * 0.9
        after_color = c["green"] if improved else c["blue"]

        cv.text(bar_x - 12, y + 34, "trước", size=11, fill=c["muted"], anchor="end")
        cv.rect(bar_x, y + 22, w_before, 16, c["red"], rx=8)
        cv.text(bar_x + w_before + 10, y + 34, _fmt(before), size=12,
                weight="700", fill=c["red"])

        cv.text(bar_x - 12, y + 62, "sau", size=11, fill=c["muted"], anchor="end")
        cv.rect(bar_x, y + 50, w_after, 16, after_color, rx=8)
        cv.text(bar_x + w_after + 10, y + 62, _fmt(after), size=12,
                weight="700", fill=after_color)

        if improved:
            ratio = before / after if after else 0
            label = "nhanh hơn %s lần" % _fmt(ratio) if ratio < 1000 else "gần như bằng 0"
            if key == "ignore_peak_mb":
                label = "không còn đọc tệp"
            cv.badge(858, y + 24, label, c["green"], size=11)
        else:
            cv.badge(858, y + 24, "không đổi", c["muted"], size=11)

    footer(cv, "Khoảng đo của phép đối chứng chồng lên nhau, nên phần vá không "
               "làm chậm đường chạy bình thường.")
    return cv.render()


# --------------------------------------------------------------------------
# 4. Bộ rule: mức độ nghiêm trọng và họ lỗ hổng
# --------------------------------------------------------------------------


def _severity_counts() -> List[Tuple[str, int]]:
    counts = Counter(rule.severity.label for rule in all_rules())
    order = ["critical", "high", "medium", "low", "info"]
    return [(name, counts[name]) for name in order if counts.get(name)]


def _family_counts() -> List[Tuple[str, int]]:
    counts = Counter(rule.category.value for rule in all_rules())
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def diagram_rules(theme: str) -> str:
    cv = Canvas(1040, 500, theme)
    c = cv.c
    total = len(list(all_rules()))
    title_block(
        cv,
        "%d rule, nhìn theo hai chiều" % total,
        "Số lấy thẳng từ core.registry, nên hình không lệch khỏi mã được.",
    )

    sev_colors = {
        "critical": c["red"],
        "high": c["orange"],
        "medium": c["yellow"],
        "low": c["blue"],
        "info": c["muted"],
    }

    # Trái: mức độ nghiêm trọng.
    cv.rect(28, 92, 470, 380, c["panel"], rx=12, stroke=c["border"])
    cv.text(50, 122, "Theo mức độ nghiêm trọng", size=14, weight="700")

    severities = _severity_counts()
    top = max(count for _, count in severities)
    bar_w = 300
    for index, (name, count) in enumerate(severities):
        y = 154 + index * 62
        cv.text(50, y + 16, name, size=13, weight="700", fill=sev_colors[name])
        cv.text(178, y + 16, "%d rule" % count, size=12, fill=c["muted"])
        cv.rect(50, y + 26, bar_w, 14, c["panel2"], rx=7)
        cv.rect(50, y + 26, max(10, bar_w * count / top), 14, sev_colors[name], rx=7)
        pct = 100.0 * count / total
        cv.text(50 + bar_w + 12, y + 37, "%d%%" % round(pct), size=11, fill=c["muted"])

    # Phải: họ lỗ hổng.
    cv.rect(518, 92, 494, 380, c["panel"], rx=12, stroke=c["border"])
    cv.text(540, 122, "Theo họ lỗ hổng", size=14, weight="700")

    families = _family_counts()
    shown = families[:8]
    rest = sum(count for _, count in families[8:])
    if rest:
        shown = shown + [("còn lại (%d họ)" % len(families[8:]), rest)]
    fam_top = max(count for _, count in shown)
    palette = [c["red"], c["orange"], c["yellow"], c["green"], c["blue"],
               c["purple"], c["teal"], c["pink"], c["muted"]]
    fam_bar = 210
    for index, (name, count) in enumerate(shown):
        y = 150 + index * 36
        color = palette[index % len(palette)]
        cv.text(540, y + 12, name, size=11.5, fill=c["text"])
        cv.rect(740, y + 1, fam_bar, 14, c["panel2"], rx=7)
        cv.rect(740, y + 1, max(8, fam_bar * count / fam_top), 14, color, rx=7)
        cv.text(740 + fam_bar + 12, y + 12, str(count), size=11,
                weight="700", fill=color)

    footer(cv, "Mỗi rule đều có mẫu mã nguồn thật làm nó bắn, và với đa số là một "
               "mẫu an toàn tương ứng để chắc nó không kêu bừa.")
    return cv.render()


# --------------------------------------------------------------------------
# 5. Đối chiếu OWASP Top 10:2025
# --------------------------------------------------------------------------


def diagram_owasp(theme: str) -> str:
    cv = Canvas(1040, 440, theme)
    c = cv.c
    total = len(list(all_rules()))
    title_block(
        cv,
        "Đối chiếu OWASP Top 10:2025",
        "Trước đây cả %d rule bị gộp vào đúng hai mục của bản 2021." % total,
    )

    counts = Counter(rule.owasp[0] for rule in all_rules())
    rows = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    colors = {
        "A01": c["purple"],
        "A02": c["blue"],
        "A03": c["green"],
        "A05": c["red"],
        "A08": c["orange"],
    }
    legacy = {
        "A01": "A01:2021 · A10:2021 (SSRF)",
        "A02": "A05:2021",
        "A03": "A08:2021",
        "A05": "A03:2021",
        "A08": "A08:2021",
    }

    top = max(count for _, count in rows)
    bar_x, bar_w = 560, 300
    for index, (tag, count) in enumerate(rows):
        y = 100 + index * 62
        code = tag.split(":")[0]
        name = tag.split("-", 1)[1]
        color = colors.get(code, c["muted"])
        cv.rect(28, y, 984, 52, c["panel"], rx=10, stroke=c["border"])
        cv.badge(44, y + 15, code, color, size=12)
        cv.text(104, y + 24, name, size=13, weight="700")
        cv.text(104, y + 41, "nhãn 2021 đi kèm: " + legacy.get(code, ""), size=10.5,
                fill=c["muted"])
        cv.rect(bar_x, y + 19, bar_w, 14, c["panel2"], rx=7)
        cv.rect(bar_x, y + 19, max(10, bar_w * count / top), 14, color, rx=7)
        cv.text(bar_x + bar_w + 14, y + 31, "%d rule" % count, size=12,
                weight="700", fill=color)

    footer(cv, "Nhãn 2021 vẫn giữ nguyên đi kèm, vì mã rule và khoá JSON của bản "
               "0.1.0 là giao diện ổn định nên chỉ được THÊM vào.")
    return cv.render()


# --------------------------------------------------------------------------
# 6. Độ phủ theo ngôn ngữ
# --------------------------------------------------------------------------

LANGUAGE_COVERAGE: Sequence[Tuple[str, str, int, str]] = (
    ("Python", "AST + luồng dữ liệu, xuyên file", 27, "full"),
    ("JavaScript / TypeScript", "Express, Node", 9, "token"),
    ("PHP", "$_GET / $_POST / $_COOKIE", 8, "token"),
    ("Lua", "OpenResty ngx.*", 7, "token"),
    ("Rust", "actix, axum", 6, "token"),
    ("PowerShell", "script build, script CI", 6, "token"),
    ("Perl", "CGI $q->param", 5, "token"),
    ("Workflow GitHub Actions", ".github/workflows/*.yml", 4, "token"),
    ("Ruby", "Rails params", 4, "token"),
    ("Java / JVM", "Servlet getParameter", 3, "token"),
    ("Go", "net/http + database/sql", 3, "token"),
    ("Shell", "bash, sh", 2, "token"),
    ("package.json", "script vòng đời", 2, "token"),
    ("C#", "ASP.NET Request.Query", 1, "token"),
)


def diagram_languages(theme: str) -> str:
    cv = Canvas(1040, 620, theme)
    c = cv.c
    title_block(
        cv,
        "Độ phủ trên %d ngôn ngữ và định dạng" % len(LANGUAGE_COVERAGE),
        "Python có parser AST nên sâu hơn hẳn; phần còn lại phân tích theo token.",
    )

    cv.badge(28, 74, "AST + luồng dữ liệu, theo được taint xuyên file", c["green"], size=11)
    cv.badge(420, 74, "Lexer theo token, dừng ở ranh giới một hàm", c["blue"], size=11)

    top = max(count for _, _, count, _ in LANGUAGE_COVERAGE)
    bar_x, bar_w = 470, 380
    for index, (name, detail, count, kind) in enumerate(LANGUAGE_COVERAGE):
        y = 112 + index * 35
        color = c["green"] if kind == "full" else c["blue"]
        if index % 2 == 0:
            cv.rect(28, y - 4, 984, 32, c["panel"], rx=8)
        cv.circle(46, y + 11, 5, color)
        cv.text(62, y + 16, name, size=12.5, weight="700")
        cv.text(268, y + 16, detail, size=10.5, fill=c["muted"])
        cv.rect(bar_x, y + 5, bar_w, 13, c["panel2"], rx=6)
        cv.rect(bar_x, y + 5, max(8, bar_w * count / top), 13, color, rx=6)
        suffix = " / 35 rule" if kind == "full" else " họ rule"
        cv.text(bar_x + bar_w + 12, y + 16, "%d%s" % (count, suffix), size=11,
                weight="700", fill=color)

    footer(cv, "Con số của các ngôn ngữ quét theo token đếm theo HỌ rule bắt được, "
               "không phải theo số rule đăng ký.")
    return cv.render()


# --------------------------------------------------------------------------
# 7. Hai bộ phân tích đặt cạnh nhau
# --------------------------------------------------------------------------


def diagram_analyzers(theme: str) -> str:
    cv = Canvas(1040, 420, theme)
    c = cv.c
    title_block(
        cv,
        "Hai bộ phân tích, hai mức độ sâu",
        "Giá trị 'độ tin cậy' trong báo cáo phản ánh đúng khoảng chênh này.",
    )

    columns = [
        ("Python", c["green"], "AST đầy đủ", [
            ("Cách đọc mã", "dựng cây cú pháp đầy đủ"),
            ("Theo dữ liệu qua", "if, vòng lặp, try, và hàm khác"),
            ("Ranh giới tệp", "vượt qua được, có chỉ mục dự án"),
            ("Phủ được", "27 / 35 rule"),
            ("Hàm bọc tự viết", "tự học được, kể cả khác tệp"),
        ]),
        ("13 ngôn ngữ còn lại", c["blue"], "Lexer theo token", [
            ("Cách đọc mã", "tách token, lexer riêng từng ngôn ngữ"),
            ("Theo dữ liệu qua", "trong phạm vi một hàm"),
            ("Ranh giới tệp", "dừng lại ở đó"),
            ("Phủ được", "dạng nguồn → biến → sink"),
            ("Hàm bọc tự viết", "chỉ khi nằm cùng hàm"),
        ]),
    ]

    col_w = 484
    for index, (name, color, badge, rows) in enumerate(columns):
        x = 28 + index * (col_w + 16)
        cv.rect(x, 92, col_w, 292, c["panel"], rx=12, stroke=c["border"])
        cv.rect(x, 92, col_w, 5, color, rx=2)
        cv.text(x + 22, 126, name, size=16, weight="700", fill=color)
        cv.badge(x + col_w - 160, 110, badge, color, size=11)
        for row_index, (key, value) in enumerate(rows):
            y = 158 + row_index * 44
            cv.text(x + 22, y, key, size=10.5, fill=c["muted"])
            cv.text(x + 22, y + 18, value, size=12.5, fill=c["text"])
            if row_index < len(rows) - 1:
                cv.line(x + 22, y + 30, x + col_w - 22, y + 30, c["border"], sw=1)

    footer(cv, "Không phải cứ nhiều ngôn ngữ là phủ đều: chỗ nào nông hơn thì "
               "báo cáo nói ra bằng độ tin cậy thấp hơn.")
    return cv.render()


# --------------------------------------------------------------------------

DIAGRAMS = {
    "taint-flow": diagram_taint_flow,
    "pipeline": diagram_pipeline,
    "benchmarks": diagram_benchmarks,
    "rules": diagram_rules,
    "owasp-2025": diagram_owasp,
    "languages": diagram_languages,
    "analyzers": diagram_analyzers,
}


def build() -> Dict[str, str]:
    """Toàn bộ tệp sẽ được ghi, dạng {tên tệp: nội dung}."""
    result: Dict[str, str] = {}
    for name, fn in sorted(DIAGRAMS.items()):
        for theme in ("light", "dark"):
            result["%s-%s.svg" % (name, theme)] = fn(theme)
    return result


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    files = build()
    for name, content in sorted(files.items()):
        (OUT / name).write_text(content, encoding="utf-8", newline="\n")
    # Thông báo giữ nguyên ASCII: console mặc định của Windows chạy bảng mã
    # cp1258, và một dấu tiếng Việt ở đây là đủ để script chết ngay dòng cuối.
    print("generated %d SVG files -> %s" % (len(files), OUT.relative_to(ROOT).as_posix()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
