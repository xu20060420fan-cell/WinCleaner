"""矩形树图（Treemap）控件。

用 squarified treemap 布局把目录树铺成矩形：面积 ∝ 体积，颜色 ∝ 用途分类。
这是"空间到底被谁吃了"最直观的一种呈现方式。

实现参考 Bruls / Huizing / van Wijk 的 squarify 算法：
每一行（列）都挑选使长宽比最接近 1 的划分点。
"""
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QRect, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QFontMetrics, QPainter, QPen
from PyQt6.QtWidgets import QSizePolicy, QWidget

from core.space_analyzer import (
    CATEGORY_COLORS,
    CAT_OTHER,
    SpaceNode,
)


# ---------------------------------------------------------------------------
# squarify 布局
# ---------------------------------------------------------------------------


def _layout_row(sizes: List[float], x: float, y: float, w: float,
                h: float) -> List[QRectF]:
    covered = sum(sizes)
    if covered <= 0 or h <= 0:
        return []
    width = covered / h
    rects = []
    for size in sizes:
        rect_h = size / width if width else 0
        rects.append(QRectF(x, y, width, rect_h))
        y += rect_h
    return rects


def _layout_col(sizes: List[float], x: float, y: float, w: float,
                h: float) -> List[QRectF]:
    covered = sum(sizes)
    if covered <= 0 or w <= 0:
        return []
    height = covered / w
    rects = []
    for size in sizes:
        rect_w = size / height if height else 0
        rects.append(QRectF(x, y, rect_w, height))
        x += rect_w
    return rects


def _layout(sizes: List[float], x: float, y: float, w: float,
            h: float) -> List[QRectF]:
    return (_layout_row(sizes, x, y, w, h) if w >= h
            else _layout_col(sizes, x, y, w, h))


def _leftover(sizes: List[float], x: float, y: float, w: float,
              h: float) -> Tuple[float, float, float, float]:
    covered = sum(sizes)
    if w >= h:
        width = covered / h if h else 0
        return x + width, y, w - width, h
    height = covered / w if w else 0
    return x, y + height, w, h - height


def _worst_ratio(sizes: List[float], x: float, y: float, w: float,
                 h: float) -> float:
    worst = 0.0
    for rect in _layout(sizes, x, y, w, h):
        if rect.width() <= 0 or rect.height() <= 0:
            continue
        ratio = max(rect.width() / rect.height(), rect.height() / rect.width())
        worst = max(worst, ratio)
    return worst


def squarify(sizes: List[float], x: float, y: float, w: float,
             h: float) -> List[QRectF]:
    """把一串**数值**（通常是体积）铺进矩形区域，返回对应的矩形列表。

    先把数值归一化成"面积"（总和 = 容器面积），再按 squarify 排版，
    这样矩形的面积比例就与数值比例一致。
    """
    values = [float(s) for s in sizes]
    if not values:
        return []
    total = sum(values)
    if total <= 0 or w <= 0 or h <= 0:
        return []
    area = w * h
    sizes = [v * area / total for v in values]
    if len(sizes) == 1:
        return _layout(sizes, x, y, w, h)

    i = 1
    while i < len(sizes) and _worst_ratio(sizes[:i], x, y, w, h) >= \
            _worst_ratio(sizes[:i + 1], x, y, w, h):
        i += 1
    current = sizes[:i]
    remaining = sizes[i:]
    lx, ly, lw, lh = _leftover(current, x, y, w, h)
    return _layout(current, x, y, w, h) + squarify(remaining, lx, ly, lw, lh)


# ---------------------------------------------------------------------------
# 控件
# ---------------------------------------------------------------------------


class TreemapWidget(QWidget):
    """可点击下钻的矩形树图。"""

    node_clicked = pyqtSignal(object)
    node_activated = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(360, 280)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        self.setMouseTracking(True)
        self._root: Optional[SpaceNode] = None
        self._rects: List[Tuple[QRectF, SpaceNode]] = []
        self._hover: Optional[SpaceNode] = None
        self._marked = set()
        self._font = QFont("Microsoft YaHei", 9)

    # -- 数据 -------------------------------------------------------------

    def set_root(self, node: Optional[SpaceNode]):
        self._root = node
        self.update()

    def set_marked(self, paths):
        """标记已加入清理计划的路径（用描边高亮）。"""
        self._marked = {normalize(p) for p in (paths or [])}
        self.update()

    # -- 绘制 -------------------------------------------------------------

    def _collect(self, node: SpaceNode) -> List[SpaceNode]:
        """当前层级要绘制的节点：有子目录用子目录，否则用文件。"""
        kids = [c for c in node.children if c.total_size() > 0]
        if not kids:
            return []
        # 如果子节点全是文件，合并成"文件"总量，直接不画（留给父级标题）
        if all(c.is_file for c in kids):
            return []
        return kids

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), QColor("#f1f5f9"))

        if self._root is None:
            painter.setPen(QColor("#94a3b8"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "尚未扫描")
            return

        self._rects = []
        nodes = self._collect(self._root)
        if not nodes:
            painter.setPen(QColor("#94a3b8"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter,
                             "该层级没有可展示的子目录")
            return

        nodes = nodes[:120]
        sizes = [n.total_size() for n in nodes]
        rects = squarify(sizes, 1, 1, self.width() - 2, self.height() - 2)

        painter.setFont(self._font)
        metrics = QFontMetrics(self._font)
        for rect, node in zip(rects, nodes):
            if rect.width() < 1 or rect.height() < 1:
                continue
            self._rects.append((rect, node))
            color = QColor(CATEGORY_COLORS.get(node.category, CATEGORY_COLORS[CAT_OTHER]))
            is_hover = self._hover is not None and self._hover.path == node.path
            if is_hover:
                color = color.lighter(140)
            painter.fillRect(rect, color)

            # 描边：已加入清理计划的用醒目色
            if node.path in self._marked:
                painter.setPen(QPen(QColor("#dc2626"), 2.5))
            else:
                painter.setPen(QPen(QColor(255, 255, 255, 110), 1))
            painter.drawRect(rect)

            # 文字标签
            if rect.width() > 42 and rect.height() > 16:
                text = node.name
                if metrics.horizontalAdvance(text) + 8 > rect.width():
                    while text and metrics.horizontalAdvance(text + "…") + 8 > rect.width():
                        text = text[:-1]
                    text += "…"
                painter.setPen(QPen(QColor(255, 255, 255, 235)))
                painter.drawText(rect.adjusted(4, 2, -4, -2),
                                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                                text)
                size_text = _format_size(node.total_size())
                if rect.height() > 34:
                    painter.setPen(QPen(QColor(255, 255, 255, 190)))
                    painter.drawText(rect.adjusted(4, 18, -4, -2),
                                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop,
                                    size_text)

    # -- 交互 -------------------------------------------------------------

    def _node_at(self, pos) -> Optional[SpaceNode]:
        for rect, node in self._rects:
            if rect.contains(pos):
                return node
        return None

    def mouseMoveEvent(self, event):
        node = self._node_at(event.position())
        if node is not self._hover:
            self._hover = node
            self.update()
        if node is not None:
            from core.utils import format_size
            pct = 0
            if self._root and self._root.total_size():
                pct = node.total_size() * 100 // self._root.total_size()
            self.setToolTip(
                f"{node.path}\n{format_size(node.total_size())}（占 {pct}%）\n"
                f"分类：{node.category}　文件数：{node.file_count}")
        else:
            self.setToolTip("")

    def leaveEvent(self, event):
        self._hover = None
        self.update()

    def mousePressEvent(self, event):
        node = self._node_at(event.position())
        if node is not None:
            self.node_clicked.emit(node)

    def mouseDoubleClickEvent(self, event):
        node = self._node_at(event.position())
        if node is not None:
            self.node_activated.emit(node)


def _format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    value = float(size)
    while value >= 1024 and idx < len(units) - 1:
        value /= 1024
        idx += 1
    return f"{value:.1f} {units[idx]}"


def normalize(path: str) -> str:
    from core.utils import normalize_path
    return normalize_path(path)
