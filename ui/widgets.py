"""可复用的小部件。"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSizePolicy,
    QTableView,
    QVBoxLayout,
)


class StatCard(QFrame):
    """仪表盘上的数据卡片，带可原地更新的数值与副标题。"""

    def __init__(self, title: str, value: str = "-", sub: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("cardFrame")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        self.title_label = QLabel(title, objectName="cardSubtitle")
        self.value_label = QLabel(value, objectName="bigNumber")
        self.sub_label = QLabel(sub, objectName="cardSubtitle")
        layout.addWidget(self.title_label)
        layout.addWidget(self.value_label)
        layout.addWidget(self.sub_label)

    def update_values(self, value: str = "", sub: str = ""):
        if value:
            self.value_label.setText(value)
        if sub:
            self.sub_label.setText(sub)


class UsageBar(QFrame):
    """磁盘/内存使用率条。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("usageBar")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self.name_label = QLabel("C:")
        self.name_label.setMinimumWidth(28)
        self.name_label.setObjectName("cardSubtitle")
        layout.addWidget(self.name_label)

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setValue(0)
        self.bar.setTextVisible(False)
        layout.addWidget(self.bar, 1)

        self.text_label = QLabel("-")
        self.text_label.setObjectName("cardSubtitle")
        self.text_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.text_label.setMinimumWidth(170)
        layout.addWidget(self.text_label)

    def set_usage(self, name: str, percent: float, text: str):
        self.name_label.setText(name)
        self.bar.setValue(int(max(0, min(100, percent))))
        self.text_label.setText(text)
        color = "#059669" if percent < 70 else ("#d97706" if percent < 88 else "#dc2626")
        self.bar.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {color}; border-radius: 6px; }}")

    def set_error(self, name: str, message: str):
        self.name_label.setText(name)
        self.bar.setValue(0)
        self.text_label.setText(f"读取失败：{message}")


class Banner(QFrame):
    """页面顶部的提示条。"""

    LEVELS = {
        "info": ("#2563eb", "#eff6ff"),
        "warn": ("#d97706", "#fffbeb"),
        "danger": ("#dc2626", "#fef2f2"),
        "ok": ("#059669", "#ecfdf5"),
    }

    def __init__(self, text: str = "", level: str = "info", parent=None):
        super().__init__(parent)
        self.setObjectName("banner")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 9, 14, 9)
        self.label = QLabel(text)
        self.label.setWordWrap(True)
        self.label.setObjectName("bannerText")
        layout.addWidget(self.label, 1)
        self.set_level(level)

    def set_level(self, level: str):
        fg, bg = self.LEVELS.get(level, self.LEVELS["info"])
        self.setStyleSheet(
            f"#banner {{ background-color: {bg}; border: 1px solid {fg}33;"
            f" border-radius: 10px; }}"
            f"#bannerText {{ color: {fg}; }}")
        self.level = level

    def set_text(self, text: str, level: str = ""):
        self.label.setText(text)
        if level:
            self.set_level(level)


def _toggle_sort(table: QTableView, column: int):
    """点击表头时切换排序。

    这里没有用 ``QTableView.setSortingEnabled``：那会让表格一开始
    就按第 0 列排序 —— 第 0 列是复选框列，排序没有意义，
    还会在表头上留下一个莫名其妙的排序箭头。
    """
    model = table.model()
    if model is None or not hasattr(model, "sort"):
        return
    if getattr(model, "_sort_column", -1) == column:
        order = (Qt.SortOrder.DescendingOrder
                 if model._sort_order == Qt.SortOrder.AscendingOrder
                 else Qt.SortOrder.AscendingOrder)
    else:
        order = Qt.SortOrder.AscendingOrder
    model.sort(column, order)
    header = table.horizontalHeader()
    header.setSortIndicator(column, order)


def make_table(parent=None) -> QTableView:
    """创建一个配置好的表格视图。"""
    table = QTableView(parent)
    table.setAlternatingRowColors(True)
    table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QTableView.SelectionMode.ExtendedSelection)
    table.setEditTriggers(QTableView.EditTrigger.NoEditTriggers)
    table.setWordWrap(False)
    table.setSortingEnabled(False)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(28)
    header = table.horizontalHeader()
    header.setStretchLastSection(True)
    header.setHighlightSections(False)
    header.setSectionsMovable(True)
    header.setSectionsClickable(True)
    header.sectionClicked.connect(lambda col: _toggle_sort(table, col))
    return table
