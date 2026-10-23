"""表格数据模型。

旧版用 ``QTableWidget`` 逐格塞 ``QTableWidgetItem``：一次扫描动辄 3.6 万行
× 7 列 = 25 万个 QObject，全部在主线程构造，界面直接卡死。

这里改用 ``QAbstractTableModel``：数据留在 Python 列表里，表格按需取数，
5 万行以上依然可以流畅滚动，并且复选框状态、过滤、排序都变得可控。
"""
from datetime import datetime
from typing import List

from PyQt6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PyQt6.QtGui import QBrush, QColor

from core.safety import get_policy
from core.utils import format_size


class BaseTableModel(QAbstractTableModel):
    """带过滤与排序的通用表格模型。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: List = []
        self._view: List[int] = []
        self._search = ""
        self._filter_field = ""
        self._filter_value = ""
        self._sort_column = -1
        self._sort_order = Qt.SortOrder.AscendingOrder

    # -- 基础接口 ---------------------------------------------------------

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        # PyQt6 里 Qt.Orientation 是纯 Enum，与整数比较不相等，
        # 所以两种写法都接受。
        if (orientation == Qt.Orientation.Horizontal or orientation == 1) and \
                role == Qt.ItemDataRole.DisplayRole:
            if 0 <= section < len(self.HEADERS):
                return self.HEADERS[section]
        return None

    # -- 数据装载 ---------------------------------------------------------

    def set_items(self, items: List):
        self.beginResetModel()
        self._items = list(items)
        self._view = list(range(len(self._items)))
        self.endResetModel()
        self._apply_filter()

    def items(self) -> List:
        return self._items

    def visible_items(self) -> List:
        return [self._items[i] for i in self._view]

    # -- 过滤 / 排序 ------------------------------------------------------

    def set_filter(self, search: str = "", field: str = "", value: str = ""):
        self._search = (search or "").strip().lower()
        self._filter_field = field or ""
        self._filter_value = value or ""
        self._apply_filter()

    def sort(self, column: int, order=Qt.SortOrder.AscendingOrder):
        self._sort_column = column
        self._sort_order = order
        self._apply_filter()

    def _passes_filter(self, item) -> bool:
        if self._search:
            # 注意不能写成 " ".join(str(tuple))——那会按字符拆开字符串
            haystack = " ".join(str(x) for x in self._searchable(item)).lower()
            if self._search not in haystack:
                return False
        if self._filter_field and self._filter_value:
            value = str(self._filter_value_of(item, self._filter_field))
            if value != self._filter_value:
                return False
        return True

    def _apply_filter(self):
        self.beginResetModel()
        self._view = [i for i, it in enumerate(self._items) if self._passes_filter(it)]
        if self._sort_column >= 0:
            key = self._sort_key
            self._view.sort(key=lambda i: key(self._items[i]),
                           reverse=self._sort_order == Qt.SortOrder.DescendingOrder)
        self.endResetModel()

    # -- 子类需要实现 -----------------------------------------------------

    def _searchable(self, item) -> tuple:
        return (getattr(item, "name", ""), getattr(item, "path", ""))

    def _filter_value_of(self, item, field: str) -> str:
        return str(getattr(item, field, ""))

    @property
    def _sort_key(self):
        def key(item):
            value = item
            for attr in self.SORT_KEYS[self._sort_column]:
                value = getattr(value, attr, "") if not isinstance(value, str) else value
            if isinstance(value, (int, float)):
                return value
            return str(value).lower()
        return key


# ---------------------------------------------------------------------------
# 垃圾清理
# ---------------------------------------------------------------------------


class JunkTableModel(BaseTableModel):
    """垃圾清理结果表。"""

    HEADERS = ["选择", "类别", "来源", "类型", "名称", "大小", "修改时间", "路径"]
    SORT_KEYS = [
        ("selected",), ("category",), ("source",), ("file_type",),
        ("name",), ("size",), ("mtime",), ("path",),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._checkable = True

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()

        if col == 0:
            if role == Qt.ItemDataRole.CheckStateRole:
                return (Qt.CheckState.Checked if getattr(item, "selected", False)
                        else Qt.CheckState.Unchecked)
            if role == Qt.ItemDataRole.DisplayRole:
                return ""
            return None

        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1:
                return get_policy(item.category).label or item.category
            if col == 2:
                return item.source
            if col == 3:
                return item.file_type
            if col == 4:
                return item.name
            if col == 5:
                return format_size(item.size)
            if col == 6:
                if not item.mtime:
                    return "-"
                return datetime.fromtimestamp(item.mtime).strftime("%Y-%m-%d %H:%M")
            if col == 7:
                return item.path
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 7:
                tip = item.path
                if item.note:
                    tip += f"\n\n说明：{item.note}"
                return tip
            if col == 4 and item.description:
                return item.description
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole and col == 5:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)

        if role == Qt.ItemDataRole.ForegroundRole and col == 3:
            brush = self._type_color(item.file_type)
            if brush:
                return brush
        return None

    @staticmethod
    def _type_color(file_type: str):
        if file_type == "照片":
            return QBrush(QColor("#0891b2"))
        if file_type == "视频":
            return QBrush(QColor("#7c3aed"))
        if file_type == "缓存/日志":
            return QBrush(QColor("#6b7280"))
        if file_type == "可执行文件":
            return QBrush(QColor("#dc2626"))
        if file_type in ("文档", "压缩包", "音频"):
            return QBrush(QColor("#d97706"))
        return None

    def flags(self, index: QModelIndex):
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            base |= Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index: QModelIndex, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or index.column() != 0:
            return False
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        item = self._items[self._view[index.row()]]
        checked = (Qt.CheckState(value) == Qt.CheckState.Checked)
        if getattr(item, "selected", False) == checked:
            return False
        item.selected = checked
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    # -- 批量操作 ---------------------------------------------------------

    def set_all_checked(self, checked: bool, only_visible: bool = True):
        targets = self._view if only_visible else range(len(self._items))
        changed = False
        for i in targets:
            item = self._items[i]
            if getattr(item, "selected", False) != checked:
                item.selected = checked
                changed = True
        if changed:
            self._notify_check_changed()
        return changed

    def invert_checked(self):
        for i in self._view:
            item = self._items[i]
            item.selected = not getattr(item, "selected", False)
        self._notify_check_changed()

    def _notify_check_changed(self):
        if not self._view:
            return
        top = self.index(0, 0)
        bottom = self.index(len(self._view) - 1, 0)
        self.dataChanged.emit(top, bottom, [Qt.ItemDataRole.CheckStateRole])

    def checked_items(self) -> List:
        return [it for it in self._items if getattr(it, "selected", False)]

    def checked_summary(self):
        items = self.checked_items()
        return len(items), sum(getattr(i, "size", 0) for i in items)

    def _searchable(self, item) -> tuple:
        return (item.name, item.path, item.category, item.source, item.file_type)

    def _filter_value_of(self, item, field: str) -> str:
        if field == "category":
            return item.category
        if field == "file_type":
            return item.file_type
        if field == "source":
            return item.source
        return str(getattr(item, field, ""))


# ---------------------------------------------------------------------------
# 大文件
# ---------------------------------------------------------------------------


class LargeFileModel(BaseTableModel):
    """大文件扫描结果表。"""

    HEADERS = ["路径", "大小", "修改时间", "类型", "所在目录"]
    SORT_KEYS = [
        ("path",), ("size",), ("mtime",), ("file_type",), ("dir",),
    ]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return item["path"]
            if col == 1:
                return item["size_text"]
            if col == 2:
                return datetime.fromtimestamp(item["mtime"]).strftime("%Y-%m-%d %H:%M")
            if col == 3:
                return item.get("file_type", "")
            if col == 4:
                return item.get("dir", "")
            return None
        if role == Qt.ItemDataRole.ToolTipRole and col == 0:
            return item["path"]
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 1:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def selected_paths(self, rows) -> List[str]:
        return [self._items[self._view[r]]["path"] for r in rows
                if 0 <= r < len(self._view)]

    def _searchable(self, item) -> tuple:
        return (item["path"],)


# ---------------------------------------------------------------------------
# 重复文件
# ---------------------------------------------------------------------------


class DupFileModel(BaseTableModel):
    """重复文件结果表（按组展示）。"""

    HEADERS = ["保留", "文件路径", "大小", "类型", "修改时间", "所属组"]
    SORT_KEYS = [
        ("keep",), ("path",), ("size",), ("file_type",), ("mtime",), ("group",),
    ]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()
        if col == 0:
            if role == Qt.ItemDataRole.CheckStateRole:
                return (Qt.CheckState.Checked if item.get("keep")
                        else Qt.CheckState.Unchecked)
            if role == Qt.ItemDataRole.DisplayRole:
                return ""
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1:
                return item["path"]
            if col == 2:
                return item["size_text"]
            if col == 3:
                return item.get("file_type", "")
            if col == 4:
                return datetime.fromtimestamp(item["mtime"]).strftime("%Y-%m-%d %H:%M")
            if col == 5:
                return item.get("group", "")
            return None
        if role == Qt.ItemDataRole.ToolTipRole and col == 1:
            return item["path"]
        if role == Qt.ItemDataRole.TextAlignmentRole and col == 2:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def flags(self, index: QModelIndex):
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            base |= Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index: QModelIndex, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or index.column() != 0:
            return False
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        item = self._items[self._view[index.row()]]
        keep = Qt.CheckState(value) == Qt.CheckState.Checked
        if item.get("keep") == keep:
            return False
        item["keep"] = keep
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    def deletable_items(self) -> List[str]:
        """返回"可删除"的路径：同组内只有勾选保留的才留，其余都是重复副本。"""
        groups = {}
        for item in self._items:
            groups.setdefault(item.get("group"), []).append(item)
        out = []
        for members in groups.values():
            keep = [m for m in members if m.get("keep")]
            for m in members:
                if not keep:
                    # 一组都没勾选保留时，什么都不删
                    continue
                if m not in keep:
                    out.append(m["path"])
        return out

    def _searchable(self, item) -> tuple:
        return (item["path"],)


# ---------------------------------------------------------------------------
# 启动项
# ---------------------------------------------------------------------------


class StartupTableModel(BaseTableModel):
    """启动项列表。"""

    HEADERS = ["状态", "名称", "类型", "来源", "命令"]
    SORT_KEYS = [
        ("enabled",), ("name",), ("type",), ("hive",), ("command",),
    ]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                if item.get("enabled"):
                    return "已启用"
                return "已禁用"
            if col == 1:
                name = item.get("name", "")
                return f"{name}（系统项）" if item.get("is_system") else name
            if col == 2:
                return item.get("type", "")
            if col == 3:
                return item.get("hive") or "启动文件夹"
            if col == 4:
                return item.get("command", "")
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            return item.get("command", "")
        if role == Qt.ItemDataRole.ForegroundRole and col == 0:
            if item.get("enabled"):
                return QBrush(QColor("#059669"))
            return QBrush(QColor("#9ca3af"))
        return None

    def _searchable(self, item) -> tuple:
        return (item.get("name", ""), item.get("command", ""))


# ---------------------------------------------------------------------------
# 流氓软件
# ---------------------------------------------------------------------------


class SpaceTableModel(BaseTableModel):
    """空间分析页的目录列表。"""

    HEADERS = ["名称", "大小", "占比", "用途分类", "文件数", "完整路径"]
    SORT_KEYS = [
        ("name",), ("size",), ("size",), ("category",), ("file_count",), ("path",),
    ]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 0:
                return item.get("name", "")
            if col == 1:
                return format_size(item.get("size", 0))
            if col == 2:
                return f"{item.get('percent', 0):.1f}%"
            if col == 3:
                return item.get("category", "")
            if col == 4:
                return str(item.get("file_count", 0))
            if col == 5:
                return item.get("path", "")
            return None
        if role == Qt.ItemDataRole.ToolTipRole and col == 5:
            return item.get("path", "")
        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 2, 4):
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ForegroundRole and col == 3:
            from core.space_analyzer import CATEGORY_COLORS
            color = CATEGORY_COLORS.get(item.get("category", ""))
            if color:
                return QBrush(QColor(color))
        return None


class AdwareTableModel(BaseTableModel):
    """流氓软件扫描结果表（多信号取证结论）。"""

    HEADERS = ["选择", "风险", "命中维度", "类型", "名称", "路径 / 命令", "主要依据"]
    SORT_KEYS = [
        ("selected",), ("risk",), ("dimensions",), ("type",), ("name",),
        ("path",), ("reason",),
    ]

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        item = self._items[self._view[index.row()]]
        col = index.column()
        if col == 0:
            if role == Qt.ItemDataRole.CheckStateRole:
                return (Qt.CheckState.Checked if item.get("selected")
                        else Qt.CheckState.Unchecked)
            if role == Qt.ItemDataRole.DisplayRole:
                return ""
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            if col == 1:
                level = item.get("level", "")
                return f"{level} {item.get('risk', 0)}"
            if col == 2:
                return "、".join(item.get("dimensions", []))
            if col == 3:
                return item.get("type", "")
            if col == 4:
                return item.get("name", "")
            if col == 5:
                return item.get("path", "")
            if col == 6:
                return item.get("reason", "")
            return None
        if role == Qt.ItemDataRole.ToolTipRole:
            if col == 5:
                return item.get("path", "")
            if col == 6:
                tip = item.get("reason", "")
                detail = item.get("detail", "")
                return detail if detail else tip
            return None
        if role == Qt.ItemDataRole.ForegroundRole and col == 1:
            risk = item.get("risk", 0)
            if risk >= 71:
                return QBrush(QColor("#dc2626"))
            if risk >= 46:
                return QBrush(QColor("#d97706"))
            if risk >= 21:
                return QBrush(QColor("#0891b2"))
            return None
        return None

    def flags(self, index: QModelIndex):
        base = Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable
        if index.column() == 0:
            base |= Qt.ItemFlag.ItemIsUserCheckable
        return base

    def setData(self, index: QModelIndex, value, role=Qt.ItemDataRole.EditRole):
        if not index.isValid() or index.column() != 0:
            return False
        if role != Qt.ItemDataRole.CheckStateRole:
            return False
        item = self._items[self._view[index.row()]]
        checked = Qt.CheckState(value) == Qt.CheckState.Checked
        if bool(item.get("selected")) == checked:
            return False
        item["selected"] = checked
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.CheckStateRole])
        return True

    def set_all_checked(self, checked: bool):
        changed = False
        for i in self._view:
            item = self._items[i]
            if bool(item.get("selected")) != checked:
                item["selected"] = checked
                changed = True
        if changed and self._view:
            self.dataChanged.emit(self.index(0, 0), self.index(len(self._view) - 1, 0),
                                  [Qt.ItemDataRole.CheckStateRole])
        return changed

    def checked_items(self) -> List[dict]:
        return [it for it in self._items if it.get("selected")]

    def _searchable(self, item) -> tuple:
        return (item.get("name", ""), item.get("path", ""), item.get("reason", ""))
