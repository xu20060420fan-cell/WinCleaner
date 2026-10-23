"""空间分析页面。

回答清理工具最难回答的问题："我的空间到底被谁吃了"。

* 左侧 **矩形树图**：一眼看清空间分布，点击下钻；
* 右侧 **目录列表**：可排序的明细；
* 底部 **清理目标清单**：把看出来的空间大户直接送进垃圾清理流程。
"""
import os
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QThread, QTimer, Qt, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableView,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.space_analyzer import (
    CATEGORY_COLORS,
    SpaceAnalyzer,
    SpaceNode,
    scan_roots,
)
from core.utils import format_size, get_user_profile
from ui.glass_dialog import GlassDialog
from ui.models import SpaceTableModel
from ui.treemap import TreemapWidget
from ui.widgets import Banner, make_table


class SpaceScanThread(QThread):
    """后台执行空间扫描。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, root: str, max_depth: int):
        super().__init__()
        self.root = root
        self.max_depth = max_depth
        self.analyzer = SpaceAnalyzer(progress_callback=self._on_progress)

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            node = self.analyzer.scan(self.root, max_depth=self.max_depth)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(node)


class SpacePage(QWidget):
    """空间分析页。"""

    #: 请求主窗口跳到垃圾清理页并带上选中的目录
    request_junk_cleanup = pyqtSignal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.root: Optional[SpaceNode] = None
        self.current: Optional[SpaceNode] = None
        self.thread: Optional[SpaceScanThread] = None
        self._marked: Dict[str, dict] = {}

        self._build_ui()
        self._set_path(get_user_profile())

    # -- 界面 -------------------------------------------------------------

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        layout.addWidget(QLabel("空间分析", objectName="sectionTitle"))
        layout.addWidget(Banner(
            "扫描磁盘空间分布，找出占用最大的目录。点击树图或双击目录可以逐层下钻；"
            "把看中的目录加入清理目标，就能直接送到垃圾清理页处理。", "info"))

        # 工具条
        bar = QFrame(objectName="cardFrame")
        bar_layout = QHBoxLayout(bar)
        bar_layout.setContentsMargins(14, 10, 14, 10)
        bar_layout.addWidget(QLabel("路径:"))
        self.path_edit = QLineEdit()
        self.path_edit.setMinimumWidth(280)
        bar_layout.addWidget(self.path_edit, 1)
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._browse)
        bar_layout.addWidget(btn_browse)
        self.drive_box = QComboBox()
        for root in scan_roots():
            self.drive_box.addItem(root)
        self.drive_box.currentTextChanged.connect(self._set_path)
        bar_layout.addWidget(self.drive_box)
        bar_layout.addWidget(QLabel("深度:"))
        self.depth_box = QComboBox()
        for d in (2, 3, 4, 5, 6):
            self.depth_box.addItem(f"{d} 层", d)
        self.depth_box.setCurrentIndex(2)
        bar_layout.addWidget(self.depth_box)
        self.btn_scan = QPushButton("开始扫描", objectName="primaryButton")
        self.btn_scan.clicked.connect(self._start_scan)
        bar_layout.addWidget(self.btn_scan)
        self.btn_stop = QPushButton("停止")
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self._stop_scan)
        bar_layout.addWidget(self.btn_stop)
        layout.addWidget(bar)

        # 主体：树图 + 列表
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.treemap = TreemapWidget()
        self.treemap.node_activated.connect(self._drill_into)
        self.treemap.node_clicked.connect(self._select_node)
        splitter.addWidget(self.treemap)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.breadcrumb = QLabel("尚未扫描")
        self.breadcrumb.setObjectName("summaryLabel")
        right_layout.addWidget(self.breadcrumb)

        self.space_model = SpaceTableModel(self)
        self.space_table = make_table()
        self.space_table.setModel(self.space_model)
        self.space_table.setColumnWidth(0, 180)
        self.space_table.setColumnWidth(1, 95)
        self.space_table.setColumnWidth(2, 70)
        self.space_table.setColumnWidth(3, 95)
        self.space_table.setColumnWidth(4, 75)
        self.space_table.doubleClicked.connect(self._on_row_activated)
        right_layout.addWidget(self.space_table, 1)

        row_btns = QHBoxLayout()
        btn_up = QPushButton("返回上层")
        btn_up.clicked.connect(self._go_up)
        row_btns.addWidget(btn_up)
        btn_open = QPushButton("打开所在位置")
        btn_open.clicked.connect(self._open_selected)
        row_btns.addWidget(btn_open)
        btn_mark = QPushButton("加入清理目标", objectName="primaryButton")
        btn_mark.clicked.connect(self._mark_selected)
        row_btns.addWidget(btn_mark)
        row_btns.addStretch()
        self.space_summary = QLabel("")
        self.space_summary.setObjectName("summaryLabel")
        row_btns.addWidget(self.space_summary)
        right_layout.addLayout(row_btns)

        splitter.addWidget(right)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 4)
        splitter.setSizes([700, 560])
        right.setMinimumWidth(460)
        layout.addWidget(splitter, 1)

        # 清理目标清单
        plan_frame = QFrame(objectName="cardFrame")
        plan_layout = QVBoxLayout(plan_frame)
        plan_layout.setContentsMargins(14, 10, 14, 10)
        head = QHBoxLayout()
        head.addWidget(QLabel("清理目标", objectName="cardTitle"))
        self.plan_label = QLabel("尚未标记任何目录")
        self.plan_label.setObjectName("summaryLabel")
        head.addWidget(self.plan_label)
        head.addStretch()
        btn_unmark = QPushButton("移除全部")
        btn_unmark.clicked.connect(self._clear_marked)
        head.addWidget(btn_unmark)
        btn_send = QPushButton("送到垃圾清理", objectName="dangerButton")
        btn_send.clicked.connect(self._send_to_junk)
        head.addWidget(btn_send)
        plan_layout.addLayout(head)

        self.plan_table = QTableWidget()
        self.plan_table.setColumnCount(3)
        self.plan_table.setHorizontalHeaderLabels(["名称", "大小", "完整路径"])
        self.plan_table.setColumnWidth(0, 200)
        self.plan_table.setColumnWidth(1, 100)
        self.plan_table.horizontalHeader().setStretchLastSection(True)
        self.plan_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.plan_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.plan_table.verticalHeader().setVisible(False)
        plan_layout.addWidget(self.plan_table)
        layout.addWidget(plan_frame)

    # -- 扫描 -------------------------------------------------------------

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "选择要分析的目录",
                                                self.path_edit.text())
        if path:
            self.path_edit.setText(path)

    def _set_path(self, path: str):
        if path:
            self.path_edit.setText(path)

    def _start_scan(self):
        root = self.path_edit.text().strip()
        if not os.path.isdir(root):
            GlassDialog.warning(self, "错误", "路径不存在。")
            return
        if self.thread is not None and self.thread.isRunning():
            return
        depth = self.depth_box.currentData()
        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.space_summary.setText("正在扫描…")
        self.thread = SpaceScanThread(root, depth)
        self.thread.progress.connect(
            lambda m, p: self.space_summary.setText(m))
        self.thread.finished_sig.connect(self._on_scan_finished)
        self.thread.failed.connect(self._on_failed)
        self.thread.start()

    def _stop_scan(self):
        if self.thread is not None and self.thread.isRunning():
            self.thread.analyzer.stop()
            self.space_summary.setText("正在停止…")

    def _on_failed(self, message: str):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.space_summary.setText("扫描失败")
        GlassDialog.error(self, "扫描失败", message)

    def _on_scan_finished(self, node):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.root = node
        self.current = node
        self.treemap.set_root(node)
        self._refresh_list()
        total = node.total_size()
        self.space_summary.setText(
            f"共 {format_size(total)}　文件 {node.file_count} 个")
        self.breadcrumb.setText(node.path)

    # -- 浏览 -------------------------------------------------------------

    def _refresh_list(self):
        if self.current is None:
            return
        total = self.current.total_size() or 1
        rows = []
        for child in self.current.largest_children(300):
            rows.append({
                "name": child.name,
                "path": child.path,
                "size": child.total_size(),
                "percent": child.total_size() * 100.0 / total,
                "category": child.category,
                "file_count": child.file_count,
                "is_dir": child.is_dir,
            })
        self.space_model.set_items(rows)
        self.breadcrumb.setText(self.current.path)

    def _select_node(self, node):
        """单击树图：选中并把目录列表切到该节点的下一层。"""
        if node is not None and node.is_dir:
            self.current = node
            self._refresh_list()

    def _drill_into(self, node):
        if node is None:
            return
        if node.is_dir:
            self.current = node
            self._refresh_list()
        else:
            QDesktopServices.openUrl(QUrl.fromLocalFile(node.path))

    def _go_up(self):
        if self.current is None or self.current.parent is None:
            return
        self.current = self.current.parent
        self._refresh_list()

    def _on_row_activated(self, index):
        items = self.space_model.visible_items()
        if index.row() < len(items):
            path = items[index.row()]["path"]
            if os.path.isdir(path):
                self.current = self._find_node(path)
                if self.current is not None:
                    self._refresh_list()
            else:
                QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def _find_node(self, path: str) -> Optional[SpaceNode]:
        if self.root is None:
            return None
        target = os.path.normcase(os.path.abspath(path))
        for node in self.root.walk():
            if os.path.normcase(os.path.abspath(node.path)) == target:
                return node
        return None

    def _open_selected(self):
        items = self.space_model.visible_items()
        rows = {i.row() for i in self.space_table.selectionModel().selectedRows()}
        if not rows:
            GlassDialog.information(self, "提示", "请先选中一个目录。")
            return
        row = sorted(rows)[0]
        if row < len(items):
            path = items[row]["path"]
            folder = path if os.path.isdir(path) else os.path.dirname(path)
            QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    # -- 清理目标 ---------------------------------------------------------

    def _mark_selected(self):
        items = self.space_model.visible_items()
        rows = {i.row() for i in self.space_table.selectionModel().selectedRows()}
        if not rows:
            GlassDialog.information(self, "提示", "请先选中要清理的目录。")
            return
        added = 0
        for row in sorted(rows):
            if row >= len(items):
                continue
            item = items[row]
            key = os.path.normcase(os.path.abspath(item["path"]))
            if key in self._marked:
                continue
            self._marked[key] = {
                "name": item["name"], "path": item["path"], "size": item["size"],
            }
            added += 1
        self._refresh_plan()
        self.treemap.set_marked(self._marked.keys())
        if added:
            self._log(f"已加入 {added} 个清理目标")

    def _clear_marked(self):
        self._marked.clear()
        self._refresh_plan()
        self.treemap.set_marked([])

    def _refresh_plan(self):
        rows = list(self._marked.values())
        self.plan_table.setRowCount(len(rows))
        for i, item in enumerate(rows):
            self.plan_table.setItem(i, 0, QTableWidgetItem(item["name"]))
            self.plan_table.setItem(i, 1, QTableWidgetItem(format_size(item["size"])))
            self.plan_table.setItem(i, 2, QTableWidgetItem(item["path"]))
        total = sum(i["size"] for i in rows)
        self.plan_label.setText(
            f"{len(rows)} 个目录，合计 {format_size(total)}" if rows
            else "尚未标记任何目录")

    def _send_to_junk(self):
        if not self._marked:
            GlassDialog.information(self, "提示", "还没有标记任何清理目标。")
            return
        reply = GlassDialog.question(
            self, "送到垃圾清理",
            f"把 {len(self._marked)} 个目录（共 "
            f"{format_size(sum(i['size'] for i in self._marked.values()))}）"
            f"送到垃圾清理页？\n\n送到那边后仍需逐项确认才会真正删除。")
        if reply != "yes":
            return
        self.request_junk_cleanup.emit(list(self._marked.values()))

    def _log(self, msg: str):
        parent = self.parent()
        if parent is not None and hasattr(parent, "_log"):
            parent._log(msg)
