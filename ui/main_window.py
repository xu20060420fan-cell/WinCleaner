"""WinCleaner 主窗口 UI。

相比旧版的改动
--------------
* 表格全部换成 ``QAbstractTableModel`` + ``QTableView``（虚拟化），
  几万行结果不再卡死主线程。
* 清理类别改为"配置驱动的安全默认值"，并补上停止扫描、全选/反选、
  搜索过滤、导出 CSV、结果明细等功能。
* 清理动作统一走"预览 → 二次确认 → 执行 → 明细"流程；
  不可逆操作（清空回收站）要求键入确认关键字。
* 启动项支持启用/禁用（可恢复），流氓软件页提供隔离与白名单。
* 仪表盘展示真实磁盘/内存数据，快速操作按钮真正会触发扫描。
"""
import csv
import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer, QUrl
from PyQt6.QtGui import QDesktopServices
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.config import get_config_path, load_config, reset_config, save_config
from core.safety import CATEGORY_ORDER, CategoryPolicy, check_delete_allowed, get_policy
from core.startup_manager import StartupManager
from core.utils import (
    delete_to_recycle_bin,
    format_size,
    get_appdata_local,
    get_disk_usage,
    get_log_dir,
    get_system_drive,
    get_user_profile,
    is_admin,
    list_drives,
    run_as_admin,
)
from ui.glass_dialog import GlassDialog
from ui.models import (
    AdwareTableModel,
    DupFileModel,
    JunkTableModel,
    LargeFileModel,
    StartupTableModel,
)
from ui.space_page import SpacePage
from ui.widgets import Banner, StatCard, UsageBar, make_table
from ui.workers import (
    AdwareThread,
    CleanThread,
    DupFileThread,
    LargeFileThread,
    ScanThread,
    StartupThread,
)

APP_VERSION = "2.0.0"

#: 页面名 → 索引。用名字而不是硬编码序号，插页时不会错位。
PAGE_INDEX = {
    "dashboard": 0,
    "junk": 1,
    "space": 2,
    "large": 3,
    "dup": 4,
    "startup": 5,
    "adware": 6,
    "log": 7,
    "settings": 8,
}

#: 手动删除（大文件 / 重复文件页）使用的策略
MANUAL_POLICY = CategoryPolicy(
    key="manual", label="手动删除", description="用户手动选择的项目",
    min_age_days=0, allow_directories=True, severity="medium",
)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"WinCleaner {APP_VERSION} — Windows 系统清理助手")
        self.resize(1280, 820)
        self.setMinimumSize(1080, 700)

        # 数据
        self.scan_results = []
        self.large_file_results = []
        self.dup_file_results = []
        self.startup_items = []
        self.adware_results = []
        self.last_clean_stats = None

        # 线程
        self.scan_thread = None
        self.clean_thread = None
        self.large_thread = None
        self.dup_thread = None
        self.adware_thread = None
        self.startup_thread = None

        self.startup_manager = StartupManager()
        self._log_lines = []

        self._setup_ui()
        self._load_settings()
        self._start_refresh_timer()
        self._log(f"程序已启动 | 管理员权限：{'是' if is_admin() else '否'} | 版本 {APP_VERSION}")
        # 后台预载启动项，让仪表盘一开始就有真实数据
        self._load_startup_items()

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------

    def closeEvent(self, event):
        """关窗即退出：先停掉全部后台线程，避免进程残留成"有进程没窗口"的僵尸态。"""
        for t in (self.scan_thread, self.clean_thread, self.large_thread,
                  self.dup_thread, self.adware_thread, self.startup_thread):
            if t is None:
                continue
            try:
                for attr in ("scanner", "cleaner", "manager"):
                    obj = getattr(t, attr, None)
                    if obj is not None and hasattr(obj, "stop"):
                        obj.stop()
                if t.isRunning():
                    t.wait(5000)
            except Exception as e:
                logging.warning(f"关闭时停止线程失败: {e}")
        event.accept()
        QApplication.quit()

    # ------------------------------------------------------------------
    # 基础 UI
    # ------------------------------------------------------------------

    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        main_layout.addWidget(self._build_nav())

        self.stack = QStackedWidget(objectName="contentFrame")
        self.stack.setContentsMargins(20, 18, 20, 18)
        self._build_dashboard()
        self._build_junk_page()
        self._build_space_page()
        self._build_large_file_page()
        self._build_dup_file_page()
        self._build_startup_page()
        self._build_adware_page()
        self._build_log_page()
        self._build_settings_page()
        main_layout.addWidget(self.stack, 1)

        self._build_status_bar()
        self.nav_buttons[0].setChecked(True)

    def _build_nav(self) -> QFrame:
        nav = QFrame(objectName="navFrame")
        nav.setLayout(QVBoxLayout())
        nav.layout().setContentsMargins(0, 12, 0, 12)
        nav.layout().setSpacing(4)

        title = QLabel("WinCleaner", objectName="navTitle")
        nav.layout().addWidget(title)
        version = QLabel(f"v{APP_VERSION}", objectName="navVersion")
        nav.layout().addWidget(version)

        pages = [
            ("仪表盘", PAGE_INDEX["dashboard"]),
            ("垃圾清理", PAGE_INDEX["junk"]),
            ("空间分析", PAGE_INDEX["space"]),
            ("大文件扫描", PAGE_INDEX["large"]),
            ("重复文件", PAGE_INDEX["dup"]),
            ("启动项管理", PAGE_INDEX["startup"]),
            ("流氓软件", PAGE_INDEX["adware"]),
            ("运行日志", PAGE_INDEX["log"]),
            ("设置", PAGE_INDEX["settings"]),
        ]
        self.nav_buttons = []
        self.btn_group = QButtonGroup(self)
        self.btn_group.setExclusive(True)
        for label, idx in pages:
            btn = QPushButton(label, objectName="navButton")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, i=idx: self._switch_page(i))
            self.btn_group.addButton(btn, idx)
            nav.layout().addWidget(btn)
            self.nav_buttons.append(btn)

        nav.layout().addStretch()

        self.admin_label = QLabel()
        self.admin_label.setObjectName("adminChip")
        self.admin_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav.layout().addWidget(self.admin_label)
        self._update_admin_chip()

        btn_elevate = QPushButton("以管理员身份重启", objectName="navElevate")
        btn_elevate.setVisible(not is_admin())
        btn_elevate.clicked.connect(self._elevate)
        self.btn_elevate = btn_elevate
        nav.layout().addWidget(btn_elevate)
        return nav

    def _build_status_bar(self):
        bar = self.statusBar()
        bar.setObjectName("statusBar")
        self.status_left = QLabel("就绪")
        bar.addWidget(self.status_left, 1)

        self.status_right = QLabel()
        bar.addPermanentWidget(self.status_right)
        self._update_status_right()

    def _update_status_right(self):
        cfg_path = get_config_path()
        self.status_right.setText(f"配置：{cfg_path}")

    def _update_admin_chip(self):
        admin = is_admin()
        self.admin_label.setText("管理员模式" if admin else "标准用户模式")
        self.admin_label.setProperty("admin", admin)
        self.admin_label.style().unpolish(self.admin_label)
        self.admin_label.style().polish(self.admin_label)
        if hasattr(self, "btn_elevate"):
            self.btn_elevate.setVisible(not admin)

    def _switch_page(self, idx: int):
        self.stack.setCurrentIndex(idx)
        for i, btn in enumerate(self.nav_buttons):
            btn.setChecked(i == idx)
        if idx == PAGE_INDEX["log"]:
            self._reload_log_file()
        if idx == PAGE_INDEX["startup"] and not self.startup_items:
            self._load_startup_items()

    def _navigate(self, page: str):
        """按页面名跳转。"""
        idx = PAGE_INDEX.get(page)
        if idx is not None:
            self._switch_page(idx)

    # ------------------------------------------------------------------
    # 页面：空间分析
    # ------------------------------------------------------------------

    def _build_space_page(self):
        self.space_page = SpacePage()
        self.space_page.request_junk_cleanup.connect(self._receive_space_targets)
        self.stack.addWidget(self.space_page)

    def _receive_space_targets(self, items: list):
        """把空间分析页标记的目录送进垃圾清理页。"""
        from core.scanner import ScanResult
        results = []
        for item in items:
            path = item.get("path", "")
            if not path or not os.path.exists(path):
                continue
            results.append(ScanResult(
                "manual_target", item.get("name", "手动指定目录"), path,
                int(item.get("size", 0) or 0),
                description="从空间分析页手动标记的目录",
                root=path, note="整目录移入回收站，可整体还原",
            ))
        if not results:
            GlassDialog.information(self, "提示", "选中的目录都已不存在。")
            return
        existing = list(self.junk_model.items())
        self.junk_model.set_items(existing + results)
        self._update_junk_summary()
        self.junk_banner.set_text(
            f"已从空间分析页加入 {len(results)} 个目录，合计 "
            f"{format_size(sum(r.size for r in results))}。确认后即可清理。", "warn")
        self._navigate("junk")
        self._log(f"从空间分析页加入 {len(results)} 个清理目标")

    # ------------------------------------------------------------------
    # 页面 0：仪表盘
    # ------------------------------------------------------------------

    def _build_dashboard(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        layout.addWidget(QLabel("仪表盘", objectName="sectionTitle"))

        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.disk_card = StatCard("系统盘可用空间", "-", "-")
        self.mem_card = StatCard("内存占用", "-", "-")
        self.startup_card = StatCard("开机启动项", "-", "-")
        self.junk_card = StatCard("最近一次扫描", "-", "尚未扫描")
        for card in (self.disk_card, self.mem_card, self.startup_card, self.junk_card):
            cards.addWidget(card)
        layout.addLayout(cards)

        # 磁盘使用率
        disk_card = QFrame(objectName="cardFrame")
        disk_layout = QVBoxLayout(disk_card)
        disk_layout.setContentsMargins(18, 16, 18, 16)
        disk_layout.setSpacing(10)
        disk_layout.addWidget(QLabel("磁盘使用率", objectName="cardTitle"))
        self.usage_bars = {}
        self.usage_container = QVBoxLayout()
        self.usage_container.setSpacing(6)
        disk_layout.addLayout(self.usage_container)
        layout.addWidget(disk_card)

        # 快速操作
        quick = QFrame(objectName="cardFrame")
        quick_layout = QVBoxLayout(quick)
        quick_layout.setContentsMargins(18, 16, 18, 16)
        quick_layout.setSpacing(12)
        quick_layout.addWidget(QLabel("快速操作", objectName="cardTitle"))

        quick_btns = QHBoxLayout()
        quick_btns.setSpacing(10)
        btn_junk = QPushButton("扫描垃圾文件", objectName="primaryButton")
        btn_junk.clicked.connect(lambda: self._quick_scan_junk())
        btn_space = QPushButton("分析空间占用", objectName="primaryButton")
        btn_space.clicked.connect(lambda: self._navigate("space"))
        btn_large = QPushButton("扫描大文件", objectName="primaryButton")
        btn_large.clicked.connect(lambda: self._navigate("large"))
        btn_dup = QPushButton("查找重复文件", objectName="primaryButton")
        btn_dup.clicked.connect(lambda: self._navigate("dup"))
        btn_rogue = QPushButton("分析流氓软件", objectName="dangerButton")
        btn_rogue.clicked.connect(lambda: self._quick_scan_adware())
        for btn in (btn_junk, btn_space, btn_large, btn_dup, btn_rogue):
            quick_btns.addWidget(btn)
        quick_btns.addStretch()
        quick_layout.addLayout(quick_btns)

        self.dashboard_banner = Banner(
            "所有删除都会先经过安全校验，并移入回收站（可还原）。"
            "清空回收站这类不可逆操作需要单独确认。", "info")
        quick_layout.addWidget(self.dashboard_banner)
        layout.addWidget(quick)

        # 最近活动
        recent = QFrame(objectName="cardFrame")
        recent_layout = QVBoxLayout(recent)
        recent_layout.setContentsMargins(18, 16, 18, 16)
        recent_layout.setSpacing(8)
        recent_layout.addWidget(QLabel("最近活动", objectName="cardTitle"))
        self.recent_log = QTextEdit()
        self.recent_log.setReadOnly(True)
        self.recent_log.setMaximumHeight(150)
        self.recent_log.setObjectName("logArea")
        recent_layout.addWidget(self.recent_log)
        layout.addWidget(recent)

        layout.addStretch()
        self.stack.addWidget(page)

    def _quick_scan_junk(self):
        self._navigate("junk")
        self._start_scan()

    def _quick_scan_adware(self):
        self._navigate("adware")
        self._start_adware_scan()

    # ------------------------------------------------------------------
    # 页面 1：垃圾清理
    # ------------------------------------------------------------------

    def _build_junk_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("垃圾清理", objectName="sectionTitle"))

        self.junk_banner = Banner(
            "扫描只读，不会删除任何文件。清理时每一项都会经过安全校验，"
            "并移入回收站（可还原）。", "info")
        layout.addWidget(self.junk_banner)

        # 类别选择
        options = QFrame(objectName="cardFrame")
        opt_layout = QVBoxLayout(options)
        opt_layout.setContentsMargins(18, 16, 18, 16)
        opt_layout.setSpacing(10)

        head = QHBoxLayout()
        head.addWidget(QLabel("清理类别", objectName="cardTitle"))
        head.addStretch()
        btn_recommend = QPushButton("使用推荐组合")
        btn_recommend.clicked.connect(self._select_recommended_categories)
        btn_none = QPushButton("全部取消")
        btn_none.clicked.connect(lambda: self._set_all_categories(False))
        head.addWidget(btn_recommend)
        head.addWidget(btn_none)
        opt_layout.addLayout(head)

        grid = QGridLayout()
        grid.setSpacing(8)
        self.junk_checks = {}
        for i, key in enumerate(CATEGORY_ORDER):
            policy = get_policy(key)
            cb = QCheckBox(policy.label)
            cb.setToolTip(f"{policy.description}\n风险：{policy.severity}\n{policy.note}")
            self.junk_checks[key] = cb
            grid.addWidget(cb, i // 3, i % 3)
        opt_layout.addLayout(grid)
        layout.addWidget(options)

        # 工具条
        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)
        self.btn_scan = QPushButton("开始扫描", objectName="primaryButton")
        self.btn_scan.clicked.connect(self._start_scan)
        self.btn_stop_scan = QPushButton("停止扫描")
        self.btn_stop_scan.clicked.connect(self._stop_scan)
        self.btn_stop_scan.setEnabled(False)
        self.btn_clean = QPushButton("清理选中项", objectName="dangerButton")
        self.btn_clean.clicked.connect(self._start_clean)
        self.btn_clean.setEnabled(False)
        toolbar.addWidget(self.btn_scan)
        toolbar.addWidget(self.btn_stop_scan)
        toolbar.addWidget(self.btn_clean)
        toolbar.addSpacing(16)

        self.junk_search = QLineEdit()
        self.junk_search.setPlaceholderText("搜索名称或路径…")
        self.junk_search.setClearButtonEnabled(True)
        self.junk_search.textChanged.connect(self._apply_junk_filter)
        self.junk_search.setMaximumWidth(260)
        toolbar.addWidget(self.junk_search)

        self.junk_category_filter = QComboBox()
        self.junk_category_filter.addItem("全部类别", "")
        self.junk_category_filter.currentIndexChanged.connect(self._apply_junk_filter)
        toolbar.addWidget(self.junk_category_filter)

        self.junk_type_filter = QComboBox()
        self.junk_type_filter.addItem("全部类型", "")
        self.junk_type_filter.currentIndexChanged.connect(self._apply_junk_filter)
        toolbar.addWidget(self.junk_type_filter)

        btn_select_all = QPushButton("全选")
        btn_select_all.clicked.connect(lambda: self._set_rows_checked(True))
        btn_select_none = QPushButton("全不选")
        btn_select_none.clicked.connect(lambda: self._set_rows_checked(False))
        btn_invert = QPushButton("反选")
        btn_invert.clicked.connect(self._invert_rows)
        btn_export = QPushButton("导出清单")
        btn_export.clicked.connect(self._export_junk_csv)
        for btn in (btn_select_all, btn_select_none, btn_invert, btn_export):
            toolbar.addWidget(btn)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.junk_summary = QLabel("尚未扫描")
        self.junk_summary.setObjectName("summaryLabel")
        layout.addWidget(self.junk_summary)

        self.junk_progress = QProgressBar()
        self.junk_progress.setRange(0, 100)
        self.junk_progress.setValue(0)
        self.junk_status = QLabel("就绪")
        progress_row = QHBoxLayout()
        progress_row.addWidget(self.junk_progress, 1)
        progress_row.addWidget(self.junk_status)
        layout.addLayout(progress_row)

        self.junk_model = JunkTableModel(self)
        self.junk_table = make_table()
        self.junk_table.setModel(self.junk_model)
        self.junk_table.setColumnWidth(0, 44)
        self.junk_table.setColumnWidth(1, 130)
        self.junk_table.setColumnWidth(2, 100)
        self.junk_table.setColumnWidth(3, 80)
        self.junk_table.setColumnWidth(4, 170)
        self.junk_table.setColumnWidth(5, 90)
        self.junk_table.setColumnWidth(6, 130)
        self.junk_table.doubleClicked.connect(self._on_junk_row_activated)
        layout.addWidget(self.junk_table, 1)

        self.stack.addWidget(page)

    def _set_all_categories(self, checked: bool):
        for cb in self.junk_checks.values():
            cb.setChecked(checked)

    def _select_recommended_categories(self):
        cfg = load_config()
        recommended = set(cfg.get("default_enabled_categories", []))
        for key, cb in self.junk_checks.items():
            cb.setChecked(key in recommended)

    def _apply_junk_filter(self):
        self.junk_model.set_filter(
            self.junk_search.text(),
            "category", self.junk_category_filter.currentData() or "",
        )
        self._update_junk_summary()

    def _set_rows_checked(self, checked: bool):
        self.junk_model.set_all_checked(checked)
        self._update_junk_summary()

    def _invert_rows(self):
        self.junk_model.invert_checked()
        self._update_junk_summary()

    def _update_junk_summary(self):
        total = len(self.junk_model.items())
        visible = len(self.junk_model.visible_items())
        count, size = self.junk_model.checked_summary()
        self.junk_summary.setText(
            f"共 {total} 项（当前显示 {visible} 项）　|　"
            f"已选 {count} 项，合计 {format_size(size)}"
        )

    def _on_junk_row_activated(self, index):
        item = self.junk_model.visible_items()[index.row()]
        path = item.path
        if path and os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    # -- 扫描 -------------------------------------------------------------

    def _start_scan(self):
        options = {k: cb.isChecked() for k, cb in self.junk_checks.items()}
        if not any(options.values()):
            GlassDialog.warning(self, "提示", "请至少勾选一个清理类别。")
            return
        if self.scan_thread is not None and self.scan_thread.isRunning():
            GlassDialog.information(self, "提示", "扫描还在进行中。")
            return

        self.btn_scan.setEnabled(False)
        self.btn_stop_scan.setEnabled(True)
        self.btn_clean.setEnabled(False)
        self.junk_table.setModel(self.junk_model)
        self.junk_model.set_items([])
        self.junk_progress.setValue(0)
        self.junk_status.setText("正在扫描…")

        self.scan_thread = ScanThread(options)
        self.scan_thread.progress.connect(self._on_scan_progress)
        self.scan_thread.finished_sig.connect(self._on_scan_finished)
        self.scan_thread.failed.connect(self._on_task_failed)
        self.scan_thread.start()

    def _stop_scan(self):
        if self.scan_thread is not None and self.scan_thread.isRunning():
            self.scan_thread.scanner.stop()
            self.junk_status.setText("正在停止…")
            self._log("用户请求停止扫描")

    def _on_scan_progress(self, msg: str, percent: int):
        self.junk_status.setText(msg)
        if percent >= 0:
            self.junk_progress.setValue(percent)

    def _on_scan_finished(self, results: list):
        self.scan_results = results
        self.btn_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.btn_clean.setEnabled(len(results) > 0)
        self.junk_progress.setValue(100)

        total_size = sum(r.size for r in results)
        self.junk_status.setText(f"扫描完成，发现 {len(results)} 项可清理文件")
        self._log(f"扫描完成，发现 {len(results)} 项，合计 {format_size(total_size)}")
        self.junk_banner.set_text(
            f"扫描完成：共 {len(results)} 项，合计 {format_size(total_size)}。"
            "请勾选需要清理的项后再执行清理。", "ok")

        self.junk_model.set_items(results)
        self._refresh_filter_choices()
        self._update_junk_summary()
        self.junk_card.update_values(f"{len(results)} 项", format_size(total_size))

    def _refresh_filter_choices(self):
        categories = sorted({r.category for r in self.junk_model.items()})
        self.junk_category_filter.blockSignals(True)
        self.junk_category_filter.clear()
        self.junk_category_filter.addItem("全部类别", "")
        for cat in categories:
            self.junk_category_filter.addItem(get_policy(cat).label or cat, cat)
        self.junk_category_filter.blockSignals(False)

        types = sorted({r.file_type for r in self.junk_model.items()})
        self.junk_type_filter.blockSignals(True)
        self.junk_type_filter.clear()
        self.junk_type_filter.addItem("全部类型", "")
        for t in types:
            self.junk_type_filter.addItem(t, t)
        self.junk_type_filter.blockSignals(False)

    def _on_task_failed(self, message: str):
        self.btn_scan.setEnabled(True)
        self.btn_stop_scan.setEnabled(False)
        self.junk_status.setText("任务失败")
        GlassDialog.error(self, "任务失败", message)

    # -- 清理 -------------------------------------------------------------

    def _start_clean(self):
        selected = self.junk_model.checked_items()
        if not selected:
            GlassDialog.information(self, "提示", "请先勾选要清理的项目。")
            return

        total_size = sum(getattr(i, "size", 0) for i in selected)
        irreversible = [i for i in selected if getattr(i, "special", "") == "empty_recycle_bin"]
        top = sorted(selected, key=lambda x: -getattr(x, "size", 0))[:8]
        detail = "\n".join(
            f"{format_size(getattr(i, 'size', 0)):>10}  {getattr(i, 'path', '')}" for i in top)
        if len(selected) > 8:
            detail += f"\n… 以及另外 {len(selected) - 8} 项"

        if irreversible:
            reply = GlassDialog.confirm_danger(
                self, "确认清空回收站",
                f"你选中了「清空回收站」这项操作。\n"
                f"清空后其中的文件将无法还原，此操作不可撤销。",
                "清空回收站", detail)
        else:
            # 常规清理是**可逆**的（进回收站），一次确认即可；
            # 不可逆的操作才需要键入关键字。
            reply = GlassDialog.question(
                self, "确认清理",
                f"即将清理 {len(selected)} 项，合计 {format_size(total_size)}。\n\n"
                f"这些内容会被移入回收站，可以在回收站中还原。",
            )
        if reply != "yes":
            return

        self.btn_scan.setEnabled(False)
        self.btn_clean.setEnabled(False)
        self.junk_progress.setValue(0)
        self.junk_status.setText("正在清理…")

        self.clean_thread = CleanThread(selected)
        self.clean_thread.progress.connect(self._on_clean_progress)
        self.clean_thread.finished_sig.connect(self._on_clean_finished)
        self.clean_thread.failed.connect(self._on_task_failed)
        # 清理前建还原点（设置页可开关）
        try:
            cfg = load_config()
            self.clean_thread.cleaner.restore_point_enabled = bool(
                cfg.get("create_restore_point_before_clean", False))
        except Exception:
            pass
        self.clean_thread.start()

    def _on_clean_progress(self, msg: str, percent: int):
        self.junk_status.setText(msg)
        if percent >= 0:
            self.junk_progress.setValue(percent)

    def _on_clean_finished(self, stats: dict):
        self.btn_scan.setEnabled(True)
        self.btn_clean.setEnabled(False)
        self.junk_progress.setValue(100)
        self.last_clean_stats = stats

        summary = (f"完成 | 移入回收站 {stats['deleted']} 项 | 跳过 {stats['skipped']} 项 | "
                   f"失败 {stats['failed']} 项 | 释放 {format_size(stats['saved'])}")
        self.junk_status.setText(summary)
        self._log(f"清理完成：{summary}")

        details = self.clean_thread.cleaner.details if self.clean_thread else []
        text = "\n".join(
            f"[{d['result']}] {d['path']}" + (f"  — {d['reason']}" if d["reason"] else "")
            for d in details[:400])
        if len(details) > 400:
            text += f"\n… 共 {len(details)} 条，完整记录见 logs/clean_actions.log"

        GlassDialog.information(
            self, "清理完成", summary, detail=text)
        self.junk_banner.set_text(summary, "ok" if stats["failed"] == 0 else "warn")

        # 只移除**真正处理成功**的行；被安全策略跳过或删除失败的行
        # 必须留在列表里，否则用户会以为它们已经被处理掉了。
        details = self.clean_thread.cleaner.details if self.clean_thread else []
        done = {d["path"] for d in details
                if d["result"] in ("已移入回收站", "已清空回收站", "DNS 缓存已刷新")}
        remaining = [r for r in self.junk_model.items() if r.path not in done]
        # 残留项取消勾选：不能留下"已武装"的状态让用户误以为还能一键执行
        for r in remaining:
            r.selected = False
        self.junk_model.set_items(remaining)
        self._update_junk_summary()
        self._refresh_filter_choices()

    def _export_junk_csv(self):
        items = self.junk_model.visible_items()
        if not items:
            GlassDialog.information(self, "提示", "当前没有可导出的条目。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出清理清单", str(Path.home() / "wincleaner_scan.csv"), "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["类别", "来源", "类型", "名称", "大小(字节)", "修改时间", "路径", "已勾选"])
                for r in items:
                    writer.writerow([
                        r.category, r.source, r.file_type, r.name, r.size,
                        datetime.fromtimestamp(r.mtime).strftime("%Y-%m-%d %H:%M") if r.mtime else "",
                        r.path, "是" if getattr(r, "selected", False) else "否",
                    ])
            GlassDialog.information(self, "导出成功", f"清单已保存到：\n{path}")
            self._log(f"导出清理清单: {path}")
        except Exception as e:
            GlassDialog.error(self, "导出失败", str(e))

    # ------------------------------------------------------------------
    # 页面 2：大文件扫描
    # ------------------------------------------------------------------

    def _build_large_file_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("大文件扫描", objectName="sectionTitle"))

        cfg = QFrame(objectName="cardFrame")
        cfg_layout = QHBoxLayout(cfg)
        cfg_layout.setContentsMargins(16, 12, 16, 12)
        cfg_layout.addWidget(QLabel("最小文件大小 (MB):"))
        self.large_min_size = QSpinBox()
        self.large_min_size.setRange(1, 102400)
        self.large_min_size.setValue(100)
        cfg_layout.addWidget(self.large_min_size)
        cfg_layout.addWidget(QLabel("扫描路径:"))
        self.large_path = QLineEdit(get_user_profile())
        cfg_layout.addWidget(self.large_path, 1)
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._browse_large_path)
        cfg_layout.addWidget(btn_browse)
        self.btn_large_scan = QPushButton("开始扫描", objectName="primaryButton")
        self.btn_large_scan.clicked.connect(self._start_large_scan)
        cfg_layout.addWidget(self.btn_large_scan)
        layout.addWidget(cfg)

        toolbar = QHBoxLayout()
        self.large_summary = QLabel("尚未扫描")
        self.large_summary.setObjectName("summaryLabel")
        toolbar.addWidget(self.large_summary)
        toolbar.addStretch()
        btn_open = QPushButton("打开所在目录")
        btn_open.clicked.connect(self._open_selected_large)
        btn_del = QPushButton("移入回收站", objectName="dangerButton")
        btn_del.clicked.connect(self._delete_selected_large)
        btn_export = QPushButton("导出")
        btn_export.clicked.connect(self._export_large_csv)
        for btn in (btn_open, btn_del, btn_export):
            toolbar.addWidget(btn)
        layout.addLayout(toolbar)

        self.large_progress = QProgressBar()
        self.large_progress.setRange(0, 100)
        layout.addWidget(self.large_progress)

        self.large_model = LargeFileModel(self)
        self.large_table = make_table()
        self.large_table.setModel(self.large_model)
        self.large_table.setColumnWidth(0, 420)
        self.large_table.setColumnWidth(1, 100)
        self.large_table.setColumnWidth(2, 140)
        self.large_table.setColumnWidth(3, 90)
        self.large_table.doubleClicked.connect(self._on_large_activated)
        layout.addWidget(self.large_table, 1)

        self.stack.addWidget(page)

    def _browse_large_path(self):
        path = QFileDialog.getExistingDirectory(self, "选择扫描目录", self.large_path.text())
        if path:
            self.large_path.setText(path)

    def _start_large_scan(self):
        root = self.large_path.text().strip()
        min_size = self.large_min_size.value()
        if not os.path.isdir(root):
            GlassDialog.warning(self, "错误", "扫描路径不存在。")
            return
        if self.large_thread is not None and self.large_thread.isRunning():
            return
        self.btn_large_scan.setEnabled(False)
        self.large_model.set_items([])
        self.large_progress.setValue(0)
        self.large_thread = LargeFileThread([root], min_size)
        self.large_thread.progress.connect(self._on_large_progress)
        self.large_thread.finished_sig.connect(self._on_large_finished)
        self.large_thread.failed.connect(self._on_task_failed)
        self.large_thread.start()

    def _on_large_progress(self, msg: str, percent: int):
        if percent >= 0:
            self.large_progress.setValue(percent)
        self.large_summary.setText(msg)

    def _on_large_finished(self, results: list):
        self.large_file_results = results
        self.btn_large_scan.setEnabled(True)
        self.large_progress.setValue(100)
        total = sum(r["size"] for r in results)
        self.large_summary.setText(f"发现 {len(results)} 个大文件，合计 {format_size(total)}")
        self._log(f"大文件扫描完成，发现 {len(results)} 个文件")
        self.large_model.set_items(results)

    def _on_large_activated(self, index):
        items = self.large_model.visible_items()
        if index.row() < len(items):
            folder = items[index.row()].get("dir", "")
            if folder:
                QDesktopServices.openUrl(QUrl.fromLocalFile(folder))

    def _open_selected_large(self):
        rows = {i.row() for i in self.large_table.selectionModel().selectedRows()}
        if not rows:
            GlassDialog.information(self, "提示", "请先在表格中选中文件。")
            return
        items = self.large_model.visible_items()
        for row in sorted(rows):
            if row < len(items):
                folder = items[row].get("dir", "")
                if folder:
                    QDesktopServices.openUrl(QUrl.fromLocalFile(folder))
                    break

    def _export_large_csv(self):
        items = self.large_model.visible_items()
        if not items:
            GlassDialog.information(self, "提示", "当前没有可导出的条目。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出大文件清单", str(Path.home() / "wincleaner_large.csv"), "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["路径", "大小(字节)", "大小", "修改时间", "类型"])
                for r in items:
                    writer.writerow([r["path"], r["size"], r["size_text"],
                                     datetime.fromtimestamp(r["mtime"]).strftime("%Y-%m-%d %H:%M"),
                                     r.get("file_type", "")])
            GlassDialog.information(self, "导出成功", f"清单已保存到：\n{path}")
        except Exception as e:
            GlassDialog.error(self, "导出失败", str(e))

    # ------------------------------------------------------------------
    # 页面 3：重复文件
    # ------------------------------------------------------------------

    def _build_dup_file_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("重复文件", objectName="sectionTitle"))
        layout.addWidget(Banner(
            "勾选每一组中要保留的那一个，未勾选的副本才可以被删除。"
            "任何一组都不勾选时，该组不会被删除。", "info"))

        cfg = QFrame(objectName="cardFrame")
        cfg_layout = QHBoxLayout(cfg)
        cfg_layout.setContentsMargins(16, 12, 16, 12)
        cfg_layout.addWidget(QLabel("最小文件大小 (MB):"))
        self.dup_min_size = QSpinBox()
        self.dup_min_size.setRange(1, 102400)
        self.dup_min_size.setValue(1)
        cfg_layout.addWidget(self.dup_min_size)
        cfg_layout.addWidget(QLabel("扫描路径:"))
        self.dup_path = QLineEdit(get_user_profile())
        cfg_layout.addWidget(self.dup_path, 1)
        btn_browse = QPushButton("浏览…")
        btn_browse.clicked.connect(self._browse_dup_path)
        cfg_layout.addWidget(btn_browse)
        self.btn_dup_scan = QPushButton("开始扫描", objectName="primaryButton")
        self.btn_dup_scan.clicked.connect(self._start_dup_scan)
        cfg_layout.addWidget(self.btn_dup_scan)
        layout.addWidget(cfg)

        toolbar = QHBoxLayout()
        self.dup_summary = QLabel("尚未扫描")
        self.dup_summary.setObjectName("summaryLabel")
        toolbar.addWidget(self.dup_summary)
        toolbar.addStretch()
        btn_keep_oldest = QPushButton("每组保留最早修改的")
        btn_keep_oldest.clicked.connect(self._keep_oldest_per_group)
        btn_del = QPushButton("删除未保留的副本", objectName="dangerButton")
        btn_del.clicked.connect(self._delete_dup_copies)
        btn_export = QPushButton("导出")
        btn_export.clicked.connect(self._export_dup_csv)
        for btn in (btn_keep_oldest, btn_del, btn_export):
            toolbar.addWidget(btn)
        layout.addLayout(toolbar)

        self.dup_progress = QProgressBar()
        self.dup_progress.setRange(0, 100)
        layout.addWidget(self.dup_progress)

        self.dup_model = DupFileModel(self)
        self.dup_table = make_table()
        self.dup_table.setModel(self.dup_model)
        self.dup_table.setColumnWidth(0, 44)
        self.dup_table.setColumnWidth(1, 420)
        self.dup_table.setColumnWidth(2, 100)
        self.dup_table.setColumnWidth(3, 90)
        self.dup_table.setColumnWidth(4, 140)
        self.dup_table.setColumnWidth(5, 70)
        layout.addWidget(self.dup_table, 1)

        self.stack.addWidget(page)

    def _browse_dup_path(self):
        path = QFileDialog.getExistingDirectory(self, "选择扫描目录", self.dup_path.text())
        if path:
            self.dup_path.setText(path)

    def _start_dup_scan(self):
        root = self.dup_path.text().strip()
        min_size = self.dup_min_size.value()
        if not os.path.isdir(root):
            GlassDialog.warning(self, "错误", "扫描路径不存在。")
            return
        if self.dup_thread is not None and self.dup_thread.isRunning():
            return
        self.btn_dup_scan.setEnabled(False)
        self.dup_model.set_items([])
        self.dup_progress.setValue(0)
        self.dup_thread = DupFileThread([root], min_size)
        self.dup_thread.progress.connect(self._on_dup_progress)
        self.dup_thread.finished_sig.connect(self._on_dup_finished)
        self.dup_thread.failed.connect(self._on_task_failed)
        self.dup_thread.start()

    def _on_dup_progress(self, msg: str, percent: int):
        if percent >= 0:
            self.dup_progress.setValue(percent)
        self.dup_summary.setText(msg)

    def _on_dup_finished(self, groups: list):
        self.dup_file_results = groups
        self.btn_dup_scan.setEnabled(True)
        self.dup_progress.setValue(100)

        flat = []
        for gi, group in enumerate(groups):
            for item in group:
                row = dict(item)
                row["group"] = f"#{gi + 1}"
                row["mtime"] = item.get("mtime", 0)
                row["file_type"] = item.get("file_type", "")
                row["keep"] = False
                flat.append(row)
        # 每组默认保留最早修改的那个
        self.dup_model.set_items(flat)
        self._keep_oldest_per_group()

        total = sum(g[0]["size"] * (len(g) - 1) for g in groups if g)
        self.dup_summary.setText(
            f"发现 {len(groups)} 组重复文件，共 {len(flat)} 个文件，"
            f"清理全部副本可释放约 {format_size(total)}")
        self._log(f"重复文件扫描完成，发现 {len(groups)} 组")

    def _keep_oldest_per_group(self):
        groups = {}
        for item in self.dup_model.items():
            groups.setdefault(item.get("group"), []).append(item)
        for members in groups.values():
            if len(members) < 2:
                continue
            keep = min(members, key=lambda m: m.get("mtime", 0))
            for m in members:
                m["keep"] = (m is keep)
        self.dup_model.set_items(self.dup_model.items())
        self.dup_model._apply_filter()

    def _export_dup_csv(self):
        items = self.dup_model.visible_items()
        if not items:
            GlassDialog.information(self, "提示", "当前没有可导出的条目。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出重复文件清单", str(Path.home() / "wincleaner_dup.csv"), "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["组", "路径", "大小(字节)", "大小", "修改时间", "是否保留"])
                for r in items:
                    writer.writerow([r.get("group", ""), r["path"], r["size"], r["size_text"],
                                     datetime.fromtimestamp(r.get("mtime", 0)).strftime("%Y-%m-%d %H:%M")
                                     if r.get("mtime") else "",
                                     "保留" if r.get("keep") else "副本"])
            GlassDialog.information(self, "导出成功", f"清单已保存到：\n{path}")
        except Exception as e:
            GlassDialog.error(self, "导出失败", str(e))

    # ------------------------------------------------------------------
    # 手动删除（大文件 / 重复文件共用）
    # ------------------------------------------------------------------

    def _delete_paths_to_recycle(self, paths, title: str) -> bool:
        """统一的"手动删除"流程：校验 → 确认 → 移入回收站。"""
        paths = [p for p in paths if p and os.path.exists(p)]
        if not paths:
            GlassDialog.information(self, "提示", "没有可删除的项目。")
            return False

        allowed, blocked = [], []
        for path in paths:
            decision = check_delete_allowed(
                path, MANUAL_POLICY, allowed_roots=None, protect_personal=True)
            if decision.allowed:
                allowed.append(path)
            else:
                blocked.append((path, decision.reason))

        if not allowed:
            detail = "\n".join(f"{p}\n  原因：{r}" for p, r in blocked[:30])
            GlassDialog.warning(
                self, "无法删除",
                f"选中的 {len(blocked)} 项全部被安全策略拦截，未做任何删除。", detail=detail)
            return False

        total = 0
        for path in allowed:
            try:
                total += os.path.getsize(path)
            except OSError:
                pass

        detail = "\n".join(allowed[:40])
        if len(allowed) > 40:
            detail += f"\n… 以及另外 {len(allowed) - 40} 项"
        if blocked:
            detail += "\n\n以下项目将被跳过：\n" + "\n".join(
                f"{p}\n  原因：{r}" for p, r in blocked[:20])

        reply = GlassDialog.confirm_danger(
            self, title,
            f"即将删除 {len(allowed)} 项，合计约 {format_size(total)}。\n"
            f"内容会移入回收站，可在回收站中还原。",
            "确认删除", detail)
        if reply != "yes":
            return False

        result = delete_to_recycle_bin(allowed)
        ok = len(result["deleted"])
        bad = len(result["failed"])
        message = (f"成功移入回收站 {ok} 项"
                   + (f"，失败 {bad} 项" if bad else "")
                   + (f"\n已跳过 {len(blocked)} 项（安全策略拦截）" if blocked else ""))
        self._log(f"{title}：{message}")
        GlassDialog.information(self, "操作完成", message)
        return ok > 0

    def _delete_selected_large(self):
        rows = sorted({i.row() for i in self.large_table.selectionModel().selectedRows()})
        if not rows:
            GlassDialog.information(self, "提示", "请先在表格中选中要删除的文件。")
            return
        items = self.large_model.visible_items()
        paths = [items[r]["path"] for r in rows if r < len(items)]
        if self._delete_paths_to_recycle(paths, "删除大文件"):
            self.large_model.set_items([i for i in items
                                        if i["path"] not in set(paths)])

    def _delete_dup_copies(self):
        paths = self.dup_model.deletable_items()
        if not paths:
            GlassDialog.information(
                self, "提示", "没有可删除的副本。请在每一组中勾选要保留的文件。")
            return
        if self._delete_paths_to_recycle(paths, "删除重复副本"):
            remaining = [i for i in self.dup_model.items() if i["path"] not in set(paths)]
            self.dup_model.set_items(remaining)

    # ------------------------------------------------------------------
    # 页面 4：启动项管理
    # ------------------------------------------------------------------

    def _build_startup_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("启动项管理", objectName="sectionTitle"))
        layout.addWidget(Banner(
            "禁用是可恢复的：注册表启动项的原值会备份到 "
            "HKCU\\Software\\WinCleaner\\DisabledStartup，随时可以还原。"
            "标记为「系统项」的条目不允许禁用。", "info"))

        toolbar = QHBoxLayout()
        btn_refresh = QPushButton("刷新列表", objectName="primaryButton")
        btn_refresh.clicked.connect(self._load_startup_items)
        toolbar.addWidget(btn_refresh)
        self.btn_disable = QPushButton("禁用选中项")
        self.btn_disable.clicked.connect(self._disable_startup)
        self.btn_enable = QPushButton("启用选中项")
        self.btn_enable.clicked.connect(self._enable_startup)
        toolbar.addWidget(self.btn_disable)
        toolbar.addWidget(self.btn_enable)
        btn_export = QPushButton("导出备份")
        btn_export.clicked.connect(self._export_startup_backup)
        toolbar.addWidget(btn_export)
        self.startup_summary = QLabel("")
        self.startup_summary.setObjectName("summaryLabel")
        toolbar.addWidget(self.startup_summary)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.startup_model = StartupTableModel(self)
        self.startup_table = make_table()
        self.startup_table.setModel(self.startup_model)
        self.startup_table.setColumnWidth(0, 80)
        self.startup_table.setColumnWidth(1, 220)
        self.startup_table.setColumnWidth(2, 110)
        self.startup_table.setColumnWidth(3, 110)
        layout.addWidget(self.startup_table, 1)

        self.stack.addWidget(page)

    def _load_startup_items(self):
        if self.startup_thread is not None and self.startup_thread.isRunning():
            return
        self.startup_summary.setText("正在读取启动项…")
        self.startup_thread = StartupThread()
        self.startup_thread.finished_sig.connect(self._on_startup_loaded)
        self.startup_thread.failed.connect(self._on_task_failed)
        self.startup_thread.start()

    def _on_startup_loaded(self, items: list):
        self.startup_items = items
        self.startup_model.set_items(items)
        enabled = sum(1 for i in items if i.get("enabled"))
        self.startup_summary.setText(
            f"共 {len(items)} 项，已启用 {enabled} 项，已禁用 {len(items) - enabled} 项")
        self.startup_card.update_values(f"{len(items)} 项", f"已启用 {enabled} 项")
        self._log(f"启动项加载完成，共 {len(items)} 项")

    def _selected_startup(self):
        rows = sorted({i.row() for i in self.startup_table.selectionModel().selectedRows()})
        items = self.startup_model.visible_items()
        return [items[r] for r in rows if r < len(items)]

    def _disable_startup(self):
        selected = [i for i in self._selected_startup() if i.get("enabled")]
        if not selected:
            GlassDialog.information(self, "提示", "请先选中要禁用的启动项。")
            return
        system_items = [i for i in selected if i.get("is_system")]
        if system_items:
            GlassDialog.warning(
                self, "无法禁用",
                "选中的项目里包含系统启动项，系统项不允许禁用：\n" +
                "\n".join(i["name"] for i in system_items))
            return
        reply = GlassDialog.question(
            self, "确认禁用",
            f"将禁用 {len(selected)} 个启动项：\n" +
            "\n".join(i["name"] for i in selected[:20]) +
            "\n\n原值会被备份，可随时还原。")
        if reply != "yes":
            return
        ok = 0
        for item in selected:
            if self.startup_manager.disable(item):
                ok += 1
            else:
                self._log(f"禁用失败: {item['name']}")
        self._log(f"已禁用 {ok}/{len(selected)} 个启动项")
        GlassDialog.information(self, "完成", f"成功禁用 {ok} 项，失败 {len(selected) - ok} 项。")
        self._load_startup_items()

    def _enable_startup(self):
        selected = [i for i in self._selected_startup() if not i.get("enabled")]
        if not selected:
            GlassDialog.information(self, "提示", "请先选中要启用的启动项。")
            return
        ok = 0
        for item in selected:
            if self.startup_manager.enable(item):
                ok += 1
        self._log(f"已启用 {ok}/{len(selected)} 个启动项")
        GlassDialog.information(self, "完成", f"成功启用 {ok} 项，失败 {len(selected) - ok} 项。")
        self._load_startup_items()

    def _export_startup_backup(self):
        path = self.startup_manager.export_backup()
        if path:
            GlassDialog.information(self, "导出成功", f"备份已保存到：\n{path}")
        else:
            GlassDialog.error(self, "导出失败", "无法写入备份文件。")

    # ------------------------------------------------------------------
    # 页面 5：流氓软件
    # ------------------------------------------------------------------

    def _build_adware_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("流氓软件 / 广告软件分析", objectName="sectionTitle"))
        layout.addWidget(Banner(
            "判定不靠关键词，而是九个维度的底层取证：数字签名、安装位置、持久化、"
            "PE 结构、发布者一致性、名称特征、分发形态、运行行为，以及多信号交叉验证。"
            "双击任意一行可查看完整证据链。", "info"))

        toolbar = QHBoxLayout()
        self.btn_adware_scan = QPushButton("开始分析", objectName="dangerButton")
        self.btn_adware_scan.clicked.connect(self._start_adware_scan)
        toolbar.addWidget(self.btn_adware_scan)
        btn_select_all = QPushButton("全选高危")
        btn_select_all.clicked.connect(self._select_high_risk)
        btn_select_none = QPushButton("全不选")
        btn_select_none.clicked.connect(lambda: self.adware_model.set_all_checked(False))
        toolbar.addWidget(btn_select_all)
        toolbar.addWidget(btn_select_none)
        btn_detail = QPushButton("查看分析详情")
        btn_detail.clicked.connect(self._show_adware_detail)
        toolbar.addWidget(btn_detail)
        btn_open = QPushButton("打开所在位置")
        btn_open.clicked.connect(self._open_adware_location)
        btn_quarantine = QPushButton("隔离到隔离区", objectName="dangerButton")
        btn_quarantine.clicked.connect(self._quarantine_adware)
        btn_trust = QPushButton("加入白名单")
        btn_trust.clicked.connect(self._trust_adware)
        for btn in (btn_open, btn_quarantine, btn_trust):
            toolbar.addWidget(btn)
        self.adware_summary = QLabel("尚未分析")
        self.adware_summary.setObjectName("summaryLabel")
        toolbar.addWidget(self.adware_summary)
        toolbar.addStretch()
        layout.addLayout(toolbar)

        self.adware_progress = QProgressBar()
        self.adware_progress.setRange(0, 100)
        layout.addWidget(self.adware_progress)

        self.adware_model = AdwareTableModel(self)
        self.adware_table = make_table()
        self.adware_table.setModel(self.adware_model)
        self.adware_table.setColumnWidth(0, 44)
        self.adware_table.setColumnWidth(1, 80)
        self.adware_table.setColumnWidth(2, 190)
        self.adware_table.setColumnWidth(3, 110)
        self.adware_table.setColumnWidth(4, 180)
        self.adware_table.setColumnWidth(5, 300)
        self.adware_table.doubleClicked.connect(self._on_adware_activated)
        layout.addWidget(self.adware_table, 1)

        self.stack.addWidget(page)

    def _start_adware_scan(self):
        if self.adware_thread is not None and self.adware_thread.isRunning():
            return
        self.btn_adware_scan.setEnabled(False)
        self.adware_model.set_items([])
        self.adware_progress.setValue(0)
        self.adware_thread = AdwareThread()
        self.adware_thread.progress.connect(self._on_adware_progress)
        self.adware_thread.finished_sig.connect(self._on_adware_finished)
        self.adware_thread.failed.connect(self._on_task_failed)
        self.adware_thread.start()

    def _on_adware_progress(self, msg: str, percent: int):
        if percent >= 0:
            self.adware_progress.setValue(percent)
        self.adware_summary.setText(msg)

    def _on_adware_finished(self, results: list):
        self.adware_results = results
        self.btn_adware_scan.setEnabled(True)
        self.adware_progress.setValue(100)
        high = sum(1 for r in results if r.get("risk", 0) >= 71)
        medium = sum(1 for r in results if 46 <= r.get("risk", 0) < 71)
        low = self.adware_thread.scanner.low_confidence_count if self.adware_thread else 0
        extra = f"，另有 {low} 项未达阈值未列出" if low else ""
        self.adware_summary.setText(
            f"发现 {len(results)} 项（高危 {high} / 可疑 {medium}）{extra}")
        self._log(f"多信号分析完成，{len(results)} 项达到预警阈值")
        self.adware_model.set_items(results)

    def _select_high_risk(self):
        for item in self.adware_model.items():
            item["selected"] = item.get("risk", 0) >= 71
        self.adware_model.set_items(self.adware_model.items())

    def _selected_adware(self):
        return self.adware_model.checked_items()

    def _current_adware(self):
        """当前选中行对应的结果（没勾选时用选中行）。"""
        rows = {i.row() for i in self.adware_table.selectionModel().selectedRows()}
        items = self.adware_model.visible_items()
        if rows:
            row = sorted(rows)[0]
            if row < len(items):
                return items[row]
        checked = self._selected_adware()
        return checked[0] if checked else None

    def _on_adware_activated(self, index):
        items = self.adware_model.visible_items()
        if index.row() < len(items):
            self._show_detail(items[index.row()])

    def _show_adware_detail(self):
        item = self._current_adware()
        if not item:
            GlassDialog.information(self, "提示", "请先选中一个可疑项。")
            return
        self._show_detail(item)

    def _show_detail(self, item: dict):
        """展示完整证据链。"""
        detail = item.get("detail") or item.get("reason", "")
        GlassDialog.detail(
            self, f"分析详情 — {item.get('name', '')}",
            f"风险评分 {item.get('risk', 0)}/100（{item.get('level', '')}）"
            f"　命中维度：{'、'.join(item.get('dimensions', []))}",
            detail)

    def _open_adware_location(self):
        items = self._selected_adware()
        if not items:
            GlassDialog.information(self, "提示", "请先勾选可疑项。")
            return
        item = items[0]
        path = item.get("path", "")
        if os.path.exists(path):
            QDesktopServices.openUrl(QUrl.fromLocalFile(
                path if os.path.isdir(path) else os.path.dirname(path)))
        else:
            GlassDialog.information(self, "提示", f"该条目没有对应的文件路径：\n{path}")

    def _quarantine_adware(self):
        items = self._selected_adware()
        if not items:
            GlassDialog.information(self, "提示", "请先勾选要隔离的项目。")
            return
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        quarantine = Path(get_appdata_local()) / "WinCleaner" / "quarantine" / stamp
        movable = [i for i in items if i.get("path") and os.path.exists(i["path"])]
        if not movable:
            GlassDialog.information(
                self, "无法隔离",
                "选中的条目没有对应的文件（注册表项 / 计划任务无法隔离），"
                "可以改用「打开所在位置」人工确认。")
            return
        reply = GlassDialog.confirm_danger(
            self, "确认隔离",
            f"将把 {len(movable)} 个项目移动到隔离区：\n{quarantine}\n\n"
            "文件不会被删除，可以随时手动取回。",
            "确认隔离")
        if reply != "yes":
            return
        ok = 0
        for item in movable:
            src = Path(item["path"])
            try:
                quarantine.mkdir(parents=True, exist_ok=True)
                dst = quarantine / src.name
                if dst.exists():
                    dst = quarantine / f"{src.stem}_{src.suffix}"
                shutil.move(str(src), str(dst))
                item["path"] = str(dst)
                ok += 1
            except Exception as e:
                self._log(f"隔离失败 {src}: {e}")
        self._log(f"已隔离 {ok}/{len(movable)} 个项目到 {quarantine}")
        GlassDialog.information(self, "隔离完成", f"已隔离 {ok} 项。\n隔离区：\n{quarantine}")
        self.adware_model.set_items(self.adware_model.items())

    def _trust_adware(self):
        items = self._selected_adware()
        if not items:
            GlassDialog.information(self, "提示", "请先勾选要加入白名单的项目。")
            return
        cfg = load_config()
        brands = list(cfg.get("trusted_brands", []))
        added = []
        for item in items:
            name = item.get("name", "").strip()
            if name and name not in brands:
                brands.append(name)
                added.append(name)
        cfg["trusted_brands"] = brands
        save_config(cfg)
        self._log(f"已把 {len(added)} 个名称加入可信品牌白名单")
        GlassDialog.information(
            self, "已加入白名单",
            f"新增 {len(added)} 条白名单：\n" + "\n".join(added[:20]) +
            ("\n…（详情见设置页）" if len(added) > 20 else ""))

    # ------------------------------------------------------------------
    # 页面 6：运行日志
    # ------------------------------------------------------------------

    def _build_log_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        layout.addWidget(QLabel("运行日志", objectName="sectionTitle"))

        toolbar = QHBoxLayout()
        self.log_level = QComboBox()
        self.log_level.addItems(["全部", "INFO", "WARNING", "ERROR"])
        self.log_level.currentIndexChanged.connect(self._reload_log_file)
        toolbar.addWidget(self.log_level)
        btn_refresh = QPushButton("刷新")
        btn_refresh.clicked.connect(self._reload_log_file)
        toolbar.addWidget(btn_refresh)
        btn_open_dir = QPushButton("打开日志目录")
        btn_open_dir.clicked.connect(self._open_log_dir)
        toolbar.addWidget(btn_open_dir)
        btn_copy = QPushButton("复制全部")
        btn_copy.clicked.connect(self._copy_log)
        toolbar.addWidget(btn_copy)
        toolbar.addStretch()
        self.log_path_label = QLabel("")
        self.log_path_label.setObjectName("summaryLabel")
        toolbar.addWidget(self.log_path_label)
        layout.addLayout(toolbar)

        self.log_area = QTextEdit(objectName="logArea")
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area, 1)

        self.stack.addWidget(page)

    def _log_file_path(self):
        return Path(get_log_dir()) / "wincleaner.log"

    def _reload_log_file(self):
        path = self._log_file_path()
        self.log_path_label.setText(str(path))
        if not path.exists():
            self.log_area.setPlainText("（日志文件尚未生成）")
            return
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.log_area.setPlainText(f"读取日志失败：{e}")
            return
        level = self.log_level.currentText()
        if level != "全部":
            lines = [ln for ln in text.splitlines() if f"[{level}]" in ln]
            text = "\n".join(lines)
        lines = text.splitlines()
        if len(lines) > 2000:
            text = "（仅显示最近 2000 行）\n" + "\n".join(lines[-2000:])
        self.log_area.setPlainText(text)
        self.log_area.moveCursor(self.log_area.textCursor().MoveOperation.End)

    def _open_log_dir(self):
        d = get_log_dir()
        d.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(d)))

    def _copy_log(self):
        QApplication.clipboard().setText(self.log_area.toPlainText())
        GlassDialog.information(self, "已复制", "日志内容已复制到剪贴板。")

    # ------------------------------------------------------------------
    # 页面 7：设置
    # ------------------------------------------------------------------

    def _build_settings_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(20, 20, 20, 20)
        outer.setSpacing(10)

        title = QLabel("设置", objectName="sectionTitle")
        outer.addWidget(title)

        # 设置项较多，放进滚动区，避免内容超出窗口时控件互相重叠
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(2, 2, 10, 2)
        layout.setSpacing(10)

        # 保护选项
        protect = QFrame(objectName="cardFrame")
        protect_layout = QVBoxLayout(protect)
        protect_layout.setContentsMargins(18, 14, 18, 14)
        protect_layout.setSpacing(8)
        protect_layout.addWidget(QLabel("安全保护", objectName="cardTitle"))
        self.cb_protect_personal = QCheckBox("保护个人数据（照片 / 视频 / 音频 / 文档 / 压缩包 不参与清理）")
        protect_layout.addWidget(self.cb_protect_personal)
        protect_layout.addWidget(QLabel(
            "建议保持开启。关闭后，清理范围会明显扩大。", objectName="cardSubtitle"))
        self.cb_restore_point = QCheckBox("清理前自动创建系统还原点（需要管理员权限）")
        protect_layout.addWidget(self.cb_restore_point)
        protect_layout.addWidget(QLabel(
            "多一层保险：万一清错了，还能从系统还原点整体回退。", objectName="cardSubtitle"))
        layout.addWidget(protect)

        # 关键词
        self.strong_edit = self._make_text_group(
            layout, "强特征关键词（一行一个，命中即判可疑）", 110)
        self.weak_edit = self._make_text_group(
            layout, "泛化关键词（一行一个，单独命中仅提示，不进入结果表）", 110)
        self.trusted_edit = self._make_text_group(
            layout, "可信品牌白名单（一行一个，命中即完全忽略）", 110)
        self.patterns_edit = self._make_text_group(
            layout, "已知流氓软件目录模式（一行一个，支持 * 通配）", 100)
        self.paths_edit = self._make_text_group(
            layout, "软件缓存路径（JSON 格式）", 180)

        layout.addStretch()
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        btns = QHBoxLayout()
        btn_save = QPushButton("保存配置", objectName="primaryButton")
        btn_save.clicked.connect(self._save_settings)
        btn_reset = QPushButton("恢复默认")
        btn_reset.clicked.connect(self._reset_settings)
        btn_open_cfg = QPushButton("打开配置文件")
        btn_open_cfg.clicked.connect(self._open_config_file)
        btns.addWidget(btn_save)
        btns.addWidget(btn_reset)
        btns.addWidget(btn_open_cfg)
        btns.addStretch()
        self.settings_path_label = QLabel("")
        self.settings_path_label.setObjectName("summaryLabel")
        btns.addWidget(self.settings_path_label)
        outer.addLayout(btns)

        self.stack.addWidget(page)

    @staticmethod
    def _make_text_group(layout, title: str, height: int):
        layout.addWidget(QLabel(title))
        edit = QTextEdit()
        edit.setFixedHeight(height)
        layout.addWidget(edit)
        return edit

    def _load_settings(self):
        cfg = load_config()
        self.strong_edit.setPlainText("\n".join(cfg.get("strong_keywords", [])))
        self.weak_edit.setPlainText("\n".join(cfg.get("weak_keywords", [])))
        self.trusted_edit.setPlainText("\n".join(cfg.get("trusted_brands", [])))
        self.patterns_edit.setPlainText("\n".join(cfg.get("known_rogue_patterns", [])))
        self.paths_edit.setPlainText(json.dumps(
            {"software_junk_paths": cfg.get("software_junk_paths", {}),
             "dev_cache_paths": cfg.get("dev_cache_paths", {})},
            ensure_ascii=False, indent=2))
        self.cb_protect_personal.setChecked(bool(cfg.get("protect_personal_files", True)))
        self.cb_restore_point.setChecked(
            bool(cfg.get("create_restore_point_before_clean", False)))
        self.settings_path_label.setText(f"配置文件：{get_config_path()}")

        # 清理类别默认勾选
        recommended = set(cfg.get("default_enabled_categories", []))
        for key, cb in self.junk_checks.items():
            cb.setChecked(key in recommended)

    def _save_settings(self):
        cfg = load_config()
        cfg["strong_keywords"] = self._lines(self.strong_edit)
        cfg["weak_keywords"] = self._lines(self.weak_edit)
        cfg["trusted_brands"] = self._lines(self.trusted_edit)
        cfg["known_rogue_patterns"] = self._lines(self.patterns_edit)
        try:
            paths = json.loads(self.paths_edit.toPlainText())
        except json.JSONDecodeError as e:
            GlassDialog.warning(self, "格式错误", f"软件缓存路径 JSON 格式错误：\n{e}")
            return
        if not isinstance(paths, dict):
            GlassDialog.warning(self, "格式错误", "软件缓存路径必须是一个 JSON 对象。")
            return
        cfg["software_junk_paths"] = paths.get("software_junk_paths", {})
        cfg["dev_cache_paths"] = paths.get("dev_cache_paths", {})
        cfg["protect_personal_files"] = self.cb_protect_personal.isChecked()
        cfg["create_restore_point_before_clean"] = self.cb_restore_point.isChecked()
        if save_config(cfg):
            GlassDialog.information(self, "成功", "配置已保存，下次扫描生效。")
            self._log("配置已保存")
        else:
            GlassDialog.warning(self, "失败", "保存配置文件失败。")

    @staticmethod
    def _lines(edit) -> list:
        return [ln.strip() for ln in edit.toPlainText().splitlines() if ln.strip()]

    def _reset_settings(self):
        reply = GlassDialog.question(
            self, "恢复默认", "将把所有配置恢复为默认值，确定继续吗？")
        if reply != "yes":
            return
        reset_config()
        self._load_settings()
        GlassDialog.information(self, "完成", "配置已恢复默认。")

    def _open_config_file(self):
        path = get_config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            save_config(load_config())
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))

    # ------------------------------------------------------------------
    # 通用
    # ------------------------------------------------------------------

    def _start_refresh_timer(self):
        self._rebuild_usage_bars()
        self._refresh_stats()
        timer = QTimer(self)
        timer.timeout.connect(self._refresh_stats)
        timer.start(5000)

    def _rebuild_usage_bars(self):
        """为每个盘符建一条使用率条。"""
        while self.usage_container.count():
            item = self.usage_container.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.usage_bars = {}
        for drive in list_drives():
            bar = UsageBar()
            self.usage_bars[drive] = bar
            self.usage_container.addWidget(bar)
            self._update_usage_bar(drive)

    def _update_usage_bar(self, drive: str):
        bar = self.usage_bars.get(drive)
        if bar is None:
            return
        usage = get_disk_usage(drive)
        if usage.get("error"):
            bar.set_error(drive, usage["error"])
            return
        free = usage["free"] / (1024 ** 3)
        total = usage["total"] / (1024 ** 3)
        bar.set_usage(drive, usage.get("percent", 0.0),
                      f"{free:.1f} GB 可用 / {total:.1f} GB")

    def _refresh_stats(self):
        """刷新仪表盘数据（每 5 秒一次）。"""
        # 磁盘
        usage = get_disk_usage(get_system_drive())
        if usage.get("error"):
            self.disk_card.update_values("读取失败", usage["error"][:40])
        else:
            free_gb = usage["free"] / (1024 ** 3)
            total_gb = usage["total"] / (1024 ** 3)
            used_pct = usage.get("percent", 0.0)
            self.disk_card.update_values(
                f"{free_gb:.1f} GB",
                f"总空间 {total_gb:.1f} GB · 已用 {used_pct:.0f}%")
        for drive in list(self.usage_bars.keys()):
            self._update_usage_bar(drive)

        # 内存
        try:
            import psutil
            mem = psutil.virtual_memory()
            used_gb = (mem.total - mem.available) / (1024 ** 3)
            total_gb = mem.total / (1024 ** 3)
            self.mem_card.update_values(f"{mem.percent}%", f"{used_gb:.1f} GB / {total_gb:.1f} GB")
        except Exception as e:
            self.mem_card.update_values("-", f"读取失败：{e}")

        # 停留在日志页时自动刷新
        if self.stack.currentIndex() == PAGE_INDEX["log"]:
            self._reload_log_file()

    def _log(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._log_lines.append(line)
        if len(self._log_lines) > 500:
            self._log_lines = self._log_lines[-500:]
        self.recent_log.append(line)
        logging.info(msg)
        self.status_left.setText(msg)

    def _elevate(self):
        reply = GlassDialog.question(
            self, "以管理员身份重启",
            "部分清理类别（Windows 更新缓存、预取文件等）需要管理员权限。\n"
            "是否以管理员身份重新启动 WinCleaner？\n\n"
            "当前未保存的操作会丢失。")
        if reply != "yes":
            return
        if run_as_admin():
            self.close()
        else:
            GlassDialog.warning(self, "提权失败", "无法以管理员身份重新启动（可能被用户取消）。")
