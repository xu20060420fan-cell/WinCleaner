"""后台任务线程。

所有耗时操作（扫描、清理、哈希比对、注册表枚举）都在这里执行，
避免阻塞主线程。线程统一暴露 ``progress`` 与 ``finished_sig`` 两个信号，
并保留 ``scanner``/``cleaner`` 引用以便随时中止。
"""
from PyQt6.QtCore import QThread, pyqtSignal

from core.adware_scanner import AdwareScanner
from core.cleaner import Cleaner
from core.dup_file_scanner import DupFileScanner
from core.large_file_scanner import LargeFileScanner
from core.scanner import SystemScanner
from core.startup_manager import StartupManager


class ScanThread(QThread):
    """后台执行系统垃圾扫描。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, options: dict):
        super().__init__()
        self.options = options
        self.scanner = SystemScanner(progress_callback=self._on_progress)

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            results = self.scanner.scan_all(self.options)
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(results)


class CleanThread(QThread):
    """后台执行清理。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, items: list, dry_run: bool = False):
        super().__init__()
        self.items = items
        self.cleaner = Cleaner(progress_callback=self._on_progress)
        self.cleaner.dry_run = dry_run

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            stats = self.cleaner.clean(self.items)
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(stats)


class LargeFileThread(QThread):
    """后台执行大文件扫描。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, roots: list, min_size_mb: int):
        super().__init__()
        self.roots = roots
        self.min_size_mb = min_size_mb
        self.scanner = LargeFileScanner(progress_callback=self._on_progress)

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            results = self.scanner.scan(self.roots, self.min_size_mb)
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(results)


class DupFileThread(QThread):
    """后台执行重复文件扫描。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self, roots: list, min_size_mb: int):
        super().__init__()
        self.roots = roots
        self.min_size_mb = min_size_mb
        self.scanner = DupFileScanner(progress_callback=self._on_progress)

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            results = self.scanner.scan(self.roots, self.min_size_mb)
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(results)


class AdwareThread(QThread):
    """后台执行流氓软件扫描。"""

    progress = pyqtSignal(str, int)
    finished_sig = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.scanner = AdwareScanner(progress_callback=self._on_progress)

    def _on_progress(self, msg: str, percent: int):
        self.progress.emit(msg, percent)

    def run(self):
        try:
            results = self.scanner.scan()
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(results)


class StartupThread(QThread):
    """后台枚举启动项（注册表遍历在主线程做会卡住窗口）。"""

    finished_sig = pyqtSignal(list)
    failed = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.manager = StartupManager()

    def run(self):
        try:
            items = self.manager.enumerate()
        except Exception as e:
            self.failed.emit(str(e))
            return
        self.finished_sig.emit(items)
