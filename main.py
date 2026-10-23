"""WinCleaner 入口文件。"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

# 确保能导入本地模块
PROJECT_ROOT = Path(__file__).parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

APP_VERSION = "2.0.0"


def _fatal(msg: str) -> None:
    """启动期致命错误：无控制台（pythonw / --windowed）时用系统弹窗告知，避免静默退出。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, msg, "WinCleaner 启动失败", 0x10)
    except Exception:
        pass
    try:
        from core.utils import get_log_dir
        log_dir = get_log_dir()
        with open(log_dir / "startup_error.log", "a", encoding="utf-8") as f:
            from datetime import datetime
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")
    except Exception:
        pass


try:
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QFont
except ModuleNotFoundError as e:
    _fatal(
        f"缺少依赖模块: {e.name}\n\n"
        "请先安装运行依赖（项目根目录执行）：\n"
        "    .venv\\Scripts\\python.exe -m pip install -r requirements.txt\n\n"
        "或直接双击项目根目录的「启动WinCleaner.bat」。"
    )
    sys.exit(1)

try:
    from ui.main_window import MainWindow
except Exception as e:
    _fatal(f"加载程序模块失败:\n{type(e).__name__}: {e}")
    sys.exit(1)


def _resource_path(*parts) -> Path:
    """定位随程序分发的资源文件。

    开发态：项目根目录下；打包后：onefile 的解包目录（``sys._MEIPASS``）。
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass).joinpath(*parts)
    return PROJECT_ROOT.joinpath(*parts)


def setup_logging():
    """配置日志输出到文件（带轮转，避免日志无限增长）。"""
    try:
        from core.utils import get_log_dir
        log_dir = get_log_dir()
    except Exception:
        log_dir = PROJECT_ROOT / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        log_dir = PROJECT_ROOT / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    handlers = [RotatingFileHandler(
        log_dir / "wincleaner.log", maxBytes=2 * 1024 * 1024,
        backupCount=3, encoding="utf-8")]

    # 打包成 --windowed 后 sys.stdout / sys.stderr 都是 None，
    # 此时挂 StreamHandler 会在第一次写日志时抛 AttributeError。
    if sys.stdout is not None:
        handlers.append(logging.StreamHandler(sys.stdout))
    elif sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers,
        force=True,
    )


def main():
    setup_logging()
    logging.info(f"WinCleaner {APP_VERSION} 启动")

    # 高 DPI 适配（必须在 QApplication 创建之前设置）
    os.environ.setdefault("QT_AUTO_SCREEN_SCALE_FACTOR", "1")
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("WinCleaner")
    app.setApplicationVersion(APP_VERSION)
    app.setFont(QFont("Microsoft YaHei", 9))

    # 加载样式表
    style_path = _resource_path("ui", "style.qss")
    if style_path.exists():
        try:
            with open(style_path, "r", encoding="utf-8") as f:
                app.setStyleSheet(f.read())
        except Exception as e:
            logging.warning(f"加载样式表失败: {e}")

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
