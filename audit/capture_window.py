"""截取桌面上**其他进程**的窗口（用于验证打包后的 exe 真实渲染效果）。

用法: .venv\\Scripts\\python.exe audit\\capture_window.py <输出png> [窗口标题包含]
"""
import ctypes
import sys
import time
from ctypes import wintypes
from pathlib import Path

from PyQt6.QtCore import QRect
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import QApplication

user32 = ctypes.windll.user32
user32.SetProcessDPIAware()


def find_window(keyword: str):
    """按标题关键字查找可见的顶层窗口，返回 (hwnd, rect)。"""
    results = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def callback(hwnd, _lparam):
        if not user32.IsWindowVisible(hwnd):
            return True
        length = user32.GetWindowTextLengthW(hwnd)
        if length == 0:
            return True
        buf = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, buf, length + 1)
        title = buf.value
        if keyword in title:
            rect = wintypes.RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                results.append((hwnd, title, rect))
        return True

    user32.EnumWindows(callback, 0)
    return results


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("audit/screens/exe_window.png")
    keyword = sys.argv[2] if len(sys.argv) > 2 else "WinCleaner"
    out.parent.mkdir(parents=True, exist_ok=True)

    app = QApplication(sys.argv)
    if not QGuiApplication.screens():
        print("没有可用屏幕")
        return 1

    found = []
    for _ in range(40):
        found = find_window(keyword)
        if found:
            break
        time.sleep(0.5)
    if not found:
        print(f"未找到标题包含「{keyword}」的窗口")
        return 2

    hwnd, title, rect = found[0]
    print(f"找到窗口: '{title}'  {rect.left},{rect.top} "
          f"{rect.right - rect.left}x{rect.bottom - rect.top}  minimized={bool(user32.IsIconic(hwnd))}")

    # 还原并带到前台
    if user32.IsIconic(hwnd):
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        time.sleep(0.8)
    user32.SetForegroundWindow(hwnd)
    user32.BringWindowToTop(hwnd)
    time.sleep(1.2)
    app.processEvents()

    # 重新取一次位置（还原后 rect 会变）
    found = find_window(keyword)
    if found:
        rect = found[0][2]
    clip = QRect(rect.left, rect.top,
                 rect.right - rect.left, rect.bottom - rect.top)
    screen = QGuiApplication.primaryScreen()
    pix = screen.grabWindow(0, clip.x(), clip.y(), clip.width(), clip.height())
    pix.save(str(out))
    print(f"已保存窗口截图: {out}  ({pix.width()}x{pix.height()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
