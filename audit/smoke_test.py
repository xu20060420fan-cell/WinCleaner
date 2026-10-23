"""WinCleaner 启动冒烟测试（offscreen，不弹窗）。

用法:
    .venv\\Scripts\\python.exe audit\\smoke_test.py

验收标准: 输出 SMOKE OK 且退出码 0。
任何一处异常都会打印 traceback 并以非 0 退出。
"""
import os
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402
from PyQt6.QtGui import QFont  # noqa: E402
from PyQt6.QtCore import QCoreApplication, QEventLoop, QTimer  # noqa: E402


def fail(stage: str, exc: BaseException):
    print(f"{stage} FAIL:")
    traceback.print_exception(type(exc), exc, exc.__traceback__)
    sys.exit(3)


try:
    from ui.main_window import MainWindow
except Exception as e:  # noqa: BLE001
    fail("IMPORT", e)

app = QApplication(sys.argv)
app.setFont(QFont("Microsoft YaHei", 9))
qss = ROOT / "ui" / "style.qss"
if qss.exists():
    with open(qss, "r", encoding="utf-8") as f:
        app.setStyleSheet(f.read())

try:
    win = MainWindow()
except Exception as e:  # noqa: BLE001
    fail("CONSTRUCT", e)

print("MainWindow 构造成功")
assert win.stack.count() == 9, f"页面数量不对: {win.stack.count()}"
print("页面数:", win.stack.count())

for i in range(win.stack.count()):
    win._switch_page(i)
print("9 个页面切换 OK")

win._refresh_stats()
disk_value = win.disk_card.layout().itemAt(1).widget().text()
mem_value = win.mem_card.layout().itemAt(1).widget().text()
print("仪表盘刷新 OK:", disk_value, "/", mem_value)
assert disk_value not in ("", "-", "0 GB"), f"磁盘信息未刷新: {disk_value}"
assert mem_value not in ("", "-"), f"内存信息未刷新: {mem_value}"

win._load_settings()
print("设置页加载 OK")

# 清理类别：默认必须是"安全的推荐组合"，且不能包含高危类别
checked = [k for k, cb in win.junk_checks.items() if cb.isChecked()]
unchecked = [k for k, cb in win.junk_checks.items() if not cb.isChecked()]
print(f"清理类别默认勾选: {checked}")
assert "recycle_bin" not in checked, "回收站绝不能默认勾选"
assert "windows_update" not in checked, "Windows 更新缓存不应默认勾选"
assert "system_restore" not in checked, "系统还原点绝不能默认勾选"
assert "hibernation" not in checked, "休眠文件不应默认勾选"
assert "browser_cookies" not in checked, "浏览器 Cookie 不应默认勾选"
assert "app_leftovers" not in checked, "卸载残留不应默认勾选"
assert "event_logs" not in win.junk_checks, "事件日志功能应已移除"
assert len(checked) > 0, "应有安全的推荐默认组合"

# 表格模型
from core.scanner import ScanResult  # noqa: E402
items = [
    ScanResult("system_temp", "临时文件", r"C:\Windows\Temp\a.tmp", 1024, root=r"C:\Windows\Temp"),
    ScanResult("thumbnails", "缩略图", r"C:\Users\x\thumbcache_1.db", 2048, root=r"C:\Users\x"),
]
win.junk_model.set_items(items)
assert win.junk_model.rowCount() == 2, "模型行数不对"
win.junk_model.set_all_checked(True)
count, size = win.junk_model.checked_summary()
assert count == 2 and size == 3072, f"勾选统计错误: {count} {size}"
win.junk_model.set_filter("a.tmp")
assert win.junk_model.rowCount() == 1, "过滤失效"
win.junk_model.set_filter("")
assert win.junk_model.rowCount() == 2, "清空过滤失效"
print("表格模型 OK（过滤 / 勾选 / 统计）")

# 启动项枚举（后台线程 + 事件循环）
def wait_for(thread, timeout_ms=20000):
    loop = QEventLoop()
    timer = QTimer()
    timer.timeout.connect(loop.quit)
    timer.start(100)
    QCoreApplication.processEvents()
    thread.finished.connect(loop.quit)
    thread.start()
    if not thread.wait(timeout_ms):
        loop.quit()
    return thread


win._load_startup_items()
if win.startup_thread is not None:
    win.startup_thread.wait(20000)
    win._on_startup_loaded(win.startup_manager.enumerate())
print("启动项条目:", len(win.startup_items))
assert isinstance(win.startup_items, list), "启动项列表类型错误"

# 流氓软件误报检查
from core.adware_scanner import AdwareScanner  # noqa: E402
ad = AdwareScanner()
for name in ("Kingsoft WPS Office", "360安全卫士", "Microsoft Visual Studio",
             "Google Chrome", "微信", "腾讯会议", "网易云音乐"):
    risk, reason = ad._evaluate_name(name)
    assert risk == 0, f"误报: {name} 被判为 risk={risk} ({reason})"
print("流氓软件白名单 OK（WPS / 360 / Chrome / 微信 均不误报）")

# 弱关键词单项命中只能算"待确认"
for name in ("爱思助手", "Trae Work 助手", "Qoder Installer Diagnostics"):
    risk, _reason = ad._evaluate_name(name)
    assert risk <= 1, f"{name} 风险等级过高: {risk}"
print("弱关键词降噪 OK（待确认项不进入结果表）")

# 强特征必须仍然命中
for name in ("2345加速浏览器", "鲁大师", "驱动精灵"):
    risk, _reason = ad._evaluate_name(name)
    assert risk >= 2, f"漏报: {name} 风险仅 {risk}"
print("强特征识别 OK（2345 / 鲁大师 / 驱动精灵 仍被识别）")

# 多信号引擎：只有名称维度的命中不得单独进表
from core.analyzer import Analysis, Signal, DIM_NAME  # noqa: E402
only_name = Analysis(path="C:\\x", name="x")
only_name.signals = [Signal(DIM_NAME, 35, "命中高危特征词")]
assert only_name.risk_without_name == 0, "名称维度不应计入非名称分数"
assert only_name.has_strong_name_hit, "强关键词命中应被识别"
print("多信号引擎 OK（名称维度权重最低）")

# 流氓软件结果表：维度列与详情字段齐备
from ui.models import AdwareTableModel  # noqa: E402
m = AdwareTableModel()
m.set_items([{
    "name": "x.exe", "path": "C:\\x.exe", "type": "可疑可执行文件",
    "risk": 88, "level": "高危", "reason": "位于临时目录；未签名",
    "dimensions": ["安装位置", "数字签名"], "detail": "证据链",
    "selected": False,
}])
assert m.rowCount() == 1
assert m.headerData(2, 1) == "命中维度", m.headerData(2, 1)
print("流氓软件结果表 OK（维度列 / 详情字段）")

# 空间分析：扫描 + 树图 + 目录表
import tempfile  # noqa: E402
from core.space_analyzer import SpaceAnalyzer  # noqa: E402
from ui.treemap import squarify  # noqa: E402

sandbox = tempfile.mkdtemp(prefix="wc_space_")
os.makedirs(os.path.join(sandbox, "big"), exist_ok=True)
os.makedirs(os.path.join(sandbox, "small"), exist_ok=True)
with open(os.path.join(sandbox, "big", "a.bin"), "wb") as f:
    f.write(b"x" * 200000)
with open(os.path.join(sandbox, "small", "b.bin"), "wb") as f:
    f.write(b"x" * 100)

an = SpaceAnalyzer()
node = an.scan(sandbox, max_depth=3)
assert node.total_size() >= 200100, f"总体积统计不对: {node.total_size()}"
assert node.file_count == 2, f"文件数不对: {node.file_count}"
names = {c.name for c in node.children}
assert "big" in names and "small" in names, str(names)
print(f"空间分析 OK（{node.total_size()} 字节 / {node.file_count} 个文件）")

# 树图布局：面积总和应等于容器面积
rects = squarify([100.0, 50.0, 25.0], 0, 0, 400, 300)
assert len(rects) == 3, f"矩形数量不对: {len(rects)}"
area = sum(r.width() * r.height() for r in rects)
assert abs(area - 400 * 300) < 1.0, f"面积不守恒: {area}"
print("树图布局 OK（面积守恒）")

print("SMOKE OK")
