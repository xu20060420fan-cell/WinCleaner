"""把主窗口的 8 个页面渲染成 PNG，便于人工核对界面。

用法: .venv\\Scripts\\python.exe audit\\render_pages.py
输出: audit\\screens\\page0_dashboard.png ...
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402
from PyQt6.QtGui import QFont  # noqa: E402

from ui.main_window import MainWindow  # noqa: E402

OUT = ROOT / "audit" / "screens"
OUT.mkdir(parents=True, exist_ok=True)

NAMES = ["dashboard", "junk", "space", "largefile", "dup", "startup", "adware",
         "log", "settings"]

app = QApplication(sys.argv)
app.setFont(QFont("Microsoft YaHei", 9))
qss = ROOT / "ui" / "style.qss"
if qss.exists():
    app.setStyleSheet(qss.read_text(encoding="utf-8"))

win = MainWindow()
win.resize(1280, 820)
win.show()
app.processEvents()

# 往垃圾清理页塞一点样例数据，让截图有内容
from core.scanner import ScanResult  # noqa: E402

samples = [
    ScanResult("system_temp", "临时文件", r"C:\Users\Administrator\AppData\Local\Temp\a1b2.tmp",
               1_048_576, root=r"C:\Users\Administrator\AppData\Local\Temp", mtime=1750000000),
    ScanResult("software_junk", "应用缓存 (通用)", r"C:\Users\Administrator\AppData\Local\SomeApp\cache\x.dat",
               524_288, root=r"C:\Users\Administrator\AppData\Local\SomeApp\cache", mtime=1750000000),
    ScanResult("thumbnails", "缩略图缓存", r"C:\Users\Administrator\AppData\Local\Microsoft\Windows\Explorer\thumbcache_256.db",
               2_097_152, root=r"C:\Users\Administrator\AppData\Local\Microsoft\Windows\Explorer", mtime=1750000000),
    ScanResult("error_reports", "错误报告文件", r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\report.wer",
               8_192, root=r"C:\ProgramData\Microsoft\Windows\WER", mtime=1750000000),
    ScanResult("dev_cache", "pip 缓存", r"C:\Users\Administrator\AppData\Local\pip\cache\wheels\x.whl",
               3_145_728, root=r"C:\Users\Administrator\AppData\Local\pip\cache", mtime=1750000000),
]
win.junk_model.set_items(samples)
win.junk_model.set_all_checked(True)
win._update_junk_summary()
win.junk_banner.set_text("扫描完成：共 12,406 项，合计 2.51 GB。请勾选需要清理的项后再执行清理。", "ok")
win.junk_status.setText("扫描完成，发现 12406 项可清理文件")

win.adware_model.set_items([
    {
        "type": "可疑可执行文件", "name": "wb2api_baseline.exe",
        "path": r"C:\Users\Administrator\AppData\Local\Temp\wb2api_baseline.exe",
        "risk": 99, "level": "高危",
        "reason": "位于临时目录（临时目录里的程序极可能是安装器或投放器）；节区熵值 8.00（高度压缩/加密）",
        "dimensions": ["数字签名", "安装位置", "PE 结构", "发布者"],
        "detail": "对象：wb2api_baseline.exe\n"
                  "路径：C:\\Users\\Administrator\\AppData\\Local\\Temp\\wb2api_baseline.exe\n"
                  "风险评分：99/100（高危）\n\n"
                  "证据明细：\n"
                  "  ＋ +45  [安装位置] 位于临时目录（临时目录里的程序极可能是安装器或投放器）\n"
                  "  ＋ +22  [PE 结构] 节区熵值 8.00（高度压缩/加密）\n"
                  "  ＋ +20  [数字签名] 文件没有任何数字签名\n"
                  "  ＋ +12  [发布者] 没有填写发布者信息（正规软件通常会填）",
        "selected": False,
    },
    {
        "type": "可疑可执行文件", "name": "YunUtilityService.exe",
        "path": r"C:\Users\Administrator\AppData\Roaming\baidu\BaiduNetdisk\YunUtilityService.exe",
        "risk": 48, "level": "可疑",
        "reason": "被登记 1 处自启动（服务 BaiduNetdiskUtility）；位于漫游配置目录",
        "dimensions": ["安装位置", "持久化", "数字签名"],
        "detail": "对象：YunUtilityService.exe\n风险评分：48/100（可疑）",
        "selected": False,
    },
    {
        "type": "可疑目录", "name": "2345浏览器",
        "path": r"C:\Program Files (x86)\2345浏览器",
        "risk": 62, "level": "可疑",
        "reason": "命中高危特征词：2345；自称发布者与目录名不符；没有卸载程序",
        "dimensions": ["名称特征", "发布者", "分发形态"],
        "detail": "对象：2345浏览器\n风险评分：62/100（可疑）",
        "selected": False,
    },
])
win.adware_summary.setText("发现 3 项（高危 1 / 可疑 2），另有 750 项未达阈值未列出")

win.startup_model.set_items([
    {"type": "注册表", "hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "name": "OneDrive", "command": r"C:\Users\Administrator\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
     "enabled": True, "is_system": True, "backup_name": ""},
    {"type": "注册表", "hive": "HKCU", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "name": "TrafficMonitor", "command": r"C:\Program Files\TrafficMonitor\TrafficMonitor.exe",
     "enabled": True, "is_system": False, "backup_name": ""},
    {"type": "注册表", "hive": "HKLM", "key": r"Software\Microsoft\Windows\CurrentVersion\Run",
     "name": "SecurityHealth", "command": r"C:\Windows\system32\SecurityHealthSystray.exe",
     "enabled": True, "is_system": True, "backup_name": ""},
    {"type": "启动文件夹", "hive": "", "key": r"C:\Users\Administrator\AppData\Roaming\...\Startup",
     "name": "startup.lnk", "command": r"C:\Users\Administrator\AppData\Roaming\...\Startup\startup.lnk",
     "enabled": False, "is_system": False, "backup_name": ""},
])
win.startup_summary.setText("共 4 项，已启用 3 项，已禁用 1 项")

for i, name in enumerate(NAMES):
    win._switch_page(i)
    app.processEvents()
    path = OUT / f"page{i}_{name}.png"
    win.grab().save(str(path))
    print("saved", path)

# 空间分析页：灌入一份真实的扫描结果
import os  # noqa: E402
import tempfile  # noqa: E402

from core.space_analyzer import SpaceAnalyzer  # noqa: E402

sandbox = tempfile.mkdtemp(prefix="wc_render_")
os.makedirs(os.path.join(sandbox, "Videos"), exist_ok=True)
os.makedirs(os.path.join(sandbox, "Downloads"), exist_ok=True)
os.makedirs(os.path.join(sandbox, "AppData", "Local", "Cache"), exist_ok=True)
os.makedirs(os.path.join(sandbox, "Documents"), exist_ok=True)
os.makedirs(os.path.join(sandbox, "Program Files", "SomeApp"), exist_ok=True)
for path, size in (
    (os.path.join(sandbox, "Videos", "movie.mp4"), 4_000_000),
    (os.path.join(sandbox, "Downloads", "setup.exe"), 1_200_000),
    (os.path.join(sandbox, "AppData", "Local", "Cache", "c.bin"), 2_500_000),
    (os.path.join(sandbox, "Documents", "report.pdf"), 300_000),
    (os.path.join(sandbox, "Program Files", "SomeApp", "app.exe"), 900_000),
):
    with open(path, "wb") as f:
        f.write(b"\0" * size)

win._switch_page(2)
app.processEvents()
an = SpaceAnalyzer()
node = an.scan(sandbox, max_depth=4)
win.space_page.root = node
win.space_page.current = node
win.space_page.treemap.set_root(node)
win.space_page._refresh_list()
win.space_page.space_summary.setText(
    f"共 {node.total_size() / 1024 / 1024:.1f} MB　文件 {node.file_count} 个")
win.space_page._marked = {
    os.path.normcase(os.path.join(sandbox, "AppData", "Local", "Cache")): {
        "name": "Cache", "path": os.path.join(sandbox, "AppData", "Local", "Cache"),
        "size": 2_500_000},
}
win.space_page._refresh_plan()
win.space_page.treemap.set_marked(win.space_page._marked.keys())
app.processEvents()
win.grab().save(str(OUT / "page2_space.png"))
print("saved", OUT / "page2_space.png")

print("RENDER DONE")
