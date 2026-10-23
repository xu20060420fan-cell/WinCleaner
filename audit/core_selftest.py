"""核心层自检：跨盘符 critical 判定、删除闸门、只读扫描。

用法: .venv\\Scripts\\python.exe audit\\core_selftest.py
只读，不删除任何文件。
"""
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.cleaner import Cleaner
from core.safety import check_delete_allowed, get_policy
from core.scanner import SystemScanner
from core.utils import is_system_critical


def main():
    print("--- [1] critical 跨盘符判定 ---")
    for p in (r"C:\$Recycle.Bin\S-1-5-1\$R.zip", r"D:\$Recycle.Bin\S-1-5-1\$R.zip",
              r"C:\Windows\System32\winevt\Logs\Security.evtx",
              r"D:\Windows\System32\winevt\Logs\Security.evtx",
              r"C:\Program Files\Foo\bar.exe", r"D:\Program Files\Foo\bar.exe",
              r"C:\Windows\Temp\x.tmp"):
        print(f"    critical={str(is_system_critical(p)):5}  {p}")

    print("--- [2] 删除闸门 ---")
    pol = get_policy("system_temp")
    cases = [
        (r"C:\Windows\Temp\x.tmp", [r"C:\Windows\Temp"]),
        (r"D:\$Recycle.Bin\x", [r"C:\Windows\Temp"]),
        (r"C:\Users\someone\Documents\a.txt", [r"C:\Windows\Temp"]),
        (r"C:\Windows\Temp\sub\..\..\etc\passwd", [r"C:\Windows\Temp"]),
    ]
    for path, roots in cases:
        d = check_delete_allowed(path, pol, allowed_roots=roots)
        print(f"    allowed={str(d.allowed):5} {d.reason}  <- {path}")

    print("--- [3] 只读扫描 ---")
    sc = SystemScanner()
    t0 = time.time()
    res = sc.scan_all({"system_temp": True, "thumbnails": True, "software_junk": True})
    print(f"    用时 {time.time() - t0:.1f}s  项数 {len(res)}  "
          f"大小 {sum(r.size for r in res) / 1024 ** 3:.3f} GB")
    for cat, n in Counter(r.category for r in res).most_common():
        size = sum(r.size for r in res if r.category == cat)
        print(f"      {cat}: {n} 项 / {size / 1024 ** 2:.1f} MB")
    for r in res[:5]:
        print(f"      样例 {r.category} | {r.path} | {r.size}")

    print("--- [4] 回收站/事件日志不再逐文件收集 ---")
    s = SystemScanner()
    s.scan_recycle_bin()
    s.scan_dns_cache()
    print(f"    回收站 + DNS 产生 {len(s.results)} 项（应为 2 个特殊动作）")
    for r in s.results:
        print(f"      {r.category} special={r.special!r} path={r.path}")

    print("--- [5] 预演清理不落盘 ---")
    sc2 = SystemScanner()
    sc2.scan_all({"system_temp": True})
    for r in sc2.results:
        r.selected = True
    cleaner = Cleaner()
    cleaner.dry_run = True
    stats = cleaner.clean(sc2.results)
    print(f"    预演统计: {stats}")
    print("SELFTEST DONE")


if __name__ == "__main__":
    main()
