"""流氓软件扫描（多信号取证）的端到端验证。

用法: .venv\\Scripts\\python.exe audit\\adware_scan_test.py
只读，不删除任何文件。
"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.adware_scanner import AdwareScanner  # noqa: E402


def main():
    scanner = AdwareScanner(progress_callback=lambda m, p: None, deep_budget=60)
    t0 = time.time()
    results = scanner.scan()
    dt = time.time() - t0

    print(f"扫描用时 {dt:.1f}s")
    print(f"进入结果表 {len(results)} 项，未达阈值 {scanner.low_confidence_count} 项\n")

    results.sort(key=lambda r: -r.get("risk", 0))
    for r in results[:20]:
        print(f"── [{r.get('level')}] {r.get('risk')} 分  {r.get('name')}")
        print(f"   路径   {r.get('path')}")
        print(f"   维度   {'、'.join(r.get('dimensions', []))}")
        print(f"   依据   {r.get('reason')}")
        sig = r.get("signature") or {}
        if sig:
            print(f"   签名   {sig.get('status_text')} "
                  f"{sig.get('signer') or ''}")
        if r.get("persistence"):
            print(f"   自启动 {r['persistence']}")
        print()

    if results:
        print("=" * 60)
        print("示例：完整证据链")
        print(results[0].get("detail", ""))


if __name__ == "__main__":
    main()
