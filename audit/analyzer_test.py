"""多信号分析引擎的真实性验证。

用法: .venv\\Scripts\\python.exe audit\\analyzer_test.py
"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.analyzer import MalwareAnalyzer  # noqa: E402


def show(analyzer, path, label):
    t0 = time.time()
    if os.path.isdir(path):
        a = analyzer.analyze_directory(path)
    else:
        a = analyzer.analyze_executable(path)
    dt = (time.time() - t0) * 1000
    print(f"\n=== {label} ===")
    print(f"  {a.name}  风险 {a.risk}/100  等级 {a.level}  ({dt:.0f} ms)")
    print(f"  维度命中: {'、'.join(a.dimensions) or '无'}")
    for s in sorted(a.signals, key=lambda x: -x.weight):
        if s.weight == 0:
            continue
        print(f"   {s.weight:+4d} [{s.dimension}] {s.detail}")
    if a.persistence:
        print(f"  持久化: {a.persistence}")
    return a


def main():
    analyzer = MalwareAnalyzer(deep_budget=40)
    t0 = time.time()
    analyzer.persistence.build()
    print(f"持久化索引建立耗时 {time.time() - t0:.1f}s，"
          f"共索引 {len(analyzer.persistence._map)} 个自启动目标")

    # 正规软件
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    for entry in os.scandir(pf):
        if entry.is_dir(follow_symlinks=False):
            show(analyzer, entry.path, f"正规安装目录: {entry.name}")
            break

    # 用户 AppData 里的应用
    la = os.environ.get("LOCALAPPDATA", "")
    count = 0
    for entry in os.scandir(la):
        if entry.is_dir(follow_symlinks=False) and count < 2:
            show(analyzer, entry.path, f"用户应用目录: {entry.name}")
            count += 1

    # 临时目录里的可执行文件（强风险位置）
    temp = os.environ.get("TEMP", "")
    for entry in os.scandir(temp):
        if entry.is_file(follow_symlinks=False) and entry.name.lower().endswith(".exe"):
            show(analyzer, entry.path, f"临时目录里的 exe: {entry.name}")
            break

    # 系统目录（应判为可信）
    show(analyzer, os.path.join(os.environ.get("SystemDrive", "C:") + "\\",
                                "Windows", "System32", "notepad.exe"),
         "系统文件 notepad.exe")

    # 关键词命中 + 未签名的组合
    fake = os.path.join(temp, "2345浏览器助手_Setup.exe")
    try:
        with open(fake, "wb") as f:
            f.write(b"MZ" + b"\x00" * 200)
        show(analyzer, fake, "伪装成 2345 的未签名程序")
    finally:
        try:
            os.unlink(fake)
        except OSError:
            pass


if __name__ == "__main__":
    main()
