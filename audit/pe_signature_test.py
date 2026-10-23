"""PE 解析与签名验证的快速自检。

用法: .venv\\Scripts\\python.exe audit\\pe_signature_test.py
"""
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.pe_inspect import parse_pe, executable_in_dir  # noqa: E402
from core.signature import get_version_info, verify_signature  # noqa: E402

SAMPLES = [
    r"C:\Windows\System32\notepad.exe",
    r"C:\Windows\System32\kernel32.dll",
    r"C:\Windows\explorer.exe",
]


def pick_samples():
    out = [p for p in SAMPLES if os.path.isfile(p)]
    # 再补几个用户目录下的 exe
    for root in (os.environ.get("LOCALAPPDATA", ""), os.environ.get("ProgramFiles", "")):
        if not root or not os.path.isdir(root):
            continue
        try:
            for entry in os.scandir(root):
                if entry.is_dir(follow_symlinks=False):
                    for exe in executable_in_dir(entry.path, limit=1):
                        out.append(exe)
                        break
                if len(out) >= 8:
                    break
        except OSError:
            continue
        if len(out) >= 8:
            break
    return out


def main():
    samples = pick_samples()
    print(f"样本 {len(samples)} 个\n")
    for path in samples:
        t0 = time.time()
        pe = parse_pe(path)
        sig = verify_signature(path)
        ver = get_version_info(path)
        dt = (time.time() - t0) * 1000
        print(f"── {Path(path).name}")
        print(f"   路径      {path}")
        print(f"   架构      {pe.arch}  时间戳 {pe.timestamp_str}  "
              f".NET={pe.is_dotnet}  链接器 {pe.linker}")
        print(f"   节区      {[(s['name'], round(s['entropy'], 2)) for s in pe.sections]}")
        print(f"   最大熵    {pe.max_entropy:.2f}   壳 {pe.packers}")
        print(f"   导入DLL   {list(pe.imports.keys())[:6]}")
        if pe.suspicious_imports:
            for cat, apis in pe.suspicious_imports.items():
                print(f"   ⚠ {cat}: {apis[:6]}")
        print(f"   签名      [{sig['status']}] {sig['status_text']}  "
              f"签名者={sig['signer'] or '-'}  颁发者={sig['issuer'] or '-'}")
        print(f"   发布者    公司={ver['company'] or '-'}  产品={ver['product'] or '-'}  "
              f"原名={ver['original_filename'] or '-'}")
        print(f"   耗时      {dt:.1f} ms\n")


if __name__ == "__main__":
    main()
