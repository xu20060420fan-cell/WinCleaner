"""WinCleaner PyInstaller 打包脚本。

相对旧版的改动
--------------
* **不再删除 spec 文件**：旧脚本每次打包前先删掉 ``WinCleaner.spec``，
  再让 PyInstaller 重新生成，导致版本控制里那份手改过的 spec 永远失效。
  现在全部参数在命令行里给，spec 由 PyInstaller 自行生成到 build 目录。
* **不再硬编码绝对路径**：旧 spec 写死了 ``D:\\stm32\\WinCleaner\\main.py``，
  换一台机器就构建失败。现在统一用相对路径 + ``cwd=PROJECT_ROOT``。
* **补齐图标与版本信息**：``--icon`` / ``--version-file``。
* **保留 --windowed**：无控制台窗口启动。

用法:
    .venv\\Scripts\\python.exe build_exe.py              # 正常打包
    .venv\\Scripts\\python.exe build_exe.py --assets-only # 只生成图标与版本信息
    .venv\\Scripts\\python.exe build_exe.py --uac-admin   # 打包为"始终以管理员运行"
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
ASSETS_DIR = PROJECT_ROOT / "assets"

sys.path.insert(0, str(PROJECT_ROOT))


def clean_old_builds():
    """清理旧的打包产物（不动 spec 文件）。"""
    for d in (DIST_DIR, BUILD_DIR):
        if d.exists():
            try:
                shutil.rmtree(str(d), ignore_errors=True)
                print(f"已清理: {d}")
            except Exception as e:
                print(f"清理 {d} 失败: {e}")


def build(uac_admin: bool = False):
    from build_assets import make_icon, make_version_info

    icon_path = make_icon()
    version_file = make_version_info()

    clean_old_builds()

    # 确保默认配置文件存在，以便打包进去
    from core.config import load_config
    load_config()

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "WinCleaner",
        "--onefile",
        "--windowed",
        "--noconfirm",
        "--clean",
        "--noupx",
        "--distpath", str(DIST_DIR),
        "--workpath", str(BUILD_DIR),
        "--specpath", str(BUILD_DIR),
        # 注意：--add-data 的相对路径是相对 **spec 所在目录** 解析的，
        # 而 spec 被放到 build/ 下，所以这里必须用绝对路径。
        "--add-data", f"{PROJECT_ROOT / 'ui' / 'style.qss'}{os.pathsep}ui",
        "--add-data", f"{PROJECT_ROOT / 'config.json'}{os.pathsep}.",
        "--version-file", str(version_file),
        "--icon", str(icon_path),
        "--hidden-import", "winreg",
        "--hidden-import", "psutil",
    ]
    if uac_admin:
        cmd.append("--uac-admin")
    cmd.append(str(PROJECT_ROOT / "main.py"))

    print("执行命令:", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    if result.returncode != 0:
        print("打包失败")
        sys.exit(1)

    # 把默认配置与使用说明一起放到 dist，方便直接分发
    shutil.copy2(PROJECT_ROOT / "config.json", DIST_DIR / "config.json")
    exe = DIST_DIR / "WinCleaner.exe"
    print(f"打包成功: {exe}  ({exe.stat().st_size / 1024 / 1024:.1f} MB)")


if __name__ == "__main__":
    if "--assets-only" in sys.argv:
        from build_assets import make_icon, make_version_info
        make_icon()
        make_version_info()
    else:
        build(uac_admin="--uac-admin" in sys.argv)
