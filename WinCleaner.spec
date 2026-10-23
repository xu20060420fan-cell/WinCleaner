# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

注意：这里的路径全部使用**相对路径**，PyInstaller 会以本 spec 所在目录为基准解析，
换到任何机器上都能直接使用（旧版写死了 D:\\stm32\\WinCleaner\\main.py）。

推荐直接用 ``.venv\\Scripts\\python.exe build_exe.py`` 打包，
本文件保留给需要手动调整高级选项的场景。
"""
import os
from pathlib import Path

BASE = Path(os.path.abspath(SPECPATH))

a = Analysis(
    [str(BASE / 'main.py')],
    pathex=[str(BASE)],
    binaries=[],
    datas=[
        (str(BASE / 'ui' / 'style.qss'), 'ui'),
        (str(BASE / 'config.json'), '.'),
    ],
    hiddenimports=['winreg', 'psutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='WinCleaner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(BASE / 'assets' / 'icon.ico'),
    version=str(BASE / 'version_info.txt'),
)
