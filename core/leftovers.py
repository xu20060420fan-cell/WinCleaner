"""残留与缓存的深度检测。

这一类"垃圾"没法靠扫文件名找到，只能靠**交叉比对**：

* **卸载残留**：注册表里的卸载表（Uninstall）没有对应项了，目录还留在
  Program Files / ProgramData / AppData 里 —— 这就是卸载不干净留下的孤儿目录。
* **浏览器缓存**：Chrome / Edge / Firefox / 360 / QQ 浏览器等各自的
  Cache、Code Cache、GPUCache、Service Worker 缓存，位置深且分散，
  手工找几乎不可能。
* **系统级缓存**：传递优化（Delivery Optimization）、Windows.old、
  CBS/DISM 日志、ETL 跟踪文件等。
"""
import glob
import logging
import os
import re
import winreg
from typing import Dict, List, Optional

from .utils import (
    get_appdata_local,
    get_appdata_roaming,
    get_program_data,
    get_system_drive,
    get_user_profile,
    normalize_path,
)

# ---------------------------------------------------------------------------
# 卸载信息
# ---------------------------------------------------------------------------

_UNINSTALL_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    (winreg.HKEY_CURRENT_USER,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
]


def get_uninstall_entries() -> List[Dict]:
    """读取注册表里的已安装软件清单。"""
    out: List[Dict] = []
    for hive, key_path in _UNINSTALL_KEYS:
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        sub = winreg.EnumKey(key, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(key, sub, 0, winreg.KEY_READ) as sk:
                            name = _value(sk, "DisplayName")
                            if not name:
                                continue
                            out.append({
                                "key": key_path,
                                "subkey": sub,
                                "name": name,
                                "publisher": _value(sk, "Publisher"),
                                "version": _value(sk, "DisplayVersion"),
                                "install_location": _value(sk, "InstallLocation"),
                                "install_date": _value(sk, "InstallDate"),
                                "uninstall": _value(sk, "UninstallString"),
                            })
                    except OSError:
                        continue
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return out


def _value(key, name: str) -> str:
    try:
        value, _ = winreg.QueryValueEx(key, name)
        return str(value).strip()
    except (FileNotFoundError, OSError):
        return ""


#: 判定"这个目录属于某个已安装软件"时忽略的目录名
_IGNORED_DIR_NAMES = {
    "windows", "system32", "syswow64", "winsxs", "sys", "servicing",
    "microsoft", "packages", "windowsapps", "temp", "tmp", "programs",
    "common files", "internet explorer", "windows nt", "windows photo viewer",
    "windows defender", "windows sidebyside", "windows portable devices",
    "windows webp photon", "windows security", "windows update",
    "desktop.ini", "amd", "nvidia corporation", "nvidia", "commonfiles",
    "system32", "uninstall", "assembly", "driverstore", "winsxs",
    "crashdumps", "microsoft office", "microsoft edge", "microsoft edge update",
}


def _norm_name(text: str) -> str:
    """把名字规范化，便于做包含关系比较。"""
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]", "", (text or "").lower())


def _known_program_names(entries: List[Dict]) -> List[str]:
    """从卸载表里提取所有可识别的程序名。"""
    names = []
    for item in entries:
        for raw in (item.get("name", ""),):
            if raw:
                names.append(_norm_name(raw))
        for raw in (item.get("install_location", ""), item.get("uninstall", "")):
            if not raw:
                continue
            path = os.path.expandvars(raw.strip().strip('"'))
            if not path:
                continue
            base = os.path.basename(os.path.normpath(path))
            if base:
                names.append(_norm_name(base))
    return [n for n in names if len(n) >= 3]


#: 硬性排除：这些目录即使看起来"没有卸载记录"也绝不能当残留清理
#: （删掉会导致软件无法卸载/修复）
HARD_EXCLUDE_DIRS = {
    "package cache",          # MSI 修复与卸载必需
    "installshield installation information",
    "difx",                  # InstallShield 的安装信息
    "msbuild",                # Visual Studio 组件
    "common files",
    "windows defender",
    "windows security",
    "windows kits",
    "windows phone",
}


def _start_menu_names() -> List[str]:
    """开始菜单里出现过的程序名（说明它是正经安装的软件）。"""
    names = []
    bases = [
        os.path.join(get_program_data(), "Microsoft", "Windows", "Start Menu",
                     "Programs"),
        os.path.join(get_appdata_roaming(), "Microsoft", "Windows", "Start Menu",
                     "Programs"),
    ]
    for base in bases:
        if not os.path.isdir(base):
            continue
        stack = [base]
        while stack:
            current = stack.pop()
            try:
                for entry in os.scandir(current):
                    if entry.is_dir(follow_symlinks=False):
                        names.append(_norm_name(entry.name))
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False) and \
                            entry.name.lower().endswith(".lnk"):
                        names.append(_norm_name(os.path.splitext(entry.name)[0]))
            except (OSError, PermissionError):
                continue
    return [n for n in names if len(n) >= 3]


def find_orphaned_directories(candidates: Optional[List[str]] = None,
                              max_depth: int = 2) -> List[Dict]:
    """找出"卸载信息已不存在、目录却还在"的孤儿目录。

    判定依据（**五条同时成立**才算残留，宁可漏报也不误删）：

    1. 不在硬性排除名单里（Package Cache 之类删了会导致无法卸载）；
    2. 目录名与注册表卸载表里的任何程序名都对不上；
    3. 目录名不在可信品牌白名单里；
    4. 开始菜单里没有同名项（说明不是正经安装的软件）；
    5. 目录里的可执行文件 **没有有效的数字签名**。
    """
    entries = get_uninstall_entries()
    known = _known_program_names(entries)
    start_menu = _start_menu_names()
    known_paths = set()
    for item in entries:
        for raw in (item.get("install_location", ""), item.get("uninstall", "")):
            if not raw:
                continue
            path = os.path.expandvars(raw.strip().strip('"'))
            if path:
                known_paths.add(os.path.normcase(os.path.normpath(path)))

    if candidates is None:
        candidates = _leftover_scan_roots()

    out: List[Dict] = []
    for root in candidates:
        if not os.path.isdir(root):
            continue
        try:
            entries_list = list(os.scandir(root))
        except (OSError, PermissionError):
            continue
        for entry in entries_list:
            if not entry.is_dir(follow_symlinks=False):
                continue
            name = entry.name
            low = name.lower()
            norm = _norm_name(name)
            # ① 硬性排除
            if low in HARD_EXCLUDE_DIRS or norm in HARD_EXCLUDE_DIRS:
                continue
            if low in _IGNORED_DIR_NAMES or low.startswith("."):
                continue
            if low.startswith("windows "):
                continue
            if os.path.normcase(os.path.normpath(entry.path)) in known_paths:
                continue
            # ② 与卸载表里的程序名对不上？
            if len(norm) >= 3 and any(
                    norm in k or (len(k) >= 4 and k in norm) for k in known):
                continue
            # ③ 可信品牌白名单
            if _matches_trusted_brand(name):
                continue
            # ④ 开始菜单里没有同名项
            if len(norm) >= 3 and any(
                    norm in k or (len(k) >= 4 and k in norm) for k in start_menu):
                continue
            exe_count = _count_executables(entry.path, max_depth)
            if not exe_count:
                continue
            # ⑤ 目录里没有有效签名的可执行文件
            if _has_signed_executable(entry.path):
                continue
            out.append({
                "name": name,
                "path": entry.path,
                "exe_count": exe_count,
                "reason": "卸载信息中已无此程序、开始菜单里也没有、"
                          "且其中的程序没有数字签名",
            })
    return out


def _matches_trusted_brand(name: str) -> bool:
    """目录名是否命中可信品牌白名单。"""
    try:
        from .config import load_config
        brands = [b.lower() for b in load_config().get("trusted_brands", [])]
    except Exception:
        brands = []
    norm = _norm_name(name)
    for brand in brands:
        b = _norm_name(brand)
        if len(b) >= 3 and (b in norm or (len(norm) >= 4 and norm in b)):
            return True
    return False


def _has_signed_executable(path: str) -> bool:
    """目录里（递归两层）是否存在有有效数字签名的可执行文件。"""
    from .signature import verify_signature

    checked = 0
    stack = [(path, 0)]
    while stack and checked < 8:
        current, depth = stack.pop()
        try:
            for entry in os.scandir(current):
                try:
                    if entry.is_file(follow_symlinks=False) and \
                            entry.name.lower().endswith((".exe", ".dll")):
                        checked += 1
                        sig = verify_signature(entry.path)
                        if sig.get("status") == "valid":
                            return True
                        if checked >= 8:
                            break
                    elif entry.is_dir(follow_symlinks=False) and depth < 2:
                        stack.append((entry.path, depth + 1))
                except OSError:
                    continue
        except (OSError, PermissionError):
            continue
    return False


def _leftover_scan_roots() -> List[str]:
    system_drive = get_system_drive()
    return [
        os.path.join(system_drive, "Program Files"),
        os.path.join(system_drive, "Program Files (x86)"),
        get_program_data(),
        get_appdata_local(),
        get_appdata_roaming(),
    ]


def _count_executables(path: str, max_depth: int) -> int:
    count = 0
    stack = [(path, 0)]
    while stack and count < 50:
        current, depth = stack.pop()
        try:
            for entry in os.scandir(current):
                if entry.is_file(follow_symlinks=False) and \
                        entry.name.lower().endswith((".exe", ".dll", ".bat", ".cmd")):
                    count += 1
                    if count >= 50:
                        break
                elif entry.is_dir(follow_symlinks=False) and depth < max_depth:
                    stack.append((entry.path, depth + 1))
        except (OSError, PermissionError):
            continue
    return count


def _looks_like_windows_component(path: str) -> bool:
    """判断目录是不是 Windows 自带组件。

    Windows 自带应用（Windows Mail / Media Player / 录音机…）在
    Program Files 下但没有标准的卸载项，光看名字会误判成"卸载残留"。
    这里看目录里的可执行文件自称的发布者是不是 Microsoft。
    """
    from .pe_inspect import executable_in_dir
    from .signature import get_version_info

    for exe in executable_in_dir(path, limit=3):
        try:
            info = get_version_info(exe)
        except Exception:
            continue
        company = (info.get("company") or "").lower()
        product = (info.get("product") or "").lower()
        original = (info.get("original_filename") or "").lower()
        if "microsoft" in company or "microsoft" in product or \
                "microsoft" in original:
            return True
    return False


def find_missing_install_records() -> List[Dict]:
    """反向检查：注册表里还有卸载记录，但安装目录已经没了。"""
    out = []
    for item in get_uninstall_entries():
        location = item.get("install_location", "")
        if not location:
            continue
        path = os.path.expandvars(location.strip())
        if not path or not os.path.isabs(path):
            continue
        if not os.path.exists(path):
            out.append({
                "name": item.get("name", ""),
                "path": path,
                "reason": "卸载记录仍在，但安装目录已不存在",
            })
    return out


# ---------------------------------------------------------------------------
# 浏览器缓存
# ---------------------------------------------------------------------------

#: 浏览器缓存目录模板（支持 * 通配）
BROWSER_CACHE_PATTERNS = [
    ("Chrome 缓存", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Cache"),
    ("Chrome 代码缓存", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Code Cache"),
    ("Chrome GPU 缓存", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\GPUCache"),
    ("Chrome Service Worker", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Service Worker\\CacheStorage"),
    ("Edge 缓存", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\Cache"),
    ("Edge 代码缓存", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\Code Cache"),
    ("Edge GPU 缓存", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\GPUCache"),
    ("Edge Service Worker", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\Service Worker\\CacheStorage"),
    ("Firefox 缓存", "%LOCALAPPDATA%\\Mozilla\\Firefox\\Profiles\\*\\cache2"),
    ("360 极速浏览器缓存", "%LOCALAPPDATA%\\360Chrome\\Chrome\\User Data\\*\\Cache"),
    ("360 安全浏览器缓存", "%LOCALAPPDATA%\\360ChromeX\\Chrome\\User Data\\*\\Cache"),
    ("QQ 浏览器缓存", "%LOCALAPPDATA%\\Tencent\\QQBrowser\\User Data\\*\\Cache"),
    ("搜狗浏览器缓存", "%APPDATA%\\SogouExplorer\\Webkit\\Cache"),
    ("网易云音乐缓存", "%LOCALAPPDATA%\\Netease\\CloudMusic\\Cache"),
    ("微信缓存", "%APPDATA%\\Tencent\\WeChat\\xwechat\\temp"),
    ("钉钉缓存", "%LOCALAPPDATA%\\DingTalk*\\*\\Cache"),
    ("百度网盘缓存", "%LOCALAPPDATA%\\BaiduNetdisk\\cache"),
    ("夸克网盘缓存", "%LOCALAPPDATA%\\QuarkCloudDrive\\Cache"),
    ("VS Code 缓存", "%APPDATA%\\Code\\Cache"),
    ("VS Code 代码缓存", "%APPDATA%\\Code\\CachedData"),
    ("VS Code 扩展缓存", "%APPDATA%\\Code\\CachedExtensions"),
    ("Microsoft Store 应用缓存", "%LOCALAPPDATA%\\Packages\\*\\LocalCache"),
    ("Microsoft Store 临时缓存", "%LOCALAPPDATA%\\Packages\\*\\TempState"),
    ("Microsoft Store 临时文件", "%LOCALAPPDATA%\\Packages\\*\\Temp"),
]

#: 浏览器 Cookie / 登录态目录（清理会让用户退出登录，需显式确认）
BROWSER_COOKIE_PATTERNS = [
    ("Chrome Cookie", "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\*\\Network\\Cookies"),
    ("Edge Cookie", "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\*\\Network\\Cookies"),
    ("360 浏览器 Cookie", "%LOCALAPPDATA%\\360Chrome\\Chrome\\User Data\\*\\Network\\Cookies"),
    ("QQ 浏览器 Cookie", "%LOCALAPPDATA%\\Tencent\\QQBrowser\\User Data\\*\\Network\\Cookies"),
]


def find_browser_caches() -> List[Dict]:
    """找出各浏览器的缓存目录。"""
    return _expand_patterns(BROWSER_CACHE_PATTERNS)


def find_browser_cookies() -> List[Dict]:
    """找出各浏览器的 Cookie / 登录态文件（单独一项，清理会掉登录）。"""
    return _expand_patterns(BROWSER_COOKIE_PATTERNS)


def _expand_patterns(patterns) -> List[Dict]:
    out = []
    seen = set()
    for label, pattern in patterns:
        raw = os.path.expandvars(pattern)
        try:
            matched = glob.glob(raw, recursive=False)
        except OSError:
            continue
        for path in matched:
            key = normalize_path(path)
            if key in seen or not os.path.exists(path):
                continue
            seen.add(key)
            out.append({
                "label": label,
                "path": path,
                "is_file": os.path.isfile(path),
            })
    return out


# ---------------------------------------------------------------------------
# 系统级缓存
# ---------------------------------------------------------------------------


def find_system_junk() -> List[Dict]:
    """系统级可清理项（体积大、位置固定）。"""
    system_drive = get_system_drive()
    out: List[Dict] = []

    def add(label, path, note, is_dir=True):
        if path and os.path.exists(path):
            out.append({"label": label, "path": path, "note": note,
                        "is_dir": is_dir})

    add("Windows 旧版本安装", os.path.join(system_drive, "Windows.old"),
        "升级到 Windows 10/11 后遗留的旧系统，可释放数十 GB")
    add("传递优化缓存",
        os.path.join(system_drive, "Windows", "SoftwareDistribution",
                     "DeliveryOptimization"),
        "Windows 更新分发用的缓存")
    add("传递优化缓存（服务账户）",
        os.path.join(system_drive, "Windows", "ServiceProfiles", "NetworkService",
                     "AppData", "Local", "Microsoft", "Windows",
                     "DeliveryOptimization"),
        "Windows 更新分发用的缓存")
    add("组件存储分析日志",
        os.path.join(system_drive, "Windows", "Logs", "CBS"),
        "系统组件服务日志")
    add("DISM 日志", os.path.join(system_drive, "Windows", "Logs", "DISM"),
        "映像维护日志")
    add("Windows 升级残留日志",
        os.path.join(system_drive, "Windows", "Panther"),
        "升级过程日志")
    add("系统错误报告队列",
        os.path.join(system_drive, "ProgramData", "Microsoft", "Windows",
                     "WER", "ReportQueue"),
        "待上报的错误报告")
    add("系统错误报告归档",
        os.path.join(system_drive, "ProgramData", "Microsoft", "Windows",
                     "WER", "ReportArchive"),
        "已归档的错误报告")
    add("用户错误报告",
        os.path.join(get_appdata_local(), "Microsoft", "Windows", "WER"),
        "当前用户的错误报告")
    add("用户崩溃转储",
        os.path.join(get_appdata_local(), "CrashDumps"),
        "程序崩溃时的转储文件")
    add("字体缓存", os.path.join(get_appdata_local(), "fontconfig", "cache"),
        "字体渲染缓存，可自动重建")
    add("DirectX 着色器缓存",
        os.path.join(get_appdata_local(), "D3DSCache"),
        "图形着色器缓存，可自动重建")
    add("缩略图数据库",
        os.path.join(get_appdata_local(), "Microsoft", "Windows", "Explorer"),
        "资源管理器缩略图与图标缓存")
    add("Internet 临时文件",
        os.path.join(get_appdata_local(), "Microsoft", "Windows", "INetCache"),
        "IE/旧式组件的临时文件")
    add("Windows 安装日志",
        os.path.join(system_drive, "Windows", "Panther", "UnattendGC"),
        "无人应答的安装日志")
    add("Windows 升级备份",
        os.path.join(system_drive, "Windows.old", "Users"),
        "旧系统中的用户数据")
    add("系统 Temp 目录",
        os.path.join(system_drive, "Windows", "Temp"),
        "系统级临时文件")
    return out


def find_old_installers(min_age_days: int = 30) -> List[Dict]:
    """临时目录/下载目录里的旧安装包。"""
    out = []
    import time
    cutoff = time.time() - min_age_days * 86400
    for base in {os.environ.get("TEMP", ""),
                 os.path.join(get_user_profile(), "Downloads")}:
        if not base or not os.path.isdir(base):
            continue
        try:
            for entry in os.scandir(base):
                if not entry.is_file(follow_symlinks=False):
                    continue
                low = entry.name.lower()
                if not low.endswith((".exe", ".msi", ".msix", ".appx", ".iso",
                                     ".zip", ".7z", ".rar")):
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if st.st_mtime > cutoff:
                    continue
                out.append({
                    "label": "旧安装包",
                    "path": entry.path,
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                    "is_file": True,
                })
        except (OSError, PermissionError):
            continue
    return out


def find_large_system_files(min_size_mb: int = 1024) -> List[Dict]:
    """系统盘根目录下的大文件（休眠文件、页面文件等）。"""
    import time
    out = []
    cutoff = time.time() - 30 * 86400
    system_drive = get_system_drive()
    for name in ("hiberfil.sys", "pagefile.sys", "swapfile.sys"):
        path = os.path.join(system_drive, name)
        if not os.path.exists(path):
            continue
        try:
            st = os.stat(path)
        except OSError:
            continue
        if st.st_mtime > cutoff:
            continue
        out.append({
            "label": name,
            "path": path,
            "size": st.st_size,
            "mtime": st.st_mtime,
            "is_file": True,
        })
    return out
