"""WinCleaner 通用工具函数。

本模块只放"无状态"的通用能力（路径、格式化、哈希、回收站 API）。
"什么可以删"的策略判断全部集中在 :mod:`core.safety`，避免规则散落各处。
"""
import os
import sys
import ctypes
import logging
import hashlib
import stat as stat_mod
from ctypes import wintypes
from pathlib import Path
from datetime import datetime

# ---------------------------------------------------------------------------
# 权限
# ---------------------------------------------------------------------------


def is_admin() -> bool:
    """判断当前进程是否拥有管理员权限。"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def run_as_admin() -> bool:
    """以管理员权限重新启动自身。返回是否成功发起提权。"""
    if is_admin():
        return True
    try:
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ret = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        # ShellExecuteW 返回值 > 32 表示成功
        return int(ret) > 32
    except Exception as e:
        logging.error(f"提权失败: {e}")
        return False


# ---------------------------------------------------------------------------
# 格式化
# ---------------------------------------------------------------------------


def format_size(size_bytes: int) -> str:
    """把字节数格式化为人类可读字符串。"""
    if size_bytes is None or size_bytes < 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB"]
    idx = 0
    size = float(size_bytes)
    while size >= 1024 and idx < len(units) - 1:
        size /= 1024
        idx += 1
    return f"{size:.2f} {units[idx]}"


def format_age(days: float) -> str:
    """把天数格式化为可读文本。"""
    if days < 1:
        hours = max(1, int(days * 24))
        return f"{hours} 小时"
    if days < 30:
        return f"{days:.1f} 天"
    return f"{days / 30:.1f} 个月"


def get_disk_usage(path: str = "C:\\") -> dict:
    """获取指定磁盘分区的使用情况。

    返回 ``{"total", "used", "free", "percent", "path", "error"}``；
    出错时 ``error`` 非空且数值全为 0，调用方必须显式处理，不要静默当成 0。
    """
    result = {"total": 0, "used": 0, "free": 0, "percent": 0.0,
              "path": path, "error": ""}
    try:
        total, used, free = psutil_usage(path)
        result.update({"total": total, "used": used, "free": free})
        if total:
            result["percent"] = used / total * 100.0
    except Exception as e:
        result["error"] = str(e)
    return result


def psutil_usage(path: str):
    """包装 psutil.disk_usage，兼容传入根目录。"""
    import psutil
    p = Path(path)
    while p and not p.exists():
        p = p.parent
    if not p or not p.exists():
        p = Path("C:\\")
    usage = psutil.disk_usage(str(p))
    return usage.total, usage.used, usage.free


def list_drives() -> list:
    """列出本机所有就绪的磁盘分区。"""
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.isdir(root):
            drives.append(root)
    return drives


def get_app_dir() -> Path:
    """程序所在目录。

    打包成 onefile 后有两种"目录"：解包目录（``sys._MEIPASS``，只读，
    存放被打包进去的 config.json / style.qss）与 exe 所在目录
    （可写，放用户自己的文件）。这里返回解包目录。
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def get_exe_dir() -> Path:
    """exe 所在目录（打包后用于存放用户自己的文件）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).resolve().parent.parent


def get_log_dir() -> Path:
    """日志目录。

    优先放在用户可写目录（``%APPDATA%\\WinCleaner\\logs``），
    这样装到 Program Files 也能写日志，打包后也不会写到临时解包目录。
    """
    base = os.environ.get("APPDATA")
    if base:
        candidate = Path(base) / "WinCleaner" / "logs"
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            pass
    fallback = get_app_dir() / "logs"
    try:
        fallback.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return fallback


# ---------------------------------------------------------------------------
# 路径
# ---------------------------------------------------------------------------


def expand_path(path: str) -> str:
    """展开环境变量和常见占位符。"""
    p = os.path.expandvars(path)
    p = os.path.expanduser(p)
    return p


def get_system_drive() -> str:
    """获取系统盘符，通常为 C:\\。"""
    return os.environ.get("SystemDrive", "C:") + "\\"


def get_user_profile() -> str:
    """获取当前用户配置文件夹路径。"""
    return os.environ.get("USERPROFILE", os.path.expanduser("~"))


def get_program_data() -> str:
    """获取 ProgramData 路径。"""
    return os.environ.get("ALLUSERSPROFILE", "C:\\ProgramData")


def get_appdata_local() -> str:
    """获取当前用户 Local AppData 路径。"""
    return os.environ.get("LOCALAPPDATA", os.path.join(get_user_profile(), "AppData", "Local"))


def get_appdata_roaming() -> str:
    """获取当前用户 Roaming AppData 路径。"""
    return os.environ.get("APPDATA", os.path.join(get_user_profile(), "AppData", "Roaming"))


def get_temp_dirs() -> list:
    """获取常见临时目录列表（已去重、已规范化）。"""
    temps = []
    sys_temp = os.path.join(get_system_drive(), "Windows", "Temp")
    if os.path.isdir(sys_temp):
        temps.append(sys_temp)
    user_temp = os.environ.get("TEMP", os.path.join(get_user_profile(), "AppData", "Local", "Temp"))
    if os.path.isdir(user_temp):
        temps.append(user_temp)
    tmp = os.environ.get("TMP")
    if tmp and tmp != user_temp and os.path.isdir(tmp):
        temps.append(tmp)
    return dedupe_paths(temps)


def normalize_path(path: str) -> str:
    """把路径规范化为可比较的形式（绝对化、去尾分隔符、统一大小写）。"""
    if not path:
        return ""
    try:
        p = os.path.normpath(os.path.abspath(os.path.expandvars(path)))
    except Exception:
        return path
    return os.path.normcase(p)


def dedupe_paths(paths) -> list:
    """按规范化路径去重，保留首次出现的原始写法。"""
    seen = set()
    out = []
    for p in paths:
        key = normalize_path(p)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def is_same_path(a: str, b: str) -> bool:
    """判断两个路径是否指向同一位置。"""
    return normalize_path(a) == normalize_path(b)


def is_within(path: str, root: str) -> bool:
    """判断 path 是否位于 root 之内（root 自身也算在内）。"""
    p = normalize_path(path)
    r = normalize_path(root)
    if not p or not r:
        return False
    if p == r:
        return True
    return p.startswith(r.rstrip("\\") + "\\")


def is_drive_root(path: str) -> bool:
    """判断路径是否是某个盘符的根目录。"""
    try:
        drive, tail = os.path.splitdrive(os.path.abspath(path))
    except Exception:
        return False
    return bool(drive) and tail in ("", "\\")


def is_recycle_bin_path(path: str) -> bool:
    """判断路径是否位于任意盘符的回收站内。"""
    try:
        _drive, tail = os.path.splitdrive(os.path.abspath(path))
    except Exception:
        return False
    parts = [p for p in tail.replace("/", "\\").split("\\") if p]
    return bool(parts) and parts[0].lower() == "$recycle.bin"


def is_reparse_point(path: str) -> bool:
    """判断路径是否是符号链接 / 目录联接（junction）等重解析点。"""
    try:
        st = os.lstat(path)
    except OSError:
        return False
    attrs = getattr(st, "st_file_attributes", 0)
    reparse = getattr(stat_mod, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    if attrs & reparse:
        return True
    return os.path.islink(path)


# ---------------------------------------------------------------------------
# 系统关键路径（动态判定，跨盘符有效）
# ---------------------------------------------------------------------------

# Windows 目录下明确允许清理的子树（其余一律保护）
_WINDOWS_ALLOWED_SUBTREES = (
    "temp",
    "prefetch",
    "softwaredistribution",
    "minidump",
    "livekernelreports",
    "logs\\cbs",
    "logs\\dism",
    "downloadedprogramfiles",
    # 传递优化缓存与升级日志位于服务账户目录 / Panther 下，
    # 扫描器只会命中其中明确列出的子目录
    "serviceprofiles",
    "panther",
)

# 任何盘符根目录下都必须保护的条目
_ROOT_PROTECTED_NAMES = (
    "$recycle.bin",
    "system volume information",
    "recovery",
    "boot",
    "efi",
    "$winreagent",
    "perflogs",
)


def _protected_prefixes() -> list:
    """构造与盘符无关的受保护前缀列表（不含 Windows 目录，那部分单独判定）。"""
    prefixes = []
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env)
        if base:
            prefixes.append(os.path.abspath(base).lower())
    return prefixes


def is_system_critical(path: str) -> bool:
    """判断路径是否属于禁止清理的系统关键区域。

    与旧版不同：这里对所有盘符一视同仁（``D:\\$Recycle.Bin`` 与
    ``C:\\$Recycle.Bin`` 同样受保护），并依据当前系统盘与 Program Files
    环境变量动态推导，不再硬编码 ``C:\\``。
    """
    if not path:
        return True
    try:
        abspath = os.path.normpath(os.path.abspath(os.path.expandvars(path)))
    except Exception:
        return True
    lower = abspath.lower()

    # 盘符根目录本身
    if is_drive_root(abspath):
        return True

    drive, tail = os.path.splitdrive(abspath)
    parts = [p for p in tail.replace("/", "\\").split("\\") if p]

    # 盘符根级保护目录
    if parts and parts[0].lower() in _ROOT_PROTECTED_NAMES:
        return True

    # 盘符根级系统文件（pagefile.sys / hiberfil.sys / swapfile.sys）
    if len(parts) == 1 and parts[0].lower() in (
            "pagefile.sys", "hiberfil.sys", "swapfile.sys", "bootmgr"):
        return True

    # Windows 目录（任意盘符都一视同仁）：只放行明确的安全子树
    if parts[0].lower() == "windows":
        wrel = "\\".join(parts[1:]).lower()
        if not wrel:
            return True
        for allowed in _WINDOWS_ALLOWED_SUBTREES:
            if wrel == allowed or wrel.startswith(allowed + "\\"):
                break
        else:
            return True

    # 程序安装目录（任意盘符）：装的是软件，不是垃圾
    if parts[0].lower() in ("program files", "program files (x86)",
                            "programfiles", "program files (x86)"):
        return True

    # Program Files 等安装区
    for prefix in _protected_prefixes():
        if lower == prefix or lower.startswith(prefix + "\\"):
            return True

    return False


# ---------------------------------------------------------------------------
# 回收站 API（唯一的可逆删除出口）
# ---------------------------------------------------------------------------


class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", ctypes.c_uint16),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


_FO_DELETE = 3
_FOF_SILENT = 0x0004
_FOF_NOCONFIRMATION = 0x0010
_FOF_NOCONFIRMMKDIR = 0x0200
_FOF_ALLOWUNDO = 0x0040
_FOF_NOERRORUI = 0x0400

_SHERB_NOCONFIRMATION = 0x00000001
_SHERB_NOPROGRESSUI = 0x00000002
_SHERB_NOSOUND = 0x00000004


def delete_to_recycle_bin(paths) -> dict:
    """把文件/目录移入回收站（可还原）。

    这是本项目**唯一允许的删除方式**。返回
    ``{"ok": bool, "deleted": [...], "failed": [(path, reason)]}``。
    """
    targets = []
    for p in dedupe_paths(paths):
        if os.path.exists(p):
            targets.append(os.path.abspath(p))
    if not targets:
        return {"ok": True, "deleted": [], "failed": []}

    deleted = []
    failed = []
    # SHFileOperationW 对单次调用的路径数量没有硬上限，但分批可避免超长字符串
    for i in range(0, len(targets), 100):
        chunk = targets[i:i + 100]
        buf = "\0".join(chunk) + "\0\0"
        op = _SHFILEOPSTRUCTW(
            None, _FO_DELETE, buf, None,
            _FOF_ALLOWUNDO | _FOF_NOCONFIRMATION | _FOF_NOCONFIRMMKDIR
            | _FOF_SILENT | _FOF_NOERRORUI,
            False, None, None,
        )
        try:
            rc = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        except Exception as e:
            for p in chunk:
                failed.append((p, f"调用回收站 API 失败: {e}"))
            continue
        if rc != 0:
            for p in chunk:
                failed.append((p, f"回收站 API 返回错误码 {rc}"))
        elif op.fAnyOperationsAborted:
            for p in chunk:
                failed.append((p, "操作被系统中止"))
        else:
            for p in chunk:
                if os.path.exists(p):
                    failed.append((p, "删除后文件仍存在"))
                else:
                    deleted.append(p)
    return {"ok": not failed, "deleted": deleted, "failed": failed}


def empty_recycle_bin(drives=None) -> dict:
    """整体清空回收站。

    逐文件删除回收站内容会破坏 ``$I`` 索引结构并造成不可逆丢失，
    因此清空回收站只能走这个整体 API。返回 ``{"ok", "failed"}``。
    """
    if drives is None:
        drives = list_drives()
    failed = []
    for drive in drives:
        try:
            rc = ctypes.windll.shell32.SHEmptyRecycleBinW(
                None, drive, _SHERB_NOCONFIRMATION | _SHERB_NOPROGRESSUI | _SHERB_NOSOUND
            )
            if rc != 0:
                failed.append((drive, f"SHEmptyRecycleBinW 返回 {rc}"))
        except Exception as e:
            failed.append((drive, str(e)))
    return {"ok": not failed, "failed": failed}


def safe_delete(path: str, to_recycle: bool = True) -> dict:
    """安全删除文件或目录。

    ``to_recycle=True``（默认）表示移入回收站，可还原；
    ``to_recycle=False`` 表示永久删除，**仅供内部维护脚本使用**，
    交互式清理流程不应传入 False。
    """
    p = Path(path)
    result = {"success": False, "message": ""}
    if not p.exists():
        result["message"] = "路径不存在"
        return result
    if to_recycle:
        res = delete_to_recycle_bin([str(p)])
        if res["deleted"]:
            result["success"] = True
        else:
            result["message"] = res["failed"][0][1] if res["failed"] else "未知错误"
        return result
    try:
        if p.is_file() or p.is_symlink():
            p.unlink()
        elif p.is_dir():
            import shutil
            shutil.rmtree(str(p), ignore_errors=False)
        result["success"] = True
    except Exception as e:
        result["message"] = str(e)
    return result


# ---------------------------------------------------------------------------
# 文件属性
# ---------------------------------------------------------------------------


def file_hash(filepath: str, algorithm: str = "md5", block_size: int = 65536) -> str:
    """计算文件哈希值，用于重复文件检测。"""
    try:
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(block_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def file_age_days(filepath: str) -> float:
    """返回文件最后修改时间距今天数；取不到时返回 -1。"""
    try:
        return (datetime.now().timestamp() - os.path.getmtime(filepath)) / 86400.0
    except OSError:
        return -1.0


def is_file_locked(path: str) -> bool:
    """检测文件是否被其他进程占用（能独占打开即未被占用）。"""
    if not os.path.isfile(path):
        return False
    try:
        with open(path, "r+b"):
            pass
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def dir_size(path: str, max_files: int = 200000) -> int:
    """估算目录总字节数（受 max_files 限制，避免超大目录拖死 UI）。"""
    total = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
        for name in filenames:
            count += 1
            if count > max_files:
                return total
            try:
                total += os.path.getsize(os.path.join(dirpath, name))
            except OSError:
                continue
    return total


# ---------------------------------------------------------------------------
# 类型识别
# ---------------------------------------------------------------------------


def detect_file_type(filepath: str) -> str:
    """根据文件扩展名和路径判断文件类型。"""
    if not filepath:
        return "其他"
    lower = filepath.lower()

    photo_ext = (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".raw", ".cr2", ".nef")
    if lower.endswith(photo_ext):
        return "照片"

    video_ext = (".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".rmvb", ".m4v", ".3gp", ".ts")
    if lower.endswith(video_ext):
        return "视频"

    audio_ext = (".mp3", ".wav", ".flac", ".aac", ".ogg", ".m4a", ".wma")
    if lower.endswith(audio_ext):
        return "音频"

    doc_ext = (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", ".csv", ".md")
    if lower.endswith(doc_ext):
        return "文档"

    archive_ext = (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso")
    if lower.endswith(archive_ext):
        return "压缩包"

    exec_ext = (".exe", ".dll", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js")
    if lower.endswith(exec_ext):
        return "可执行文件"

    cache_ext = (".tmp", ".temp", ".cache", ".log", ".dmp", ".pf", ".db", ".idx", ".dat")
    if lower.endswith(cache_ext) or "\\cache\\" in lower or "\\caches\\" in lower or "\\temp\\" in lower:
        return "缓存/日志"

    return "其他"


#: 会被视为"个人数据"的文件类型（保护模式下一律跳过）
PERSONAL_FILE_TYPES = ("照片", "视频", "音频", "文档", "压缩包")

#: 属于安装载荷的扩展名（常规清理不允许触碰）
INSTALLER_EXTENSIONS = (".exe", ".dll", ".sys", ".msi", ".msp", ".msu", ".cab", ".esd", ".apk", ".appx", ".iso")


def is_installer_payload(filepath: str) -> bool:
    """判断文件是否属于安装载荷（可执行体 / 安装包）。"""
    return filepath.lower().endswith(INSTALLER_EXTENSIONS)


def is_personal_file(filepath: str) -> bool:
    """判断文件是否疑似用户个人数据。"""
    return detect_file_type(filepath) in PERSONAL_FILE_TYPES


def detect_source(filepath: str) -> str:
    """根据路径判断文件来源软件或系统组件。"""
    if not filepath:
        return "未知"
    lower = filepath.lower().replace("\\", "/")

    source_map = [
        ("tencent/qq", "QQ"),
        ("tencent/wechat", "微信"),
        ("tencent/wxwork", "企业微信"),
        ("tencent/qqlive", "腾讯视频"),
        ("tencent/qqmusic", "QQ 音乐"),
        ("dingtalk", "钉钉"),
        ("kingsoft/wps", "WPS"),
        ("kingsoft/office", "WPS"),
        ("baidunetdisk", "百度网盘"),
        ("thunder network", "迅雷"),
        ("netease/cloudmusic", "网易云音乐"),
        ("iqiyi", "爱奇艺"),
        ("youku", "优刻"),
        ("adobe", "Adobe"),
        ("microsoft/teams", "Microsoft Teams"),
        ("microsoft/visualstudio", "Visual Studio"),
        ("google/chrome", "Chrome"),
        ("microsoft/edge", "Edge"),
        ("mozilla/firefox", "Firefox"),
        ("360", "360 系列"),
        ("2345", "2345 系列"),
        ("sogou", "搜狗"),
        ("duba", "毒霸"),
        ("ksafe", "金山毒霸"),
        ("qihoo", "360"),
        ("windows/temp", "系统临时"),
        ("windows/prefetch", "系统预取"),
        ("windows/softwaredistribution", "Windows Update"),
        ("windows/explorer", "缩略图缓存"),
        ("windows/wer", "错误报告"),
        ("windows/minidump", "内存转储"),
        ("$recycle.bin", "回收站"),
        ("pip/cache", "Python pip"),
        ("npm-cache", "Node.js npm"),
        (".nuget/packages", "NuGet"),
        (".m2/repository", "Maven"),
    ]

    for pattern, name in source_map:
        if pattern in lower:
            return name

    if "/windows/" in lower:
        return "Windows 系统"

    return "其他软件"


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------


def log_message(msg: str, level: str = "info") -> None:
    """统一日志输出。"""
    ts = datetime.now().strftime("%H:%M:%S")
    if level == "error":
        logging.error(f"[{ts}] {msg}")
    elif level == "warning":
        logging.warning(f"[{ts}] {msg}")
    else:
        logging.info(f"[{ts}] {msg}")
