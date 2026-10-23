"""清理安全策略层。

这里集中定义 **"什么可以删"**。任何删除动作都必须先通过
:func:`check_delete_allowed`，UI 与 CLI 共用同一套判断，避免规则散落。

设计要点
--------
1. **单一数据源**：类别策略只在本文件定义一次，扫描器用它决定扫描什么，
   清理器用它决定放行什么，两边不会各写一套。
2. **跨盘符一致**：不再出现 "C 盘受保护、D 盘不设防" 的历史缺陷。
3. **可逆删除**：删除一律走回收站（见 :func:`core.utils.delete_to_recycle_bin`），
   永久删除只保留给"整体清空回收站"这一个用户明确知晓的特例。
4. **默认保守**：任何拿不准的情况一律跳过，并给出可读原因。
"""
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

from .utils import (
    is_drive_root,
    is_file_locked,
    is_installer_payload,
    is_personal_file,
    is_recycle_bin_path,
    is_system_critical,
    is_within,
)

# 严重级别
SEV_LOW = "low"
SEV_MEDIUM = "medium"
SEV_HIGH = "high"

SEV_LABEL = {SEV_LOW: "低", SEV_MEDIUM: "中", SEV_HIGH: "高"}


@dataclass(frozen=True)
class CategoryPolicy:
    """单个清理类别的安全策略。"""

    key: str
    label: str
    description: str
    min_age_days: int = 7
    allow_directories: bool = False
    allow_installers: bool = False
    requires_admin: bool = False
    severity: str = SEV_LOW
    default_enabled: bool = False
    #: 特殊执行方式："" 普通文件 / "empty_recycle_bin" / "flush_dns"
    special: str = ""
    #: 该类别的说明性备注，会展示在界面上
    note: str = ""
    #: 是否豁免"系统关键区"保护。
    #: 只有"卸载残留"需要——它要处理的正是 Program Files 里的孤儿目录，
    #: 而 Program Files 本身是被保护的安装区。
    ignore_system_protection: bool = False


CATEGORY_POLICIES: Dict[str, CategoryPolicy] = {
    "system_temp": CategoryPolicy(
        key="system_temp",
        label="系统临时文件",
        description="%TEMP% 与 C:\\Windows\\Temp 下的临时文件",
        min_age_days=2,
        severity=SEV_LOW,
        default_enabled=True,
        note="仅清理 2 天前且未被占用的文件；系统目录部分需要管理员权限。",
    ),
    "windows_update": CategoryPolicy(
        key="windows_update",
        label="Windows 更新缓存",
        description="已下载但未安装的更新安装包",
        min_age_days=14,
        requires_admin=True,
        severity=SEV_HIGH,
        default_enabled=False,
        note="会先停止 wuauserv/BITS 服务再清理，完成后自动恢复。"
             "清理后若要安装已下载的更新需重新下载。",
    ),
    "thumbnails": CategoryPolicy(
        key="thumbnails",
        label="缩略图缓存",
        description="资源管理器缩略图数据库",
        min_age_days=1,
        severity=SEV_LOW,
        default_enabled=True,
        note="删除后资源管理器会重新生成，首次浏览文件夹会略慢。",
    ),
    "error_reports": CategoryPolicy(
        key="error_reports",
        label="Windows 错误报告",
        description="崩溃报告与 WER 队列",
        min_age_days=7,
        severity=SEV_LOW,
        default_enabled=True,
    ),
    "memory_dumps": CategoryPolicy(
        key="memory_dumps",
        label="内存转储文件",
        description="蓝屏/内核转储，用于排查系统崩溃",
        min_age_days=7,
        severity=SEV_MEDIUM,
        default_enabled=False,
        note="转储文件是排查蓝屏问题的证据，清理后无法再分析。",
    ),
    "recycle_bin": CategoryPolicy(
        key="recycle_bin",
        label="回收站",
        description="清空回收站中的全部内容",
        min_age_days=0,
        severity=SEV_HIGH,
        default_enabled=False,
        special="empty_recycle_bin",
        note="清空后文件无法还原，属于不可逆操作，执行前会要求二次确认。",
    ),
    "prefetch": CategoryPolicy(
        key="prefetch",
        label="预取文件",
        description="Windows 预读加速数据",
        min_age_days=30,
        requires_admin=True,
        severity=SEV_MEDIUM,
        default_enabled=False,
        note="清理后前几次启动会变慢，系统会自行重建。",
    ),
    "dns_cache": CategoryPolicy(
        key="dns_cache",
        label="DNS 缓存",
        description="刷新本地 DNS 解析缓存",
        min_age_days=0,
        severity=SEV_LOW,
        default_enabled=True,
        special="flush_dns",
        note="不删除任何文件，仅刷新解析缓存。",
    ),
    "software_junk": CategoryPolicy(
        key="software_junk",
        label="应用缓存残留",
        description="各应用的缓存/日志/崩溃转储目录",
        min_age_days=7,
        severity=SEV_MEDIUM,
        default_enabled=True,
        note="只命中名称明确的缓存目录；应用安装目录与数据目录会被自动排除。",
    ),
    "dev_cache": CategoryPolicy(
        key="dev_cache",
        label="开发工具缓存",
        description="pip / npm / NuGet / Maven / node-gyp 等构建缓存",
        min_age_days=14,
        severity=SEV_LOW,
        default_enabled=True,
        note="删除后依赖需要重新下载，不影响已安装的包。",
    ),
    "browser_cache": CategoryPolicy(
        key="browser_cache",
        label="浏览器缓存",
        description="Chrome / Edge / Firefox / 360 / QQ 等浏览器的网页与代码缓存",
        min_age_days=1,
        severity=SEV_LOW,
        default_enabled=True,
        note="网页缓存可自动重建；不影响书签与密码。",
    ),
    "browser_cookies": CategoryPolicy(
        key="browser_cookies",
        label="浏览器 Cookie（登录态）",
        description="会清掉网站登录状态与部分站点偏好",
        min_age_days=0,
        severity=SEV_HIGH,
        default_enabled=False,
        note="默认不勾选。清理后需要重新登录各个网站。",
    ),
    "app_leftovers": CategoryPolicy(
        key="app_leftovers",
        label="卸载残留",
        description="卸载信息已消失、但目录与可执行文件仍留在磁盘上的软件残骸",
        min_age_days=30,
        allow_directories=True,
        severity=SEV_MEDIUM,
        default_enabled=False,
        ignore_system_protection=True,
        note="依据是「注册表卸载表中已无此程序」。仍建议人工确认后再清理。",
    ),
    "system_junk": CategoryPolicy(
        key="system_junk",
        label="系统日志与崩溃转储",
        description="CBS / DISM / WER 日志、崩溃转储、字体与着色器缓存",
        min_age_days=7,
        severity=SEV_LOW,
        default_enabled=True,
        note="日志是排查系统问题的证据，清理后无法再回溯。",
    ),
    "old_installers": CategoryPolicy(
        key="old_installers",
        label="遗留安装包",
        description="临时目录与下载目录里长期没动的安装包与压缩包",
        min_age_days=60,
        severity=SEV_LOW,
        default_enabled=False,
        note="请确认里面没有你需要保留的安装包。",
    ),
    "delivery_optimization": CategoryPolicy(
        key="delivery_optimization",
        label="传递优化缓存",
        description="Windows 更新分发用的 P2P 缓存",
        min_age_days=7,
        severity=SEV_LOW,
        default_enabled=True,
        note="会占用较多磁盘，但删除后系统更新需要重新下载。",
    ),
    "windows_component_store": CategoryPolicy(
        key="windows_component_store",
        label="组件存储（WinSxS）",
        description="通过 DISM 分析并清理被取代的系统组件版本",
        min_age_days=0,
        requires_admin=True,
        severity=SEV_HIGH,
        default_enabled=False,
        special="dism_component_cleanup",
        note="会先执行 DISM /AnalyzeComponentStore 判断是否建议清理，"
             "确认后用 /StartComponentCleanup 正式执行。",
    ),
    "windows_old": CategoryPolicy(
        key="windows_old",
        label="Windows 旧版本安装",
        description="升级后遗留的 Windows.old（可能几十 GB）",
        min_age_days=0,
        requires_admin=True,
        severity=SEV_HIGH,
        default_enabled=False,
        special="dism_remove_old_installation",
        note="将调用系统自带的映像清理移除旧系统。旧系统里的个人文件也会一并删除。",
    ),
    "hibernation": CategoryPolicy(
        key="hibernation",
        label="休眠文件",
        description="hiberfil.sys（关闭休眠后即可释放，通常 8~16 GB）",
        min_age_days=0,
        requires_admin=True,
        severity=SEV_HIGH,
        default_enabled=False,
        special="powercfg_hibernate_off",
        note="关闭休眠会同时失去「休眠」与「快速启动」功能，可在系统设置里重新开启。",
    ),
    "system_restore": CategoryPolicy(
        key="system_restore",
        label="系统还原点",
        description="删除卷影副本占用的空间",
        min_age_days=0,
        requires_admin=True,
        severity=SEV_HIGH,
        default_enabled=False,
        special="vssadmin_delete_shadows",
        note="删除后无法再使用「还原此电脑」功能，请谨慎操作。",
    ),
    "manual_target": CategoryPolicy(
        key="manual_target",
        label="手动指定目录",
        description="从空间分析页手动标记、需要清理的目录",
        min_age_days=0,
        allow_directories=True,
        severity=SEV_MEDIUM,
        default_enabled=False,
        note="整目录移入回收站，可以在回收站里整体还原。",
    ),
}

#: 界面上展示的类别顺序
CATEGORY_ORDER: List[str] = list(CATEGORY_POLICIES.keys())


def get_policy(key: str) -> CategoryPolicy:
    """按 key 取策略；未知 key 返回一条最严格的兜底策略。"""
    return CATEGORY_POLICIES.get(key) or CategoryPolicy(
        key=key, label=key, description="未知类别", min_age_days=30,
        severity=SEV_HIGH, default_enabled=False,
    )


# ---------------------------------------------------------------------------
# 缓存目录识别
# ---------------------------------------------------------------------------

#: 明确属于缓存性质的目录名（小写比较）
CACHE_DIR_NAMES = {
    "cache", "caches", "cache2", "cache_data", "cachedata", "code cache",
    "gpucache", "shadercache", "shader cache", "webcache", "web cache",
    "downloadcache", "download cache", "thumbcache", "thumbnailcache",
    "temp", "tmp", "logs", "log", "crashpad", "crash dumps", "crashdumps",
    "crashes", "dumps", "tempdir", "temp files", "tempfiles",
    "service worker", "blob_storage", "dawncache", "dawn cache",
    "v8 cache", "component cache", "grshadercache", "d3d cache",
    "installer cache", "package cache", "squirrel temp",
}

#: 明确属于"应用数据/安装目录"的目录名，命中即整体排除
NON_CACHE_DIR_NAMES = {
    "backup", "backups", "userdata", "user data", "documents", "doc",
    "roaming", "local", "programs", "program files", "temp files",
    "downloads", "download", "music", "pictures", "videos", "movies",
    "desktop", "favorites", "contacts", "profile", "profiles", "sessions",
}


def looks_like_cache_dir(path: str) -> bool:
    """判断目录名是否明确属于缓存性质。"""
    name = os.path.basename(os.path.normpath(path)).lower()
    if not name:
        return False
    if name in NON_CACHE_DIR_NAMES:
        return False
    return name in CACHE_DIR_NAMES or any(
        token in name for token in ("cache", "缓存", "临时", "temp")
    )


def looks_like_app_install_dir(path: str) -> bool:
    """判断目录是否像一个应用的安装目录（而非缓存）。

    判定依据：目录根部存在可执行文件，或存在卸载程序（``unins*.exe``）。
    这种目录一旦被当垃圾清理，会连同整个软件与用户数据一起消失
    （2026-10-14 的 WPS Office 事故即源于此）。

    注意：**只看根层**。``node-gyp\\Cache`` 内部虽带 ``node.exe``，
    但根层没有任何可执行文件，属于正常的下载缓存，不能误判。
    """
    p = os.path.normpath(path)
    if not os.path.isdir(p):
        return False
    try:
        entries = list(os.scandir(p))
    except OSError:
        return False
    for entry in entries:
        try:
            if not entry.is_file(follow_symlinks=False):
                continue
            name = entry.name.lower()
            if name.endswith((".exe", ".dll", ".msi")):
                return True
            if name.startswith("unins") and name.endswith(".exe"):
                return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# 删除准入判断
# ---------------------------------------------------------------------------


@dataclass
class DeleteDecision:
    """一次删除判定的结果。"""

    allowed: bool
    reason: str = ""
    severity: str = SEV_LOW
    code: str = ""

    def __iter__(self):
        # 兼容 (allowed, reason) 元组用法
        yield self.allowed
        yield self.reason


def check_delete_allowed(
    path: str,
    policy: CategoryPolicy,
    allowed_roots: Optional[List[str]] = None,
    protect_personal: bool = True,
    is_admin: Optional[bool] = None,
) -> DeleteDecision:
    """判断某个路径是否允许清理。

    这是删除前最后一道闸门，按顺序执行：

    ① 路径基本合法性        ② 系统关键区 / 回收站
    ③ 必须落在允许根目录内  ④ 文件年龄
    ⑤ 安装载荷 / 个人数据   ⑥ 进程占用      ⑦ 管理员权限
    """
    if not path:
        return DeleteDecision(False, "空路径", SEV_HIGH, "invalid")

    try:
        abspath = os.path.normpath(os.path.abspath(os.path.expandvars(path)))
    except Exception:
        return DeleteDecision(False, "路径无法解析", SEV_HIGH, "invalid")

    # ① 基本合法性
    if is_drive_root(abspath):
        return DeleteDecision(False, "盘符根目录不可清理", SEV_HIGH, "drive_root")

    # ② 系统关键区与回收站
    if is_recycle_bin_path(abspath):
        return DeleteDecision(
            False, "回收站内容只能整体清空，不能逐文件删除", SEV_HIGH, "recycle_bin")
    if is_system_critical(abspath) and not policy.ignore_system_protection:
        return DeleteDecision(False, "系统关键路径，已保护", SEV_HIGH, "system_critical")

    # ③ 必须落在允许根目录内（防止通配符误捕整个应用目录）
    if allowed_roots:
        if not any(is_within(abspath, root) for root in allowed_roots):
            return DeleteDecision(
                False, "不在允许清理的根目录内", SEV_HIGH, "outside_root")

    is_dir = os.path.isdir(abspath)
    if is_dir and not policy.allow_directories:
        return DeleteDecision(False, "该类别只清理文件，不清理目录", SEV_MEDIUM, "dir_not_allowed")

    # ④ 文件年龄
    if policy.min_age_days > 0:
        try:
            age = (time.time() - os.path.getmtime(abspath)) / 86400.0
        except OSError:
            return DeleteDecision(False, "无法读取文件属性", SEV_MEDIUM, "no_stat")
        if age < policy.min_age_days:
            return DeleteDecision(
                False, f"文件过新（{age:.1f} 天 < {policy.min_age_days} 天）",
                SEV_MEDIUM, "too_new")

    # ⑤ 安装载荷与个人数据
    if not policy.allow_installers and is_installer_payload(abspath):
        return DeleteDecision(
            False, "安装/可执行载荷，不走常规清理", SEV_HIGH, "installer")
    if protect_personal and not is_dir and is_personal_file(abspath):
        return DeleteDecision(
            False, "疑似个人数据（照片/视频/文档等），已跳过", SEV_HIGH, "personal_data")

    # ⑥ 占用检测
    if not is_dir and is_file_locked(abspath):
        return DeleteDecision(False, "文件被其他程序占用", SEV_LOW, "locked")

    # ⑦ 管理员权限
    if policy.requires_admin:
        from .utils import is_admin as _is_admin
        admin = _is_admin() if is_admin is None else is_admin
        if not admin:
            return DeleteDecision(
                False, "该类别需要管理员权限", SEV_MEDIUM, "need_admin")

    return DeleteDecision(True, "ok", policy.severity, "")


def summarize_decisions(decisions: List[DeleteDecision]) -> Dict[str, int]:
    """统计各拒绝原因的分布，用于界面提示。"""
    stats: Dict[str, int] = {}
    for d in decisions:
        if d.allowed:
            continue
        stats[d.reason] = stats.get(d.reason, 0) + 1
    return stats
