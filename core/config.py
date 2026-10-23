"""WinCleaner 配置文件管理。

要点
----
* **单一数据源**：默认配置只在本模块维护一份；``config.json`` 是它的磁盘镜像。
* **用户配置与程序目录分离**：可写配置放在 ``%APPDATA%\\WinCleaner\\config.json``，
  避免"装到 Program Files 后配置无法保存"，也避免打包目录里出现多份配置分叉。
* **版本迁移**：旧版配置（v1）里把应用安装目录当成"缓存"的危险条目会被自动替换。
"""
import json
import logging
import os
import shutil
import sys
import tempfile
from pathlib import Path

CONFIG_VERSION = 2

#: 强特征关键词：命中即判定为高可疑（多为已知流氓/捆绑安装品牌）
STRONG_KEYWORDS = [
    "2345", "hao123", "duba", "cmcm", "liebao", "ludashi", "ksafe",
    "百度卫士", "可牛", "微点", "瑞星", "江民", "鲁大师", "驱动精灵", "驱动人生",
    "快压", "好压", "速压", "万能五笔", "极点五笔", "美图看看", "世界之窗",
    "遨游", "暴风影音", "迅雷看看", "比特彗星", "电驴", "快车", "魔方", "软媒",
    "crack", "keygen", "activator", "破解", "破解版", "注册机", "绿色版",
    "黑客", "木马", "蠕虫", "捆绑安装", "静默安装",
]

#: 弱特征关键词：单独命中只作提示，需要多个命中才升级风险
WEAK_KEYWORDS = [
    "助手", "加速", "管家", "壁纸", "屏保", "天气", "日历", "输入法",
    "压缩", "看图", "影音", "直播", "清理", "优化", "杀毒", "安全",
    "浏览器", "导航", "搜索", "网址", "主页", "劫持", "推广", "广告",
    "神器", "福利", "红包", "赚钱", "极速版", "p2p", "download",
    "installer", "setup", "bundle", "toolbar", "高速下载", "安全下载",
    "普通下载", "下载站", "patch", "loader", "drive", "sentinel",
]

#: 已知流氓软件目录特征（glob）
KNOWN_ROGUE_PATTERNS = [
    "*2345*", "*hao123*", "*duba*", "*cmcm*", "*liebao*", "*ludashi*",
    "*快压*", "*好压*", "*速压*", "*鲁大师*", "*驱动精灵*", "*驱动人生*",
    "*百度卫士*", "*可牛*", "*万能五笔*", "*极点五笔*", "*美图看看*",
    "*世界之窗*", "*暴风影音*", "*迅雷看看*", "*比特彗星*", "*电驴*",
    "*魔方*", "*软媒*", "*万能下载地址*",
]

#: 可信品牌白名单 —— 命中即整体忽略（白名单优先级高于任何可疑规则）
TRUSTED_BRANDS = [
    "kingsoft", "wps", "microsoft", "windows", "tencent", "wechat",
    "wxwork", "dingtalk", "qq", "baidu", "alibaba", "taobao", "tmall",
    "jd", "huawei", "xiaomi", "lenovo", "sogou", "iflytek", "360",
    "qihoo", "netease", "adobe", "autodesk", "jetbrains", "pycharm",
    "intellij", "visual studio", "vscode", "git", "node.js", "nodejs",
    "python", "anaconda", "miniconda", "vmware", "virtualbox", "docker",
    "postman", "navicat", "dbeaver", "sublime", "notepad++", "7-zip",
    "7zip", "winrar", "everything", "potplayer", "vlc", "obs",
    "discord", "telegram", "zoom", "notion", "obsidian", "trae",
    "claude", "cursor", "qoder", "doubao", "deepseek", "openai", "chrome",
    "firefox", "edge", "codeium", "codebuddy", "iflytek",
]

#: 明确属于缓存性质的目录（可安全清理），只包含缓存子目录，绝不含安装目录
SOFTWARE_JUNK_PATHS = {
    "应用缓存 (通用)": "%LOCALAPPDATA%\\*\\cache",
    "应用缓存 (通用·深层)": "%LOCALAPPDATA%\\*\\*\\cache",
    "Electron 缓存": "%LOCALAPPDATA%\\*\\Cache_Data",
    "Electron 缓存 (深层)": "%LOCALAPPDATA%\\*\\*\\Cache_Data",
    "GPU 缓存": "%LOCALAPPDATA%\\*\\GPUCache",
    "着色器缓存": "%LOCALAPPDATA%\\*\\ShaderCache",
    "代码缓存": "%LOCALAPPDATA%\\*\\Code Cache",
    "崩溃转储 (应用)": "%LOCALAPPDATA%\\*\\dumps",
    "崩溃转储 (Crashpad)": "%LOCALAPPDATA%\\*\\crashpad",
    "系统崩溃转储": "%LOCALAPPDATA%\\CrashDumps",
    "WPS 缓存": "%LOCALAPPDATA%\\Kingsoft\\WPS Office\\*\\office6\\cache",
    "WPS 备份缓存": "%LOCALAPPDATA%\\Kingsoft\\WPS Office\\*\\office6\\backup",
    "钉钉缓存": "%LOCALAPPDATA%\\DingTalk*\\*\\Cache",
    "字体缓存": "%LOCALAPPDATA%\\fontconfig\\cache",
}

#: 开发工具缓存（删除后需要重新下载，不影响已安装的软件）
DEV_CACHE_PATHS = {
    "pip 缓存": "%LOCALAPPDATA%\\pip\\cache",
    "npm 缓存": "%LOCALAPPDATA%\\npm-cache",
    "node-gyp 缓存": "%LOCALAPPDATA%\\node-gyp\\Cache",
    "Yarn 缓存": "%LOCALAPPDATA%\\Yarn\\Cache",
    "pnpm 缓存": "%LOCALAPPDATA%\\pnpm\\store",
    "NuGet 包缓存": "%USERPROFILE%\\.nuget\\packages",
    "Maven 仓库": "%USERPROFILE%\\.m2\\repository",
    "Gradle 缓存": "%USERPROFILE%\\.gradle\\caches",
}

DEFAULT_CONFIG = {
    "config_version": CONFIG_VERSION,
    "strong_keywords": STRONG_KEYWORDS,
    "weak_keywords": WEAK_KEYWORDS,
    "known_rogue_patterns": KNOWN_ROGUE_PATTERNS,
    "trusted_brands": TRUSTED_BRANDS,
    "software_junk_paths": SOFTWARE_JUNK_PATHS,
    "dev_cache_paths": DEV_CACHE_PATHS,
    "protect_personal_files": True,
    "create_restore_point_before_clean": False,
    "default_enabled_categories": [
        "system_temp", "thumbnails", "error_reports", "dns_cache",
        "software_junk", "dev_cache", "browser_cache", "system_junk",
        "delivery_optimization",
    ],
}


# ---------------------------------------------------------------------------
# 配置文件位置
# ---------------------------------------------------------------------------


def _app_dir() -> Path:
    """程序所在目录（打包后为 exe 目录）。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent
    return Path(__file__).parent.parent


def _bundle_dir() -> Path:
    """打包资源目录（onefile 下为解包目录，存放随程序分发的默认配置）。"""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return _app_dir()


def _user_config_dir() -> Path:
    """用户可写配置目录。"""
    base = os.environ.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return Path(base) / "WinCleaner"


def get_config_path() -> Path:
    """返回用户配置文件的完整路径。"""
    return _user_config_dir() / "config.json"


def get_seed_config_path() -> Path:
    """返回随程序分发的默认配置（只读种子）。"""
    return _bundle_dir() / "config.json"


CONFIG_FILE = get_config_path()


# ---------------------------------------------------------------------------
# 读写
# ---------------------------------------------------------------------------


def _merge_keywords(user_list, defaults) -> list:
    """合并用户自定义与默认关键词，去重且保持顺序。"""
    out = []
    seen = set()
    for item in list(user_list or []) + list(defaults or []):
        key = str(item).strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(str(item).strip())
    return out


def migrate_config(cfg: dict) -> dict:
    """把旧版本配置升级到当前版本。

    v1 → v2 的关键变更：把"应用安装目录"从软件垃圾路径中移除，
    拆分强/弱关键词，并新增可信品牌白名单。
    """
    version = cfg.get("config_version", 1)
    if version >= CONFIG_VERSION:
        return cfg

    logging.info(f"配置版本 {version} → {CONFIG_VERSION}，执行迁移")

    old_paths = cfg.get("software_junk_paths", {}) or {}
    migrated = dict(SOFTWARE_JUNK_PATHS)
    for label, raw in old_paths.items():
        if label in migrated:
            continue
        # 只保留本身就带缓存语义的自定义路径，其余一律丢弃
        low = str(raw).lower()
        if any(t in low for t in ("cache", "temp", "tmp", "log", "crash", "dump")):
            migrated[label] = raw
    cfg["software_junk_paths"] = migrated

    if "dev_cache_paths" not in cfg:
        cfg["dev_cache_paths"] = dict(DEV_CACHE_PATHS)

    legacy = list(cfg.get("suspicious_keywords", []) or [])
    cfg["strong_keywords"] = _merge_keywords(
        [k for k in legacy if any(s.lower() in k.lower() for s in STRONG_KEYWORDS)],
        STRONG_KEYWORDS)
    cfg["weak_keywords"] = _merge_keywords(
        [k for k in legacy if k not in cfg["strong_keywords"]],
        WEAK_KEYWORDS)

    if "trusted_brands" not in cfg:
        cfg["trusted_brands"] = list(TRUSTED_BRANDS)

    if "protect_personal_files" not in cfg:
        cfg["protect_personal_files"] = True
    if "default_enabled_categories" not in cfg:
        cfg["default_enabled_categories"] = list(DEFAULT_CONFIG["default_enabled_categories"])

    cfg["config_version"] = CONFIG_VERSION
    return cfg


def load_config() -> dict:
    """加载配置；不存在时用默认配置创建。"""
    path = get_config_path()
    cfg = None
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
        except Exception as e:
            logging.error(f"配置文件损坏，改用默认配置: {e}")
            cfg = None

    if cfg is None:
        # 优先使用随程序分发的种子配置，其次使用内置默认值
        seed = get_seed_config_path()
        if seed.exists() and seed.resolve() != path.resolve():
            try:
                with open(seed, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            except Exception as e:
                logging.warning(f"读取种子配置失败: {e}")
                cfg = None
        if cfg is None:
            cfg = dict(DEFAULT_CONFIG)
        save_config(cfg)

    cfg = migrate_config(dict(cfg))

    # 补全缺失的键
    for key, value in DEFAULT_CONFIG.items():
        if key not in cfg:
            cfg[key] = value

    # 补上"新增的、策略上默认开启"的类别（不动用户已有的选择）
    try:
        from .safety import CATEGORY_POLICIES
        current = list(cfg.get("default_enabled_categories", []))
        for key, policy in CATEGORY_POLICIES.items():
            if policy.default_enabled and key not in current:
                current.append(key)
        cfg["default_enabled_categories"] = current
    except Exception:
        pass
    return cfg


def save_config(cfg: dict) -> bool:
    """原子保存配置到用户配置目录。"""
    path = get_config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        # 先写临时文件再替换，避免中途崩溃导致配置损坏
        fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".config-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            shutil.move(tmp, str(path))
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return True
    except Exception as e:
        logging.error(f"保存配置文件失败: {e}")
        return False


def reset_config() -> dict:
    """恢复默认配置。"""
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    save_config(cfg)
    return cfg
