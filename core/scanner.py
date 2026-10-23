"""WinCleaner 垃圾扫描引擎。

扫描器只负责 **发现**，不做任何删除。安全准入判断在 :mod:`core.safety`，
删除执行在 :mod:`core.cleaner`，三者职责严格分离。
"""
import glob
import logging
import os
import time
from typing import Dict, List, Optional, Tuple

from .config import load_config
from .safety import (
    get_policy,
    looks_like_app_install_dir,
    looks_like_cache_dir,
)
from .utils import (
    detect_file_type,
    detect_source,
    expand_path,
    get_appdata_local,
    get_program_data,
    get_system_drive,
    is_reparse_point,
    is_system_critical,
    normalize_path,
)


class ScanResult:
    """单个扫描结果项。"""

    def __init__(
        self,
        category: str,
        name: str,
        path: str,
        size: int = 0,
        description: str = "",
        root: str = "",
        mtime: float = 0.0,
        special: str = "",
        note: str = "",
    ):
        self.category = category
        self.name = name
        self.path = path
        self.size = size
        self.description = description
        #: 允许清理的根目录——清理时会校验路径必须落在其中
        self.root = root or (os.path.dirname(path) if path else "")
        self.mtime = mtime
        #: 特殊执行方式："" 普通文件 / "empty_recycle_bin" / "flush_dns"
        self.special = special
        self.note = note
        self.file_type = detect_file_type(path) if path else "其他"
        self.source = detect_source(path) if path else "未知"
        #: 安全默认：不勾选。必须由用户明确选择。
        self.selected = False

    @property
    def age_days(self) -> float:
        if not self.mtime:
            return 0.0
        return max(0.0, (time.time() - self.mtime) / 86400.0)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "description": self.description,
            "root": self.root,
            "file_type": self.file_type,
            "source": self.source,
            "selected": self.selected,
        }


class SystemScanner:
    """系统垃圾扫描器。"""

    def __init__(self, progress_callback=None):
        self.results: List[ScanResult] = []
        self.progress_callback = progress_callback
        self.stop_flag = False
        self._seen: set = set()

    # -- 基础设施 ---------------------------------------------------------

    def stop(self):
        self.stop_flag = True

    def reset(self):
        self.results.clear()
        self._seen.clear()
        self.stop_flag = False

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    def _add(self, result: ScanResult) -> bool:
        """加入结果（按规范化路径去重）。"""
        key = normalize_path(result.path)
        if key and key in self._seen:
            return False
        if key:
            self._seen.add(key)
        self.results.append(result)
        return True

    # -- 入口 -------------------------------------------------------------

    def scan_all(self, options: Dict[str, bool]) -> List[ScanResult]:
        """根据选项执行全部扫描。"""
        self.reset()
        steps = [
            ("系统临时文件", options.get("system_temp", False), self.scan_system_temp),
            ("Windows 更新缓存", options.get("windows_update", False), self.scan_windows_update),
            ("缩略图缓存", options.get("thumbnails", False), self.scan_thumbnails),
            ("Windows 错误报告", options.get("error_reports", False), self.scan_error_reports),
            ("内存转储文件", options.get("memory_dumps", False), self.scan_memory_dumps),
            ("回收站", options.get("recycle_bin", False), self.scan_recycle_bin),
            ("预取文件", options.get("prefetch", False), self.scan_prefetch),
            ("DNS 缓存", options.get("dns_cache", False), self.scan_dns_cache),
            ("应用缓存残留", options.get("software_junk", False), self.scan_software_junk),
            ("开发工具缓存", options.get("dev_cache", False), self.scan_dev_cache),
            ("浏览器缓存", options.get("browser_cache", False), self.scan_browser_cache),
            ("浏览器 Cookie", options.get("browser_cookies", False), self.scan_browser_cookies),
            ("卸载残留", options.get("app_leftovers", False), self.scan_app_leftovers),
            ("系统日志与转储", options.get("system_junk", False), self.scan_system_junk),
            ("传递优化缓存", options.get("delivery_optimization", False),
             self.scan_delivery_optimization),
            ("遗留安装包", options.get("old_installers", False), self.scan_old_installers),
            ("组件存储", options.get("windows_component_store", False),
             self.scan_windows_component_store),
            ("Windows 旧版本", options.get("windows_old", False), self.scan_windows_old),
            ("休眠文件", options.get("hibernation", False), self.scan_hibernation),
            ("系统还原点", options.get("system_restore", False), self.scan_system_restore),
        ]
        total = len(steps)
        for idx, (label, enabled, scanner) in enumerate(steps):
            if self.stop_flag:
                break
            if not enabled:
                continue
            self._report(f"正在扫描: {label}", int(idx / total * 100))
            try:
                scanner()
            except Exception as e:
                logging.error(f"扫描 {label} 失败: {e}")
        self._report("扫描完成", 100)
        return self.results

    # -- 文件收集 ---------------------------------------------------------

    def _collect_files(
        self,
        root: str,
        category: str,
        name: str,
        min_age_days: int = 0,
        max_depth: int = 8,
        suffixes: Optional[Tuple[str, ...]] = None,
    ) -> int:
        """递归收集文件。

        与旧版 ``glob.iglob(root/**/pattern)`` 的差别：

        * 不跟随符号链接与目录联接，避免 ``AppData\\Local\\Application Data``
          这类自引用环导致的死循环；
        * 统一应用"文件年龄"门槛；
        * 按规范化路径去重，避免同一条 Temp 路径被两条链路重复收集。
        """
        if not root or not os.path.isdir(root):
            return 0
        if is_system_critical(root):
            logging.info(f"跳过系统关键目录: {root}")
            return 0

        cutoff = time.time() - min_age_days * 86400 if min_age_days > 0 else None
        added = 0
        stack = [(os.path.abspath(root), 0)]
        while stack:
            if self.stop_flag:
                return added
            current, depth = stack.pop()
            try:
                entries = list(os.scandir(current))
            except (OSError, PermissionError):
                continue
            for entry in entries:
                if self.stop_flag:
                    return added
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if depth >= max_depth:
                            continue
                        if is_reparse_point(entry.path):
                            continue
                        stack.append((entry.path, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        if suffixes and not entry.name.lower().endswith(suffixes):
                            continue
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if cutoff and st.st_mtime > cutoff:
                            continue
                        result = ScanResult(
                            category, name, entry.path, st.st_size,
                            root=os.path.abspath(root), mtime=st.st_mtime,
                        )
                        if self._add(result):
                            added += 1
                except (OSError, PermissionError):
                    continue
        return added

    # -- 各类别 -----------------------------------------------------------

    def scan_system_temp(self):
        """扫描系统与用户临时目录。"""
        from .utils import get_temp_dirs
        policy = get_policy("system_temp")
        for temp_dir in get_temp_dirs():
            if self.stop_flag:
                return
            self._collect_files(temp_dir, "system_temp", "临时文件",
                                min_age_days=policy.min_age_days)

    def scan_windows_update(self):
        """扫描 Windows Update 下载缓存（仅已下载未安装的包）。"""
        policy = get_policy("windows_update")
        root = os.path.join(get_system_drive(), "Windows", "SoftwareDistribution", "Download")
        self._collect_files(root, "windows_update", "更新安装包",
                            min_age_days=policy.min_age_days, max_depth=4)

    def scan_thumbnails(self):
        """扫描资源管理器缩略图缓存。"""
        policy = get_policy("thumbnails")
        root = os.path.join(get_appdata_local(), "Microsoft", "Windows", "Explorer")
        self._collect_files(root, "thumbnails", "缩略图缓存",
                            min_age_days=policy.min_age_days, max_depth=2,
                            suffixes=(".db",))

    def scan_error_reports(self):
        """扫描 Windows 错误报告。"""
        policy = get_policy("error_reports")
        roots = [
            os.path.join(get_program_data(), "Microsoft", "Windows", "WER"),
            os.path.join(get_appdata_local(), "Microsoft", "Windows", "WER"),
        ]
        for root in roots:
            if self.stop_flag:
                return
            self._collect_files(root, "error_reports", "错误报告文件",
                                min_age_days=policy.min_age_days, max_depth=5)

    def scan_memory_dumps(self):
        """扫描内存转储文件。"""
        policy = get_policy("memory_dumps")
        files = [
            os.path.join(get_system_drive(), "Windows", "MEMORY.DMP"),
        ]
        dirs = [
            os.path.join(get_system_drive(), "Windows", "Minidump"),
            os.path.join(get_system_drive(), "Windows", "LiveKernelReports"),
        ]
        for path in files:
            if os.path.isfile(path):
                try:
                    st = os.stat(path)
                    self._add(ScanResult("memory_dumps", "内存转储文件", path,
                                         st.st_size, root=get_system_drive(),
                                         mtime=st.st_mtime))
                except OSError:
                    pass
        for root in dirs:
            if self.stop_flag:
                return
            self._collect_files(root, "memory_dumps", "内存转储文件",
                                min_age_days=policy.min_age_days, max_depth=3,
                                suffixes=(".dmp",))

    def scan_recycle_bin(self):
        """回收站：只登记一个"整体清空"动作。

        旧版会递归收集 ``$Recycle.Bin`` 下的 ``$I``/``$R`` 文件并逐个
        ``unlink()``，这既绕过了回收站造成不可逆丢失，又破坏了 ``$I``
        索引结构。这里改为登记一个由 ``SHEmptyRecycleBinW`` 执行的特例。
        """
        policy = get_policy("recycle_bin")
        self._add(ScanResult(
            "recycle_bin", "清空回收站", "recycle_bin", 0,
            description="整体清空所有盘符的回收站",
            special="empty_recycle_bin", note=policy.note,
        ))

    def scan_prefetch(self):
        """扫描 Windows 预取文件。"""
        policy = get_policy("prefetch")
        root = os.path.join(get_system_drive(), "Windows", "Prefetch")
        self._collect_files(root, "prefetch", "预取文件",
                            min_age_days=policy.min_age_days, max_depth=2,
                            suffixes=(".pf",))

    def scan_dns_cache(self):
        """DNS 缓存是内存态，登记为一个特殊动作。"""
        policy = get_policy("dns_cache")
        self._add(ScanResult(
            "dns_cache", "DNS 解析缓存", "dns_cache", 0,
            description="刷新本地 DNS 解析缓存", special="flush_dns",
            note=policy.note,
        ))

    def scan_software_junk(self):
        """扫描应用缓存残留。

        只清理 **名称明确属于缓存** 的目录；应用安装目录与数据目录
        （例如 ``%LOCALAPPDATA%\\Kingsoft\\WPS Office``）会被自动排除。
        """
        policy = get_policy("software_junk")
        cfg = load_config()
        for label, pattern in (cfg.get("software_junk_paths") or {}).items():
            if self.stop_flag:
                return
            for root in self._expand_junk_pattern(pattern):
                if not os.path.isdir(root):
                    continue
                # 只清理"名称明确属于缓存"的目录。
                # 应用安装目录（如 %LOCALAPPDATA%\Kingsoft\WPS Office）
                # 名称不是缓存名，会在这里被直接排除。
                if not looks_like_cache_dir(root):
                    logging.info(f"跳过非缓存目录: {root}")
                    continue
                self._collect_files(root, "software_junk", label,
                                    min_age_days=policy.min_age_days, max_depth=6)

    def scan_dev_cache(self):
        """扫描开发工具缓存（显式配置，信任用户意图，但仍受年龄与安装目录检查约束）。"""
        policy = get_policy("dev_cache")
        cfg = load_config()
        for label, pattern in (cfg.get("dev_cache_paths") or {}).items():
            if self.stop_flag:
                return
            for root in self._expand_junk_pattern(pattern):
                if not os.path.isdir(root):
                    continue
                if looks_like_app_install_dir(root):
                    logging.warning(f"跳过疑似应用安装目录: {root}")
                    continue
                self._collect_files(root, "dev_cache", label,
                                    min_age_days=policy.min_age_days, max_depth=6)

    # -- 深度检测：浏览器缓存 ---------------------------------------------

    def scan_browser_cache(self):
        """扫描各浏览器的缓存目录。"""
        from .leftovers import find_browser_caches
        policy = get_policy("browser_cache")
        for item in find_browser_caches():
            if self.stop_flag:
                return
            path = item["path"]
            if item.get("is_file"):
                self._add_file(path, "browser_cache", item["label"], policy)
            else:
                self._collect_files(path, "browser_cache", item["label"],
                                    min_age_days=policy.min_age_days, max_depth=6)

    def scan_browser_cookies(self):
        """扫描浏览器 Cookie（会清掉登录态，默认不勾选）。"""
        from .leftovers import find_browser_cookies
        policy = get_policy("browser_cookies")
        for item in find_browser_cookies():
            if self.stop_flag:
                return
            if item.get("is_file"):
                self._add_file(item["path"], "browser_cookies", item["label"], policy)
            else:
                self._collect_files(item["path"], "browser_cookies", item["label"],
                                    min_age_days=0, max_depth=2)

    # -- 深度检测：卸载残留 -----------------------------------------------

    def scan_app_leftovers(self):
        """扫描卸载残留：卸载信息已消失、目录还在的孤儿目录。"""
        from .leftovers import find_orphaned_directories
        policy = get_policy("app_leftovers")
        for item in find_orphaned_directories():
            if self.stop_flag:
                return
            path = item["path"]
            try:
                age = (time.time() - os.path.getmtime(path)) / 86400.0
            except OSError:
                continue
            if age < policy.min_age_days:
                continue
            # 整目录作为一个清理目标：移入回收站即可整体还原
            result = ScanResult("app_leftovers", item["name"], path, 0,
                                description=item["reason"], root=path,
                                note=f"目录内有 {item['exe_count']} 个可执行文件")
            self._add(result)

    # -- 深度检测：系统级垃圾 ---------------------------------------------

    def scan_system_junk(self):
        """扫描系统日志、崩溃转储、字体与着色器缓存。"""
        from .leftovers import find_system_junk
        policy = get_policy("system_junk")
        for item in find_system_junk():
            if self.stop_flag:
                return
            path = item["path"]
            if os.path.isfile(path):
                self._add_file(path, "system_junk", item["label"], policy)
            else:
                self._collect_files(path, "system_junk", item["label"],
                                    min_age_days=policy.min_age_days, max_depth=4)

    def scan_delivery_optimization(self):
        """扫描 Windows 传递优化缓存。"""
        from .leftovers import find_system_junk
        policy = get_policy("delivery_optimization")
        for item in find_system_junk():
            if self.stop_flag:
                return
            if "传递优化" not in item["label"]:
                continue
            path = item["path"]
            if os.path.isdir(path):
                self._collect_files(path, "delivery_optimization", item["label"],
                                    min_age_days=policy.min_age_days, max_depth=4)

    def scan_old_installers(self):
        """扫描临时目录与下载目录里的旧安装包。"""
        from .leftovers import find_old_installers
        policy = get_policy("old_installers")
        for item in find_old_installers(min_age_days=policy.min_age_days):
            if self.stop_flag:
                return
            result = ScanResult("old_installers", "旧安装包", item["path"],
                                item.get("size", 0),
                                root=os.path.dirname(item["path"]),
                                mtime=item.get("mtime", 0.0),
                                note="长期未使用的安装包/压缩包")
            self._add(result)

    # -- 系统级特殊动作 ----------------------------------------------------

    def _scan_special(self, key: str, path: str, name: str, description: str):
        """登记一个"系统级特殊动作"（由清理器调用对应的系统命令执行）。"""
        policy = get_policy(key)
        self._add(ScanResult(key, name, path, 0, description=description,
                             special=policy.special, note=policy.note))

    def scan_windows_component_store(self):
        """组件存储：由清理器调用 DISM 分析 + 清理。"""
        self._scan_special("windows_component_store", "component_store",
                           "组件存储（WinSxS）",
                           "分析并清理被取代的系统组件版本")

    def scan_windows_old(self):
        """Windows.old：移除升级遗留的旧系统。"""
        old = os.path.join(get_system_drive(), "Windows.old")
        if not os.path.exists(old):
            return
        self._scan_special("windows_old", old, "Windows 旧版本安装",
                           "移除升级后遗留的旧系统目录")

    def scan_hibernation(self):
        """休眠文件：通过 powercfg 关闭休眠来释放。"""
        hiber = os.path.join(get_system_drive(), "hiberfil.sys")
        if not os.path.exists(hiber):
            return
        try:
            size = os.path.getsize(hiber)
        except OSError:
            size = 0
        policy = get_policy("hibernation")
        self._add(ScanResult("hibernation", "休眠文件", hiber, size,
                             description="关闭休眠以释放 hiberfil.sys",
                             special=policy.special, note=policy.note))

    def scan_system_restore(self):
        """系统还原点：删除卷影副本。"""
        self._scan_special("system_restore", "shadow_copies", "系统还原点",
                           "删除卷影副本占用的磁盘空间")

    # -- 工具 -------------------------------------------------------------

    def _add_file(self, path: str, category: str, name: str, policy):
        """加入单个文件（带年龄门槛）。"""
        try:
            st = os.stat(path)
        except OSError:
            return
        if policy.min_age_days > 0:
            age = (time.time() - st.st_mtime) / 86400.0
            if age < policy.min_age_days:
                return
        self._add(ScanResult(category, name, path, st.st_size,
                             root=os.path.dirname(path), mtime=st.st_mtime))

    def _expand_junk_pattern(self, pattern: str) -> List[str]:
        """展开配置中的路径（支持 glob 通配）。"""
        if not pattern:
            return []
        raw = expand_path(pattern)
        if not any(ch in raw for ch in "*?"):
            return [raw] if os.path.isdir(raw) else []
        try:
            matched = glob.glob(raw, recursive=False)
        except Exception as e:
            logging.warning(f"展开路径失败 {raw}: {e}")
            return []
        return [m for m in matched if os.path.isdir(m)]

    # -- 统计 -------------------------------------------------------------

    def get_summary(self) -> Dict[str, object]:
        """获取扫描结果统计。"""
        total_size = sum(r.size for r in self.results)
        by_category: Dict[str, int] = {}
        count_by_category: Dict[str, int] = {}
        for r in self.results:
            by_category[r.category] = by_category.get(r.category, 0) + r.size
            count_by_category[r.category] = count_by_category.get(r.category, 0) + 1
        return {
            "total_size": total_size,
            "total_count": len(self.results),
            "by_category": by_category,
            "count_by_category": count_by_category,
        }
