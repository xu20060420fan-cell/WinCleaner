"""多信号取证分析引擎。

**设计前提：关键词不是判据，只是线索之一。**

判断一个东西是不是垃圾/流氓，靠的是多条**互相独立**的底层证据：

============  ==========================================================
维度          底层证据
============  ==========================================================
数字签名      WinVerifyTrust 的 Authenticode 校验结果（有效/未签名/
              签名无效/不受信任）——这是"文件是否被改过"的硬证据
安装位置      正规软件装在 Program Files；装在 %TEMP%/%APPDATA% 根/
              Downloads 里的可执行文件本身就是强信号
持久化        同一个 exe 被注册进几处自启动（Run/RunOnce/启动文件夹/
              服务/计划任务）——捆绑安装的典型特征
PE 结构       节区熵值（打包/加密）、壳特征、导入表里有没有注入/
              键盘记录/静默下载的 API
发布者        版本资源里自称的公司与它所在目录/文件名的宣称是否一致
名称特征      关键词命中（**权重最低**的一维）
分发形态      没有卸载程序、目录里堆满随机名文件、像"安装包"
行为          进程是否正在运行、是否在临时目录里活动
============  ==========================================================

最后还有一层 **交叉验证**：单个信号弱，但"未签名 + 装在临时目录 +
自称知名品牌"这种组合，往往就是铁证。
"""
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .config import load_config
from .pe_inspect import (
    PEInfo,
    executable_in_dir,
    looks_like_executable,
    parse_pe,
)
from .signature import get_version_info, verify_signature
from .utils import (
    get_appdata_local,
    get_appdata_roaming,
    get_program_data,
    get_system_drive,
    get_user_profile,
    normalize_path,
)

# ---------------------------------------------------------------------------
# 信号与结论
# ---------------------------------------------------------------------------

DIM_SIGNATURE = "数字签名"
DIM_LOCATION = "安装位置"
DIM_PERSISTENCE = "持久化"
DIM_PE = "PE 结构"
DIM_PUBLISHER = "发布者"
DIM_NAME = "名称特征"
DIM_DISTRIBUTION = "分发形态"
DIM_BEHAVIOR = "运行行为"
DIM_COMBINATION = "交叉验证"

ALL_DIMENSIONS = [
    DIM_SIGNATURE, DIM_LOCATION, DIM_PERSISTENCE, DIM_PE, DIM_PUBLISHER,
    DIM_NAME, DIM_DISTRIBUTION, DIM_BEHAVIOR, DIM_COMBINATION,
]

LEVEL_NONE = "无"
LEVEL_LOW = "待确认"
LEVEL_MEDIUM = "可疑"
LEVEL_HIGH = "高危"


@dataclass
class Signal:
    """一条底层证据。"""

    dimension: str
    weight: int
    detail: str
    level: str = ""

    def to_dict(self) -> dict:
        return {
            "dimension": self.dimension,
            "weight": self.weight,
            "detail": self.detail,
            "level": self.level,
        }


@dataclass
class Analysis:
    """一个对象的完整分析结论。"""

    path: str
    name: str
    kind: str = "目录"
    risk: int = 0
    level: str = LEVEL_NONE
    signals: List[Signal] = field(default_factory=list)
    signature: dict = field(default_factory=dict)
    pe: dict = field(default_factory=dict)
    publisher: dict = field(default_factory=dict)
    persistence: List[str] = field(default_factory=list)
    deep_analyzed: bool = False

    @property
    def summary(self) -> str:
        """最主要的依据（按权重排序取前两条）。"""
        if not self.signals:
            return "未发现异常"
        top = sorted(self.signals, key=lambda s: -s.weight)[:2]
        return "；".join(s.detail for s in top if s.weight > 0) or "未发现异常"

    @property
    def risk_without_name(self) -> int:
        """剔除"名称特征"维度后的分数。

        关键词是最弱的一维——只靠名字命中就进结果表，噪音会淹没真问题。
        """
        return max(0, min(100, sum(s.weight for s in self.signals
                                   if s.dimension != DIM_NAME)))

    @property
    def has_strong_name_hit(self) -> bool:
        """名称维度是否命中了**强特征**（而非泛化词）。"""
        for s in self.signals:
            if s.dimension == DIM_NAME and s.weight >= 35:
                return True
        return False

    @property
    def dimensions(self) -> List[str]:
        """命中的维度名（供界面显示标签）。"""
        out = []
        for dim in ALL_DIMENSIONS:
            if any(s.dimension == dim and s.weight > 0 for s in self.signals):
                out.append(dim)
        return out

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "kind": self.kind,
            "risk": self.risk,
            "level": self.level,
            "summary": self.summary,
            "dimensions": self.dimensions,
            "signals": [s.to_dict() for s in self.signals],
            "signature": self.signature,
            "pe": self.pe,
            "publisher": self.publisher,
            "persistence": list(self.persistence),
            "deep_analyzed": self.deep_analyzed,
        }

    def detail_text(self) -> str:
        """生成给人看的完整证据链文本。"""
        lines = [f"对象：{self.name}", f"路径：{self.path}", f"类型：{self.kind}",
                 f"风险评分：{self.risk}/100（{self.level}）", ""]
        if self.signature:
            lines.append(f"[{DIM_SIGNATURE}] {self.signature.get('status_text', '')}")
            if self.signature.get("signer"):
                lines.append(f"    签名者：{self.signature['signer']}")
            if self.signature.get("issuer"):
                lines.append(f"    颁发者：{self.signature['issuer']}")
        if self.publisher:
            lines.append(f"[{DIM_PUBLISHER}] 自称发布者："
                         f"{self.publisher.get('company') or '(空)'} / "
                         f"{self.publisher.get('product') or '(空)'}")
        if self.pe:
            lines.append(f"[{DIM_PE}] {self.pe.get('summary', '')}")
        if self.persistence:
            lines.append(f"[{DIM_PERSISTENCE}] 自启动登记 {len(self.persistence)} 处：")
            for p in self.persistence[:8]:
                lines.append(f"    - {p}")
        lines.append("")
        lines.append("证据明细：")
        for s in sorted(self.signals, key=lambda x: -x.weight):
            mark = "＋" if s.weight > 0 else ("－" if s.weight < 0 else "  ")
            lines.append(f"  {mark}{s.weight:+4d}  [{s.dimension}] {s.detail}")
        return "\n".join(lines)


def level_of(risk: int) -> str:
    if risk >= 71:
        return LEVEL_HIGH
    if risk >= 46:
        return LEVEL_MEDIUM
    if risk >= 21:
        return LEVEL_LOW
    return LEVEL_NONE


# ---------------------------------------------------------------------------
# 命令行里的可执行文件路径提取
# ---------------------------------------------------------------------------

_EXE_QUOTED_RE = re.compile(r'"([^"]+\.(?:exe|dll|com|bat|cmd|sys|scr|ocx))"', re.IGNORECASE)
_EXE_PLAIN_RE = re.compile(
    r"([^<>\"']+\.(?:exe|dll|com|bat|cmd|sys|scr|ocx))", re.IGNORECASE)


def extract_exe_path(command: str) -> str:
    """从命令行里抽出可执行文件路径。

    **优先取引号里的那个**：``rundll32.exe "C:\\a\\b\\c.dll",Entry`` 的真正
    目标是引号里的 dll，而不是前面的 rundll32.exe。
    """
    if not command:
        return ""
    text = os.path.expandvars(command.strip())
    match = _EXE_QUOTED_RE.search(text) or _EXE_PLAIN_RE.search(text)
    if not match:
        return ""
    path = (match.group(1) or "").strip().strip('"')
    if not path:
        return ""
    if not os.path.isabs(path):
        # 相对路径（SYSTEM32\svchost.exe 之类）交给上层按系统目录补全
        for base in (os.path.join(get_system_drive(), "Windows", "System32"),
                     os.path.join(get_system_drive(), "Windows")):
            candidate = os.path.join(base, path)
            if os.path.exists(candidate):
                return candidate
        return ""
    drive, tail = os.path.splitdrive(path)
    if not drive:
        # 形如 \SystemRoot\system32\drivers\xxx.sys 的注册表路径没有盘符
        lowered = path.lower()
        system_drive = get_system_drive()
        windows = os.path.join(system_drive, "Windows")
        if lowered.startswith("\\systemroot\\"):
            return os.path.normpath(os.path.join(windows, path[len("\\systemroot\\"):]))
        if lowered == "\\systemroot":
            return windows
        # 其它无盘符的根路径按系统盘解释
        candidate = os.path.normpath(os.path.join(system_drive, path.lstrip("\\")))
        if os.path.exists(candidate):
            return candidate
        return ""
    return os.path.normpath(path)


# ---------------------------------------------------------------------------
# 持久化索引
# ---------------------------------------------------------------------------


class PersistenceIndex:
    """索引系统里所有自启动入口，按可执行文件路径归拢。

    "同一个 exe 被登记在 3 处" 是捆绑安装最典型的特征。
    """

    def __init__(self, include_scheduled_tasks: bool = True):
        self._map: Dict[str, List[str]] = {}
        #: 规范化路径 → 原始路径（保留大小写，便于展示）
        self._orig: Dict[str, str] = {}
        self._include_tasks = include_scheduled_tasks
        self._built = False

    def build(self):
        if self._built:
            return
        self._built = True
        self._build_startup()
        self._build_services()
        if self._include_tasks:
            self._build_tasks()

    def _add(self, exe_path: str, source: str):
        if not exe_path:
            return
        key = normalize_path(exe_path)
        if not key:
            return
        self._map.setdefault(key, [])
        self._orig.setdefault(key, exe_path)
        if source not in self._map[key]:
            self._map[key].append(source)

    def _build_startup(self):
        try:
            from .startup_manager import StartupManager
            for item in StartupManager().enumerate():
                exe = extract_exe_path(item.get("command", ""))
                if exe:
                    self._add(exe, f"{item.get('hive') or '启动文件夹'} "
                                   f"{item.get('key', '')}\\{item.get('name', '')}")
        except Exception as e:  # noqa: BLE001
            import logging
            logging.debug(f"枚举启动项失败: {e}")

    def _build_services(self):
        try:
            import winreg
            base = r"SYSTEM\CurrentControlSet\Services"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0,
                                winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(key, name, 0, winreg.KEY_READ) as sub:
                            value, _ = winreg.QueryValueEx(sub, "ImagePath")
                    except OSError:
                        continue
                    exe = extract_exe_path(str(value))
                    if exe:
                        self._add(exe, f"服务 {name}")
        except Exception as e:  # noqa: BLE001
            import logging
            logging.debug(f"枚举服务失败: {e}")

    def _build_tasks(self):
        try:
            import subprocess
            proc = subprocess.run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                capture_output=True, text=True, errors="ignore", timeout=90,
                creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                               if os.name == "nt" else 0))
            if proc.returncode != 0:
                return
            for block in proc.stdout.split("\n\n"):
                if not block.strip():
                    continue
                task_name = ""
                command = ""
                for line in block.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("任务名称") or stripped.startswith("TaskName"):
                        task_name = line.split(":", 1)[-1].strip()
                    elif (stripped.startswith("任务要运行的命令")
                          or stripped.startswith("Task To Run")):
                        command = line.split(":", 1)[-1].strip()
                if command:
                    exe = extract_exe_path(command)
                    if exe:
                        self._add(exe, f"计划任务 {task_name or '?'}")
        except Exception as e:  # noqa: BLE001
            import logging
            logging.debug(f"枚举计划任务失败: {e}")

    def entries_for(self, path: str) -> List[str]:
        self.build()
        return list(self._map.get(normalize_path(path), []))

    def original_paths(self) -> List[str]:
        """索引里所有自启动目标（保留原始大小写）。"""
        self.build()
        return list(self._orig.values())


# ---------------------------------------------------------------------------
# 分析器
# ---------------------------------------------------------------------------


class MalwareAnalyzer:
    """对目录 / 可执行文件做多信号取证分析。"""

    def __init__(self, progress_callback=None, deep_budget: int = 60,
                 include_scheduled_tasks: bool = True):
        self.progress_callback = progress_callback
        self.deep_budget = deep_budget
        self._deep_used = 0
        self.persistence = PersistenceIndex(include_scheduled_tasks)
        self._sig_cache: Dict[str, tuple] = {}
        self._pe_cache: Dict[str, tuple] = {}
        self._running_exes = self._collect_running_exes()

        cfg = load_config()
        self.trusted_brands = [b.lower() for b in cfg.get("trusted_brands", [])]
        self.strong_keywords = [k.lower() for k in cfg.get("strong_keywords", [])]
        self.weak_keywords = [k.lower() for k in cfg.get("weak_keywords", [])]
        self.rogue_patterns = [p.strip("*").lower()
                               for p in cfg.get("known_rogue_patterns", [])]

    # -- 工具 -------------------------------------------------------------

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    @staticmethod
    def _collect_running_exes() -> set:
        """当前正在运行的可执行文件路径集合。"""
        out = set()
        try:
            import psutil
            for proc in psutil.process_iter(["exe"]):
                try:
                    exe = proc.info.get("exe")
                    if exe:
                        out.add(normalize_path(exe))
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def _verify_cached(self, path: str) -> dict:
        try:
            st = os.stat(path)
            key = normalize_path(path)
            cached = self._sig_cache.get(key)
            if cached and cached[0] == (st.st_mtime, st.st_size):
                return cached[1]
        except OSError:
            return {}
        info = verify_signature(path)
        try:
            st = os.stat(path)
            self._sig_cache[normalize_path(path)] = ((st.st_mtime, st.st_size), info)
        except OSError:
            pass
        return info

    def _parse_cached(self, path: str) -> PEInfo:
        try:
            st = os.stat(path)
            key = normalize_path(path)
            cached = self._pe_cache.get(key)
            if cached and cached[0] == (st.st_mtime, st.st_size):
                return cached[1]
        except OSError:
            return PEInfo()
        info = parse_pe(path)
        try:
            st = os.stat(path)
            self._pe_cache[normalize_path(path)] = ((st.st_mtime, st.st_size), info)
        except OSError:
            pass
        return info

    # -- 信任判定 ---------------------------------------------------------

    def is_trusted_brand(self, text: str) -> str:
        """命中可信品牌白名单则返回品牌名。"""
        if not text:
            return ""
        low = text.lower()
        for brand in self.trusted_brands:
            if brand and brand in low:
                return brand
        return ""

    # -- 各维度信号 -------------------------------------------------------

    def _signal_location(self, path: str, signed: bool = False) -> Signal:
        """安装位置是否体面。

        ``signed=True`` 时（文件有受信任的数字签名）大幅降低位置权重——
        用户刚下载的正规安装包也会临时落在 %TEMP%，那不是流氓行为。
        """
        p = normalize_path(path)
        local = normalize_path(get_appdata_local())
        roaming = normalize_path(get_appdata_roaming())
        progdata = normalize_path(get_program_data())
        temp = normalize_path(os.environ.get("TEMP", ""))
        sys_temp = normalize_path(os.path.join(get_system_drive(), "Windows", "Temp"))
        program_files = normalize_path(os.environ.get("ProgramFiles", ""))
        system32 = normalize_path(os.path.join(get_system_drive(), "Windows", "System32"))
        downloads = normalize_path(os.path.join(get_user_profile(), "Downloads"))

        def under(child: str, parent: str) -> bool:
            return bool(parent) and child.startswith(parent + "\\")

        if under(p, sys_temp) or (temp and under(p, temp)):
            if signed:
                return Signal(DIM_LOCATION, 18,
                              "位于临时目录，但签名有效（可能是正规安装包）")
            return Signal(DIM_LOCATION, 45, "位于临时目录（临时目录里的程序极可能是安装器或投放器）")
        if downloads and under(p, downloads):
            return Signal(DIM_LOCATION, 30 if signed else 40, "位于下载目录")
        if under(p, system32) or under(p, normalize_path(
                os.path.join(get_system_drive(), "Windows"))):
            return Signal(DIM_LOCATION, -30, "位于 Windows 系统目录")
        if program_files and under(p, program_files):
            return Signal(DIM_LOCATION, -25, "位于 Program Files（正规安装位置）")
        if under(p, progdata):
            return Signal(DIM_LOCATION, 12, "位于 ProgramData（系统级公共数据目录）")
        if under(p, roaming):
            return Signal(DIM_LOCATION, 12, "位于漫游配置目录")
        if under(p, local):
            # %LOCALAPPDATA%\Programs\ 是微软商店/每用户安装的标准位置
            programs = normalize_path(os.path.join(local, "Programs"))
            if under(p, programs):
                return Signal(DIM_LOCATION, -20, "位于标准用户安装目录（%LOCALAPPDATA%\\Programs）")
            # 只有**直接躺在 %LOCALAPPDATA% 根目录**的可执行文件才可疑；
            # %LOCALAPPDATA%\<某个应用>\ 是现代软件的正常形态。
            depth = p[len(local):].count("\\")
            if depth == 0:
                return Signal(DIM_LOCATION, 32, "可执行文件直接位于用户数据目录根部")
            return Signal(DIM_LOCATION, 6, "位于用户应用数据目录")
        return Signal(DIM_LOCATION, 5, "位置普通")

    def _signal_persistence(self, path: str) -> Signal:
        entries = self.persistence.entries_for(path)
        if not entries:
            return Signal(DIM_PERSISTENCE, 0, "未发现自启动登记")
        # 系统组件天然是"常驻"的（驱动、svchost 之类），不算异常
        if self._is_trusted_location(path):
            return Signal(DIM_PERSISTENCE, -5,
                          f"系统组件（{len(entries)} 处服务/驱动登记属正常）")
        weight = min(70, 18 * len(entries))
        if len(entries) >= 2:
            weight = min(85, weight + 12)
        return Signal(DIM_PERSISTENCE, weight,
                      f"被登记 {len(entries)} 处自启动（{'、'.join(entries[:3])}）")

    def _signal_pe(self, pe: PEInfo, signed: bool = False) -> Signal:
        if not pe.valid:
            if pe.error:
                # 有 MZ 头却解析不出来 = 结构损坏/被刻意构造
                return Signal(DIM_PE, 15, f"PE 结构异常（{pe.error}）")
            return Signal(DIM_PE, 0, "不是有效的 PE 文件")
        details = []
        weight = 0
        if pe.max_entropy >= 7.2:
            # 签名有效的高熵文件多半是压缩过的正规安装包
            weight += 8 if signed else 22
            details.append(f"节区熵值 {pe.max_entropy:.2f}（高度压缩/加密）")
        if pe.packers:
            weight += 18
            details.append("疑似加壳：" + ",".join(pe.packers))
        for category, apis in pe.suspicious_imports.items():
            if category in ("注入与进程操纵", "键盘记录与截屏"):
                weight += 20 if category == "键盘记录与截屏" else 16
            elif category in ("网络下载与通信", "自删除与反取证"):
                weight += 12
            else:
                weight += 6
            details.append(f"{category}（{', '.join(apis[:3])}）")
        if pe.overlay_size > 0 and pe.size and pe.overlay_size / pe.size > 0.1:
            weight += 8
            details.append("文件尾附加了额外数据（overlay）")
        if weight == 0:
            return Signal(DIM_PE, 0, "PE 结构未见异常")
        return Signal(DIM_PE, min(70, weight), "；".join(details))

    def _signal_publisher(self, path: str, version: dict, sig: dict,
                          trusted_location: bool = False) -> Signal:
        company = (version.get("company") or "").strip()
        product = (version.get("product") or "").strip()
        original = (version.get("original_filename") or "").strip()
        current = os.path.basename(path)
        dir_name = os.path.basename(os.path.dirname(path))

        # 自称信息里带破解/绿色版等字样
        blob = f"{company} {product} {version.get('description', '')}"
        bad_words = ("破解", "绿色版", "注册机", "激活器", "keygen", "crack",
                     "patch", "免注册", "中文版", "特别版", "吾爱", "分享")
        for word in bad_words:
            if word in blob.lower():
                return Signal(DIM_PUBLISHER, 45,
                              f"版本信息自称包含「{word}」（典型盗版/破解标识）")

        # 系统安装目录里的软件不需要靠元数据证明自己
        if trusted_location:
            return Signal(DIM_PUBLISHER, -10,
                          f"位于正规安装目录，自称发布者「{company or product or '未知'}」")

        # 签名有效 = 身份已被认证，不再追究"自称"
        if sig.get("status") == "valid":
            return Signal(DIM_PUBLISHER, -15,
                          f"签名有效，发布者身份已认证（{company or product or '未标注'}）")

        if not company and not product:
            return Signal(DIM_PUBLISHER, 12, "没有填写发布者信息（正规软件通常会填）")

        # 自称发布者与所在目录/文件名严重不符
        if company:
            c_low = company.lower()
            claimed = f"{dir_name} {current}".lower()
            if (c_low not in claimed and company not in version.get("product", "")
                    and len(company) > 3):
                weight = 18
                detail = f"自称发布者「{company}」与文件名/目录名「{dir_name}」不符"
                if sig.get("status") == "unsigned":
                    weight += 18
                    detail += "，且文件未签名"
                return Signal(DIM_PUBLISHER, weight, detail)

        # 原始文件名与当前文件名完全不同
        if original and current and not original.lower().startswith(
                os.path.splitext(current)[0].lower()[:4]):
            if len(original) > 4 and os.path.splitext(current)[0].lower() not in original.lower():
                return Signal(DIM_PUBLISHER, 15,
                              f"原始文件名「{original}」与当前文件名「{current}」不同")
        return Signal(DIM_PUBLISHER, -5, f"自称发布者「{company or product}」")

    def _signal_name(self, path: str) -> Signal:
        """关键词命中——**权重最低的一维**，只作为线索。"""
        name = os.path.basename(path)
        dir_name = os.path.basename(os.path.dirname(path))
        text = f"{name} {dir_name}".lower()
        strong = [k for k in self.strong_keywords if k in text]
        weak = [k for k in self.weak_keywords if k in text]
        if not strong and not weak:
            return Signal(DIM_NAME, 0, "名称未命中任何特征词")
        weight = 0
        details = []
        if strong:
            weight += 35
            details.append(f"命中高危特征词：{', '.join(strong[:4])}")
        if weak:
            weight += 10
            details.append(f"命中泛化特征词：{', '.join(weak[:4])}")
        for pattern in self.rogue_patterns:
            if pattern and pattern in text:
                weight += 20
                details.append(f"命中已知流氓品牌：{pattern}")
                break
        return Signal(DIM_NAME, min(55, weight), "；".join(details))

    def _signal_distribution(self, path: str) -> Signal:
        """分发形态：像不像一个被正规安装的软件。"""
        if not os.path.isdir(path):
            return Signal(DIM_DISTRIBUTION, 0, "非目录")
        try:
            entries = list(os.scandir(path))
        except OSError:
            return Signal(DIM_DISTRIBUTION, 0, "无法读取目录")
        exes = [e for e in entries
                if e.is_file(follow_symlinks=False) and looks_like_executable(e.path)]
        has_uninstall = any(
            e.name.lower().startswith(("unins", "uninstall")) for e in entries)
        details = []
        weight = 0
        if len(exes) >= 3 and not has_uninstall:
            weight += 12
            details.append(f"目录内有 {len(exes)} 个可执行文件却没有卸载程序")
        elif not has_uninstall and exes:
            weight += 8
            details.append("没有卸载程序")
        if len(entries) > 200:
            weight += 8
            details.append(f"目录内有 {len(entries)} 个条目")
        if weight == 0:
            return Signal(DIM_DISTRIBUTION, 0, "目录结构正常")
        return Signal(DIM_DISTRIBUTION, weight, "；".join(details))

    def _signal_behavior(self, path: str) -> Signal:
        if normalize_path(path) in self._running_exes:
            return Signal(DIM_BEHAVIOR, 12, "该程序当前正在运行")
        return Signal(DIM_BEHAVIOR, 0, "当前未在运行")

    def _signal_signature(self, sig: dict, is_pe: bool = True) -> Signal:
        status = sig.get("status", "error")
        if not is_pe:
            # .bat / .cmd / 脚本之类的非 PE 文件本来就无法做 Authenticode 校验
            return Signal(DIM_SIGNATURE, 0, "非 PE 可执行格式，不适用签名校验")
        if status == "valid":
            return Signal(DIM_SIGNATURE, -28, "数字签名有效且受信任")
        if status == "unsigned":
            return Signal(DIM_SIGNATURE, 20, "文件没有任何数字签名")
        if status == "invalid":
            return Signal(DIM_SIGNATURE, 55, "签名校验失败（文件内容与签名不符，可能被篡改）")
        if status == "untrusted":
            return Signal(DIM_SIGNATURE, 40, "签名不受信任（自签名或证书链有问题）")
        if status == "expired":
            return Signal(DIM_SIGNATURE, 15, "签名证书已过期")
        return Signal(DIM_SIGNATURE, 0, sig.get("status_text", "签名状态未知"))

    # -- 交叉验证 ---------------------------------------------------------

    def _combination_signals(self, signals: List[Signal]) -> List[Signal]:
        """把多条弱信号组合成强证据。"""
        out: List[Signal] = []
        by_dim = {s.dimension: s.weight for s in signals}

        sig_w = by_dim.get(DIM_SIGNATURE, 0)
        loc_w = by_dim.get(DIM_LOCATION, 0)
        pe_w = by_dim.get(DIM_PE, 0)
        pub_w = by_dim.get(DIM_PUBLISHER, 0)
        per_w = by_dim.get(DIM_PERSISTENCE, 0)

        # 未签名 + 装在临时/下载目录 + 自称某品牌 = 伪装投放
        if sig_w >= 20 and loc_w >= 30 and pub_w >= 15:
            out.append(Signal(DIM_COMBINATION, 30,
                              "未签名 + 位于临时/下载目录 + 自称发布者存疑：典型的伪装投放"))
        # 加壳 + 未签名 + 注入类 API = 明确的恶意组合
        if pe_w >= 40 and sig_w >= 20:
            out.append(Signal(DIM_COMBINATION, 28,
                              "文件经过加壳/加密且未签名：常见的恶意载荷特征"))
        # 多处自启动 + 未签名 = 捆绑持久化
        if per_w >= 30 and sig_w >= 20:
            out.append(Signal(DIM_COMBINATION, 20,
                              "未签名程序在多处注册自启动：典型的捆绑安装"))
        # 签名有效 + 正规位置 + 结构正常 = 明确可信
        if sig_w <= -20 and loc_w <= -20 and pe_w <= 0:
            out.append(Signal(DIM_COMBINATION, -25,
                              "签名有效、位于正规安装位置、结构无异常：可信软件"))
        return out

    # -- 主入口 -----------------------------------------------------------

    def quick_score(self, path: str, kind: str = "目录") -> int:
        """预筛打分：只跑**便宜**的信号（位置/名称/形态/持久化）。

        不做签名校验与 PE 解析，用来在几百个候选里快速挑出值得深挖的对象。
        """
        total = 0
        total += self._signal_location(path, signed=False).weight
        total += self._signal_name(path).weight
        if kind == "目录":
            total += self._signal_distribution(path).weight
        else:
            total += self._signal_behavior(path).weight
        total += self._signal_persistence(path).weight
        return total

    def analyze_directory(self, path: str) -> Analysis:
        """分析一个目录（安装目录 / 残留目录）。"""
        result = Analysis(path=path, name=os.path.basename(path.rstrip("\\")) or path,
                          kind="目录")
        signals: List[Signal] = []

        # 目录级深挖：取目录里的主可执行文件
        main_exe = self._main_executable(path)
        if main_exe:
            sub = self._analyze_executable(main_exe, deep=True)
            result.signature = sub.signature
            result.pe = sub.pe
            result.publisher = sub.publisher
            result.deep_analyzed = sub.deep_analyzed
            result.persistence = list(sub.persistence)
            signals.extend(sub.signals)
        else:
            signals.append(self._signal_location(path, signed=False))

        signals.append(self._signal_name(path))
        signals.append(self._signal_distribution(path))
        signals.append(self._signal_persistence(path))

        signals.extend(self._combination_signals(signals))
        self._finalize(result, signals)
        return result

    def analyze_executable(self, path: str) -> Analysis:
        """分析一个可执行文件。"""
        result = Analysis(path=path, name=os.path.basename(path), kind="可执行文件")
        sub = self._analyze_executable(path, deep=True)
        result.signature = sub.signature
        result.pe = sub.pe
        result.publisher = sub.publisher
        result.deep_analyzed = sub.deep_analyzed
        result.persistence = list(sub.persistence)
        signals: List[Signal] = list(sub.signals)
        signals.append(self._signal_name(path))
        signals.append(self._signal_persistence(path))
        signals.append(self._signal_behavior(path))
        signals.extend(self._combination_signals(signals))
        self._finalize(result, signals)
        return result

    def _analyze_executable(self, path: str, deep: bool) -> Analysis:
        """对可执行文件做深度取证（签名 + PE + 发布者 + 位置）。"""
        result = Analysis(path=path, name=os.path.basename(path), kind="可执行文件")

        if not deep and self._deep_used >= self.deep_budget:
            return result
        if deep:
            self._deep_used += 1

        version = get_version_info(path)
        result.publisher = version
        result.signature = self._verify_cached(path)
        signed = result.signature.get("status") == "valid"
        pe = self._parse_cached(path)
        result.pe = pe.to_dict()
        result.pe["summary"] = pe.summary()
        result.persistence = self.persistence.entries_for(path)

        # 有 MZ 头就说明它自称是 PE——即使解析失败也要按"未签名"处理，
        # 否则一个伪造的 exe 头就能绕开签名这一维。
        is_pe = pe.valid or self._has_mz_header(path)

        result.signals.append(self._signal_location(path, signed=signed))
        result.signals.append(self._signal_signature(result.signature, is_pe=is_pe))
        if is_pe:
            # 非 PE 文件（.bat/.cmd 等）没有发布者元数据可言
            result.signals.append(self._signal_publisher(
                path, version, result.signature,
                trusted_location=self._is_trusted_location(path)))
        result.signals.append(self._signal_pe(pe, signed=signed))
        return result

    @staticmethod
    def _has_mz_header(path: str) -> bool:
        try:
            with open(path, "rb") as f:
                return f.read(2) == b"MZ"
        except OSError:
            return False

    def _is_trusted_location(self, path: str) -> bool:
        """是否位于系统安装目录（这类位置不需要靠元数据自证清白）。"""
        p = normalize_path(path)
        for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            base = os.environ.get(env)
            if base and p.startswith(normalize_path(base) + "\\"):
                return True
        win = normalize_path(os.path.join(get_system_drive(), "Windows"))
        return p.startswith(win + "\\")

    @staticmethod
    def _main_executable(directory: str) -> str:
        """挑一个目录里"最有代表性"的可执行文件：优先与目录同名的。"""
        base = os.path.basename(directory.rstrip("\\")).lower()
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return ""
        exes = [e.path for e in entries
                if e.is_file(follow_symlinks=False) and looks_like_executable(e.path)]
        if not exes:
            return ""
        for path in exes:
            stem = os.path.splitext(os.path.basename(path))[0].lower()
            if stem and stem == base:
                return path
        # 否则取最大的一个
        best = ""
        best_size = -1
        for path in exes:
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > best_size:
                best, best_size = path, size
        return best

    @staticmethod
    def _finalize(result: Analysis, signals: List[Signal]):
        """汇总分数与等级。"""
        result.signals = signals
        total = sum(s.weight for s in signals)
        result.risk = max(0, min(100, total))
        result.level = level_of(result.risk)
