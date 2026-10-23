"""广告软件 / 流氓软件扫描模块。

**判定不再依赖关键词。** 关键词只是九个维度之一（而且权重最低），
真正的判断来自 :mod:`core.analyzer` 的多信号取证：

    数字签名 / 安装位置 / 持久化 / PE 结构 / 发布者 / 名称特征 /
    分发形态 / 运行行为 / 交叉验证

扫描流程是"两段式"的：

1. **预筛**（便宜，全量跑）：位置、名称、目录形态、自启动登记。
2. **深挖**（贵，只跑可疑的）：Authenticode 校验、PE 结构解析、
   发布者一致性核验。

这样几百个候选目录也只要几秒。
"""
import glob
import logging
import os
import subprocess
import winreg
from typing import Callable, Dict, List, Optional

from .analyzer import (
    LEVEL_HIGH,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_NONE,
    MalwareAnalyzer,
    extract_exe_path,
)
from .config import load_config
from .utils import (
    get_appdata_local,
    get_appdata_roaming,
    get_program_data,
    get_system_drive,
    get_user_profile,
)

#: 预筛阈值：低于这个分数不做昂贵的深度取证
QUICK_THRESHOLD = 22
#: 进入结果表的最低风险分
REPORT_THRESHOLD = 21


class AdwareScanner:
    """扫描广告软件、流氓软件残留（多信号取证）。"""

    #: 只有风险等级达到该阈值才进入结果表
    REPORT_THRESHOLD = REPORT_THRESHOLD
    QUICK_THRESHOLD = QUICK_THRESHOLD

    def __init__(self, progress_callback: Callable = None, deep_budget: int = 90):
        self.results: List[Dict] = []
        self.progress_callback = progress_callback
        self.stop_flag = False
        #: 只命中泛化关键词、未进入结果表的项目数
        self.low_confidence_count = 0
        self.analyzer = MalwareAnalyzer(progress_callback=None,
                                        deep_budget=deep_budget)
        cfg = load_config()
        self.strong_keywords = [k.lower() for k in cfg.get("strong_keywords", [])]
        self.weak_keywords = [k.lower() for k in cfg.get("weak_keywords", [])]
        self.known_rogue_patterns = list(cfg.get("known_rogue_patterns", []))
        self.trusted_brands = [b.lower() for b in cfg.get("trusted_brands", [])]

    def stop(self):
        self.stop_flag = True

    def reset(self):
        self.results.clear()
        self.low_confidence_count = 0
        self.stop_flag = False

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    # -- 入口 -------------------------------------------------------------

    def scan(self) -> List[Dict]:
        """执行流氓软件扫描。"""
        self.reset()
        self._report("正在建立自启动索引…", 5)
        self.analyzer.persistence.build()

        candidates = self._collect_candidates()
        self._report(f"共 {len(candidates)} 个候选，开始取证分析…", 15)

        total = max(1, len(candidates))
        for idx, (kind, path, label) in enumerate(candidates):
            if self.stop_flag:
                break
            if idx % 5 == 0:
                self._report(f"正在分析: {label}", 15 + int(idx / total * 80))
            self._analyze_candidate(kind, path, label)

        self._report("扫描完成", 100)
        return self.results

    # -- 候选收集 ---------------------------------------------------------

    def _collect_candidates(self) -> List[tuple]:
        """收集待分析的对象：(kind, path, label)。"""
        candidates: List[tuple] = []
        seen = set()

        def add(kind: str, path: str, label: str = ""):
            key = (kind, os.path.normcase(path))
            if key in seen:
                return
            seen.add(key)
            candidates.append((kind, path, label or os.path.basename(path)))

        # ① 安装目录与用户数据目录的**顶层**目录
        roots = [
            os.path.join(get_system_drive(), "Program Files"),
            os.path.join(get_system_drive(), "Program Files (x86)"),
            get_program_data(),
            get_appdata_local(),
            get_appdata_roaming(),
        ]
        for root in roots:
            if not os.path.isdir(root):
                continue
            try:
                for entry in os.scandir(root):
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if is_reparse(entry.path):
                        continue
                    add("目录", entry.path)
            except (OSError, PermissionError):
                continue

        # ② 临时目录 / 下载目录里的可执行文件（高风险位置）
        for base in {os.environ.get("TEMP", ""),
                     os.path.join(get_user_profile(), "Downloads"),
                     os.path.join(get_user_profile(), "Desktop")}:
            if not base or not os.path.isdir(base):
                continue
            try:
                for entry in os.scandir(base):
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if entry.name.lower().endswith((".exe", ".scr", ".bat", ".cmd")):
                        add("可执行文件", entry.path)
            except (OSError, PermissionError):
                continue

        # ③ 自启动项指向的可执行文件（重点排查）
        for exe in self._persistence_executables():
            add("可执行文件", exe)

        # ④ 已知流氓品牌模式
        for pattern in self.known_rogue_patterns:
            for root in roots:
                if not os.path.isdir(root):
                    continue
                try:
                    for matched in glob.glob(os.path.join(root, pattern),
                                            recursive=False):
                        if os.path.isdir(matched):
                            add("目录", matched, "已知流氓软件目录")
                except OSError:
                    continue

        return candidates

    def _persistence_executables(self) -> List[str]:
        """从自启动索引里取出所有可执行文件。"""
        out = []
        try:
            out = self.analyzer.persistence.original_paths()
        except Exception as e:  # noqa: BLE001
            logging.debug(f"读取持久化索引失败: {e}")
        return out

    # -- 分析 -------------------------------------------------------------

    def _analyze_candidate(self, kind: str, path: str, label: str):
        """分析单个候选，够格才进结果表。"""
        try:
            # ① 可信品牌白名单：命中直接排除
            brand = self.analyzer.is_trusted_brand(
                f"{label} {os.path.basename(path)}")
            if brand and not self._is_structurally_suspicious(path):
                self.low_confidence_count += 1
                return

            # ② 预筛：只跑便宜信号
            quick = self.analyzer.quick_score(path, kind)
            if quick < QUICK_THRESHOLD:
                self.low_confidence_count += 1
                return

            # ③ 深度取证
            if kind == "可执行文件":
                analysis = self.analyzer.analyze_executable(path)
            else:
                analysis = self.analyzer.analyze_directory(path)

            if analysis.risk < REPORT_THRESHOLD:
                self.low_confidence_count += 1
                return

            # 只靠名字（泛化关键词）命中的不进表——关键词是最弱的一维，
            # 靠它筛会满屏都是"Downloaded Installations"这种正常目录。
            if (analysis.risk_without_name < REPORT_THRESHOLD
                    and not analysis.has_strong_name_hit):
                self.low_confidence_count += 1
                return

            self.results.append(self._to_entry(analysis, kind, label))
        except Exception as e:  # noqa: BLE001
            logging.debug(f"分析 {path} 失败: {e}")

    def _is_structurally_suspicious(self, path: str) -> bool:
        """白名单命中时，仍然检查有没有硬伤（签名无效 / 加壳 / 可疑 API）。"""
        try:
            sig = self.analyzer._verify_cached(path) if os.path.isfile(path) else {}
            if sig.get("status") in ("invalid", "untrusted"):
                return True
        except Exception:
            pass
        return False

    @staticmethod
    def _to_entry(analysis, kind: str, label: str) -> Dict:
        data = analysis.to_dict()
        data.update({
            "type": f"可疑{analysis.kind}" if kind == "目录" else "可疑可执行文件",
            "path": analysis.path,
            "name": analysis.name,
            "risk": analysis.risk,
            "level": analysis.level,
            "reason": analysis.summary,
            "dimensions": analysis.dimensions,
            "signals": analysis.signals if isinstance(analysis.signals, list)
            else [s.to_dict() for s in analysis.signals],
            "detail": analysis.detail_text(),
            "selected": False,
        })
        return data

    # -- 兼容旧的关键词评估接口 -------------------------------------------

    def _is_trusted(self, text: str) -> bool:
        """白名单判定：命中可信品牌即整体忽略。"""
        return bool(self.analyzer.is_trusted_brand(text))

    def _evaluate_name(self, text: str):
        """按名称评估风险等级，返回 ``(risk_score, reason)``。

        保留这个接口是为了兼容旧的检查脚本；真正的判定请走
        :meth:`MalwareAnalyzer.analyze_executable` / ``analyze_directory``。
        """
        if not text:
            return 0, ""
        lower = text.lower()
        for brand in self.trusted_brands:
            if brand and brand in lower:
                return 0, ""

        strong_hits = [kw for kw in self.strong_keywords if kw in lower]
        weak_hits = [kw for kw in self.weak_keywords if kw in lower]

        rogue_hit = ""
        for pattern in self.known_rogue_patterns:
            pat = pattern.strip("*").lower()
            if pat and pat in lower:
                rogue_hit = pattern.strip("*")
                break

        if not strong_hits and not weak_hits and not rogue_hit:
            return 0, ""

        score = 0
        reasons = []
        if rogue_hit:
            score = 3
            reasons.append(f"匹配已知流氓软件特征: {rogue_hit}")
        if strong_hits:
            score = max(score, 3 if len(strong_hits) >= 2 else 2)
            reasons.append(f"命中高危特征: {', '.join(strong_hits[:5])}")
        if weak_hits:
            if len(weak_hits) >= 3:
                score = max(score, 3)
            elif len(weak_hits) == 2:
                score = max(score, 2)
            elif score == 0:
                score = 1
            reasons.append(f"命中泛化关键词: {', '.join(weak_hits[:5])}")

        if score == 0:
            return 0, ""
        if score == 1:
            reason = reasons[0] + "（仅提示，请人工确认）"
        else:
            reason = "；".join(reasons[:3])
        return score, reason


def is_reparse(path: str) -> bool:
    """目录是否是符号链接 / 目录联接（避免跟随到别处）。"""
    from .utils import is_reparse_point
    return is_reparse_point(path)
