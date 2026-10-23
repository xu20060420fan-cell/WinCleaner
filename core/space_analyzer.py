"""磁盘空间分析。

清理工具最难回答的问题是"我的空间到底被谁吃了"。本模块扫描一棵目录树，
统计每个节点的体积并给出**用途分类**，供矩形树图（treemap）可视化。

设计要点
--------
* **一次遍历建树，事后汇总体积**：不在遍历时往每个祖先累加，
  否则深目录会出现 O(深度²) 的开销。
* **跳过重解析点**（junction / 符号链接）：否则 ``AppData\\Local\\Application Data``
  这类自引用会让扫描永远跑不完。
* **分级扫描**：``深度=2`` 几秒出结果（概览），``深度=6`` 才做完整体检。
* 权限不足、文件被占用都只跳过、不中断。
"""
import os
import time
from typing import Dict, List, Optional

from .utils import (
    get_appdata_local,
    get_appdata_roaming,
    get_user_profile,
    is_reparse_point,
    normalize_path,
)

# ---------------------------------------------------------------------------
# 用途分类
# ---------------------------------------------------------------------------

CAT_SYSTEM = "系统"
CAT_PROGRAM = "程序"
CAT_USERDATA = "用户数据"
CAT_CACHE = "缓存"
CAT_MEDIA = "影音"
CAT_DOCUMENT = "文档"
CAT_ARCHIVE = "压缩包"
CAT_OTHER = "其他"

CATEGORY_COLORS = {
    CAT_SYSTEM: "#64748b",
    CAT_PROGRAM: "#3b82f6",
    CAT_USERDATA: "#10b981",
    CAT_CACHE: "#f59e0b",
    CAT_MEDIA: "#8b5cf6",
    CAT_DOCUMENT: "#0ea5e9",
    CAT_ARCHIVE: "#ec4899",
    CAT_OTHER: "#94a3b8",
}

CATEGORY_ORDER = [CAT_SYSTEM, CAT_PROGRAM, CAT_USERDATA, CAT_CACHE,
                  CAT_MEDIA, CAT_DOCUMENT, CAT_ARCHIVE, CAT_OTHER]

#: 扩展名 → 分类
_EXT_CATEGORY = {
    ".mp4": CAT_MEDIA, ".mkv": CAT_MEDIA, ".avi": CAT_MEDIA, ".mov": CAT_MEDIA,
    ".wmv": CAT_MEDIA, ".flv": CAT_MEDIA, ".rmvb": CAT_MEDIA, ".m4v": CAT_MEDIA,
    ".ts": CAT_MEDIA, ".webm": CAT_MEDIA,
    ".mp3": CAT_MEDIA, ".wav": CAT_MEDIA, ".flac": CAT_MEDIA, ".aac": CAT_MEDIA,
    ".ogg": CAT_MEDIA, ".m4a": CAT_MEDIA, ".wma": CAT_MEDIA,
    ".jpg": CAT_MEDIA, ".jpeg": CAT_MEDIA, ".png": CAT_MEDIA, ".gif": CAT_MEDIA,
    ".bmp": CAT_MEDIA, ".webp": CAT_MEDIA, ".heic": CAT_MEDIA, ".raw": CAT_MEDIA,
    ".doc": CAT_DOCUMENT, ".docx": CAT_DOCUMENT, ".xls": CAT_DOCUMENT,
    ".xlsx": CAT_DOCUMENT, ".ppt": CAT_DOCUMENT, ".pptx": CAT_DOCUMENT,
    ".pdf": CAT_DOCUMENT, ".txt": CAT_DOCUMENT, ".rtf": CAT_DOCUMENT,
    ".csv": CAT_DOCUMENT, ".md": CAT_DOCUMENT, ".epub": CAT_DOCUMENT,
    ".zip": CAT_ARCHIVE, ".rar": CAT_ARCHIVE, ".7z": CAT_ARCHIVE,
    ".tar": CAT_ARCHIVE, ".gz": CAT_ARCHIVE, ".bz2": CAT_ARCHIVE,
    ".xz": CAT_ARCHIVE, ".iso": CAT_ARCHIVE,
}

#: 路径关键字 → 分类（按子串匹配，命中即定分类）
#: 顺序很重要：越"具体"的规则越靠前，否则 AppData\Local\Temp 会把
#: 嵌在它下面的 Program Files 抢走。
_PATH_CATEGORY_RULES = (
    ("\\windows\\installer", CAT_SYSTEM),
    ("\\windows\\winsxs", CAT_SYSTEM),
    ("\\windows\\servicing", CAT_SYSTEM),
    ("\\windows\\system32", CAT_SYSTEM),
    ("\\program files (x86)", CAT_PROGRAM),
    ("\\program files", CAT_PROGRAM),
    ("\\programdata", CAT_PROGRAM),
    ("\\appdata\\local\\pip\\cache", CAT_CACHE),
    ("\\appdata\\local\\npm-cache", CAT_CACHE),
    ("\\appdata\\local\\node-gyp", CAT_CACHE),
    ("\\appdata\\local\\temp", CAT_CACHE),
    ("\\appdata\\local\\packages", CAT_USERDATA),
    ("\\appdata\\roaming", CAT_USERDATA),
    ("\\appdata\\local", CAT_USERDATA),
)

#: 目录**本身**的名字像缓存时才算缓存
#: （不能只按路径包含 "\temp" 判断——那会把 Temp 目录下的所有东西
#:   都标成缓存，包括用户的视频和文档）
_CACHE_DIR_NAMES = {
    "cache", "caches", "cache2", "cache_data", "cachedata", "code cache",
    "gpucache", "shadercache", "shader cache", "webcache", "downloadcache",
    "download cache", "temp", "tmp", "logs", "log", "crashpad", "crash dumps",
    "crashdumps", "dumps", "thumbcache", "inetcache", "inetsvc",
    "d3dscache", "fontconfig\\cache", "pip\\cache", "npm-cache",
}

#: 目录**本身**的名字像用户数据时
_USER_DIR_NAMES = {
    "documents", "desktop", "pictures", "videos", "music", "downloads",
    "download", "profile", "profiles", "roaming", "local", "packages",
    "user data", "userdata",
}


class SpaceNode:
    """目录树中的一个节点。"""

    __slots__ = ("path", "name", "is_file", "size", "children", "parent",
                 "category", "file_count", "mtime")

    def __init__(self, path: str, name: str, is_file: bool = False,
                 parent: Optional["SpaceNode"] = None):
        self.path = path
        self.name = name
        self.is_file = is_file
        self.size = 0
        self.children: List["SpaceNode"] = []
        self.parent = parent
        self.category = CAT_OTHER
        self.file_count = 0
        self.mtime = 0.0

    @property
    def is_dir(self) -> bool:
        return not self.is_file

    def add_child(self, child: "SpaceNode"):
        child.parent = self
        self.children.append(child)

    def total_size(self) -> int:
        """含子目录的总体积。"""
        if self.is_file:
            return self.size
        return sum(c.total_size() for c in self.children)

    def walk(self):
        """深度优先遍历自身及所有后代。"""
        yield self
        for child in self.children:
            yield from child.walk()

    def largest_children(self, limit: int = 40) -> List["SpaceNode"]:
        """按体积降序的前 N 个子节点。"""
        kids = [c for c in self.children if c.total_size() > 0]
        kids.sort(key=lambda c: c.total_size(), reverse=True)
        return kids[:limit]

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "name": self.name,
            "is_file": self.is_file,
            "size": self.size,
            "category": self.category,
            "file_count": self.file_count,
            "children": [c.to_dict() for c in self.children],
        }


class SpaceAnalyzer:
    """目录树体积扫描器。"""

    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self.stop_flag = False
        self.scanned_files = 0
        self.skipped = 0

    def stop(self):
        self.stop_flag = True

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    # -- 扫描 -------------------------------------------------------------

    def scan(self, root: str, max_depth: int = 4, min_file_size: int = 0,
             follow_reparse: bool = False) -> SpaceNode:
        """扫描 ``root`` 目录树，返回根节点。"""
        self.stop_flag = False
        self.scanned_files = 0
        self.skipped = 0
        root_path = os.path.abspath(root)
        root_node = SpaceNode(root_path, os.path.basename(root_path.rstrip("\\")) or root_path)
        if not os.path.isdir(root_path):
            return root_node

        self._report(f"正在扫描: {root_path}", 0)
        # 用栈做深度优先，栈里放 (目录路径, 父节点, 当前深度)
        stack = [(root_path, root_node, 0)]
        while stack:
            if self.stop_flag:
                break
            current, parent, depth = stack.pop()
            try:
                entries = list(os.scandir(current))
            except (OSError, PermissionError):
                self.skipped += 1
                continue
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        if not follow_reparse and is_reparse_point(entry.path):
                            continue
                        child = SpaceNode(entry.path, entry.name, False, parent)
                        parent.add_child(child)
                        if depth + 1 < max_depth:
                            stack.append((entry.path, child, depth + 1))
                    elif entry.is_file(follow_symlinks=False):
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        if st.st_size < min_file_size:
                            continue
                        child = SpaceNode(entry.path, entry.name, True, parent)
                        child.size = st.st_size
                        child.mtime = st.st_mtime
                        parent.add_child(child)
                        self.scanned_files += 1
                except (OSError, PermissionError):
                    continue

        self._summarize(root_node)
        self._report("扫描完成", 100)
        return root_node

    def _summarize(self, node: SpaceNode):
        """自底向上汇总体积、文件数并判定分类。"""
        for child in node.children:
            if child.is_dir:
                self._summarize(child)
        if node.is_file:
            node.category = _EXT_CATEGORY.get(
                os.path.splitext(node.name)[1].lower(), CAT_OTHER)
            node.file_count = 1
            return

        total = 0
        count = 0
        category_size: Dict[str, int] = {}
        for child in node.children:
            if child.is_dir:
                total += child.size
                count += child.file_count
                category_size[child.category] = category_size.get(child.category, 0) + child.size
            else:
                total += child.size
                count += 1
                category_size[child.category] = category_size.get(child.category, 0) + child.size
        node.size = total
        node.file_count = count
        node.category = classify_path(node.path, category_size, total)

    # -- 便捷统计 ---------------------------------------------------------

    @staticmethod
    def category_breakdown(node: SpaceNode) -> List[Dict]:
        """按用途分类汇总当前节点的子目录。"""
        out = []
        for child in node.largest_children(200):
            out.append({
                "name": child.name,
                "path": child.path,
                "size": child.total_size(),
                "category": child.category,
                "is_dir": child.is_dir,
                "file_count": child.file_count,
            })
        out.sort(key=lambda x: x["size"], reverse=True)
        return out


def classify_path(path: str, category_size: Optional[Dict[str, int]] = None,
                  total: int = 0) -> str:
    """判定一个目录的用途分类。

    优先级：
    1. 目录**自身**的名字（cache/temp/logs → 缓存；documents/desktop → 用户数据）
    2. 已知系统位置（Windows、Program Files、AppData…）
    3. 目录里**占比最大**的文件类型
    """
    normalized = os.path.normpath(path)
    base = os.path.basename(normalized).lower()
    parent = os.path.basename(os.path.dirname(normalized)).lower()

    if base in _CACHE_DIR_NAMES or f"{parent}\\{base}" in _CACHE_DIR_NAMES:
        return CAT_CACHE
    if base in _USER_DIR_NAMES:
        return CAT_USERDATA

    lower = os.path.normcase(normalized)
    for keyword, category in _PATH_CATEGORY_RULES:
        if keyword in lower:
            return category

    if category_size and total > 0:
        best = max(category_size.items(), key=lambda kv: kv[1])
        if best[1] / total > 0.5:
            return best[0]
    return CAT_OTHER


def scan_roots() -> List[str]:
    """可分析的根目录列表。"""
    out = []
    for letter in "CDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if os.path.isdir(root):
            out.append(root)
    return out


def quick_profile() -> List[Dict]:
    """用户目录的快速占用画像（深度 2，几秒出结果）。"""
    analyzer = SpaceAnalyzer()
    results = []
    roots = [
        ("用户目录", get_user_profile()),
        ("本地应用数据", get_appdata_local()),
        ("漫游应用数据", get_appdata_roaming()),
    ]
    for label, path in roots:
        if not os.path.isdir(path):
            continue
        node = analyzer.scan(path, max_depth=2)
        results.append({
            "label": label,
            "path": path,
            "size": node.total_size(),
            "children": SpaceAnalyzer.category_breakdown(node)[:20],
        })
    return results
