"""重复文件扫描模块。"""
import os
import logging
from collections import defaultdict
from typing import List, Callable
from .utils import format_size, file_hash, is_system_critical, detect_file_type


class DupFileScanner:
    """按文件内容哈希扫描重复文件。"""

    def __init__(self, progress_callback: Callable = None):
        self.groups = []
        self.progress_callback = progress_callback
        self.stop_flag = False

    def stop(self):
        self.stop_flag = True

    def reset(self):
        self.groups.clear()
        self.stop_flag = False

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    def scan(self, root_paths: List[str], min_size_mb: int = 1,
             max_depth: int = 5) -> List[List[dict]]:
        """扫描重复文件，返回分组列表。"""
        self.reset()
        min_bytes = min_size_mb * 1024 * 1024

        # 第一阶段：按大小分组
        size_map = defaultdict(list)
        for root in root_paths:
            if self.stop_flag:
                break
            self._collect_by_size(root, min_bytes, max_depth, size_map)

        # 第二阶段：对相同大小的文件计算哈希
        size_items = list(size_map.items())
        total = max(1, len(size_items))
        hash_map = defaultdict(list)
        for idx, (size, files) in enumerate(size_items):
            if self.stop_flag:
                break
            if len(files) < 2:
                continue
            self._report(f"正在比对: {len(files)} 个大小相同的文件", int(idx / total * 100))
            for path, mtime in files:
                if self.stop_flag:
                    break
                h = file_hash(path)
                if h:
                    hash_map[(size, h)].append((path, mtime))

        # 第三阶段：整理结果
        for (size, h), files in hash_map.items():
            if len(files) < 2:
                continue
            group = []
            for path, mtime in files:
                group.append({
                    "path": path,
                    "size": size,
                    "size_text": format_size(size),
                    "hash": h,
                    "mtime": mtime,
                    "file_type": detect_file_type(path),
                })
            self.groups.append(group)

        # 按组释放空间排序
        self.groups.sort(key=lambda g: len(g) * g[0]["size"], reverse=True)
        self._report("扫描完成", 100)
        return self.groups

    def _collect_by_size(self, root: str, min_bytes: int, max_depth: int,
                         size_map: dict, current_depth: int = 0):
        if self.stop_flag:
            return
        if current_depth > max_depth:
            return
        if is_system_critical(root):
            return
        try:
            for entry in os.scandir(root):
                if self.stop_flag:
                    return
                try:
                    if entry.is_symlink():
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        self._collect_by_size(entry.path, min_bytes, max_depth, size_map, current_depth + 1)
                    elif entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        if st.st_size >= min_bytes:
                            size_map[st.st_size].append((entry.path, st.st_mtime))
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError) as e:
            logging.warning(f"扫描目录失败 {root}: {e}")
