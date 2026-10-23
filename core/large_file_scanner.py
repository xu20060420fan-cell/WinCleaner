"""大文件扫描模块。"""
import os
import logging
from typing import List, Callable
from .utils import format_size, is_system_critical, detect_file_type


class LargeFileScanner:
    """扫描指定目录下的大文件。"""

    def __init__(self, progress_callback: Callable = None):
        self.results = []
        self.progress_callback = progress_callback
        self.stop_flag = False

    def stop(self):
        self.stop_flag = True

    def reset(self):
        self.results.clear()
        self.stop_flag = False

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    def scan(self, root_paths: List[str], min_size_mb: int = 100,
             max_depth: int = 5) -> List[dict]:
        """扫描指定路径下超过 min_size_mb 的文件。"""
        self.reset()
        min_bytes = min_size_mb * 1024 * 1024
        total_roots = len(root_paths)
        for ridx, root in enumerate(root_paths):
            if self.stop_flag:
                break
            if not os.path.isdir(root):
                continue
            self._report(f"正在扫描: {root}", int(ridx / total_roots * 100))
            self._scan_directory(root, min_bytes, max_depth, current_depth=0)
        self.results.sort(key=lambda x: x["size"], reverse=True)
        self._report("扫描完成", 100)
        return self.results

    def _scan_directory(self, root: str, min_bytes: int, max_depth: int, current_depth: int):
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
                        self._scan_directory(entry.path, min_bytes, max_depth, current_depth + 1)
                    elif entry.is_file(follow_symlinks=False):
                        st = entry.stat(follow_symlinks=False)
                        if st.st_size >= min_bytes:
                            self.results.append({
                                "path": entry.path,
                                "dir": os.path.dirname(entry.path),
                                "size": st.st_size,
                                "size_text": format_size(st.st_size),
                                "mtime": st.st_mtime,
                                "file_type": detect_file_type(entry.path),
                            })
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError) as e:
            logging.warning(f"扫描目录失败 {root}: {e}")
