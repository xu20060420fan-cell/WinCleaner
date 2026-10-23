"""清理历史与系统还原点。

两件事：

1. **清理历史**——每次清理都留一条记录（时间、类别、项数、体积、明细），
   写进 ``%APPDATA%\\WinCleaner\\history.json``。之前"删了什么完全不可追溯"
   的问题，就是因为成功项不写日志。
2. **系统还原点**——清理前可以先建一个还原点（需要管理员权限），
   万一删错还能整体回退。这是"可逆"承诺的最后一层保险。
"""
import ctypes
import json
import logging
import os
from ctypes import wintypes
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .utils import get_log_dir

_HISTORY_FILE = "history.json"
_MAX_RECORDS = 200


def _history_path() -> Path:
    return get_log_dir().parent / _HISTORY_FILE


def load_history() -> List[Dict]:
    """读取清理历史（按时间倒序）。"""
    path = _history_path()
    if not path.exists():
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        logging.warning(f"读取清理历史失败: {e}")
        return []


def save_history(records: List[Dict]) -> bool:
    path = _history_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records[:_MAX_RECORDS], f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logging.warning(f"保存清理历史失败: {e}")
        return False


def add_record(record: Dict) -> bool:
    """追加一条清理记录。"""
    record = dict(record)
    record.setdefault("ts", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    records = load_history()
    records.insert(0, record)
    return save_history(records)


def clear_history() -> bool:
    return save_history([])


def summarize(records: List[Dict]) -> Dict:
    """汇总历史：总次数、总释放量、按类别统计。"""
    by_category: Dict[str, Dict] = {}
    total_size = 0
    total_count = 0
    for rec in records:
        cat = rec.get("category", "未分类")
        size = int(rec.get("saved", 0) or 0)
        count = int(rec.get("deleted", 0) or 0)
        total_size += size
        total_count += count
        item = by_category.setdefault(cat, {"size": 0, "count": 0, "times": 0})
        item["size"] += size
        item["count"] += count
        item["times"] += 1
    return {
        "times": len(records),
        "total_size": total_size,
        "total_count": total_count,
        "by_category": by_category,
    }


# ---------------------------------------------------------------------------
# 系统还原点
# ---------------------------------------------------------------------------

_SRP_EVENT_BEGIN_SYSTEM_CHECKPOINT = 0x0000000C
_SRP_TYPE_MANUAL = 12
_SRP_TYPE_APPLICATION_INSTALL = 0


class _RESTOREPOINTINFOW(ctypes.Structure):
    _fields_ = [
        ("dwEventType", wintypes.DWORD),
        ("dwRestorePointType", wintypes.DWORD),
        ("szDescription", wintypes.WCHAR * 260),
        ("dwCreationFlags", wintypes.DWORD),
    ]


def create_restore_point(description: str = "WinCleaner 清理前快照",
                         system_restore: bool = True) -> Dict:
    """创建一个系统还原点。

    返回 ``{"ok": bool, "message": str}``。需要管理员权限；
    失败不会阻断清理流程（只是少一层保险）。
    """
    result = {"ok": False, "message": ""}
    try:
        srclient = ctypes.WinDLL("srclient")
    except OSError as e:
        result["message"] = f"系统还原服务不可用: {e}"
        return result
    try:
        srclient.SRSetRestorePointW.argtypes = [
            ctypes.POINTER(_RESTOREPOINTINFOW), ctypes.c_void_p]
        srclient.SRSetRestorePointW.restype = wintypes.BOOL
    except Exception as e:
        result["message"] = f"调用系统还原接口失败: {e}"
        return result

    info = _RESTOREPOINTINFOW()
    info.dwEventType = _SRP_EVENT_BEGIN_SYSTEM_CHECKPOINT
    info.dwRestorePointType = (_SRP_TYPE_MANUAL if system_restore
                               else _SRP_TYPE_APPLICATION_INSTALL)
    info.szDescription = description[:259]
    info.dwCreationFlags = 0

    try:
        ok = srclient.SRSetRestorePointW(ctypes.byref(info), None)
    except Exception as e:
        result["message"] = f"创建还原点异常: {e}"
        return result

    if ok:
        result["ok"] = True
        result["message"] = f"已创建系统还原点：{description}"
    else:
        code = ctypes.GetLastError()
        result["message"] = (f"创建还原点失败（错误码 {code}）。"
                             "系统还原服务可能被禁用，或当前不是管理员。")
    return result


def list_restore_points() -> List[Dict]:
    """列出最近的系统还原点（PowerShell 查询，较慢，仅供查看）。"""
    import subprocess
    out = []
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             "Get-ComputerRestorePoint | Sort-Object CreationTime -Descending | "
             "Select-Object -First 10 SequenceNumber,Description,CreationTime "
             "| ConvertTo-Json -Compress"],
            capture_output=True, text=True, errors="ignore", timeout=60,
            creationflags=(getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                           if os.name == "nt" else 0))
        if proc.returncode != 0 or not proc.stdout.strip():
            return out
        data = json.loads(proc.stdout.strip())
        if isinstance(data, dict):
            data = [data]
        for item in data:
            out.append({
                "sequence": item.get("SequenceNumber"),
                "description": item.get("Description", ""),
                "created": item.get("CreationTime", ""),
            })
    except Exception as e:
        logging.debug(f"读取还原点失败: {e}")
    return out
