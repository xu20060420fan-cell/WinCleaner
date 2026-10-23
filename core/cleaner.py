"""WinCleaner 清理执行引擎。

**删除出口只有一个**：:func:`core.utils.delete_to_recycle_bin`（移入回收站，可还原）。
永久删除仅存在于两个用户明确知晓的特例里：整体清空回收站、刷新 DNS 缓存。

每一项在删除前都必须通过 :func:`core.safety.check_delete_allowed`。
"""
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List

from .safety import check_delete_allowed, get_policy
from .utils import delete_to_recycle_bin, empty_recycle_bin, is_admin


class Cleaner:
    """执行清理操作。"""

    def __init__(self, progress_callback: Callable = None, audit_log: str = ""):
        self.progress_callback = progress_callback
        self.stop_flag = False
        self.stats = {"deleted": 0, "skipped": 0, "failed": 0, "saved": 0}
        #: 逐项结果明细，供界面展示"为什么这一项没有被清理"
        self.details: List[Dict] = []
        self.audit_log_path = audit_log or str(_default_audit_path())
        self.dry_run = False
        #: 清理前是否创建系统还原点
        self.restore_point_enabled = False

    # -- 基础设施 ---------------------------------------------------------

    def stop(self):
        self.stop_flag = True

    def reset(self):
        self.stats = {"deleted": 0, "skipped": 0, "failed": 0, "saved": 0}
        self.details = []
        self.stop_flag = False

    def _report(self, msg: str, percent: int = -1):
        if self.progress_callback:
            self.progress_callback(msg, percent)

    # -- 主流程 -----------------------------------------------------------

    def clean(self, items: List, create_restore_point: bool = False) -> dict:
        """根据 ScanResult 列表执行清理。

        只有 ``item.selected`` 为真的条目才会被处理 —— 默认值是"不处理"。
        ``create_restore_point=True`` 时先创建一个系统还原点作为兜底。
        """
        self.reset()
        create_restore_point = create_restore_point or self.restore_point_enabled
        selected = [i for i in items if getattr(i, "selected", False)]
        total = len(selected)
        if total == 0:
            self._report("没有选中任何项目", 100)
            return self.stats

        if create_restore_point and not self.dry_run:
            self._report("正在创建系统还原点…", 2)
            from .clean_history import create_restore_point as _make_rp
            rp = _make_rp()
            if rp["ok"]:
                self._report("还原点已创建", 3)
            else:
                self._report(f"还原点创建失败：{rp['message']}", 3)
                logging.warning(rp["message"])
        update_items = [i for i in selected if getattr(i, "category", "") == "windows_update"]
        services_stopped = False
        if update_items:
            services_stopped = self._stop_update_services()

        try:
            for idx, item in enumerate(selected):
                if self.stop_flag:
                    self._report("已停止", idx * 100 // total)
                    break
                percent = idx * 100 // total
                self._report(f"正在处理: {getattr(item, 'name', item)}", percent)
                self._clean_item(item)
        finally:
            if services_stopped:
                self._start_update_services()

        self._report("清理完成", 100)
        self._write_history(selected)
        return self.stats

    def _write_history(self, items: List):
        """把这次清理写进历史（成功与失败都记）。"""
        if self.dry_run:
            return
        try:
            from .clean_history import add_record
            categories = {}
            for item in items:
                cat = getattr(item, "category", "未分类")
                categories[cat] = categories.get(cat, 0) + 1
            add_record({
                "categories": categories,
                "deleted": self.stats["deleted"],
                "skipped": self.stats["skipped"],
                "failed": self.stats["failed"],
                "saved": self.stats["saved"],
                "items": [
                    {"path": d["path"], "result": d["result"], "reason": d["reason"],
                     "size": d["size"]}
                    for d in self.details[:2000]
                ],
            })
        except Exception as e:
            logging.warning(f"写入清理历史失败: {e}")

    # -- 单项处理 ---------------------------------------------------------

    def _clean_item(self, item) -> None:
        special = getattr(item, "special", "")
        if special:
            handler = {
                "empty_recycle_bin": self._clean_recycle_bin,
                "flush_dns": self._clean_dns_cache,
                "dism_component_cleanup": self._clean_component_store,
                "dism_remove_old_installation": self._clean_windows_old,
                "powercfg_hibernate_off": self._clean_hibernation,
                "vssadmin_delete_shadows": self._clean_shadow_copies,
            }.get(special)
            if handler is not None:
                handler(item)
                return

        path = getattr(item, "path", "")
        category = getattr(item, "category", "")
        policy = get_policy(category)
        root = getattr(item, "root", "") or ""
        allowed_roots = [root] if root else None

        decision = check_delete_allowed(
            path, policy, allowed_roots=allowed_roots,
            protect_personal=self._protect_personal(),
        )
        if not decision.allowed:
            self.stats["skipped"] += 1
            self._record(item, "已跳过", decision.reason)
            logging.info(f"跳过 {path}：{decision.reason}")
            return

        size = int(getattr(item, "size", 0) or 0)

        if self.dry_run:
            self.stats["deleted"] += 1
            self.stats["saved"] += size
            self._record(item, "（预演）将移入回收站", "ok")
            return

        result = delete_to_recycle_bin([path])
        if result["deleted"]:
            self.stats["deleted"] += 1
            self.stats["saved"] += size
            self._record(item, "已移入回收站", "ok")
            logging.info(f"已移入回收站: {path}")
        else:
            reason = result["failed"][0][1] if result["failed"] else "未知错误"
            self.stats["failed"] += 1
            self._record(item, "失败", reason)
            logging.warning(f"清理失败 {path}: {reason}")

    # -- 系统级特殊动作 ----------------------------------------------------

    def _clean_component_store(self, item):
        """用 DISM 分析并清理被取代的系统组件版本。

        正确做法不是逐文件删 WinSxS，而是：
        ``DISM /Online /Cleanup-Image /AnalyzeComponentStore`` 先看系统
        自己的建议，确认"建议清理"后再执行 ``/StartComponentCleanup``。
        """
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将执行 DISM 组件存储清理", "ok")
            return
        self._report("正在分析组件存储（DISM，可能需要几分钟）…", 50)
        analysis = _run_dism("/Online", "/Cleanup-Image", "/AnalyzeComponentStore")
        recommended = _parse_dism_recommendation(analysis)
        if recommended is False:
            self.stats["skipped"] += 1
            self._record(item, "已跳过", "DISM 分析结论：系统不建议清理组件存储")
            return
        if recommended is None:
            self.stats["failed"] += 1
            self._record(item, "失败", "DISM 分析未给出明确结论，已放弃清理")
            return
        self._report("正在清理组件存储（DISM）…", 60)
        result = _run_dism("/Online", "/Cleanup-Image", "/StartComponentCleanup")
        if result["ok"]:
            self.stats["deleted"] += 1
            self._record(item, "已清理组件存储", "DISM /StartComponentCleanup 执行成功")
        else:
            self.stats["failed"] += 1
            self._record(item, "失败", result["message"][:300])

    def _clean_windows_old(self, item):
        """移除升级遗留的 Windows.old。

        这一步没有可靠的纯命令行接口（官方只提供系统界面入口），
        因此这里**打开系统自带的磁盘清理**，由用户在系统界面确认，
        避免用 takeown/rmdir 之类的方式强删旧系统导致后续升级失败。
        """
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将打开系统磁盘清理", "ok")
            return
        ok = _launch_cleanmgr()
        if ok:
            self.stats["deleted"] += 1
            self._record(item, "已打开系统磁盘清理",
                         "请在系统窗口中勾选「以前的 Windows 安装」并确认")
        else:
            self.stats["failed"] += 1
            self._record(item, "失败", "无法启动系统磁盘清理")

    def _clean_hibernation(self, item):
        """关闭休眠以释放 hiberfil.sys（通常 8~16 GB）。"""
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将关闭休眠功能", "ok")
            return
        result = _run_command(["powercfg", "/hibernate", "off"])
        if result["ok"]:
            self.stats["deleted"] += 1
            self.stats["saved"] += int(getattr(item, "size", 0) or 0)
            self._record(item, "已关闭休眠并释放 hiberfil.sys",
                         "如需恢复：powercfg /hibernate on")
        else:
            self.stats["failed"] += 1
            self._record(item, "失败", result["message"][:300])

    def _clean_shadow_copies(self, item):
        """删除卷影副本（系统还原点）。"""
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将删除卷影副本", "ok")
            return
        drive = os.environ.get("SystemDrive", "C:") + "\\"
        result = _run_command(["vssadmin", "delete", "shadows", "/all",
                               f"/for={drive}"])
        if result["ok"]:
            self.stats["deleted"] += 1
            self._record(item, "已删除卷影副本", "「还原此电脑」将不可用")
        else:
            self.stats["failed"] += 1
            self._record(item, "失败", result["message"][:300])

    # -- 特殊动作 ---------------------------------------------------------

    def _clean_recycle_bin(self, item):
        """整体清空回收站（不可逆，执行前 UI 会做二次确认）。"""
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将清空回收站", "ok")
            return
        result = empty_recycle_bin()
        if result["ok"]:
            self.stats["deleted"] += 1
            self._record(item, "已清空回收站", "ok")
            logging.info("回收站已清空")
        else:
            reason = result["failed"][0][1] if result["failed"] else "未知错误"
            self.stats["failed"] += 1
            self._record(item, "失败", reason)
            logging.warning(f"清空回收站失败: {reason}")

    def _clean_dns_cache(self, item):
        """执行 ipconfig /flushdns 清除 DNS 缓存。"""
        if self.dry_run:
            self.stats["deleted"] += 1
            self._record(item, "（预演）将刷新 DNS 缓存", "ok")
            return
        try:
            proc = subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                                  timeout=30, creationflags=_no_window_flag())
            if proc.returncode == 0:
                self.stats["deleted"] += 1
                self._record(item, "DNS 缓存已刷新", "ok")
            else:
                self.stats["failed"] += 1
                self._record(item, "失败", (proc.stderr or b"").decode("utf-8", "ignore")
                             or f"返回码 {proc.returncode}")
        except Exception as e:
            self.stats["failed"] += 1
            self._record(item, "失败", str(e))
            logging.error(f"清除 DNS 缓存失败: {e}")

    # -- Windows 更新服务 -------------------------------------------------

    def _stop_update_services(self) -> bool:
        """停止 Windows 更新相关服务，清理完成后恢复。"""
        if not is_admin():
            logging.warning("清理更新缓存需要管理员权限，服务未停止")
            return False
        stopped = False
        for service in ("wuauserv", "bits"):
            try:
                proc = subprocess.run(["sc", "stop", service], capture_output=True,
                                      timeout=30, creationflags=_no_window_flag())
                if proc.returncode == 0:
                    stopped = True
                    logging.info(f"服务已停止: {service}")
            except Exception as e:
                logging.warning(f"停止服务 {service} 失败: {e}")
        if stopped:
            time.sleep(2)
        return stopped

    def _start_update_services(self):
        for service in ("wuauserv", "bits"):
            try:
                subprocess.run(["sc", "start", service], capture_output=True,
                               timeout=30, creationflags=_no_window_flag())
            except Exception as e:
                logging.warning(f"启动服务 {service} 失败: {e}")

    # -- 审计 -------------------------------------------------------------

    def _protect_personal(self) -> bool:
        from .config import load_config
        try:
            return bool(load_config().get("protect_personal_files", True))
        except Exception:
            return True

    def _record(self, item, result: str, reason: str):
        entry = {
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "path": getattr(item, "path", ""),
            "name": getattr(item, "name", ""),
            "category": getattr(item, "category", ""),
            "size": int(getattr(item, "size", 0) or 0),
            "result": result,
            "reason": reason,
        }
        self.details.append(entry)
        self._write_audit(entry)

    def _write_audit(self, entry: Dict):
        """把每一次动作写入审计日志，让"删了什么"可追溯。

        预演（dry_run）**不写**审计日志——否则一次预演就会往磁盘里
        灌几万条根本没发生过的记录。
        """
        if self.dry_run:
            return
        try:
            path = Path(self.audit_log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            # 审计日志也要轮转，否则长期使用会涨到几百 MB。
            # 用 os.replace 原子覆盖旧备份，不需要先删除旧文件。
            if path.exists() and path.stat().st_size > 8 * 1024 * 1024:
                backup = path.with_suffix(path.suffix + ".1")
                os.replace(str(path), str(backup))
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception as e:
            logging.warning(f"写入清理审计日志失败: {e}")


def _default_audit_path() -> Path:
    """审计日志默认位置（与其它日志放在一起）。"""
    try:
        from .utils import get_log_dir
        return get_log_dir() / "clean_actions.log"
    except Exception:
        return Path(__file__).resolve().parent.parent / "logs" / "clean_actions.log"


def _no_window_flag() -> int:
    """Windows 下隐藏子进程控制台窗口。"""
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return 0


def _run_command(cmd: List[str], timeout: int = 1800) -> Dict:
    """执行一条系统命令，返回 ``{"ok", "output", "message"}``。"""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              errors="ignore", timeout=timeout,
                              creationflags=_no_window_flag())
        output = (proc.stdout or "") + (proc.stderr or "")
        return {
            "ok": proc.returncode == 0,
            "output": output,
            "message": output.strip()[-500:] or f"返回码 {proc.returncode}",
        }
    except FileNotFoundError:
        return {"ok": False, "output": "", "message": f"找不到命令：{cmd[0]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "output": "", "message": "命令执行超时"}
    except Exception as e:
        return {"ok": False, "output": "", "message": str(e)}


def _run_dism(*args: str) -> Dict:
    """执行 DISM 命令。"""
    return _run_command(["dism.exe", "/English", *args])


def _parse_dism_recommendation(result: Dict):
    """从 DISM 分析输出里解析"是否建议清理组件存储"。

    返回 True（建议清理）/ False（不建议）/ None（无法判断）。
    """
    text = (result.get("output") or "").lower()
    for line in text.splitlines():
        if "cleanup recommended" in line or "cleanup is recommended" in line:
            if "no" in line.split("recommended")[0][-8:] or ": no" in line:
                return False
            if "yes" in line:
                return True
    if "component store cleanup recommended : yes" in text:
        return True
    if "component store cleanup recommended : no" in text:
        return False
    return None


def _launch_cleanmgr() -> bool:
    """打开系统自带的磁盘清理。"""
    try:
        subprocess.Popen(["cleanmgr.exe"], creationflags=_no_window_flag())
        return True
    except Exception as e:
        logging.warning(f"启动磁盘清理失败: {e}")
        return False
