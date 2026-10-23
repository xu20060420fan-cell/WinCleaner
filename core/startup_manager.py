"""启动项管理模块。

旧版"禁用"的实现是直接 ``winreg.DeleteValue()``：删掉即永久消失，
没有任何备份、没有恢复入口，``enable()`` 也只支持启动文件夹。

新版的禁用是 **可逆** 的：

* 注册表启动项的原值会被备份到 ``HKCU\\Software\\WinCleaner\\DisabledStartup``，
  然后从原位置移除；"启用"时从备份原样写回。
* 启动文件夹条目通过改名加 ``.disabled`` 后缀实现，同样可一键还原。
* 系统关键启动项会被标记为"系统项"，界面上不允许禁用。
"""
import json
import logging
import os
import winreg
from datetime import datetime
from pathlib import Path
from typing import Dict, List

#: 备份存储位置
BACKUP_KEY = r"Software\WinCleaner\DisabledStartup"

#: 系统关键启动项：这些项禁用可能影响系统功能，界面上只提示不提供禁用
SYSTEM_STARTUP_NAMES = {
    "securityhealth", "securityhealthsystray", "systray", "sysmain",
    "rtkauduservice", "one drive", "onedrive", "onedriveupdater",
    "windowsdefender", "windowsupdate", "cryptsvc", "wudfusr",
    "wsearch", "searchindexer", "audiodg", "backgroundintelligence",
    "microsoftonedrive", "msteams", "update", "usoclient",
}


class StartupManager:
    """读取和管理 Windows 启动项。"""

    def __init__(self):
        self.items: List[Dict] = []

    # -- 枚举 -------------------------------------------------------------

    def enumerate(self) -> List[Dict]:
        """枚举所有启动项（含已禁用项）。"""
        self.items.clear()
        self._enum_registry(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU")
        self._enum_registry(winreg.HKEY_LOCAL_MACHINE,
                            r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM")
        self._enum_registry(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU")
        self._enum_registry(winreg.HKEY_LOCAL_MACHINE,
                            r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM")
        self._enum_startup_folders()
        self._mark_disabled_registry_items()
        return self.items

    def _enum_registry(self, hive, key_path: str, hive_name: str):
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        index += 1
                    except OSError:
                        break
                    self.items.append({
                        "type": "注册表",
                        "hive": hive_name,
                        "key": key_path,
                        "name": str(name),
                        "command": str(value),
                        "enabled": True,
                        "is_system": str(name).strip().lower() in SYSTEM_STARTUP_NAMES,
                        "backup_name": self._backup_name(hive_name, key_path, str(name)),
                    })
        except (FileNotFoundError, PermissionError, OSError):
            pass

    def _enum_startup_folders(self):
        folders = [
            (os.environ.get("APPDATA", ""), "用户启动文件夹"),
            (os.environ.get("PROGRAMDATA", ""), "公共启动文件夹"),
        ]
        for base, label in folders:
            if not base:
                continue
            folder = os.path.join(base, "Microsoft", "Windows", "Start Menu",
                                  "Programs", "Startup")
            if not os.path.isdir(folder):
                continue
            try:
                for entry in os.scandir(folder):
                    if not entry.is_file():
                        continue
                    lower = entry.name.lower()
                    if lower.endswith(".disabled"):
                        original = entry.name[:-len(".disabled")]
                        self.items.append({
                            "type": "启动文件夹",
                            "hive": "",
                            "key": folder,
                            "name": original,
                            "command": entry.path[:-len(".disabled")],
                            "enabled": False,
                            "is_system": False,
                            "backup_name": "",
                        })
                    elif lower.endswith((".lnk", ".exe", ".bat", ".cmd")):
                        self.items.append({
                            "type": "启动文件夹",
                            "hive": "",
                            "key": folder,
                            "name": entry.name,
                            "command": entry.path,
                            "enabled": True,
                            "is_system": False,
                            "backup_name": "",
                        })
            except (OSError, PermissionError):
                pass

    def _mark_disabled_registry_items(self):
        """把已备份但未恢复的注册表启动项补进列表，状态为"已禁用"。"""
        backups = self._list_backups()
        if not backups:
            return
        known = {(i["hive"], i["key"], i["name"]) for i in self.items
                 if i["type"] == "注册表"}
        for (hive, key_path, name), value in backups.items():
            if (hive, key_path, name) in known:
                continue
            self.items.append({
                "type": "注册表",
                "hive": hive,
                "key": key_path,
                "name": name,
                "command": value,
                "enabled": False,
                "is_system": name.strip().lower() in SYSTEM_STARTUP_NAMES,
                "backup_name": self._backup_name(hive, key_path, name),
            })

    # -- 备份存储 ---------------------------------------------------------

    @staticmethod
    def _backup_name(hive: str, key_path: str, value_name: str) -> str:
        return f"{hive}|{key_path}|{value_name}"

    def _list_backups(self) -> Dict:
        """读取全部备份：``{(hive, key, name): value}``。"""
        out = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, BACKUP_KEY, 0,
                                winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        index += 1
                    except OSError:
                        break
                    parts = str(name).split("|", 2)
                    if len(parts) == 3:
                        out[(parts[0], parts[1], parts[2])] = str(value)
        except (FileNotFoundError, PermissionError, OSError):
            pass
        return out

    def _write_backup(self, backup_name: str, value: str):
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, BACKUP_KEY, 0,
                                winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, backup_name, 0, winreg.REG_SZ, value)

    def _delete_backup(self, backup_name: str):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, BACKUP_KEY, 0,
                                winreg.KEY_WRITE) as key:
                winreg.DeleteValue(key, backup_name)
        except (FileNotFoundError, OSError):
            pass

    # -- 启用 / 禁用 ------------------------------------------------------

    def disable(self, item: Dict) -> bool:
        """禁用启动项（可恢复）。"""
        try:
            if item.get("is_system"):
                logging.warning(f"拒绝禁用系统启动项: {item.get('name')}")
                return False
            if item["type"] == "注册表":
                hive = (winreg.HKEY_CURRENT_USER if item["hive"] == "HKCU"
                        else winreg.HKEY_LOCAL_MACHINE)
                with winreg.OpenKey(hive, item["key"], 0, winreg.KEY_READ) as key:
                    value, _ = winreg.QueryValueEx(key, item["name"])
                # 先备份再删除，保证一定能恢复
                self._write_backup(item["backup_name"], str(value))
                try:
                    with winreg.OpenKey(hive, item["key"], 0, winreg.KEY_WRITE) as key:
                        winreg.DeleteValue(key, item["name"])
                except Exception:
                    # 删除失败就把备份撤掉，避免出现"两边都没有"的死档
                    self._delete_backup(item["backup_name"])
                    raise
                return True
            if item["type"] == "启动文件夹":
                src = item["command"]
                dst = src + ".disabled"
                if os.path.exists(dst):
                    os.unlink(dst)
                os.rename(src, dst)
                return True
        except Exception as e:
            logging.error(f"禁用启动项失败: {e}")
            return False
        return False

    def enable(self, item: Dict) -> bool:
        """启用（恢复）启动项。"""
        try:
            if item["type"] == "注册表":
                hive = (winreg.HKEY_CURRENT_USER if item["hive"] == "HKCU"
                        else winreg.HKEY_LOCAL_MACHINE)
                backups = self._list_backups()
                value = backups.get((item["hive"], item["key"], item["name"]))
                if value is None:
                    return False
                with winreg.CreateKeyEx(hive, item["key"], 0, winreg.KEY_WRITE) as key:
                    winreg.SetValueEx(key, item["name"], 0, winreg.REG_SZ, value)
                self._delete_backup(item["backup_name"])
                return True
            if item["type"] == "启动文件夹":
                src = item["command"] + ".disabled"
                dst = item["command"]
                if not os.path.exists(src):
                    return False
                os.rename(src, dst)
                return True
        except Exception as e:
            logging.error(f"启用启动项失败: {e}")
            return False
        return False

    # -- 备份导出 ---------------------------------------------------------

    def export_backup(self, path: str = "") -> str:
        """把已禁用的启动项导出为 JSON，便于事后人工恢复。"""
        backups = self._list_backups()
        if not path:
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            path = str(Path(__file__).resolve().parent.parent
                       / "logs" / f"startup_backup-{stamp}.json")
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            payload = [
                {"hive": h, "key": k, "name": n, "value": v}
                for (h, k, n), v in backups.items()
            ]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            return path
        except Exception as e:
            logging.error(f"导出启动项备份失败: {e}")
            return ""
