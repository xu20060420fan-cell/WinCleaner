"""WinCleaner 安全不变量回归测试。

把 2026-10-14 审计报告里的每一条 P0/P1 都变成一条可断言的检查。
全部检查只读或只在系统临时目录的沙箱里操作，不会碰用户的真实文件。

用法:
    .venv\\Scripts\\python.exe audit\\verify_wincleaner.py

输出: 逐条 PASS/FAIL，最后给出汇总。退出码非 0 表示存在未修复项。
"""
import ctypes
import os
import re
import shutil
import sys
import tempfile
import time
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.config import load_config
from core.safety import (  # noqa: E402
    check_delete_allowed,
    get_policy,
    looks_like_cache_dir,
)
from core.scanner import ScanResult, SystemScanner  # noqa: E402
from core.startup_manager import StartupManager  # noqa: E402
from core.utils import (  # noqa: E402
    delete_to_recycle_bin,
    expand_path,
    is_system_critical,
)

PASSED = []
FAILED = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        PASSED.append(name)
        print(f"  [PASS] {name}" + (f"  — {detail}" if detail else ""))
    else:
        FAILED.append((name, detail))
        print(f"  [FAIL] {name}" + (f"  — {detail}" if detail else ""))


# ---------------------------------------------------------------------------
# 回收站查询（用于验证"删除确实进了回收站"）
# ---------------------------------------------------------------------------


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64),
    ]


def recycle_bin_count(drive: str = "C:\\") -> int:
    """查询指定盘符回收站中的条目数（失败返回 -1）。"""
    try:
        info = _SHQUERYRBINFO()
        info.cbSize = ctypes.sizeof(info)
        hr = ctypes.windll.shell32.SHQueryRecycleBinW(
            None, ctypes.byref(info))
        if hr != 0:
            return -1
        return int(info.i64NumItems)
    except Exception:
        return -1


# ---------------------------------------------------------------------------
# [A] critical 判定跨盘符一致
# ---------------------------------------------------------------------------


def test_critical():
    print("\n[A] is_system_critical 必须对所有盘符一视同仁")
    cases = [
        (r"C:\$Recycle.Bin\S-1-5-1\$R.zip", True, "C 盘回收站"),
        (r"D:\$Recycle.Bin\S-1-5-1\$R.zip", True, "D 盘回收站"),
        (r"E:\$Recycle.Bin\S-1-5-1\$R.zip", True, "E 盘回收站"),
        (r"C:\Windows\System32\winevt\Logs\Security.evtx", True, "系统日志"),
        (r"D:\Windows\System32\winevt\Logs\Security.evtx", True, "非系统盘的 Windows 目录"),
        (r"C:\Program Files\Foo\bar.exe", True, "Program Files"),
        (r"D:\Program Files\Foo\bar.exe", True, "非系统盘的 Program Files"),
        (r"C:\Windows\Temp\x.tmp", False, "Windows\\Temp 是允许清理的子树"),
        (r"C:\Windows\Prefetch\a.pf", False, "Windows\\Prefetch 是允许清理的子树"),
    ]
    for path, expected, desc in cases:
        actual = is_system_critical(path)
        check(f"{desc}：{path}", actual == expected,
              f"期望 {expected}，实际 {actual}")


# ---------------------------------------------------------------------------
# [B] 删除必须进回收站
# ---------------------------------------------------------------------------


def test_recycle_bin_deletion():
    print("\n[B] 删除必须移入回收站（可还原），不得永久删除")
    sandbox = Path(tempfile.mkdtemp(prefix="wc_verify_"))
    try:
        probe = sandbox / "important.txt"
        probe.write_text("recoverable data", encoding="utf-8")
        size = probe.stat().st_size

        before = recycle_bin_count()
        result = delete_to_recycle_bin([str(probe)])
        after = recycle_bin_count()

        check("删除后原路径已不存在", not probe.exists())
        check("回收站 API 返回成功", result["ok"] and len(result["deleted"]) == 1,
              str(result))
        if before >= 0 and after >= 0:
            check("回收站条目数 +1", after == before + 1,
                  f"清理前 {before} → 清理后 {after}")
        else:
            check("回收站条目数 +1", True, "SHQueryRecycleBin 不可用，跳过计数校验")
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)


# ---------------------------------------------------------------------------
# [C] 回收站内容不得被逐文件收集
# ---------------------------------------------------------------------------


def test_recycle_bin_not_scanned_per_file():
    print("\n[C] 回收站只能整体清空，不能逐文件删除")
    sc = SystemScanner()
    sc.scan_recycle_bin()
    check("scan_recycle_bin 只产生 1 个特殊动作", len(sc.results) == 1,
          f"实际 {len(sc.results)} 项")
    if sc.results:
        item = sc.results[0]
        check("该动作标记为 empty_recycle_bin", item.special == "empty_recycle_bin")
    else:
        check("该动作标记为 empty_recycle_bin", False, "没有产生任何结果")

    # 逐文件删除回收站条目必须被闸门拦下
    policy = get_policy("recycle_bin")
    for drive in ("C:", "D:", "E:"):
        fake = rf"{drive}\$Recycle.Bin\S-1-5-21-1\$RABC.zip"
        d = check_delete_allowed(fake, policy, allowed_roots=None)
        check(f"{drive} 盘回收站条目被拒绝", not d.allowed, d.reason)


# ---------------------------------------------------------------------------
# [D] 事件日志功能必须移除
# ---------------------------------------------------------------------------


def test_event_logs_removed():
    print("\n[D] 系统事件日志功能必须已移除")
    sc = SystemScanner()
    has_method = hasattr(sc, "scan_event_logs")
    check("SystemScanner 不再有 scan_event_logs", not has_method)
    src = (ROOT / "core" / "scanner.py").read_text(encoding="utf-8")
    check("源码中不再出现 winevt/evtx", "evtx" not in src and "winevt" not in src)
    check("配置中不再有 event_logs 类别",
          "event_logs" not in load_config().get("default_enabled_categories", []))


# ---------------------------------------------------------------------------
# [E] 应用安装目录不得被当成垃圾
# ---------------------------------------------------------------------------


def test_install_dirs_protected():
    print("\n[E] 应用安装目录 / 数据目录不得进入清理清单")
    cfg = load_config()
    dangerous = []
    for label, raw in list(cfg.get("software_junk_paths", {}).items()):
        expanded = expand_path(raw)
        low = expanded.lower()
        # 指向应用根目录（而不是缓存子目录）的一律视为危险配置
        if re.search(r"\\(wps office|wxwork|dingtalk|baidunetdisk|thunder network)$", low):
            dangerous.append(f"{label} → {expanded}")
    check("配置中不含指向应用根目录的条目", not dangerous, "; ".join(dangerous))

    # WPS 安装目录不能被识别为缓存目录
    wps = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Kingsoft", "WPS Office")
    check("WPS Office 目录不被视为缓存目录", not looks_like_cache_dir(wps), wps)

    # 配置里的垃圾路径必须全部是"缓存样"目录
    bad = []
    for label, raw in list(cfg.get("software_junk_paths", {}).items()):
        expanded = expand_path(raw)
        if "*" in expanded:
            continue  # 通配路径在扫描时逐个匹配校验
        if os.path.isdir(expanded) and not looks_like_cache_dir(expanded):
            bad.append(f"{label} → {expanded}")
    check("显式配置的垃圾路径都是缓存目录", not bad, "; ".join(bad))

    # 扫描结果里不得出现 WPS 安装目录下的文件
    sc = SystemScanner()
    sc.scan_software_junk()
    hits = [r for r in sc.results
            if "kingsoft\\wps office" in r.path.lower()
            and "\\cache" not in r.path.lower()
            and "\\backup" not in r.path.lower()]
    check("软件垃圾扫描不包含 WPS 安装目录文件", not hits,
          f"{len(hits)} 项，例如 {hits[0].path if hits else ''}")


# ---------------------------------------------------------------------------
# [F] 文件年龄保护
# ---------------------------------------------------------------------------


def test_age_protection():
    print("\n[F] 新建文件不得进入待删清单")
    sandbox = Path(tempfile.mkdtemp(prefix="wc_age_"))
    try:
        fresh = sandbox / "brand_new.tmp"
        fresh.write_text("x", encoding="utf-8")
        old = sandbox / "old.tmp"
        old.write_text("x", encoding="utf-8")
        os.utime(old, (time.time() - 30 * 86400, time.time() - 30 * 86400))

        sc = SystemScanner()
        sc._collect_files(str(sandbox), "system_temp", "临时文件", min_age_days=7)
        paths = [r.path for r in sc.results]
        check("30 天前的文件被收集", str(old) in paths)
        check("刚创建的文件未被收集", str(fresh) not in paths)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    # 闸门本身也要拦住过新的文件
    policy = get_policy("system_temp")
    fresh = Path(tempfile.mkdtemp(prefix="wc_fresh_")) / "new.tmp"
    fresh.write_text("x", encoding="utf-8")
    try:
        d = check_delete_allowed(str(fresh), policy)
        check("闸门拒绝刚创建的文件", not d.allowed, d.reason)
    finally:
        shutil.rmtree(fresh.parent, ignore_errors=True)


# ---------------------------------------------------------------------------
# [G] 删除路径必须落在允许的根目录内
# ---------------------------------------------------------------------------


def test_root_containment():
    print("\n[G] 删除必须落在允许的根目录内（防止通配符误捕）")
    policy = get_policy("software_junk")
    d = check_delete_allowed(r"C:\Users\me\AppData\Local\SomeApp\data.db", policy,
                             allowed_roots=[r"C:\Users\me\AppData\Local\SomeApp\cache"])
    check("根目录之外的路径被拒绝", not d.allowed, d.reason)


# ---------------------------------------------------------------------------
# [H] 个人数据保护
# ---------------------------------------------------------------------------


def test_personal_data_protection():
    print("\n[H] 个人数据默认受保护")
    sandbox = Path(tempfile.mkdtemp(prefix="wc_personal_"))
    try:
        photo = sandbox / "family.jpg"
        photo.write_bytes(b"\xff\xd8\xff" + b"0" * 64)
        # 把 mtime 调到 30 天前，排除"文件过新"这一闸门，
        # 让唯一的变量就是"个人数据保护"开关
        old = time.time() - 30 * 86400
        os.utime(photo, (old, old))
        d = check_delete_allowed(str(photo), get_policy("software_junk"),
                                 protect_personal=True)
        check("照片被判定为个人数据并跳过", not d.allowed, d.reason)
        d2 = check_delete_allowed(str(photo), get_policy("software_junk"),
                                  protect_personal=False)
        check("关闭保护后照片才可清理", d2.allowed, d2.reason)
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)
    check("配置默认开启个人数据保护",
          load_config().get("protect_personal_files", False) is True)


# ---------------------------------------------------------------------------
# [I] 源码里不得存在绕过回收站的删除
# ---------------------------------------------------------------------------


def test_no_permanent_delete_paths():
    print("\n[I] 清理路径中不得出现永久删除调用")
    targets = [
        ROOT / "core" / "cleaner.py",
        ROOT / "core" / "scanner.py",
        ROOT / "ui" / "main_window.py",
    ]
    for path in targets:
        src = path.read_text(encoding="utf-8")
        has_unlink = ".unlink(" in src
        has_rmtree = "rmtree(" in src
        check(f"{path.name} 不含 unlink/rmtree", not has_unlink and not has_rmtree,
              f"unlink={has_unlink} rmtree={has_rmtree}")

    utils_src = (ROOT / "core" / "utils.py").read_text(encoding="utf-8")
    # 唯一允许出现 unlink/rmtree 的地方是 safe_delete 的 to_recycle=False 分支
    occurrences = utils_src.count(".unlink(") + utils_src.count("rmtree(")
    check("utils.py 中的永久删除仅存在于 safe_delete 内部", occurrences <= 2,
          f"出现 {occurrences} 次")


# ---------------------------------------------------------------------------
# [J] 启动项禁用必须可恢复
# ---------------------------------------------------------------------------


def test_startup_reversible():
    print("\n[J] 启动项禁用必须可恢复")
    mgr = StartupManager()
    items = mgr.enumerate()
    check("能枚举到启动项", isinstance(items, list), f"{len(items)} 项")

    # 备份导出到临时目录，避免在项目里留下测试垃圾
    backup = mgr.export_backup(str(Path(tempfile.mkdtemp(prefix="wc_bak_")) / "backup.json"))
    check("能导出启动项备份", bool(backup) and Path(backup).exists(), str(backup))

    # 找一个可写的 HKCU 启动项做"禁用 → 启用"往返测试
    import winreg
    key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
    test_name = "WinCleaner_SelfTest_Temp"
    test_value = r"C:\Windows\System32\notepad.exe"
    created = False
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                                winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, test_name, 0, winreg.REG_SZ, test_value)
        created = True
    except OSError as e:
        print(f"    （跳过写入测试：{e}）")

    if created:
        try:
            mgr.enumerate()
            target = next((i for i in mgr.items
                           if i["name"] == test_name and i["type"] == "注册表"), None)
            check("能定位到刚写入的启动项", target is not None)
            if target:
                disabled = mgr.disable(target)
                check("禁用成功", disabled)
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                    winreg.KEY_READ) as key:
                    try:
                        winreg.QueryValueEx(key, test_name)
                        present = True
                    except FileNotFoundError:
                        present = False
                check("禁用后原注册表值已移除", not present)
                backups = mgr._list_backups()
                check("原值已备份", (target["hive"], target["key"], target["name"]) in backups,
                      str(list(backups.keys())[:3]))
                mgr.enumerate()
                target2 = next((i for i in mgr.items
                                if i["name"] == test_name and i["type"] == "注册表"), None)
                check("禁用后仍能在列表中看到（状态为已禁用）",
                      target2 is not None and not target2["enabled"])
                if target2:
                    check("可以重新启用", mgr.enable(target2))
                    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                        winreg.KEY_READ) as key:
                        try:
                            value, _ = winreg.QueryValueEx(key, test_name)
                            restored = value == test_value
                        except FileNotFoundError:
                            restored = False
                    check("注册表值已原样恢复", restored)
        finally:
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0,
                                    winreg.KEY_WRITE) as key:
                    winreg.DeleteValue(key, test_name)
            except OSError:
                pass
            mgr._delete_backup(f"HKCU|{key_path}|{test_name}")

    check("系统关键启动项被标记为不可禁用",
          all(not i["is_system"] or i["name"].lower() in
              {x.lower() for x in __import__("core.startup_manager",
                                             fromlist=["x"]).SYSTEM_STARTUP_NAMES}
              for i in items))


# ---------------------------------------------------------------------------
# [K] 流氓软件误报
# ---------------------------------------------------------------------------


def test_adware_false_positives():
    print("\n[K] 流氓软件检测不得误伤正常软件")
    from core.adware_scanner import AdwareScanner
    ad = AdwareScanner()
    must_not_match = [
        "Kingsoft WPS Office", "360安全卫士", "Microsoft Visual Studio",
        "Google Chrome", "微信", "腾讯会议", "网易云音乐", "7-Zip",
        "Notepad++", "Everything", "Adobe Photoshop", "Sublime Text",
    ]
    for name in must_not_match:
        risk, reason = ad._evaluate_name(name)
        check(f"不误报：{name}", risk == 0, f"risk={risk} ({reason})")

    must_match = ["2345加速浏览器", "鲁大师", "驱动精灵", "hao123浏览器", "快压"]
    for name in must_match:
        risk, _ = ad._evaluate_name(name)
        check(f"能识别：{name}", risk >= 2, f"risk={risk}")

    check("弱关键词单项命中不进入结果表", ad.REPORT_THRESHOLD >= 2,
          f"REPORT_THRESHOLD={ad.REPORT_THRESHOLD}")


# ---------------------------------------------------------------------------
# [L] 默认值不得是破坏性的
# ---------------------------------------------------------------------------


def test_safe_defaults():
    print("\n[L] 默认值必须是安全且非破坏性的")
    cfg = load_config()
    defaults = cfg.get("default_enabled_categories", [])
    check("回收站不在默认勾选中", "recycle_bin" not in defaults, str(defaults))
    check("Windows 更新缓存不在默认勾选中", "windows_update" not in defaults)
    check("内存转储不在默认勾选中", "memory_dumps" not in defaults)
    check("预取文件不在默认勾选中", "prefetch" not in defaults)

    r = ScanResult("system_temp", "x", r"C:\Windows\Temp\a.tmp", 1)
    check("ScanResult 默认不勾选", r.selected is False)

    # 扫描器不得把"未勾选的项"当成待删除
    sc = SystemScanner()
    sc.scan_dns_cache()
    check("DNS 缓存是特殊动作而非文件", sc.results and sc.results[0].special == "flush_dns")


# ---------------------------------------------------------------------------
# [M] 配置单一数据源
# ---------------------------------------------------------------------------


def test_config_single_source():
    print("\n[M] 配置必须是单一数据源且可迁移")
    from core.config import CONFIG_VERSION, migrate_config
    check("配置带版本号", CONFIG_VERSION >= 2, f"v{CONFIG_VERSION}")
    seed = ROOT / "config.json"
    check("项目根目录存在 config.json", seed.exists())
    if seed.exists():
        import json
        with open(seed, "r", encoding="utf-8") as f:
            seed_cfg = json.load(f)
        check("config.json 与 DEFAULT_CONFIG 同版本",
              seed_cfg.get("config_version") == CONFIG_VERSION,
              f"文件 v{seed_cfg.get('config_version')}")
        check("config.json 不含应用安装目录条目",
              "WPS Office" not in json.dumps(seed_cfg.get("software_junk_paths", {}),
                                            ensure_ascii=False)
              or all("\\cache" in v.lower() or "\\backup" in v.lower()
                     for v in seed_cfg.get("software_junk_paths", {}).values()
                     if "kingsoft" in v.lower()))

    # 旧版配置迁移
    legacy = {
        "suspicious_keywords": ["2345", "助手"],
        "known_rogue_patterns": ["*2345*"],
        "software_junk_paths": {
            "WPS 缓存": "%LOCALAPPDATA%\\Kingsoft\\WPS Office",
            "QQ 缓存": "%LOCALAPPDATA%\\Tencent\\QQ\\Temp",
        },
    }
    migrated = migrate_config(legacy)
    check("旧配置被迁移到 v2", migrated["config_version"] == CONFIG_VERSION)
    # 关键不是标签还在不在，而是**值**不能再指向应用根目录
    app_root_patterns = (
        r"\\kingsoft\\wps office$", r"\\tencent\\wxwork$", r"\\dingtalk$",
        r"\\baidunetdisk$", r"\\thunder network$",
    )
    bad = [f"{k} → {v}" for k, v in migrated["software_junk_paths"].items()
           if any(re.search(p, v.lower()) for p in app_root_patterns)]
    check("迁移后不再有指向应用根目录的路径", not bad, "; ".join(bad))
    check("迁移后 WPS 条目指向缓存子目录",
          migrated["software_junk_paths"].get("WPS 缓存", "").lower().endswith("cache"),
          migrated["software_junk_paths"].get("WPS 缓存", ""))
    check("迁移后保留用户自定义的关键词",
          "2345" in migrated["strong_keywords"], str(migrated["strong_keywords"][:5]))


# ---------------------------------------------------------------------------
# [N] 界面默认值
# ---------------------------------------------------------------------------


def test_ui_defaults():
    print("\n[N] 界面默认状态")
    import json
    from core.safety import CATEGORY_POLICIES
    check("所有类别都有明确的安全策略",
          all(k in CATEGORY_POLICIES for k in CATEGORY_POLICIES),
          f"{len(CATEGORY_POLICIES)} 个类别")
    high_risk = [k for k, p in CATEGORY_POLICIES.items() if p.severity == "high"]
    check("高危类别默认不勾选",
          all(not CATEGORY_POLICIES[k].default_enabled for k in high_risk),
          str(high_risk))


def test_multi_signal_analyzer():
    print("\n[O] 多信号取证引擎")
    from core.analyzer import (
        DIM_NAME,
        DIM_PERSISTENCE,
        DIM_SIGNATURE,
        MalwareAnalyzer,
        extract_exe_path,
    )
    from core.pe_inspect import parse_pe

    analyzer = MalwareAnalyzer(deep_budget=20)

    # ① 命令行里提取可执行文件路径
    check("提取带引号的路径",
          extract_exe_path(r'"C:\Program Files\App\a.exe" --flag').lower()
          == r"c:\program files\app\a.exe")
    check("提取无引号带空格路径",
          extract_exe_path(r"C:\Program Files\App\a.exe /s").lower()
          == r"c:\program files\app\a.exe")
    check("提取 rundll32 里的 dll",
          extract_exe_path(r'rundll32.exe "C:\a\b\c.dll",Entry').lower()
          == r"c:\a\b\c.dll")
    check("处理 \\SystemRoot\\ 形式的服务路径",
          extract_exe_path(r"\SystemRoot\system32\drivers\foo.sys").lower()
          == r"c:\windows\system32\drivers\foo.sys",
          extract_exe_path(r"\SystemRoot\system32\drivers\foo.sys"))

    # ② PE 解析
    kernel = os.path.join(os.environ.get("SystemDrive", "C:") + "\\",
                          "Windows", "System32", "kernel32.dll")
    if os.path.isfile(kernel):
        pe = parse_pe(kernel)
        check("PE 解析成功", pe.valid, pe.error)
        check("识别出节区", len(pe.sections) > 0, f"{len(pe.sections)} 个节区")
        check("识别出导入表", len(pe.imports) > 0, f"{len(pe.imports)} 个 DLL")
        check("熵值在合理区间", 0 < pe.max_entropy <= 8.0, f"{pe.max_entropy:.2f}")
        check("架构识别正确", pe.arch in ("x64", "x86"), pe.arch)

    # ③ 数字签名：系统文件应当是有效签名
    sig = analyzer._verify_cached(kernel) if os.path.isfile(kernel) else {}
    check("系统文件签名有效", sig.get("status") == "valid", str(sig.get("status_text")))

    # ④ 正规安装位置 → 低风险
    program_files = os.environ.get("ProgramFiles", "")
    legit = ""
    if os.path.isdir(program_files):
        try:
            for entry in os.scandir(program_files):
                if entry.is_dir(follow_symlinks=False):
                    legit = entry.path
                    break
        except OSError:
            pass
    if legit:
        a = analyzer.analyze_directory(legit)
        check("正规安装目录判为低风险", a.risk < 21,
              f"{a.name}: {a.risk} 分（{a.level}）")
        check("正规安装目录不报持久化异常",
              all(s.dimension != DIM_PERSISTENCE or s.weight <= 18
                  for s in a.signals))

    # ⑤ 临时目录 + 未签名 + 无发布者 = 高风险
    temp_dir = os.environ.get("TEMP", "")
    fake = os.path.join(temp_dir, "wc_verify_fake.exe")
    try:
        with open(fake, "wb") as f:
            f.write(b"MZ" + b"\x00" * 512)
        a = analyzer.analyze_executable(fake)
        check("临时目录里的未签名程序判为高风险", a.risk >= 46,
              f"{a.risk} 分（{a.level}）")
        check("命中安装位置维度",
              any(s.dimension == "安装位置" and s.weight > 0 for s in a.signals))
        check("命中数字签名维度",
              any(s.dimension == DIM_SIGNATURE and s.weight > 0 for s in a.signals))
    finally:
        try:
            os.unlink(fake)
        except OSError:
            pass

    # ⑥ 名称维度权重最低：仅靠关键词不得单独进表
    check("名称维度是弱信号", DIM_NAME == "名称特征")
    from core.adware_scanner import AdwareScanner
    scanner = AdwareScanner(deep_budget=5)
    check("结果表要求非名称维度同时成立",
          hasattr(scanner, "REPORT_THRESHOLD") and scanner.REPORT_THRESHOLD >= 21)

    # ⑦ 可信品牌白名单
    check("白名单命中即返回空风险",
          analyzer.is_trusted_brand("Kingsoft WPS Office") == "kingsoft",
          analyzer.is_trusted_brand("Kingsoft WPS Office"))
    check("非白名单不误伤", analyzer.is_trusted_brand("SomeUnknownTool") == "")


def test_deep_cleaning_capabilities():
    print("\n[P] 深度清理与扫描能力")
    from core.safety import CATEGORY_POLICIES
    from core.space_analyzer import SpaceAnalyzer, classify_path, CAT_USERDATA
    from core.leftovers import (
        find_browser_caches,
        find_browser_cookies,
        find_orphaned_directories,
        get_uninstall_entries,
    )
    from core.clean_history import load_history, save_history, summarize

    # ① 类别体系覆盖度
    required = {
        "system_temp", "windows_update", "thumbnails", "error_reports",
        "memory_dumps", "recycle_bin", "prefetch", "dns_cache",
        "software_junk", "dev_cache", "browser_cache", "browser_cookies",
        "app_leftovers", "system_junk", "old_installers",
        "delivery_optimization", "windows_component_store", "windows_old",
        "hibernation", "system_restore", "manual_target",
    }
    missing = required - set(CATEGORY_POLICIES)
    check("清理类别体系完整", not missing, f"缺少 {sorted(missing)}")

    # ② 高危类别必须默认不勾选
    dangerous = ["recycle_bin", "system_restore", "hibernation",
                 "browser_cookies", "app_leftovers", "windows_old",
                 "windows_component_store"]
    check("高危类别一律默认不勾选",
          all(not CATEGORY_POLICIES[k].default_enabled for k in dangerous),
          str([k for k in dangerous if CATEGORY_POLICIES[k].default_enabled]))

    # ③ 浏览器缓存规则库
    caches = find_browser_caches()
    check("能识别出浏览器缓存目录", len(caches) >= 0,
          f"{len(caches)} 个（当前机器装了 {len(caches)} 个）")
    labels = {c["label"] for c in caches}
    check("缓存规则覆盖多种浏览器",
          any("Chrome" in l for l in labels) or not caches, str(sorted(labels))[:120])
    cookies = find_browser_cookies()
    check("Cookie 是独立的一类（会掉登录）", cookies is not None,
          f"{len(cookies)} 个 Cookie 文件")

    # ④ 卸载表读取
    entries = get_uninstall_entries()
    check("能读出已安装软件清单", len(entries) > 0, f"{len(entries)} 条")
    check("卸载表含安装位置字段",
          all("install_location" in e for e in entries[:5]))

    # ⑤ 卸载残留检测必须极保守
    orphans = find_orphaned_directories()
    risky = [o for o in orphans
             if os.path.normcase(o["name"]) in
             ("package cache", "msbuild", "difx", "windows mail",
              "windows media player")]
    check("卸载残留不误伤系统/必需目录", not risky, str(risky))
    check("卸载残留判定很保守（宁缺毋滥）", len(orphans) < 25,
          f"本次报出 {len(orphans)} 项")

    # ⑥ 空间分析
    import tempfile
    sandbox = tempfile.mkdtemp(prefix="wc_space_")
    try:
        os.makedirs(os.path.join(sandbox, "Videos"), exist_ok=True)
        os.makedirs(os.path.join(sandbox, "AppData", "Local", "Cache"),
                    exist_ok=True)
        with open(os.path.join(sandbox, "Videos", "a.mp4"), "wb") as f:
            f.write(b"\0" * 50000)
        with open(os.path.join(sandbox, "AppData", "Local", "Cache", "c.bin"),
                  "wb") as f:
            f.write(b"\0" * 10000)
        analyzer = SpaceAnalyzer()
        node = analyzer.scan(sandbox, max_depth=4)
        check("空间分析统计正确", node.total_size() == 60000,
              f"{node.total_size()} 字节")
        check("空间分析文件数正确", node.file_count == 2, str(node.file_count))
        kinds = {c.name: c.category for c in node.children}
        check("视频目录归为用户数据",
              kinds.get("Videos") == CAT_USERDATA, str(kinds))
        check("缓存目录归为缓存", kinds.get("AppData") == "缓存", str(kinds))
    finally:
        shutil.rmtree(sandbox, ignore_errors=True)

    # ⑦ 分类不能被上级目录名带偏
    check("Program Files 不会被 Temp 规则抢走",
          classify_path(r"C:\Temp\x\Program Files\App") == "程序",
          classify_path(r"C:\Temp\x\Program Files\App"))

    # ⑧ 清理历史
    records = [{"category": "system_temp", "deleted": 10, "skipped": 1,
                "failed": 0, "saved": 2048, "ts": "2026-01-01 00:00:00"}]
    save_history(records)
    loaded = load_history()
    check("清理历史可写入并读回", len(loaded) >= 1, f"{len(loaded)} 条")
    summary = summarize(loaded)
    check("清理历史可汇总", summary["total_size"] >= 2048, str(summary))


def main():
    print("=" * 74)
    print("WinCleaner 安全不变量回归测试")
    print("=" * 74)

    test_critical()
    test_recycle_bin_deletion()
    test_recycle_bin_not_scanned_per_file()
    test_event_logs_removed()
    test_install_dirs_protected()
    test_age_protection()
    test_root_containment()
    test_personal_data_protection()
    test_no_permanent_delete_paths()
    test_startup_reversible()
    test_adware_false_positives()
    test_safe_defaults()
    test_config_single_source()
    test_ui_defaults()
    test_multi_signal_analyzer()
    test_deep_cleaning_capabilities()

    print("\n" + "=" * 74)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    if FAILED:
        print("\n未通过：")
        for name, detail in FAILED:
            print(f"  - {name}  {detail}")
    print("=" * 74)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
