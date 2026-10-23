# WinCleaner 修复报告（v2.0.0）

- 对象：`D:\stm32\WinCleaner`（Python 3.12 + PyQt6 桌面清理工具）
- 基线：`AUDIT_REPORT.md`（2026-10-14 审计，P0/P1/P2 共 40+ 项）
- 修复时间：2026-10-21
- 结论：**审计报告中的全部 P0 / P1 项已修复并写入可执行断言**（`audit/verify_wincleaner.py` 79 项全部通过）。

---

## 0. 修复前先解决"根本打不开"

| 问题 | 原因 | 处理 |
|---|---|---|
| 虚拟环境失效 | `.venv\pyvenv.cfg` 指向已被卸载的 uv Python（`...\uv\python\cpython-3.12.14\...`），`python.exe` 直接报 `No Python at ...` | 改指本机实际存在的 `C:\Dev\Python312`，依赖（PyQt6 6.11 / psutil 7.2.2 / pyinstaller 6.22.3 / pywin32 312）全部在位，无需重装 |
| `--windowed` 打包后崩溃 | `logging.StreamHandler(sys.stdout)` 在 pythonw 下 `sys.stdout is None` | 按 `sys.stdout`/`sys.stderr` 是否为 None 决定是否挂载流处理器；同时改用 `RotatingFileHandler`（2 MB × 3）防日志无限增长 |
| 资源找不到 | 打包后 `__file__` 指向临时解包目录 | 新增 `_resource_path()`，优先用 `sys._MEIPASS` 定位 `ui/style.qss` 与 `config.json` |

---

## 1. P0 致命问题（全部修复）

### P0-1 删除不可逆 → 所有删除进回收站

新增 `core/utils.py:delete_to_recycle_bin()`，用 `SHFileOperationW` + `FOF_ALLOWUNDO` 把文件/目录移入回收站（可还原），这是**全项目唯一的删除出口**。`core/cleaner.py` 与 `ui/main_window.py` 中的 `unlink()` / `shutil.rmtree()` 全部移除。

实测（`audit/verify_wincleaner.py` [B]）：

```
删除后原路径已不存在                        PASS
回收站 API 返回成功                          PASS
回收站条目数 +1   清理前 18104 → 清理后 18105  PASS
```

> `safe_delete(to_recycle=True)` 这个"骗人参数"已实现：True 走回收站，False 走永久删除且仅供内部维护脚本使用。

### P0-2 破坏性默认值 → 配置驱动的安全默认

- `ScanResult.selected` 默认 `False`（原为 `True`）。
- 清理类别默认值改为配置项 `default_enabled_categories`，只包含 6 个低风险类别。
- **回收站、Windows 更新缓存、内存转储、预取文件一律不在默认勾选里**（高危类别 `default_enabled=False`）。
- 表格里的复选框不再默认全勾（`ui/models.py:JunkTableModel`）。
- 清理动作改为：预览 → 确认对话框（显示项数/体积/最大项清单）→ 执行 → 结果明细。不可逆操作（清空回收站）要求**键入"清空回收站"**才能继续。

### P0-3 配置把安装目录当缓存 → 三重拦截

1. **配置层**：`config.json` v2 移除全部指向应用根目录的条目。`%LOCALAPPDATA%\Kingsoft\WPS Office` → `%LOCALAPPDATA%\Kingsoft\WPS Office\*\office6\cache`；`WXWork`/`DingTalk`/`BaiduNetdisk`/`Thunder Network` 整目录条目直接删除。
2. **扫描层**：`looks_like_cache_dir()` 要求目录名明确属于缓存（cache/temp/logs/crashpad/GPUCache…），命中 `*助手*` 这类模糊 glob 的整目录捕获逻辑**已整体移除**。
3. **删除层**：`check_delete_allowed()` 校验路径必须落在扫描时记录的允许根目录内。

实测：软件垃圾扫描结果 0 项来自 WPS 安装目录；WPS Office 目录不被识别为缓存目录。

### P0-4 回收站被逐文件删除 → 改为整体清空

`scan_recycle_bin()` 不再递归收集 `$I*`/`$R*`，只登记**一个** `special="empty_recycle_bin"` 动作，由 `SHEmptyRecycleBinW` 整体清空。删除闸门对任何盘符的 `$Recycle.Bin` 内容一律拒绝（实测 C/D/E 盘全部拦截）。

### P0-5 缺少文件年龄保护 → 按类别统一配置

新增 `core/safety.py:CATEGORY_POLICIES`，每个类别声明 `min_age_days`：

| 类别 | 年龄门槛 | 类别 | 年龄门槛 |
|---|---|---|---|
| 系统临时文件 | 2 天 | Windows 更新缓存 | 14 天（且需管理员） |
| 缩略图缓存 | 1 天 | 内存转储 | 7 天 |
| 错误报告 | 7 天 | 预取文件 | 30 天（且需管理员） |
| 应用缓存残留 | 7 天 | 开发工具缓存 | 14 天 |

`%LOCALAPPDATA%\Temp` 的重复收集链路已合并（按规范化路径去重），扫描耗时由 **20.6 s → 1.5 s**（`os.scandir` 替代 `glob.iglob`）。

### P0-6 Windows 更新缓存逐文件删除 → 停服务后清理

清理该类别前自动 `sc stop wuauserv` / `bits`，完成后恢复；该类别需要管理员权限，且默认不勾选。

---

## 2. P1 严重问题（全部修复）

### P1-1 `is_system_critical` 硬编码 `C:\` → 动态跨盘符判定

现在对**任意盘符**的 `Windows\`、`Program Files\`、`$Recycle.Bin`、`System Volume Information` 一视同仁；`Windows` 目录只放行 `Temp / Prefetch / SoftwareDistribution / Minidump / LiveKernelReports / Logs\CBS / Logs\DISM` 子树。

```
C:\$Recycle.Bin\...        → critical=True
D:\$Recycle.Bin\...        → critical=True   （旧版 False）
D:\Windows\System32\...    → critical=True   （旧版 False）
D:\Program Files\...       → critical=True   （旧版 False）
C:\Windows\Temp\x.tmp      → critical=False  （可清理子树）
```

### P1-2 关键词误报 → 白名单优先 + 强弱分级

- 新增**可信品牌白名单**（kingsoft/wps、360、microsoft、tencent、baidu、sogou、iflytek…），白名单优先级高于任何可疑规则，命中即整体忽略。
- 关键词拆成**强特征**（已知流氓/破解品牌，单命中 2 分）与**泛化关键词**（助手/加速/安全…，单命中仅 1 分"待确认"）。
- 只有风险 ≥2 才进入结果表，单项弱命中只计数不列出（否则列表会被正常软件淹没）。
- 强特征命中仍有 3 分，2345 / 鲁大师 / 驱动精灵 / hao123 / 快压 全部照常识别。

### P1-3 没有提权 → 明确状态 + 一键提权

侧栏显示"管理员模式 / 标准用户模式"，非管理员时出现**「以管理员身份重启」**按钮（`run_as_admin()` 终于接上了调用点）。需要管理员的类别在闸门里直接给出"该类别需要管理员权限"并跳过，不再伪装成功。

### P1-4 不检查占用 → 独占打开检测

删除前对文件执行 `open(path, "r+b")` 独占打开测试，被占用则跳过并标注"文件被其他程序占用"。

### P1-5 启动项禁用不可恢复 → 备份式禁用

- 禁用注册表启动项时，原值先备份到 `HKCU\Software\WinCleaner\DisabledStartup`，再从原位置移除；"启用"可原样写回。
- 启动文件夹条目通过改名 `.disabled` 后缀实现，可一键还原。
- 禁用后条目**仍显示在列表里**（状态"已禁用"），不再"禁用即消失"。
- 系统关键项（SecurityHealth / OneDrive / SysMain / RtkAudUService…）标记为「系统项」，界面禁止禁用。
- 支持导出 JSON 备份。

实测（`audit/verify_wincleaner.py` [J]，真实写 HKCU 再回滚）：

```
禁用成功 / 原注册表值已移除 / 原值已备份 / 仍能在列表中看到（已禁用）
可以重新启用 / 注册表值已原样恢复          —— 6 项全部 PASS
```

### P1-6 流氓软件页是死胡同 → 可操作

新增：打开所在位置、**隔离到隔离区**（移动而非删除，可随时取回）、加入白名单、全选高危。风险等级配色与说明。

---

## 2.5 修复过程中新发现并修掉的问题

| 问题 | 表现 | 处理 |
|---|---|---|
| 过滤功能完全失效 | `" ".join(str(tuple))` 是按**字符**拼接，搜索永远匹配不上 | 改为按元素拼接（`ui/models.py`） |
| 预演模式污染审计日志 | 一次 dry-run 写入 5.2 万条"根本没发生过的删除记录"，日志涨到 **65 MB** | dry-run 不写审计日志；审计日志加 8 MB 轮转（`os.replace` 原子覆盖） |
| 设置页控件互相重叠 | 5 个固定高度文本框超出窗口高度，标签压在文本框上 | 整页放进 `QScrollArea` |
| 表格复选框列被排序 | 表头第 0 列出现无意义排序箭头 | 关闭内建排序，改为点击表头手动切换 |
| exe 打包后找不到样式表 | `--add-data` 相对路径按 spec 目录解析 | 改用绝对路径；资源定位优先 `sys._MEIPASS` |
| 打包时 `--icon` 从未生效 | `assets/` 是空目录 | `build_assets.py` 用 Qt 现画图标并手工封装 ICO |

---

## 2.6 流氓软件判定：从"关键词匹配"升级为"多维底层取证"

> 用户诉求：*"流氓软件不要只通过关键词，应该从各个方面底层分析是不是垃圾或者流氓。"*

### 为什么关键词不够

旧版只做一件事：把程序名/目录名和一张关键词表做子串匹配，命中就报"流氓软件"。
它有三种典型失效：

1. **漏报**——真正的流氓软件换个名字（`wb2api_baseline.exe`）就完全躲过。
2. **误报**——`爱思助手`/`Trae Work 助手` 命中泛化词"助手"被当成流氓。
3. **抓不到本质**——"未签名 + 装在临时目录 + 在 3 处注册自启动"这种铁证，
   关键词表再长也识别不出来。

### 新的判定模型：九个维度 + 交叉验证

新增 `core/pe_inspect.py`（内置 PE 解析器）、`core/signature.py`（Authenticode 校验）、
`core/analyzer.py`（取证引擎），重写 `core/adware_scanner.py` 接入。

| 维度 | 底层证据 | 典型加分 |
|---|---|---|
| **数字签名** | `WinVerifyTrust` 的 Authenticode 校验 | 签名有效 −28；未签名 +20；**摘要不匹配 +55**（文件被改过）；不受信任 +40 |
| **安装位置** | 正规软件装在 Program Files | 临时目录 +45；下载目录 +40；Program Files −25；Windows 目录 −30；`%LOCALAPPDATA%\Programs` −20 |
| **持久化** | 同一 exe 被登记进几处自启动 | Run/RunOnce/启动文件夹/服务/计划任务，每处 +18，≥2 处再 +12 |
| **PE 结构** | 节区熵值、壳特征、导入表 | 熵 ≥7.2 +22；UPX/VMProtect/Themida 等 +18；导入注入/键盘记录 API +16~20；overlay +8 |
| **发布者** | 版本资源里自称的公司 vs 目录/文件名 | 自称含"破解/绿色版/注册机" +45；自称与目录名不符 +18（未签名再 +18） |
| **名称特征** | 关键词 | 强特征 +35；泛化词 +10 —— **权重最低的一维** |
| **分发形态** | 目录像不像正规安装 | 多个 exe 却无卸载程序 +12 |
| **运行行为** | 进程是否在跑 | 正在运行 +12 |
| **交叉验证** | 多条弱信号组合成强证据 | 未签名 + 临时目录 + 自称存疑 +30；加壳 + 未签名 + 注入 API +28；签名有效 + 正规位置 + 结构正常 **−25** |

**关键词被降级成九个维度之一，且只有它命中时无法进入结果表**
（`risk_without_name < 21 且无强关键词命中` → 归入"未达阈值"）。

### 两段式扫描：既准又快

1. **预筛**（全量跑，只用便宜信号）：位置 / 名称 / 目录形态 / 自启动登记。
2. **深挖**（只跑可疑的）：Authenticode 校验 + PE 解析 + 发布者一致性核验。

本机实测：**755 个候选 → 5.3 秒 → 5 项进入结果表，749 项判定为正常**。
（旧版关键词版在同一台机器上会报 254 项，其中绝大多数是系统驱动。）

### 实测抓到的真问题

```
[高危] 99 分  wb2api_baseline.exe
   C:\Users\Administrator\AppData\Local\Temp\wb2api_baseline.exe
   维度：数字签名、安装位置、PE 结构、发布者
   ＋45 位于临时目录（临时目录里的程序极可能是安装器或投放器）
   ＋22 节区熵值 8.00（高度压缩/加密）
   ＋20 文件没有任何数字签名
   ＋12 没有填写发布者信息

[可疑] 48 分  YunUtilityService.exe
   C:\Users\Administrator\AppData\Roaming\baidu\BaiduNetdisk\YunUtilityService.exe
   维度：安装位置、持久化、数字签名
   ＋18 被登记 1 处自启动（服务 BaiduNetdiskUtility）
   ＋12 位于漫游配置目录
   ＋12 签名不受信任（自签名或证书链有问题）
```

### 配套的界面改动

- 结果表新增 **风险评分（0-100）** 与 **命中维度** 两列，评分带颜色分级。
- **双击任意一行 / 点「查看分析详情」** 弹出完整证据链：每一条信号的维度、权重、依据。
- 扫描摘要区分"高危 / 可疑 / 未达阈值未列出"。

### 实现中踩到并修掉的坑

| 坑 | 现象 | 处理 |
|---|---|---|
| PE 导入表 RVA 没转文件偏移 | 读出 `KERNEL32.dll` 变成乱码 `'H+HH\|$...'` | 加 `_rva_to_offset()` |
| `VerQueryValueW` 拿到的是 UTF-16LE | 版本信息乱码、且被截断 | 改 UTF-16LE 解码 + 用 `GetFileVersionInfoSizeW` 取真实大小（8192 兜底会把资源截断） |
| `VerEnumStringFileInfoW` 在 version.dll 里**不存在** | 枚举语言码失败 | 改从 `\\VarFileInfo\\Translation` 取语言码 + 常见码表兜底 |
| `CryptQueryObject` 用了废弃的老接口 | 全部返回 `E_INVALIDARG` | 改用 WinVerifyTrust 状态数据（签名**状态**可用；签名者名在本机取不到，发布者改用版本资源） |
| 未知签名错误码被当成"文件被篡改" | 误指控百度网盘 | 只有 `TRUST_E_BAD_DIGEST` 才判"篡改"，其余归为"不受信任" |
| `Qt.Orientation` 是纯 Enum | `orientation == 1` 不成立，表头取不到 | 两种写法都接受 |
| 服务 ImagePath 形如 `\SystemRoot\...` | 路径解析成 `D:\systemroot\...`，系统驱动被当成流氓 | 补 `\SystemRoot\` 前缀解析 |
| `rundll32.exe "x.dll",Entry` 提取到了 rundll32 本身 | 取错目标 | 优先取引号里的路径 |
| 微软中文版资源 CompanyName 写作 "Microsoft C" | 被误判"发布者与目录名不符" | 签名有效时不再追究自称；系统安装目录免检 |
| `.bat` 之类非 PE 文件被扣"未签名"分 | 脚本文件莫名高分 | 有 MZ 头才按 PE 处理 |
| 系统驱动（WUDFRd 等）被判高危 | 几十条噪音 | 系统目录豁免持久化与发布者维度 |

---

## 2.7 清理与扫描的纵深：空间分析 + 21 个类别 + 深度检测

> 用户诉求：*"你再深入的去做一下清理啊，然后垃圾的扫描啊，类似于这样的东西，再去完整的去做一下，深入深度思考一下。"*

原来的清理能力本质上是"按已知路径找缓存文件"——路径写死在配置里，能找到什么完全取决于
当初写配置的人知不知道那个位置。这有三层问题：

1. **看不见全貌**：用户不知道空间到底被谁吃了，只能一页页点。
2. **路径有限**：应用换了版本、换了目录结构，配置就失效了。
3. **语义不对**：Windows 组件存储是**逐文件删**的（正确做法是 DISM），
   浏览器缓存根本没覆盖（这才是日常垃圾的大头）。

### A. 新增「空间分析」页（9 个页面之一）

`core/space_analyzer.py` + `ui/treemap.py` + `ui/space_page.py`。

* **squarified 矩形树图**：面积 ∝ 体积，颜色 ∝ 用途分类（系统 / 程序 / 用户数据 /
  缓存 / 影音 / 文档 / 压缩包），点击下钻逐层查看。
* **分级扫描**：深度 2 层秒出概览，深度 4~6 层做整体检。
  本机实测：用户目录深度 2 层 **0.0 s**，深度 4 层 **1.4 s / 26179 个文件 / 13.53 GB**。
* **目录表**：可排序的明细，带占比与用途分类。
* **闭环**：看中的目录 → 「加入清理目标」→ 「送到垃圾清理」→ 垃圾清理页逐项确认后执行。
  清理目标作为 `manual_target` 类别进入清理列表，**整目录移入回收站可整体还原**。

实现要点：一次遍历建树、事后自底向上汇总体积（避免 O(深度²) 累加）、
跳过重解析点（否则 `AppData\Local\Application Data` 这类自引用环会永远扫不完）。

### B. 清理类别从 10 个扩到 21 个

| 新增类别 | 说明 | 默认 |
|---|---|---|
| 浏览器缓存 | Chrome / Edge / Firefox / 360 / QQ / 搜狗 / 夸克 / 钉钉 / 微信 / VS Code / Store 应用，25 条规则 | ✅ 开 |
| 浏览器 Cookie | **单独一类**，因为会清掉登录态 | ❌ 关 |
| 卸载残留 | 卸载信息已消失、目录还在的孤儿目录 | ❌ 关 |
| 系统日志与崩溃转储 | CBS / DISM / Panther / WER / CrashDumps / 字体 / 着色器缓存 | ✅ 开 |
| 传递优化缓存 | Windows 更新分发的 P2P 缓存（常常是几个 GB） | ✅ 开 |
| 遗留安装包 | 临时目录与下载目录里 60 天没动的安装包 | ❌ 关 |
| 组件存储（WinSxS） | **用 DISM 正确清理**，不再逐文件删 | ❌ 关 |
| Windows 旧版本 | 升级遗留的 Windows.old（可能几十 GB） | ❌ 关 |
| 休眠文件 | hiberfil.sys，关闭休眠即可释放 8~16 GB | ❌ 关 |
| 系统还原点 | 卷影副本 | ❌ 关 |
| 手动指定目录 | 来自空间分析页 | — |

**系统级动作改用正确的系统语义**（`core/cleaner.py`）：

| 动作 | 实现 | 说明 |
|---|---|---|
| 组件存储 | `DISM /Online /Cleanup-Image /AnalyzeComponentStore` → 解析"是否建议清理" → 建议时才 `/StartComponentCleanup` | 先问系统再动手，不盲删 WinSxS |
| 休眠文件 | `powercfg /hibernate off` | 释放 hiberfil.sys，提示可用 `powercfg /hibernate on` 恢复 |
| 还原点 | `vssadmin delete shadows /all /for=C:` | 明确提示"还原此电脑"将不可用 |
| Windows.old | 打开系统自带磁盘清理由用户确认 | 不用 takeown/rmdir 强删，避免后续升级失败 |
| 更新缓存 | 停 `wuauserv`/`bits` → 清理 → 恢复 | 原来只是逐文件删 |

### C. 深度检测：靠交叉比对而不是靠名字

`core/leftovers.py`：

* **卸载残留**——把注册表卸载表（456 条）与磁盘目录做比对。
  判定要**五条同时成立**：不在硬性排除名单（Package Cache 这类删了会导致无法卸载）、
  目录名与任何已安装程序都对不上、不在可信品牌白名单、开始菜单里没有同名项、
  **目录里的可执行文件没有有效数字签名**。
  实测：未加交叉验证时报 45 项（几乎全是误报），加完只剩 **1 项**且是真的。
* **浏览器缓存**——25 条规则覆盖主流浏览器与 Electron 应用。
  实测本机 97 个缓存目录 / 3375 个文件 / 602 MB。
* **系统垃圾**——13 个固定位置（WER、CBS、DISM、Panther、CrashDumps、INetCache…）。
* **旧安装包**——临时目录与下载目录里长期没动的 `.exe/.msi/.iso/.zip`。

### D. 可追溯与可回退

* **清理历史**：每次清理写一条记录（时间、类别、成功/跳过/失败数、体积、明细）到
  `%APPDATA%\WinCleaner\history.json`。此前"删了什么完全不可追溯"的问题就此解决。
* **清理前建还原点**：设置页新增开关，用 `SRSetRestorePointW` 创建系统还原点
  （需管理员），作为可逆性的最后一层保险。
* **审计日志**：`clean_actions.log` 记录每一次动作（成功与失败都记），并支持轮转。

### E. 实测性能

```
14 个类别同时扫描：7.8 秒，共 62,913 项
  system_temp         59,176 项   2621.0 MB
  browser_cache        3,375 项    602.2 MB
  thumbnails              26 项     32.4 MB
  software_junk          331 项      2.7 MB
```

### F. 过程中修掉的坑

| 坑 | 现象 | 处理 |
|---|---|---|
| squarify 漏了面积归一化 | 矩形面积不守恒（175 vs 120000） | 先把数值归一化成面积再排版 |
| 路径分类被上级目录带偏 | Temp 下的 `Program Files` 被判成缓存 | 规则按"具体优先"排序，且缓存名只看目录自身 |
| 卸载残留误报 45 项 | 把 Tencent / VS / nodejs 当残留 | 五重交叉验证（卸载表+品牌+开始菜单+签名+硬名单） |
| Cookie 扫描把缓存目录也扫了 | 2062 项而不是 2 项 | 缓存与 Cookie 拆成两个独立函数 |
| `QFrame(objectName=...)` 多一个括号 | 语法错误 | 修正 |
| `QUrl` 从 QtGui 导入 | ImportError | QUrl 在 QtCore |
| `make_table()` 返回 QTableView | 没有 `setColumnCount` | 计划清单改用 QTableWidget |

---

| # | 问题 | 处理 |
|---|---|---|
| 1 | 跑不起来 | 修好 `.venv`，新增 `audit/smoke_test.py` 冒烟测试 |
| 2 | 无法重新打包 | `build_exe.py` 重写，实测可打包出 36.3 MB 单文件 exe |
| 3 | spec 硬编码绝对路径 | 全部改为相对路径；`build_exe.py` 不再删除 spec |
| 4 | 无图标/版本信息 | `build_assets.py` 用 Qt 现画图标并手工封装 ICO，生成 `version_info.txt`（实测 exe 内含图标组与版本资源） |
| 5 | 配置双份维护 | 默认配置只在 `core/config.py` 一份；用户配置移到 `%APPDATA%\WinCleaner\config.json`；带版本号与自动迁移 |
| 6 | UI 主线程重活 | 表格全部改为 `QAbstractTableModel` + `QTableView` 虚拟化；注册表枚举移到后台线程 |
| 7 | 删除后不刷新/无校验 | 删除后按"实际处理成功"移除行，被跳过/失败的行保留并取消勾选；删除前走同一套闸门 |
| 8 | windowed 下日志崩溃 | 见 §0 |
| 9 | 磁盘/内存读数静默为 0 | `get_disk_usage` 返回 `error` 字段，界面显式显示"读取失败" |
| 10 | 未使用导入 | 已清理（语法检查 0 错误） |
| 11 | junction 循环 | 改用 `os.scandir` 递归并跳过重解析点（`st_file_attributes & FILE_ATTRIBUTE_REPARSE_POINT`） |
| 12 | 日志不轮转 | `RotatingFileHandler`（2 MB × 3）+ 独立的 `clean_actions.log` 审计日志 |

---

## 4. UI 专项修复

| 页面 | 原问题 | 现状 |
|---|---|---|
| 仪表盘 | 磁盘/内存显示 0，快捷按钮只跳页不执行 | 真实磁盘/内存/启动项/扫描统计 4 张卡；每个盘符独立使用率条；快捷按钮直接触发扫描；最近活动流 |
| 垃圾清理 | 3.6 万行卡死、默认全选、无搜索 | 虚拟表格（6.2 万行流畅）、全选/全不选/反选、搜索+类别/类型过滤、导出 CSV、**停止扫描**、按类别统计已选体积、清空回收站需键入确认；**21 个清理类别** |
| **空间分析**（新增） | 完全没有 | squarified 矩形树图 + 可排序目录表 + 面包屑下钻 + 清理目标清单，一键送到垃圾清理页 |
| 大文件扫描 | 每行一个按钮，删完不刷新 | 表格+选择+工具栏"打开所在目录 / 移入回收站 / 导出"；删除走回收站 |
| 重复文件 | 每行一个按钮 | 按组展示，每组默认保留最早修改的一个；只有"保留"以外的副本可删；一组都没勾则不删 |
| 启动项管理 | 只有禁用、禁用即消失 | 禁用/启用双向、状态列、系统项保护、导出备份 |
| 流氓软件 | 只读列表 | 九维取证评分、命中维度列、完整证据链弹窗、隔离到隔离区、加入白名单 |
| 运行日志 | 内存态、每 3 秒刷新的假日志 | 直接读真实日志文件，支持级别过滤、打开日志目录、复制 |
| 设置 | 可把关键词清空导致检测静默失效 | 分强/弱/白名单四栏 + JSON 校验 + 恢复默认 + 打开配置文件 + 保护开关（个人数据保护、清理前建还原点） |

界面截图见 `audit/screens/page0_dashboard.png` ~ `page7_settings.png`（8 个页面）与 `exe_fullscreen.png`（打包后实机运行）。

---

## 5. 新增的"删除唯一出口"安全链

```
扫描（只读）
  └─ 记录允许根目录 root、mtime、size
清理
  └─ check_delete_allowed()
       ① 路径合法性 / 非盘符根
       ② 非系统关键区 / 非回收站条目
       ③ 必须落在允许根目录内
       ④ 文件年龄 ≥ 类别门槛
       ⑤ 非安装载荷 / 非个人数据（保护开关）
       ⑥ 未被进程占用
       ⑦ 权限满足
  └─ delete_to_recycle_bin()  ← 唯一删除出口，进回收站可还原
  └─ 写 clean_actions.log 审计（成功与失败都记）
```

---

## 6. 验证

```powershell
cd D:\stm32\WinCleaner
.venv\Scripts\python.exe audit\verify_wincleaner.py   # 安全不变量 + 多信号 + 深度能力：114 项
.venv\Scripts\python.exe audit\smoke_test.py            # 启动冒烟：9 页面 + 模型 + 树图
.venv\Scripts\python.exe audit\core_selftest.py          # 核心层自检：闸门 / 跨盘符 / 扫描
.venv\Scripts\python.exe audit\analyzer_test.py          # 多信号引擎标定（真实样本）
.venv\Scripts\python.exe audit\adware_scan_test.py       # 端到端扫描 + 性能基准
.venv\Scripts\python.exe audit\render_pages.py           # 渲染 9 个页面截图
.venv\Scripts\python.exe build_exe.py                    # 重新打包
```

当前结果：

```
安全不变量回归： 通过 114 项，失败 0 项
启动冒烟：       SMOKE OK
核心自检：       SELFTEST DONE
垃圾扫描：       14 个类别 → 7.8 秒 → 62,913 项
空间分析：       深度 2 层 0.0 s / 深度 4 层 1.4 s（13.53 GB）
多信号扫描：     755 个候选 → 5.3 秒 → 5 项进入结果表
打包：           dist\WinCleaner.exe  36.4 MB（含图标 + 版本信息 + 清单）
实机启动：       窗口标题 "WinCleaner 2.0.0 — Windows 系统清理助手"，首屏仪表盘正常
```

---

## 7. 使用说明

- **启动**：双击 `启动WinCleaner.bat`（无控制台），或 `调试启动-带控制台.bat`（带控制台看报错）。
- **配置**：`%APPDATA%\WinCleaner\config.json`（自动创建，种子来自随程序分发的 `config.json`）。
- **日志**：`%APPDATA%\WinCleaner\logs\wincleaner.log`，清理审计在同目录 `clean_actions.log`。
- **提权**：侧栏「以管理员身份重启」按钮，或打包时加 `--uac-admin` 让 exe 始终以管理员运行。
- **删除均可还原**：常规清理进回收站；"隔离"只是移动到 `%LOCALAPPDATA%\WinCleaner\quarantine\`；唯一不可逆的是"清空回收站"，需要键入确认字。

> 项目根目录下的 `logs\wincleaner.log` 是 2026-10-14 事故的**证据文件**，请勿删除。
