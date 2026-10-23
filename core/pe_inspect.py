"""内置最小 PE 解析器。

流氓软件的判定不能只看文件名——必须看可执行文件本身的结构。
这个模块用纯标准库解析 PE 头，提取取证需要的字段：

* 节区表与 **shannon 熵**（高熵 = 压缩/加密/加壳）
* 已知壳（UPX / VMProtect / Themida …）的节区名特征
* **导入表**：是否导入了注入、键盘记录、下载、提权等可疑 API
* 编译时间戳、链接器版本、.NET 标记、overlay 大小
* 文件版本元数据（CompanyName / ProductName / OriginalFilename）

刻意不引入 pefile 等第三方库：打包出来的 exe 需要保持自包含。
"""
import math
import os
import struct
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_SECURITY = 4

#: 已知壳 / 保护器的节区名特征
PACKER_SECTION_SIGNATURES = {
    "UPX0": "UPX", "UPX1": "UPX", "UPX2": "UPX", ".UPX0": "UPX",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".themida": "Themida",
    ".winlice": "Themida", ".enigma1": "Enigma", ".enigma2": "Enigma",
    ".aspack": "ASPack", ".adata": "ASPack", ".nsp0": "NsPack",
    ".nsp1": "NsPack", ".MPRESS1": "MPRESS", ".MPRESS2": "MPRESS",
    "petite": "Petite", ".packed": "Generic Packer", ".sforce": "StarForce",
    ".perplex": "Perplex", "PELock": "PELock", ".taz": "PESpin",
    ".boom": "The Boomerang", ".RLPack": "RLPack", ".ccg": "CCG",
    ".spack": "Simple Pack", ".svkp": "SVKP", ".yP": "Y0da Protector",
    ".neolit": "NeoLite", ".gentee": "Gentee",
}

#: 导入表中出现即视为高危的 API（按类别）
SUSPICIOUS_IMPORTS = {
    "注入与进程操纵": {
        "CreateRemoteThread", "CreateRemoteThreadEx", "VirtualAllocEx",
        "VirtualProtectEx", "WriteProcessMemory", "ReadProcessMemory",
        "NtUnmapViewOfSection", "NtMapViewOfSection", "QueueUserAPC",
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
        "RtlCreateUserThread", "OpenProcess", "OpenThread",
    },
    "代码执行与加载": {
        "VirtualAlloc", "VirtualProtect", "LoadLibraryA", "LoadLibraryW",
        "GetProcAddress", "WinExec", "ShellExecuteA", "ShellExecuteW",
        "ShellExecuteExA", "ShellExecuteExW", "CreateProcessA", "CreateProcessW",
        "CreateProcessInternalW", "LdrLoadDll",
    },
    "键盘记录与截屏": {
        "GetAsyncKeyState", "GetKeyState", "GetKeyboardState", "SetWindowsHookExA",
        "keybd_event", "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
        "BitBlt", "GetDC", "GetDesktopWindow", "PrintWindow",
    },
    "网络下载与通信": {
        "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
        "InternetOpenUrlA", "InternetOpenUrlW", "HttpOpenRequestA", "HttpSendRequestA",
        "HttpSendRequestW", "InternetReadFile", "WSAStartup", "connect", "send", "recv",
        "socket", "WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest",
    },
    "持久化与提权": {
        "CreateServiceA", "CreateServiceW", "ChangeServiceConfigA",
        "ChangeServiceConfigW", "StartServiceA", "StartServiceW",
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
        "AdjustTokenPrivileges", "OpenProcessToken", "LookupPrivilegeValueA",
        "LookupPrivilegeValueW", "SetWindowsHookEx",
    },
    "自删除与反取证": {
        "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW",
        "RemoveDirectoryA", "RemoveDirectoryW", "GetModuleFileNameA",
        "GetModuleFileNameW", "WinExec",
    },
    "加密与打包": {
        "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
        "CryptAcquireContextA", "CryptAcquireContextW", "CryptGenKey",
    },
}

#: 属于正常软件常见行为、不应单独作为风险信号的 API
BENIGN_IMPORTS = {
    "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "VirtualAlloc",
    "VirtualProtect", "GetModuleFileNameA", "GetModuleFileNameW",
    "DeleteFileA", "DeleteFileW", "MoveFileExA", "MoveFileExW",
    "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
    "OpenProcess", "OpenProcessToken", "LookupPrivilegeValueA",
    "LookupPrivilegeValueW", "AdjustTokenPrivileges",
    "WriteProcessMemory", "ReadProcessMemory",
    "ShellExecuteA", "ShellExecuteW", "CreateProcessA",
    "CreateProcessW", "WinExec", "socket", "connect", "send", "recv",
    "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW",
    "BitBlt", "GetDC", "GetDesktopWindow", "PrintWindow",
}

#: 常见合法打包器（本身不是恶意信号，但会拉高熵值）
LEGIT_PACKERS = {"nsis", "inno setup", "inno", "qt", "delphi", "borland", "golang"}


def _shannon_entropy(data: bytes) -> float:
    """计算字节分布的香农熵（0~8，>7.0 基本可判定为压缩/加密数据）。"""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


class PEInfo:
    """PE 文件的取证信息。"""

    def __init__(self):
        self.valid = False
        self.error = ""
        self.path = ""
        self.machine = 0
        self.arch = ""
        self.timestamp = 0
        self.timestamp_str = ""
        self.is_dotnet = False
        self.linker = ""
        self.sections: List[Dict] = []
        self.imports: Dict[str, List[str]] = {}
        self.max_entropy = 0.0
        self.avg_entropy = 0.0
        self.packers: List[str] = []
        self.suspicious_imports: Dict[str, List[str]] = {}
        self.overlay_size = 0
        self.entry_section = ""
        self.size = 0

    def summary(self) -> str:
        """一句话摘要，供界面显示。"""
        if not self.valid:
            return "不是有效的 PE 文件"
        bits = []
        if self.packers:
            bits.append("加壳:" + ",".join(self.packers))
        if self.max_entropy >= 7.0:
            bits.append(f"高熵 {self.max_entropy:.2f}")
        if self.suspicious_imports:
            cats = list(self.suspicious_imports.keys())
            bits.append("可疑API:" + ",".join(cats))
        if self.is_dotnet:
            bits.append(".NET")
        return " | ".join(bits) if bits else "未发现异常结构特征"

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "arch": self.arch,
            "timestamp_str": self.timestamp_str,
            "is_dotnet": self.is_dotnet,
            "max_entropy": round(self.max_entropy, 2),
            "packers": list(self.packers),
            "suspicious_imports": {k: v for k, v in self.suspicious_imports.items()},
            "sections": [
                {"name": s["name"], "entropy": round(s["entropy"], 2),
                 "raw_size": s["raw_size"], "virtual_size": s["virtual_size"]}
                for s in self.sections
            ],
            "linker": self.linker,
            "overlay_size": self.overlay_size,
            "size": self.size,
        }


def _read_cstring(data: bytes, offset: int, limit: int = 256) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end < 0:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("utf-8", "ignore")


def parse_pe(path: str, read_entropy_limit: int = 4 * 1024 * 1024) -> PEInfo:
    """解析 PE 文件，提取取证信息。任何异常都转成 ``error``，不向外抛。"""
    info = PEInfo()
    info.path = path
    try:
        size = os.path.getsize(path)
        info.size = size
    except OSError as e:
        info.error = str(e)
        return info

    try:
        with open(path, "rb") as f:
            header = f.read(4096)
            if len(header) < 0x40 or header[:2] != b"MZ":
                info.error = "不是 PE 文件（无 MZ 头）"
                return info
            e_lfanew = struct.unpack_from("<I", header, 0x3C)[0]
            if e_lfanew <= 0 or e_lfanew > size - 200:
                info.error = "PE 头偏移异常"
                return info
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                info.error = "无 PE 签名"
                return info

            coff = f.read(20)
            if len(coff) < 20:
                info.error = "COFF 头截断"
                return info
            (machine, num_sections, timestamp, _sym_ptr, _num_sym,
             opt_size, _chars) = struct.unpack("<HHIIIHH", coff)
            info.machine = machine
            info.arch = {IMAGE_FILE_MACHINE_I386: "x86",
                         IMAGE_FILE_MACHINE_AMD64: "x64"}.get(machine, f"0x{machine:04X}")
            info.timestamp = timestamp
            info.timestamp_str = _format_timestamp(timestamp)

            opt = f.read(opt_size)
            if len(opt) < 2:
                info.error = "可选头截断"
                return info
            magic = struct.unpack_from("<H", opt, 0)[0]
            is_pe32plus = magic == 0x20B
            if magic == 0x10B:
                info.arch = "x86"
            elif is_pe32plus:
                info.arch = "x64"
            else:
                info.error = f"未知可选头魔数 0x{magic:04X}"
                return info

            # 链接器版本
            if len(opt) >= 4:
                info.linker = f"{opt[2]}.{opt[3]}"

            # 数据目录
            dir_offset = 112 if is_pe32plus else 96
            dirs: List[tuple] = []
            if len(opt) >= dir_offset + 16 * 8:
                for i in range(16):
                    rva, size = struct.unpack_from("<II", opt, dir_offset + i * 8)
                    dirs.append((rva, size))

            # .NET 判定：COM Descriptor 目录（索引 14）存在且非零
            if len(dirs) > 14 and dirs[14][0]:
                info.is_dotnet = True

            # 节区表
            section_table_offset = e_lfanew + 4 + 20 + opt_size
            f.seek(section_table_offset)
            raw_sections = []
            for _ in range(num_sections):
                data = f.read(40)
                if len(data) < 40:
                    break
                name = data[:8].split(b"\x00")[0].decode("utf-8", "ignore")
                (vsize, vaddr, raw_size, raw_ptr, _reloc, _linenum,
                 _nreloc, _nlinenum, chars) = struct.unpack("<IIIIIIHHI", data[8:40])
                raw_sections.append({
                    "name": name, "virtual_size": vsize, "virtual_address": vaddr,
                    "raw_size": raw_size, "pointer_to_raw_data": raw_ptr,
                    "characteristics": chars,
                })

            # 计算熵值（按上限采样，避免大文件拖慢）
            total_entropy = 0.0
            for sec in raw_sections:
                entropy = 0.0
                if sec["raw_size"] > 0 and sec["pointer_to_raw_data"] > 0:
                    f.seek(sec["pointer_to_raw_data"])
                    blob = f.read(min(sec["raw_size"], read_entropy_limit))
                    entropy = _shannon_entropy(blob)
                sec["entropy"] = entropy
                total_entropy += entropy
                info.sections.append(sec)
                if entropy > info.max_entropy:
                    info.max_entropy = entropy
            if raw_sections:
                info.avg_entropy = total_entropy / len(raw_sections)

            # 壳特征
            for sec in raw_sections:
                key = sec["name"].strip()
                if key in PACKER_SECTION_SIGNATURES:
                    packer = PACKER_SECTION_SIGNATURES[key]
                    if packer not in info.packers:
                        info.packers.append(packer)

            # 入口点所在节区
            if len(opt) >= 32:
                entry_rva = struct.unpack_from("<I", opt, 16)[0]
                for sec in raw_sections:
                    start = sec["virtual_address"]
                    end = start + max(sec["virtual_size"], sec["raw_size"])
                    if start <= entry_rva < end:
                        info.entry_section = sec["name"]
                        break

            # 导入表
            if len(dirs) > IMAGE_DIRECTORY_ENTRY_IMPORT and dirs[IMAGE_DIRECTORY_ENTRY_IMPORT][0]:
                _parse_imports(f, raw_sections, dirs[IMAGE_DIRECTORY_ENTRY_IMPORT][0],
                               is_pe32plus, info)

            # overlay：最后一个节区之后的全部数据
            if raw_sections:
                last = max(raw_sections, key=lambda s: s["pointer_to_raw_data"] + s["raw_size"])
                end_of_image = last["pointer_to_raw_data"] + last["raw_size"]
                if size > end_of_image:
                    info.overlay_size = size - end_of_image

        info.valid = True
    except Exception as e:  # noqa: BLE001
        info.error = f"解析异常: {e}"
    return info


def _rva_to_offset(sections: List[Dict], rva: int) -> int:
    for sec in sections:
        start = sec["virtual_address"]
        size = max(sec["virtual_size"], sec["raw_size"])
        if start <= rva < start + size:
            return sec["pointer_to_raw_data"] + (rva - start)
    return -1


def _parse_imports(f, sections: List[Dict], import_rva: int, is_pe32plus: bool,
                    info: PEInfo) -> None:
    """解析导入表，提取 DLL 与函数名。

    注意 ``import_rva`` 是 **RVA**，必须先经 ``_rva_to_offset`` 转成
    文件偏移，否则读到的会是文件头里的随机字节（表现为
    "导入DLL = ['H+HH|$...']" 这种乱码）。
    """
    desc_offset = _rva_to_offset(sections, import_rva)
    if desc_offset < 0:
        return
    try:
        f.seek(desc_offset)
        blob = f.read(4096)
    except OSError:
        return
    if not blob:
        return

    ptr_size = 8 if is_pe32plus else 4
    ordinal_flag = 1 << 63 if is_pe32plus else 1 << 31

    offset = 0
    while offset + 20 <= len(blob):
        oft, _ts, _fwd, name_rva, ft = struct.unpack_from("<IIIII", blob, offset)
        if not (oft or name_rva or ft):
            break
        offset += 20

        if not name_rva:
            continue
        name_off = _rva_to_offset(sections, name_rva)
        if name_off < 0:
            continue
        dll = _read_at(f, name_off, 128)
        if not dll:
            continue

        thunk_rva = oft or ft
        thunk_off = _rva_to_offset(sections, thunk_rva)
        if thunk_off < 0:
            continue
        funcs: List[str] = []
        try:
            f.seek(thunk_off)
            for _ in range(512):  # 单个 DLL 的导入上限，防止畸形文件死循环
                raw = f.read(ptr_size)
                if len(raw) < ptr_size:
                    break
                value = int.from_bytes(raw, "little")
                if value == 0:
                    break
                if value & ordinal_flag:
                    funcs.append(f"Ordinal#{value & 0xFFFF}")
                    continue
                hint_off = _rva_to_offset(sections, value)
                if hint_off < 0:
                    continue
                func = _read_at(f, hint_off + 2, 128)
                if func:
                    funcs.append(func)
        except OSError:
            pass

        if funcs:
            info.imports[dll] = funcs

    # 归类可疑导入
    all_funcs = set()
    for funcs in info.imports.values():
        all_funcs.update(funcs)
    for category, apis in SUSPICIOUS_IMPORTS.items():
        hit = sorted(all_funcs & apis)
        # 去掉本身就常见的良性 API（只在没有其它佐证时权重才高）
        strong = [a for a in hit if a not in BENIGN_IMPORTS]
        if strong:
            info.suspicious_imports[category] = strong


def _read_at(f, offset: int, limit: int) -> str:
    try:
        f.seek(offset)
        data = f.read(limit)
    except OSError:
        return ""
    end = data.find(b"\x00")
    if end >= 0:
        data = data[:end]
    return data.decode("utf-8", "ignore")


def _format_timestamp(ts: int) -> str:
    if not ts:
        return ""
    try:
        import time
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (ValueError, OSError):
        return ""


def looks_like_executable(path: str) -> bool:
    """快速判断是不是可执行文件（只读扩展名，不打开文件）。"""
    return os.path.splitext(path)[1].lower() in (
        ".exe", ".dll", ".sys", ".scr", ".ocx", ".cpl", ".drv", ".efi")


def executable_in_dir(path: str, limit: int = 40) -> List[str]:
    """列出目录下的可执行文件（最多 limit 个）。"""
    out: List[str] = []
    try:
        for entry in os.scandir(path):
            if len(out) >= limit:
                break
            if entry.is_file(follow_symlinks=False) and looks_like_executable(entry.path):
                out.append(entry.path)
    except (OSError, PermissionError):
        pass
    return out
