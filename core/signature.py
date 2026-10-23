"""Windows 数字签名与文件元数据取证。

流氓软件最常见的两种伪装手法，都能靠这里揭穿：

1. **伪造发布者**——在文件名/目录名上写"腾讯""百度卫士"，但真正的
   Authenticode 签名者完全是另一家（甚至根本没有签名）。
2. **签名无效**——拿合法证书改个名，或者直接改 PE 内容导致签名校验失败
   （``TRUST_E_BAD_DIGEST``）。这比"没有签名"严重得多。

本模块只做"读"，不修改任何系统状态。
"""
import ctypes
import logging
import os
from ctypes import wintypes
from typing import Dict

# ---------------------------------------------------------------------------
# WinVerifyTrust
# ---------------------------------------------------------------------------


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPCWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


#: WINTRUST_ACTION_GENERIC_VERIFY_V2
_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

_WTD_UI_NONE = 2
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
_WTD_REVOCATION_CHECK_NONE = 0x10

# WinVerifyTrust 返回码
_TRUST_E_NOSIGNATURE = 0x800B0100
_TRUST_E_SUBJECT_NOT_TRUSTED = 0x800B0004
_TRUST_E_BAD_DIGEST = 0x80096010
_TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
_TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
_CERT_E_EXPIRED = 0x800B0101
_CERT_E_UNTRUSTEDROOT = 0x800B0109
_CERT_E_CHAINING = 0x800B010A
_CERT_E_WRONG_USAGE = 0x800B0110
_TRUST_E_TIME_STAMP = 0x80096004
_TRUST_E_SELF_SIGNED = 0x800B0102
_TRUST_E_UNKNOWN = 0x80092003


def _verify_trust(path: str):
    """调用 WinVerifyTrust 校验 Authenticode 签名。

    返回 ``(hr, signer, issuer)``：签名者与颁发者取自 WinVerifyTrust 的
    状态数据（``WTHelperProvDataFromStateData`` → 签名者链 → 证书），
    这条路不依赖已废弃的 ``CryptQueryObject``。
    """
    try:
        wintrust = ctypes.WinDLL("wintrust")
    except OSError:
        return -1, "", ""

    wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [ctypes.c_void_p, wintypes.DWORD]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p]
    wintrust.WTHelperGetProvCertFromChain.restype = ctypes.c_void_p

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(file_info)
    file_info.pcwszFilePath = path
    file_info.hFile = None

    data = _WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.pPolicyCallbackData = None
    data.pSIPClientData = None
    data.dwUIChoice = _WTD_UI_NONE
    # 不联网做吊销检查：既快，也不会在离线环境卡住
    data.fdwRevocationChecks = _WTD_REVOCATION_CHECK_NONE
    data.dwUnionChoice = _WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = _WTD_STATEACTION_VERIFY
    data.hWVTStateData = None
    data.pwszURLReference = None
    data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL
    data.dwUIContext = 0
    data.pSignatureSettings = None

    hr = wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                                 ctypes.byref(data))

    signer = issuer = ""
    try:
        if data.hWVTStateData:
            prov_data = wintrust.WTHelperProvDataFromStateData(data.hWVTStateData)
            if prov_data:
                sgnr = wintrust.WTHelperGetProvSignerFromChain(prov_data, 0)
                if sgnr:
                    cert = wintrust.WTHelperGetProvCertFromChain(sgnr)
                    if cert:
                        signer = _cert_name(cert, _CERT_NAME_SIMPLE_DISPLAY_TYPE)
                        issuer = _cert_name(cert, _CERT_NAME_ISSUER_TYPE)
    except Exception as e:  # noqa: BLE001
        logging.debug(f"提取签名者失败: {e}")

    # 必须关闭状态数据，否则会泄漏
    data.dwStateAction = _WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2),
                            ctypes.byref(data))
    return int(ctypes.c_uint32(hr).value), signer, issuer


# ---------------------------------------------------------------------------
# 证书名称读取
# ---------------------------------------------------------------------------

_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
_CERT_NAME_ISSUER_TYPE = 5

_crypt32 = None
_crypt32_ready = False


def _get_crypt32():
    """加载 crypt32 并配置好原型（只做一次）。"""
    global _crypt32, _crypt32_ready
    if _crypt32_ready:
        return _crypt32
    try:
        crypt32 = ctypes.WinDLL("crypt32")
        crypt32.CertGetNameStringW.argtypes = [
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            wintypes.LPWSTR, wintypes.DWORD]
        crypt32.CertGetNameStringW.restype = wintypes.DWORD
        _crypt32 = crypt32
    except Exception as e:  # noqa: BLE001
        logging.debug(f"加载 crypt32 失败: {e}")
        _crypt32 = None
    _crypt32_ready = True
    return _crypt32


def _cert_name(cert, name_type: int) -> str:
    """从证书上下文取名称（签名者 / 颁发者）。"""
    try:
        crypt32 = _get_crypt32()
        if crypt32 is None:
            return ""
        size = wintypes.DWORD(0)
        crypt32.CertGetNameStringW(cert, name_type, 0, None, None,
                                   ctypes.byref(size))
        if not size.value:
            return ""
        buf = ctypes.create_unicode_buffer(size.value)
        if not crypt32.CertGetNameStringW(cert, name_type, 0, None, buf,
                                          ctypes.byref(size)):
            return ""
        return buf.value
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# 文件版本信息
# ---------------------------------------------------------------------------

#: 常见的语言-代码页组合（Translation 取不到时的兜底）
_FALLBACK_TRANSLATIONS = ["080404B0", "040904B0", "040904E4", "080404E4",
                          "080904B0", "0C0A0409", "041104E4"]


def get_version_info(path: str) -> Dict[str, str]:
    """读取 PE 的版本资源（CompanyName / ProductName / OriginalFilename …）。

    VS_VERSIONINFO 里的字符串是 **UTF-16LE**，用 utf-8 解会得到乱码。
    """
    info = {
        "company": "", "product": "", "description": "",
        "original_filename": "", "internal_name": "", "file_version": "",
    }
    try:
        version = ctypes.windll.version
        version.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD)]
        version.GetFileVersionInfoW.restype = wintypes.BOOL
        version.VerQueryValueW.argtypes = [
            ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT)]
        version.VerQueryValueW.restype = wintypes.BOOL

        size = wintypes.DWORD(0)
        version.GetFileVersionInfoW(path, 0, 0, None, ctypes.byref(size))
        if not size.value:
            size = wintypes.DWORD(8192)
        buf = ctypes.create_string_buffer(size.value)
        if not version.GetFileVersionInfoW(path, 0, size.value, buf, None):
            return info

        def query(query_path: str) -> str:
            ptr = ctypes.c_void_p()
            sub_len = wintypes.UINT(0)
            if not version.VerQueryValueW(buf, query_path, ctypes.byref(ptr),
                                          ctypes.byref(sub_len)):
                return ""
            if not ptr:
                return ""
            raw = ctypes.string_at(ptr, sub_len.value)
            return raw.decode("utf-16-le", "ignore").rstrip("\x00")

        codes = []
        trans_raw = query("\\VarFileInfo\\Translation")
        if trans_raw:
            raw = trans_raw.encode("utf-16-le")
            for i in range(0, len(raw) - 3, 4):
                val = int.from_bytes(raw[i:i + 4], "little")
                codes.append(f"{val & 0xFFFF:04X}{val >> 16:04X}")
        codes += _FALLBACK_TRANSLATIONS

        for code in codes:
            base = f"\\StringFileInfo\\{code}\\"
            info["company"] = info["company"] or query(base + "CompanyName")
            info["product"] = info["product"] or query(base + "ProductName")
            info["description"] = info["description"] or query(base + "FileDescription")
            info["original_filename"] = info["original_filename"] or query(
                base + "OriginalFilename")
            info["internal_name"] = info["internal_name"] or query(base + "InternalName")
            info["file_version"] = info["file_version"] or query(base + "FileVersion")
            if info["company"] or info["product"]:
                break
    except Exception as e:
        logging.debug(f"读取版本信息失败: {e}")
    return info


# ---------------------------------------------------------------------------
# 对外接口
# ---------------------------------------------------------------------------


def verify_signature(path: str) -> Dict:
    """验证 Authenticode 签名。

    返回::

        {
          "status": "valid" | "unsigned" | "invalid" | "untrusted" | "expired" | "error",
          "status_text": "中文描述",
          "signer": "签名者（部分系统上取不到，为空）",
          "issuer": "证书颁发者",
          "self_signed": bool,
          "hresult": int,
        }
    """
    result = {
        "status": "error", "status_text": "", "signer": "", "issuer": "",
        "self_signed": False, "hresult": -1,
    }
    if not os.path.isfile(path):
        result["status_text"] = "文件不存在"
        return result

    try:
        hr, signer, issuer = _verify_trust(path)
    except Exception as e:  # noqa: BLE001
        result["status_text"] = f"签名校验异常: {e}"
        return result

    result["hresult"] = hr
    if hr == 0:
        result["status"] = "valid"
        result["status_text"] = "签名有效"
    elif hr == _TRUST_E_NOSIGNATURE:
        result["status"] = "unsigned"
        result["status_text"] = "未签名"
    elif hr == _TRUST_E_BAD_DIGEST:
        # 只有摘要对不上才说明内容被改过，这是最硬的一条证据
        result["status"] = "invalid"
        result["status_text"] = "签名摘要不匹配（文件内容被修改过）"
    elif hr in (_CERT_E_EXPIRED, _TRUST_E_TIME_STAMP):
        result["status"] = "expired"
        result["status_text"] = "证书已过期"
    elif hr in (_TRUST_E_SUBJECT_NOT_TRUSTED, _CERT_E_UNTRUSTEDROOT,
                _CERT_E_CHAINING, _TRUST_E_PROVIDER_UNKNOWN,
                _TRUST_E_SUBJECT_FORM_UNKNOWN, _CERT_E_WRONG_USAGE,
                _TRUST_E_SELF_SIGNED, _TRUST_E_UNKNOWN):
        result["status"] = "untrusted"
        result["status_text"] = "签名不受信任（自签名或证书链有问题）"
    else:
        # 未知错误码不能乱下结论——尤其不能断言"文件被篡改"
        result["status"] = "untrusted"
        result["status_text"] = f"签名未通过校验（0x{hr:08X}）"

    result["signer"] = signer
    result["issuer"] = issuer
    if signer and issuer:
        result["self_signed"] = signer.strip().lower() == issuer.strip().lower()
    return result


def get_publisher(path: str) -> str:
    """取程序自称的发布者。

    优先用 Authenticode 签名者；取不到时退回版本资源里的 CompanyName。
    流氓软件最爱在"自称"这一栏动手脚，所以它要和签名真实性分开看。
    """
    try:
        sig = verify_signature(path)
        if sig.get("signer"):
            return sig["signer"]
    except Exception:
        pass
    try:
        return get_version_info(path).get("company", "")
    except Exception:
        return ""


def quick_signature_state(path: str) -> str:
    """只要一个结论字符串（用于列表展示）。"""
    return verify_signature(path)["status_text"] or "未知"

