"""Authenticode signature check through WinVerifyTrust (ctypes, Windows only).

Programs carry their signature inside the file; most of Windows' own files are
signed through a catalog instead, so an unsigned file is looked up in the system
catalogs before it is called unsigned. Revocation isn't checked online (a scan
must not wait on the network).
"""

from __future__ import annotations

import ctypes
import logging
from ctypes import wintypes
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SIGNED, UNSIGNED, INVALID, UNKNOWN = "signed", "unsigned", "invalid", "unknown"

_UNSIGNED_CODES = {0x800B0100, 0x800B0003, 0x800B0001}
_INVALID_CODES = {
    0x80096010,
    0x80096004,
    0x800B0111,
    0x800B0109,
    0x800B010A,
    0x800B0101,
    0x800B010C,
}

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_CHOICE_CATALOG = 2
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1)


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


WINTRUST_ACTION_GENERIC_VERIFY_V2 = GUID(
    0xAAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pUnion", ctypes.c_void_p),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class CRYPT_PROVIDER_CERT(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("pCert", ctypes.c_void_p)]


class CRYPT_PROVIDER_SGNR(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("sftVerifyAsOf", wintypes.FILETIME),
        ("csCertChain", wintypes.DWORD),
        ("pasCertChain", ctypes.POINTER(CRYPT_PROVIDER_CERT)),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wintypes.DWORD), ("wszCatalogFile", wintypes.WCHAR * 260)]


_api: tuple[Any, Any] | None = None


def _dlls() -> tuple[Any, Any]:
    global _api
    if _api is None:
        wintrust: Any = ctypes.WinDLL("wintrust.dll")
        crypt32: Any = ctypes.WinDLL("crypt32.dll")
        wintrust.WinVerifyTrust.argtypes = [wintypes.HANDLE, ctypes.POINTER(GUID), ctypes.c_void_p]
        wintrust.WinVerifyTrust.restype = wintypes.LONG
        wintrust.WTHelperProvDataFromStateData.argtypes = [wintypes.HANDLE]
        wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
        wintrust.WTHelperGetProvSignerFromChain.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.BOOL,
            wintypes.DWORD,
        ]
        wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.POINTER(CRYPT_PROVIDER_SGNR)
        wintrust.CryptCATAdminAcquireContext2.argtypes = [
            ctypes.POINTER(wintypes.HANDLE),
            ctypes.POINTER(GUID),
            wintypes.LPCWSTR,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        wintrust.CryptCATAdminAcquireContext2.restype = wintypes.BOOL
        wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
        ]
        wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
        wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_ubyte),
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.HANDLE),
        ]
        wintrust.CryptCATAdminEnumCatalogFromHash.restype = wintypes.HANDLE
        wintrust.CryptCATCatalogInfoFromContext.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(CATALOG_INFO),
            wintypes.DWORD,
        ]
        wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
        wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
            wintypes.HANDLE,
            wintypes.HANDLE,
            wintypes.DWORD,
        ]
        wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        crypt32.CertGetNameStringW.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.LPWSTR,
            wintypes.DWORD,
        ]
        crypt32.CertGetNameStringW.restype = wintypes.DWORD
        _api = (wintrust, crypt32)
    return _api


def _signer(state: wintypes.HANDLE) -> str:
    wintrust, crypt32 = _dlls()
    prov = wintrust.WTHelperProvDataFromStateData(state)
    if not prov:
        return ""
    sgnr = wintrust.WTHelperGetProvSignerFromChain(prov, 0, False, 0)
    if not sgnr or not sgnr.contents.csCertChain:
        return ""
    cert = sgnr.contents.pasCertChain[0].pCert
    buf = ctypes.create_unicode_buffer(256)
    crypt32.CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, len(buf))
    return buf.value


def _verify(choice: int, union: ctypes.c_void_p) -> tuple[int, str]:
    wintrust, _ = _dlls()
    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(data)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = choice
    data.pUnion = union
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
    action = ctypes.byref(WINTRUST_ACTION_GENERIC_VERIFY_V2)
    code = wintrust.WinVerifyTrust(INVALID_HANDLE_VALUE, action, ctypes.byref(data))
    code &= 0xFFFFFFFF
    signer = _signer(data.hWVTStateData) if code == 0 else ""
    data.dwStateAction = WTD_STATEACTION_CLOSE
    wintrust.WinVerifyTrust(INVALID_HANDLE_VALUE, action, ctypes.byref(data))
    return code, signer


def _embedded(path: str) -> tuple[int, str]:
    info = WINTRUST_FILE_INFO()
    info.cbStruct = ctypes.sizeof(info)
    info.pcwszFilePath = path
    return _verify(WTD_CHOICE_FILE, ctypes.cast(ctypes.pointer(info), ctypes.c_void_p))


def _catalog(path: str) -> tuple[int, str] | None:
    """Verify through the catalog that lists the file's hash; None when none does."""
    import msvcrt

    wintrust, _ = _dlls()
    admin = wintypes.HANDLE()
    if not wintrust.CryptCATAdminAcquireContext2(ctypes.byref(admin), None, "SHA256", None, 0):
        return None
    try:
        with Path(path).open("rb") as f:
            handle = wintypes.HANDLE(msvcrt.get_osfhandle(f.fileno()))
            size = wintypes.DWORD(0)
            wintrust.CryptCATAdminCalcHashFromFileHandle2(
                admin, handle, ctypes.byref(size), None, 0
            )
            if not size.value:
                return None
            digest = (ctypes.c_ubyte * size.value)()
            if not wintrust.CryptCATAdminCalcHashFromFileHandle2(
                admin, handle, ctypes.byref(size), digest, 0
            ):
                return None
            cat = wintrust.CryptCATAdminEnumCatalogFromHash(admin, digest, size, 0, None)
            if not cat:
                return None
            try:
                cat_info = CATALOG_INFO()
                cat_info.cbStruct = ctypes.sizeof(cat_info)
                if not wintrust.CryptCATCatalogInfoFromContext(cat, ctypes.byref(cat_info), 0):
                    return None
                info = WINTRUST_CATALOG_INFO()
                info.cbStruct = ctypes.sizeof(info)
                info.pcwszCatalogFilePath = cat_info.wszCatalogFile
                info.pcwszMemberTag = bytes(digest).hex().upper()
                info.pcwszMemberFilePath = path
                info.hMemberFile = handle
                info.pbCalculatedFileHash = digest
                info.cbCalculatedFileHash = size.value
                info.hCatAdmin = admin
                return _verify(
                    WTD_CHOICE_CATALOG, ctypes.cast(ctypes.pointer(info), ctypes.c_void_p)
                )
            finally:
                wintrust.CryptCATAdminReleaseCatalogContext(admin, cat, 0)
    finally:
        wintrust.CryptCATAdminReleaseContext(admin, 0)


def _status(code: int) -> str:
    if code == 0:
        return SIGNED
    if code in _UNSIGNED_CODES:
        return UNSIGNED
    if code in _INVALID_CODES:
        return INVALID
    return UNKNOWN


def verify(path: str) -> tuple[str, str]:
    """(signed | unsigned | invalid | unknown, signer name) for a file."""
    try:
        code, signer = _embedded(path)
        status = _status(code)
        if status != UNSIGNED:
            return status, signer
        found = _catalog(path)
        if found is None:
            return UNSIGNED, ""
        cat_code, cat_signer = found
        return (SIGNED, cat_signer) if cat_code == 0 else (_status(cat_code), "")
    except OSError as e:
        logger.debug("Signature check failed for %s: %s", path, e)
        return UNKNOWN, ""
