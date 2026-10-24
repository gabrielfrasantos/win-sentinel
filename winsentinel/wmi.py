"""WMI queries and COM objects through pywin32 (Windows only).

``query()`` returns plain dicts (property name -> Python value, plus ``__CLASS``), so
no COM object leaks out to other threads. Every thread that uses COM must call
``ensure_com()`` first; ``query()`` and ``dispatch()`` do it for you.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from typing import Any

from winsentinel import winapi

logger = logging.getLogger(__name__)

_thread = threading.local()


class WmiError(RuntimeError):
    """A WMI query or COM call failed (or this isn't Windows)."""


def ensure_com() -> None:
    """Initialize COM once for the calling thread (left initialized until it ends)."""
    if getattr(_thread, "ready", False):
        return
    import pythoncom

    pythoncom.CoInitialize()
    _thread.ready = True


def com_message(error: BaseException) -> str:
    """Readable text for a pywintypes.com_error (the excepinfo description if any)."""
    args: tuple[Any, ...] = tuple(getattr(error, "args", ()))
    if len(args) >= 3 and args[2] and len(args[2]) >= 3 and args[2][2]:
        return str(args[2][2]).strip()
    if len(args) >= 2 and args[1]:
        return f"{args[1]} (0x{int(args[0]) & 0xFFFFFFFF:08X})"
    return str(error)


def dispatch(progid: str) -> Any:
    """A late-bound COM object (no generated wrappers, which a frozen app can't write)."""
    if not winapi.WINDOWS:
        raise WmiError(f"{progid} needs Windows")
    ensure_com()
    import pywintypes
    import win32com.client.dynamic

    try:
        return win32com.client.dynamic.Dispatch(progid)
    except pywintypes.com_error as e:
        raise WmiError(f"{progid}: {com_message(e)}") from None


def _value(v: Any) -> Any:
    if isinstance(v, tuple):
        return [_value(x) for x in v]
    return v


def _connect(namespace: str) -> Any:
    import win32com.client

    return win32com.client.GetObject(
        f"winmgmts:{{impersonationLevel=impersonate}}!\\\\.\\{namespace}"
    )


def _rows(service: Any, wql: str) -> list[dict[str, Any]]:
    rows = []
    for obj in service.ExecQuery(wql):
        row = {p.Name: _value(p.Value) for p in obj.Properties_}
        row["__CLASS"] = str(obj.Path_.Class)
        rows.append(row)
    return rows


def query(wql: str, namespace: str = r"root\cimv2") -> list[dict[str, Any]]:
    """Run a WQL query; raises WmiError (e.g. a namespace that doesn't exist)."""
    if not winapi.WINDOWS:
        raise WmiError("WMI needs Windows")
    ensure_com()
    import pywintypes

    try:
        return _rows(_connect(namespace), wql)
    except pywintypes.com_error as e:
        raise WmiError(f"{namespace}: {com_message(e)}") from None


def sample(wql: str, namespace: str = r"root\cimv2", gap: float = 1.0) -> list[dict[str, Any]]:
    """Read a formatted performance class twice on one connection, ``gap`` seconds apart:
    rates (CPU, GPU utilization) are only meaningful on the second read."""
    if not winapi.WINDOWS:
        raise WmiError("WMI needs Windows")
    ensure_com()
    import pywintypes

    try:
        service = _connect(namespace)
        _rows(service, wql)
        time.sleep(gap)
        return _rows(service, wql)
    except pywintypes.com_error as e:
        raise WmiError(f"{namespace}: {com_message(e)}") from None


def cim_datetime(value: Any) -> dt.datetime | None:
    """WMI's 'yyyymmddHHMMSS.ffffff+UUU' (or a pywintypes time) as a naive local datetime."""
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.replace(tzinfo=None)
    text = str(value)
    try:
        return dt.datetime.strptime(text[:14], "%Y%m%d%H%M%S")
    except ValueError:
        return None
