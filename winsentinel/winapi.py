"""Small Windows helpers: admin check, elevation, hidden subprocesses, opening files.

Every function degrades to something harmless off Windows so the pure logic stays
testable with mocks.
"""

from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

WINDOWS = sys.platform == "win32"
CREATE_NO_WINDOW = 0x08000000
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
DETACHED_PROCESS = 0x00000008


def no_window() -> dict[str, Any]:
    """Popen kwargs that keep a console program from flashing a window."""
    return {"creationflags": CREATE_NO_WINDOW} if WINDOWS else {}


def is_admin() -> bool:
    if WINDOWS:
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except OSError:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def relaunch_as_admin(args: list[str]) -> bool:
    """Start this program again elevated (UAC prompt). True if the prompt was accepted."""
    if not WINDOWS:
        return False
    if getattr(sys, "frozen", False):
        program, params = sys.executable, args
    else:
        program, params = sys.executable, ["-m", "winsentinel.gui", *args]
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", program, subprocess.list2cmdline(params), None, 1
    )
    return int(rc) > 32


def system_root() -> Path:
    return Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")


def system32(name: str) -> str:
    """Full path of a System32 program (never resolved through PATH) when on Windows."""
    if not WINDOWS:
        return name
    return str(system_root() / "System32" / name)


def run_hidden(args: list[str], timeout: float = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
        **no_window(),
    )


def open_path(path: Path | str) -> None:
    """Open a file or folder with its default program."""
    try:
        if WINDOWS:
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.run(["open", str(path)], check=False)
        else:
            subprocess.run(["xdg-open", str(path)], check=False)
    except OSError as e:
        logger.warning("Could not open %s: %s", path, e)


def reveal(path: Path | str) -> None:
    """Show a file selected in Explorer (its folder elsewhere)."""
    p = Path(path)
    if WINDOWS and p.exists():
        subprocess.Popen(["explorer.exe", f"/select,{p}"])
    else:
        open_path(p.parent if p.suffix else p)


def spawn_detached(args: list[str]) -> None:
    """Start a program that must outlive this one (the updater's installer).

    Breaking away from a job object keeps Task Scheduler (which started the app at
    logon) from taking the installer down with it; not every job allows that.
    """
    if not WINDOWS:
        subprocess.Popen(args, start_new_session=True)
        return
    try:
        subprocess.Popen(args, creationflags=DETACHED_PROCESS | CREATE_BREAKAWAY_FROM_JOB)
    except OSError:
        subprocess.Popen(args, creationflags=DETACHED_PROCESS)


def computer_name() -> str:
    import socket

    return os.environ.get("COMPUTERNAME") or socket.gethostname()
