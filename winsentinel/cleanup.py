"""Disk cleanup: temp folders, caches, logs, crash dumps, Recycle Bin, DNS cache and the
Windows component store.

Only caches and leftovers are touched, never documents, settings or the registry.
The walker never follows symlinks or junctions and never descends into reparse
points (OneDrive placeholders included), files in use are skipped, and temp files
younger than ``min_age_hours`` stay (installers may still need them).
"""

from __future__ import annotations

import ctypes
import fnmatch
import glob
import logging
import os
import re
import stat
import subprocess
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from winsentinel import winapi
from winsentinel.report import ALERT, OK, Cancelled, Context, Report, human_size, table

logger = logging.getLogger(__name__)

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass(frozen=True)
class Target:
    """One cleanup item. ``paths`` may hold %ENV% variables and ``*`` wildcards;
    ``patterns`` limits deletion to matching file names."""

    id: str
    label: str
    paths: tuple[str, ...] = ()
    description: str = ""
    default: bool = True
    admin: bool = False
    kind: str = "files"
    patterns: tuple[str, ...] = ()
    aged: bool = False


_CHROMIUM_CACHES = ("Cache", "Code Cache", "GPUCache")

TARGETS: tuple[Target, ...] = (
    Target("user-temp", "User temp files", ("%TEMP%",), "your %TEMP% folder", aged=True),
    Target(
        "windows-temp",
        "Windows temp files",
        (r"%SystemRoot%\Temp",),
        r"C:\Windows\Temp",
        admin=True,
        aged=True,
    ),
    Target(
        "update-cache",
        "Windows Update downloads",
        (r"%SystemRoot%\SoftwareDistribution\Download",),
        "already installed update packages",
        admin=True,
    ),
    Target(
        "delivery-optimization",
        "Delivery Optimization cache",
        (
            r"%SystemRoot%\SoftwareDistribution\DeliveryOptimization",
            r"%SystemRoot%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows"
            r"\DeliveryOptimization\Cache",
        ),
        "update files shared with other PCs",
        admin=True,
    ),
    Target(
        "setup-logs",
        "Windows setup logs",
        (r"%SystemRoot%\Logs\CBS", r"%SystemRoot%\Logs\DISM"),
        "CBS and DISM logs",
        admin=True,
    ),
    Target(
        "error-reports",
        "Windows error reports",
        (
            r"%ProgramData%\Microsoft\Windows\WER\ReportArchive",
            r"%ProgramData%\Microsoft\Windows\WER\ReportQueue",
            r"%LOCALAPPDATA%\Microsoft\Windows\WER",
        ),
        "crash reports already sent (or never sent) to Microsoft",
        admin=True,
    ),
    Target("crash-dumps", "App crash dumps", (r"%LOCALAPPDATA%\CrashDumps",), "per-app dumps"),
    Target(
        "system-dumps",
        "System crash dumps",
        (r"%SystemRoot%\Minidump", r"%SystemRoot%\MEMORY.DMP"),
        "keep them while you diagnose blue screens",
        default=False,
        admin=True,
    ),
    Target(
        "thumbnails",
        "Thumbnail and icon cache",
        (r"%LOCALAPPDATA%\Microsoft\Windows\Explorer",),
        "rebuilt by Explorer as needed",
        patterns=("thumbcache_*.db", "iconcache_*.db"),
    ),
    Target(
        "inet-cache",
        "Internet cache (legacy)",
        (r"%LOCALAPPDATA%\Microsoft\Windows\INetCache",),
        "IE / WebView temporary files",
    ),
    Target(
        "chrome-cache",
        "Google Chrome cache",
        tuple(rf"%LOCALAPPDATA%\Google\Chrome\User Data\*\{c}" for c in _CHROMIUM_CACHES),
        "all profiles; close Chrome for a full clean",
    ),
    Target(
        "edge-cache",
        "Microsoft Edge cache",
        tuple(rf"%LOCALAPPDATA%\Microsoft\Edge\User Data\*\{c}" for c in _CHROMIUM_CACHES),
        "all profiles; close Edge for a full clean",
    ),
    Target(
        "firefox-cache",
        "Firefox cache",
        (r"%LOCALAPPDATA%\Mozilla\Firefox\Profiles\*\cache2",),
        "all profiles; close Firefox for a full clean",
    ),
    Target(
        "shader-cache",
        "DirectX shader cache",
        (r"%LOCALAPPDATA%\D3DSCache",),
        "rebuilt by games as needed",
    ),
    Target(
        "prefetch",
        "Prefetch",
        (r"%SystemRoot%\Prefetch",),
        "Windows rebuilds it; programs start slower until then",
        default=False,
        admin=True,
    ),
    Target("recycle-bin", "Recycle Bin", description="all drives", kind="recyclebin"),
    Target("dns-cache", "DNS resolver cache", description="flush only, frees no space", kind="dns"),
    Target(
        "component-store",
        "Windows component store (DISM)",
        description="removes superseded Windows components; takes several minutes",
        admin=True,
        kind="dism",
    ),
)
TARGETS_BY_ID = {t.id: t for t in TARGETS}
DEFAULT_TARGETS = tuple(t.id for t in TARGETS if t.default)


def selected_targets(ids: Iterable[str] | None) -> list[Target]:
    """Targets for the saved selection (None = the defaults), in display order."""
    chosen = set(DEFAULT_TARGETS if ids is None else ids)
    return [t for t in TARGETS if t.id in chosen]


_ENV_VAR = re.compile(r"%([^%]+)%")


def expand(pattern: str) -> list[Path]:
    """Existing paths for a target pattern: %VAR% expanded (unset = no match), then globbed."""
    missing = False

    def sub(m: re.Match[str]) -> str:
        nonlocal missing
        value = os.environ.get(m.group(1))
        if not value:
            missing = True
            return ""
        return glob.escape(value)

    expanded = _ENV_VAR.sub(sub, pattern)
    if missing:
        return []
    if os.sep != "\\":
        expanded = expanded.replace("\\", os.sep)
    return sorted(Path(p) for p in glob.glob(expanded))  # noqa: PTH207


def _is_link(entry: os.DirEntry[str]) -> bool:
    if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
        return True
    try:
        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


@dataclass
class Tally:
    files: int = 0
    bytes: int = 0
    skipped: int = 0


def _files(
    root: Path, patterns: tuple[str, ...], newest: float | None
) -> Iterator[tuple[Path, int]]:
    """(path, size) of every deletable file under root, never crossing a link."""
    if root.is_file():
        try:
            st = root.stat()
        except OSError:
            return
        if newest is None or st.st_mtime <= newest:
            yield root, st.st_size
        return
    stack = [root]
    while stack:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            try:
                if _is_link(entry):
                    continue
                if entry.is_dir(follow_symlinks=False):
                    stack.append(Path(entry.path))
                    continue
                if patterns and not any(fnmatch.fnmatch(entry.name.lower(), p) for p in patterns):
                    continue
                st = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if newest is not None and st.st_mtime > newest:
                continue
            yield Path(entry.path), st.st_size


def _cutoff(target: Target, min_age_hours: int) -> float | None:
    if not target.aged or min_age_hours <= 0:
        return None
    return time.time() - min_age_hours * 3600


def _roots(target: Target) -> list[Path]:
    return [p for pattern in target.paths for p in expand(pattern)]


def measure(target: Target, min_age_hours: int = 0) -> Tally:
    tally = Tally()
    if target.kind == "recyclebin":
        size, count = recycle_bin_size()
        return Tally(files=count, bytes=size)
    newest = _cutoff(target, min_age_hours)
    for root in _roots(target):
        for _, size in _files(root, target.patterns, newest):
            tally.files += 1
            tally.bytes += size
    return tally


def _remove(path: Path) -> bool:
    try:
        path.unlink()
        return True
    except PermissionError:
        try:
            path.chmod(stat.S_IWRITE)
            path.unlink()
            return True
        except OSError:
            return False
    except OSError:
        return False


def _folders(root: Path) -> list[tuple[Path, float]]:
    """Every folder under root (not root, never through a link), parents first, with
    its modification time."""
    found: list[tuple[Path, float]] = []
    stack = [root]
    while stack:
        folder = stack.pop()
        try:
            entries = list(os.scandir(folder))
        except OSError:
            continue
        for entry in entries:
            try:
                if _is_link(entry) or not entry.is_dir(follow_symlinks=False):
                    continue
                mtime = entry.stat(follow_symlinks=False).st_mtime
            except OSError:
                continue
            found.append((Path(entry.path), mtime))
            stack.append(Path(entry.path))
    return found


def _prune(folders: list[tuple[Path, float]], newest: float | None) -> None:
    """Remove the folders that are empty now, deepest first. Ages come from before the
    clean (deleting a file touches its folder), so recent folders stay."""
    for folder, mtime in reversed(folders):
        if newest is not None and mtime > newest:
            continue
        try:
            folder.rmdir()
        except OSError:
            pass


def clean_files(target: Target, min_age_hours: int, ctx: Context) -> Tally:
    tally = Tally()
    newest = _cutoff(target, min_age_hours)
    for root in _roots(target):
        folders = _folders(root) if not target.patterns and root.is_dir() else []
        for path, size in _files(root, target.patterns, newest):
            if tally.files % 200 == 0:
                ctx.check()
            if _remove(path):
                tally.files += 1
                tally.bytes += size
            else:
                tally.skipped += 1
        _prune(folders, newest)
    return tally


class _SHQUERYRBINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("i64Size", ctypes.c_int64),
        ("i64NumItems", ctypes.c_int64),
    ]


def recycle_bin_size() -> tuple[int, int]:
    """(bytes, items) in the Recycle Bins of all drives; (0, 0) off Windows."""
    if not winapi.WINDOWS:
        return 0, 0
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    hr = ctypes.windll.shell32.SHQueryRecycleBinW(None, ctypes.byref(info))
    if hr != 0:
        return 0, 0
    return int(info.i64Size), int(info.i64NumItems)


def empty_recycle_bin() -> Tally:
    size, count = recycle_bin_size()
    if not winapi.WINDOWS or count == 0:
        return Tally()
    flags = 0x1 | 0x2 | 0x4
    hr = ctypes.windll.shell32.SHEmptyRecycleBinW(None, None, flags)
    if hr != 0:
        return Tally(skipped=count)
    return Tally(files=count, bytes=size)


def flush_dns() -> None:
    if winapi.WINDOWS:
        dnsapi = ctypes.WinDLL("dnsapi.dll")
        if not dnsapi.DnsFlushResolverCache():
            raise OSError("DnsFlushResolverCache failed")


def run_dism(ctx: Context) -> None:
    if not winapi.WINDOWS:
        return
    ctx.progress("Cleaning the Windows component store (DISM, several minutes)...")
    result = winapi.run_hidden(
        [winapi.system32("dism.exe"), "/Online", "/Cleanup-Image", "/StartComponentCleanup"],
        timeout=3600,
    )
    if result.returncode != 0:
        tail = (result.stdout or result.stderr).strip().splitlines()[-1:] or ["no output"]
        raise RuntimeError(f"DISM exit {result.returncode}: {tail[0]}")


@dataclass
class TargetScan:
    target: Target
    files: int = 0
    bytes: int = 0
    note: str = ""


@dataclass
class TargetResult:
    target: Target
    files: int = 0
    bytes: int = 0
    skipped: int = 0
    error: str = ""


@dataclass
class CleanResult:
    results: list[TargetResult] = field(default_factory=list)
    cancelled: bool = False

    @property
    def total_bytes(self) -> int:
        return sum(r.bytes for r in self.results)

    @property
    def total_files(self) -> int:
        return sum(r.files for r in self.results)


def _blocked(target: Target) -> str:
    if target.admin and not winapi.is_admin():
        return "needs administrator"
    return ""


def analyze(targets: Iterable[Target], min_age_hours: int, ctx: Context) -> list[TargetScan]:
    """Size up each target without deleting anything; each TargetScan also goes to ctx.item."""
    scans: list[TargetScan] = []
    targets = list(targets)
    for i, target in enumerate(targets):
        ctx.check()
        ctx.progress(f"Analyzing {target.label}...", i / max(1, len(targets)))
        if target.kind in ("dns", "dism"):
            scan = TargetScan(target, note=target.description)
        else:
            tally = measure(target, min_age_hours)
            scan = TargetScan(target, tally.files, tally.bytes, _blocked(target))
        scans.append(scan)
        ctx.item(scan)
    return scans


def clean(targets: Iterable[Target], min_age_hours: int, ctx: Context) -> CleanResult:
    """Clean each target; a failing one is recorded and the rest still run."""
    result = CleanResult()
    targets = list(targets)
    try:
        for i, target in enumerate(targets):
            ctx.check()
            ctx.progress(f"Cleaning {target.label}...", i / max(1, len(targets)))
            item = TargetResult(target)
            blocked = _blocked(target)
            if blocked:
                item.error = blocked
            else:
                try:
                    if target.kind == "recyclebin":
                        tally = empty_recycle_bin()
                    elif target.kind == "dns":
                        flush_dns()
                        tally = Tally()
                    elif target.kind == "dism":
                        run_dism(ctx)
                        tally = Tally()
                    else:
                        tally = clean_files(target, min_age_hours, ctx)
                    item.files, item.bytes, item.skipped = tally.files, tally.bytes, tally.skipped
                except (OSError, RuntimeError, subprocess.SubprocessError) as e:
                    item.error = str(e)
            logger.info(
                "%s: freed %s (%d files, %d in use)%s",
                target.label,
                human_size(item.bytes),
                item.files,
                item.skipped,
                f" - {item.error}" if item.error else "",
            )
            result.results.append(item)
            ctx.item(item)
    except Cancelled:
        result.cancelled = True
    return result


def report(result: CleanResult) -> Report:
    rows = [
        (
            r.target.label,
            human_size(r.bytes),
            str(r.files),
            str(r.skipped) if r.skipped else "",
            r.error,
        )
        for r in result.results
    ]
    body = table(rows, ("Item", "Freed", "Files", "In use", "Note"))
    body += f"\n\nTotal freed: {human_size(result.total_bytes)} in {result.total_files} files."
    if result.cancelled:
        body += "\nStopped before the end."
    errors = [r for r in result.results if r.error and r.error != "needs administrator"]
    subject = f"Cleanup: {human_size(result.total_bytes)} freed"
    if errors:
        subject += f" ({len(errors)} item(s) failed)"
    return Report("clean", subject, body, ALERT if errors else OK, result)
