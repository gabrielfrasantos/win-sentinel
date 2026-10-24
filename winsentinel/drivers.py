"""Driver updates through the Windows Update Agent API, plus devices with problems.

The search asks Windows Update (COM: Microsoft.Update.Session) for driver updates
that apply to this PC and are not installed yet: the list Settings > Windows Update
> Optional updates shows. Installs run one driver at a time so a failure doesn't stop
the rest; a reboot is never forced, only reported. Device problems come from Device
Manager's error codes (WMI Win32_PnPEntity.ConfigManagerErrorCode).
"""

from __future__ import annotations

import ctypes
import logging
import os
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from winsentinel import APP_NAME, winapi, wmi
from winsentinel.report import ALERT, ERROR, NOTICE, OK, Context, Report, human_size, table

logger = logging.getLogger(__name__)

WU_SEARCH = "IsInstalled=0 and Type='Driver' and IsHidden=0"
PROBLEMS_QUERY = (
    "SELECT Name, PNPClass, DeviceID, ConfigManagerErrorCode FROM Win32_PnPEntity "
    "WHERE ConfigManagerErrorCode <> 0"
)
RESULT_NAMES = {
    0: "NotStarted",
    1: "InProgress",
    2: "Succeeded",
    3: "SucceededWithErrors",
    4: "Failed",
    5: "Aborted",
}

PROBLEM_CODES = {
    1: "not configured correctly",
    3: "driver may be corrupted",
    10: "device cannot start",
    12: "not enough free resources",
    14: "needs a restart",
    18: "drivers need reinstalling",
    19: "registry configuration damaged",
    21: "being removed",
    22: "disabled",
    24: "not present or not working",
    28: "drivers not installed",
    29: "disabled by the firmware",
    31: "Windows cannot load the drivers",
    32: "driver service disabled",
    37: "driver failed to initialize",
    39: "driver corrupted or missing",
    41: "hardware not found after loading the driver",
    43: "stopped: the device reported a problem",
    47: "prepared for safe removal",
    48: "driver blocked (known compatibility problem)",
    52: "driver signature could not be verified",
}
IGNORED_CODES = {45}


@dataclass(frozen=True)
class DriverUpdate:
    id: str
    title: str
    driver_class: str = ""
    provider: str = ""
    manufacturer: str = ""
    model: str = ""
    date: str = ""
    hardware_id: str = ""
    size: int = 0


@dataclass(frozen=True)
class ProblemDevice:
    name: str
    device_class: str
    device_id: str
    code: int

    @property
    def problem(self) -> str:
        return f"code {self.code}: {PROBLEM_CODES.get(self.code, 'see Device Manager')}"


@dataclass
class DriverScan:
    updates: list[DriverUpdate] = field(default_factory=list)
    problems: list[ProblemDevice] = field(default_factory=list)
    error: str = ""


@dataclass(frozen=True)
class InstallOutcome:
    update: DriverUpdate
    result: str
    hresult: int = 0
    reboot: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return self.result in ("Succeeded", "SucceededWithErrors")


@dataclass
class InstallResult:
    outcomes: list[InstallOutcome] = field(default_factory=list)

    @property
    def reboot_required(self) -> bool:
        return any(o.reboot for o in self.outcomes)


def parse_problems(rows: Iterable[dict[str, Any]]) -> list[ProblemDevice]:
    devices = [
        ProblemDevice(
            name=str(d.get("Name") or d.get("DeviceID") or "Unknown device"),
            device_class=str(d.get("PNPClass") or ""),
            device_id=str(d.get("DeviceID") or ""),
            code=int(d.get("ConfigManagerErrorCode") or 0),
        )
        for d in rows
    ]
    return [d for d in devices if d.code not in IGNORED_CODES]


def problem_devices() -> list[ProblemDevice]:
    return parse_problems(wmi.query(PROBLEMS_QUERY))


def to_update(u: Any) -> DriverUpdate:
    """A DriverUpdate from a WUA IUpdate / IWindowsDriverUpdate COM object."""
    date = wmi.cim_datetime(u.DriverVerDate)
    return DriverUpdate(
        id=str(u.Identity.UpdateID),
        title=str(u.Title),
        driver_class=str(u.DriverClass or ""),
        provider=str(u.DriverProvider or ""),
        manufacturer=str(u.DriverManufacturer or ""),
        model=str(u.DriverModel or ""),
        date=f"{date:%Y-%m-%d}" if date else "",
        hardware_id=str(u.DriverHardwareID or ""),
        size=int(u.MaxDownloadSize or 0),
    )


def _session() -> Any:
    session = wmi.dispatch("Microsoft.Update.Session")
    session.ClientApplicationID = APP_NAME
    return session


def _offered(session: Any) -> list[Any]:
    updates = session.CreateUpdateSearcher().Search(WU_SEARCH).Updates
    return [updates.Item(i) for i in range(updates.Count)]


def _search_updates() -> list[DriverUpdate]:
    return [to_update(u) for u in _offered(_session())]


def _abandonable[T](fn: Callable[[], T], ctx: Context, name: str) -> T:
    """Run a blocking COM call in its own thread so Stop doesn't have to wait for it."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as e:
            box["error"] = e

    worker = threading.Thread(target=run, daemon=True, name=name)
    worker.start()
    while worker.is_alive():
        worker.join(0.2)
        ctx.check()
    if "error" in box:
        raise box["error"]
    value: T = box["value"]
    return value


def _com_errors() -> tuple[type[BaseException], ...]:
    try:
        import pywintypes
    except ImportError:
        return (wmi.WmiError,)
    return (wmi.WmiError, pywintypes.com_error)


def search(ctx: Context) -> DriverScan:
    """Devices with problems, then the Windows Update driver search (minutes)."""
    scan = DriverScan()
    if not winapi.WINDOWS:
        scan.error = "driver updates need Windows"
        return scan
    ctx.progress("Checking devices for problems...")
    try:
        scan.problems = problem_devices()
    except wmi.WmiError as e:
        scan.error = f"device check failed: {e}"
    ctx.progress("Searching Windows Update for drivers (this can take a few minutes)...")
    try:
        scan.updates = _abandonable(_search_updates, ctx, "driver-search")
    except _com_errors() as e:
        scan.error = f"Windows Update search failed: {wmi.com_message(e)}"
    for update in scan.updates:
        ctx.item(update)
    logger.info(
        "Driver check: %d update(s), %d device problem(s)", len(scan.updates), len(scan.problems)
    )
    return scan


def _install_one(session: Any, u: Any, update: DriverUpdate) -> InstallOutcome:
    if not u.EulaAccepted:
        u.AcceptEula()
    batch = wmi.dispatch("Microsoft.Update.UpdateColl")
    batch.Add(u)
    downloader = session.CreateUpdateDownloader()
    downloader.Updates = batch
    downloader.Download()
    installer = session.CreateUpdateInstaller()
    installer.Updates = batch
    result = installer.Install()
    one = result.GetUpdateResult(0)
    return InstallOutcome(
        update,
        RESULT_NAMES.get(int(one.ResultCode), "Failed"),
        int(one.HResult) & 0xFFFFFFFF,
        bool(result.RebootRequired),
    )


def install(updates: Iterable[DriverUpdate], ctx: Context) -> InstallResult:
    """Download and install the given updates one by one; never reboots. Stop takes
    effect between drivers (an install in progress always finishes)."""
    todo = {u.id: u for u in updates}
    result = InstallResult()
    if not todo:
        return result
    if not winapi.WINDOWS or not winapi.is_admin():
        why = "needs Windows" if not winapi.WINDOWS else "needs administrator"
        result.outcomes = [InstallOutcome(u, "Failed", error=why) for u in todo.values()]
        return result
    total = len(todo)
    ctx.progress(f"Preparing {total} driver update(s)...", 0.0)
    errors = _com_errors()
    try:
        session = _session()
        offered = {str(u.Identity.UpdateID): u for u in _offered(session)}
    except errors as e:
        message = wmi.com_message(e)
        result.outcomes = [InstallOutcome(u, "Failed", error=message) for u in todo.values()]
        return result
    for n, update in enumerate(todo.values(), 1):
        if ctx.stopped:
            outcome = InstallOutcome(update, "NotStarted", error="stopped")
        elif update.id not in offered:
            outcome = InstallOutcome(update, "Failed", error="no longer offered by Windows Update")
        else:
            ctx.progress(f"Installing {n}/{total}: {update.title}", (n - 1) / total)
            try:
                outcome = _install_one(session, offered[update.id], update)
            except errors as e:
                outcome = InstallOutcome(update, "Failed", error=wmi.com_message(e))
        logger.info("Driver %s: %s %s", update.title, outcome.result, outcome.error)
        result.outcomes.append(outcome)
        ctx.item(outcome)
    return result


def open_device_manager() -> None:
    if winapi.WINDOWS:
        os.startfile("devmgmt.msc")


def rescan_devices() -> None:
    """Device Manager's "Scan for hardware changes" (cfgmgr32)."""
    if not winapi.WINDOWS:
        return
    cfgmgr: Any = ctypes.WinDLL("cfgmgr32.dll")
    root = ctypes.c_uint32()
    if cfgmgr.CM_Locate_DevNodeW(ctypes.byref(root), None, 0) == 0:
        cfgmgr.CM_Reenumerate_DevNode(root, 1)


def scan_report(scan: DriverScan, installed: InstallResult | None = None) -> Report:
    parts: list[str] = []
    rows: list[tuple[str, ...]]
    installed_ids = {o.update.id for o in installed.outcomes} if installed else set()
    pending = [u for u in scan.updates if u.id not in installed_ids]
    if installed and installed.outcomes:
        rows = [(o.update.title, o.result, o.error) for o in installed.outcomes]
        parts.append("Installed:\n" + table(rows, ("Driver", "Result", "Error")))
        if installed.reboot_required:
            parts.append("A restart is needed to finish installing.")
    if pending:
        rows = [(u.title, u.driver_class, u.date, human_size(u.size)) for u in pending]
        parts.append(
            "Available driver updates:\n" + table(rows, ("Driver", "Class", "Date", "Size"))
        )
    elif not installed:
        parts.append("No driver updates available.")
    if scan.problems:
        rows = [(d.name, d.device_class, d.problem) for d in scan.problems]
        parts.append("Devices with problems:\n" + table(rows, ("Device", "Class", "Problem")))
    if scan.error:
        parts.append(f"Error: {scan.error}")

    failed = [o for o in installed.outcomes if not o.ok] if installed else []
    if scan.error:
        severity, subject = ERROR, "Driver check FAILED"
    elif failed:
        severity, subject = ALERT, f"Drivers: {len(failed)} install(s) failed"
    elif installed and installed.outcomes:
        severity, subject = NOTICE, f"Drivers: {len(installed.outcomes)} installed"
        if installed.reboot_required:
            subject += ", restart needed"
    elif pending or scan.problems:
        severity = NOTICE
        subject = f"Drivers: {len(pending)} update(s) available, {len(scan.problems)} problem(s)"
    else:
        severity, subject = OK, "Drivers: up to date"
    return Report("drivers", subject, "\n\n".join(parts), severity, (scan, installed))
