"""Security scan: gathers what is running, who it talks to, what starts with Windows,
how Defender is doing and which devices share the network, then hands it to
``rules.evaluate()`` for the findings.

Sources: psutil (processes, connections, services), WMI (Defender, firewall, DNS
cache, GPU engines, ARP table, WMI event consumers), the Task Scheduler COM API,
the registry (winreg) and WinVerifyTrust for signatures. Nothing here changes the
system (the LAN sweep only sends one empty UDP packet per address so the ARP table
fills up). Each source is independent: one that fails is noted in
``SecurityScan.errors`` and the scan carries on.
"""

from __future__ import annotations

import concurrent.futures
import datetime as dt
import ipaddress
import logging
import ntpath
import os
import re
import socket
import subprocess
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from winsentinel import capture, settings, winapi, wmi
from winsentinel.report import ALERT, NOTICE, OK, Context, Report, table

logger = logging.getLogger(__name__)

CRITICAL, WARNING, INFO = "critical", "warning", "info"
SEVERITY_RANK = {CRITICAL: 0, WARNING: 1, INFO: 2}
CPU_SAMPLE_SECONDS = 3.0
MAX_SIGNATURE_CHECKS = 400
MAX_SWEEP_HOSTS = 1024


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    detail: str = ""
    key: str = ""
    pid: int | None = None
    path: str = ""


@dataclass
class Proc:
    pid: int
    name: str
    exe: str = ""
    cmdline: str = ""
    user: str = ""
    cpu: float = 0.0
    gpu: float = 0.0
    signature: str = ""
    signer: str = ""


@dataclass
class Conn:
    pid: int
    process: str
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    inbound: bool = False
    hosts: tuple[str, ...] = ()

    @property
    def external(self) -> bool:
        return is_external(self.remote_ip)


@dataclass
class Listener:
    pid: int
    process: str
    ip: str
    port: int

    @property
    def exposed(self) -> bool:
        return self.ip in ("0.0.0.0", "::")


@dataclass
class Autostart:
    source: str
    name: str
    command: str
    path: str = ""
    enabled: bool = True
    signature: str = ""
    signer: str = ""


@dataclass
class Device:
    ip: str
    mac: str
    name: str = ""
    first_seen: str = ""
    new: bool = False
    router: bool = False

    @property
    def random_mac(self) -> bool:
        return len(self.mac) > 1 and int(self.mac[1], 16) & 0x2 == 0x2


@dataclass
class SystemInfo:
    """What the system collectors returned, section by section."""

    dns: list[dict[str, Any]] = field(default_factory=list)
    tasks: list[dict[str, Any]] = field(default_factory=list)
    startup: list[dict[str, Any]] = field(default_factory=list)
    defender: dict[str, Any] | None = None
    exclusions: list[str] = field(default_factory=list)
    threats: list[dict[str, Any]] = field(default_factory=list)
    antivirus: list[dict[str, Any]] = field(default_factory=list)
    firewall: list[dict[str, Any]] = field(default_factory=list)
    wmi: list[dict[str, Any]] = field(default_factory=list)
    gpu: dict[int, float] = field(default_factory=dict)
    neighbors: list[dict[str, Any]] = field(default_factory=list)
    route: dict[str, Any] | None = None
    registry: dict[str, Any] = field(default_factory=dict)
    hosts_redirects: list[tuple[str, str]] = field(default_factory=list)
    hosts_blocks: int = 0

    def names_for(self, ip: str) -> tuple[str, ...]:
        names = {
            str(n).lower().rstrip(".")
            for d in self.dns
            if d.get("data") == ip
            for n in (d.get("entry"), d.get("name"))
            if n
        }
        return tuple(sorted(names))


@dataclass
class SecurityScan:
    findings: list[Finding] = field(default_factory=list)
    processes: list[Proc] = field(default_factory=list)
    connections: list[Conn] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    autostarts: list[Autostart] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    info: SystemInfo = field(default_factory=SystemInfo)
    capture: capture.CaptureSummary | None = None
    errors: list[str] = field(default_factory=list)
    devices_baselined: bool = False

    def active(self, ignored: Iterable[str]) -> list[Finding]:
        skip = set(ignored)
        return [f for f in self.findings if f.key not in skip]


def is_external(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip.split("%")[0])
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


STANDARD_CIMV2 = r"root\StandardCimv2"
DEFENDER_NS = r"root\Microsoft\Windows\Defender"
GPU_QUERY = (
    "SELECT Name, UtilizationPercentage FROM "
    "Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine"
)
THREAT_WINDOW = dt.timedelta(days=30)
TASK_ENUM_HIDDEN = 1
TASK_ACTION_EXEC = 0
NEIGHBOR_GONE = (0, 1)

_GPU_NAME = re.compile(r"pid_(\d+)_", re.IGNORECASE)


def parse_gpu(rows: Iterable[dict[str, Any]]) -> dict[int, float]:
    """Busiest GPU engine per process, as Task Manager shows it."""
    usage: dict[int, float] = {}
    for row in rows:
        m = _GPU_NAME.search(str(row.get("name", "")))
        if not m:
            continue
        pid = int(m.group(1))
        usage[pid] = max(usage.get(pid, 0.0), float(row.get("percent") or 0))
    return usage


def _route() -> list[dict[str, Any]]:
    rows = wmi.query(
        "SELECT InterfaceIndex, NextHop, RouteMetric FROM MSFT_NetRoute "
        "WHERE DestinationPrefix = '0.0.0.0/0'",
        STANDARD_CIMV2,
    )
    if not rows:
        return []
    best = min(rows, key=lambda r: int(r.get("RouteMetric") or 0))
    return [{"interface": int(best["InterfaceIndex"]), "gateway": str(best.get("NextHop") or "")}]


def _gpu() -> list[dict[str, Any]]:
    rows = wmi.sample(GPU_QUERY, gap=1.2)
    return [{"name": r.get("Name"), "percent": r.get("UtilizationPercentage")} for r in rows]


def _dns() -> list[dict[str, Any]]:
    rows = wmi.query("SELECT Entry, Name, Type, Data FROM MSFT_DNSClientCache", STANDARD_CIMV2)
    return [
        {"entry": r.get("Entry"), "name": r.get("Name"), "data": r.get("Data")}
        for r in rows
        if int(r.get("Type") or 0) in (1, 28)
    ]


def _tasks() -> list[dict[str, Any]]:
    service = wmi.dispatch("Schedule.Service")
    service.Connect()
    out: list[dict[str, Any]] = []
    folders = [service.GetFolder("\\")]
    while folders:
        folder = folders.pop()
        for task in folder.GetTasks(TASK_ENUM_HIDDEN):
            try:
                enabled = bool(task.Enabled)
                for action in task.Definition.Actions:
                    if int(action.Type) == TASK_ACTION_EXEC:
                        out.append(
                            {
                                "name": str(task.Path),
                                "state": "Ready" if enabled else "Disabled",
                                "execute": str(action.Path or ""),
                                "arguments": str(action.Arguments or ""),
                            }
                        )
            except Exception as e:
                logger.debug("Task %s unreadable: %s", getattr(task, "Path", "?"), e)
        folders.extend(folder.GetFolders(0))
    return out


def startup_folders() -> list[Path]:
    folders = []
    if os.environ.get("APPDATA"):
        folders.append(
            Path(os.environ["APPDATA"]) / "Microsoft/Windows/Start Menu/Programs/Startup"
        )
    if os.environ.get("ProgramData"):
        folders.append(
            Path(os.environ["ProgramData"]) / "Microsoft/Windows/Start Menu/Programs/StartUp"
        )
    return folders


def _startup() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    shell = None
    for folder in startup_folders():
        if not folder.is_dir():
            continue
        for item in folder.iterdir():
            if not item.is_file() or item.name.lower() == "desktop.ini":
                continue
            target, arguments = str(item), ""
            if item.suffix.lower() == ".lnk":
                shell = shell or wmi.dispatch("WScript.Shell")
                link = shell.CreateShortcut(str(item))
                target, arguments = str(link.TargetPath or ""), str(link.Arguments or "")
            out.append({"file": str(item), "target": target, "arguments": arguments})
    return out


def _defender() -> list[dict[str, Any]]:
    rows = wmi.query(
        "SELECT AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, "
        "AntivirusSignatureAge FROM MSFT_MpComputerStatus",
        DEFENDER_NS,
    )
    return [
        {
            "service": bool(r.get("AMServiceEnabled")),
            "antivirus": bool(r.get("AntivirusEnabled")),
            "realtime": bool(r.get("RealTimeProtectionEnabled")),
            "signature_age": int(r.get("AntivirusSignatureAge") or 0),
        }
        for r in rows[:1]
    ]


def _exclusions() -> list[str]:
    rows = wmi.query(
        "SELECT ExclusionPath, ExclusionProcess, ExclusionExtension FROM MSFT_MpPreference",
        DEFENDER_NS,
    )
    values: list[str] = []
    for r in rows[:1]:
        for key in ("ExclusionPath", "ExclusionProcess", "ExclusionExtension"):
            values.extend(str(v) for v in (r.get(key) or []) if v)
    return [v for v in values if not v.startswith("N/A")]


def _threats() -> list[dict[str, Any]]:
    names = {
        str(r.get("ThreatID")): str(r.get("ThreatName") or "")
        for r in wmi.query("SELECT ThreatID, ThreatName FROM MSFT_MpThreat", DEFENDER_NS)
    }
    cutoff = dt.datetime.now() - THREAT_WINDOW
    found = []
    for r in wmi.query(
        "SELECT ThreatID, InitialDetectionTime, Resources, ActionSuccess "
        "FROM MSFT_MpThreatDetection",
        DEFENDER_NS,
    ):
        when = wmi.cim_datetime(r.get("InitialDetectionTime"))
        if when is None or when < cutoff:
            continue
        found.append(
            {
                "name": names.get(str(r.get("ThreatID")), ""),
                "time": when.isoformat(timespec="seconds"),
                "resources": "; ".join(str(x) for x in (r.get("Resources") or [])),
                "removed": bool(r.get("ActionSuccess")),
            }
        )
    return sorted(found, key=lambda t: str(t["time"]), reverse=True)[:25]


def _antivirus() -> list[dict[str, Any]]:
    rows = wmi.query(
        "SELECT displayName, productState FROM AntiVirusProduct", r"root\SecurityCenter2"
    )
    return [{"name": r.get("displayName"), "state": int(r.get("productState") or 0)} for r in rows]


def _firewall() -> list[dict[str, Any]]:
    rows = wmi.query("SELECT Name, Enabled FROM MSFT_NetFirewallProfile", STANDARD_CIMV2)
    return [{"name": r.get("Name"), "enabled": int(r.get("Enabled") or 0) != 0} for r in rows]


def _wmi_consumers() -> list[dict[str, Any]]:
    rows = wmi.query("SELECT * FROM __EventConsumer", r"root\subscription")
    return [
        {
            "kind": r.get("__CLASS"),
            "name": r.get("Name"),
            "command": r.get("CommandLineTemplate") or r.get("ExecutablePath") or "",
            "script": r.get("ScriptText") or "",
        }
        for r in rows
    ]


def _neighbors() -> list[dict[str, Any]]:
    rows = wmi.query(
        "SELECT IPAddress, LinkLayerAddress, State, InterfaceIndex FROM MSFT_NetNeighbor "
        "WHERE AddressFamily = 2",
        STANDARD_CIMV2,
    )
    return [
        {
            "ip": r.get("IPAddress"),
            "mac": r.get("LinkLayerAddress"),
            "interface": r.get("InterfaceIndex"),
        }
        for r in rows
        if r.get("LinkLayerAddress") and int(r.get("State") or 0) not in NEIGHBOR_GONE
    ]


COLLECTORS: tuple[tuple[str, Callable[[], Any]], ...] = (
    ("route", _route),
    ("gpu", _gpu),
    ("dns", _dns),
    ("tasks", _tasks),
    ("startup", _startup),
    ("defender", _defender),
    ("exclusions", _exclusions),
    ("threats", _threats),
    ("antivirus", _antivirus),
    ("firewall", _firewall),
    ("wmi", _wmi_consumers),
    ("neighbors", _neighbors),
)


def collect_system(ctx: Context) -> tuple[SystemInfo, list[str]]:
    """Run every collector; one that fails becomes an error line, not a failed scan."""
    ctx.progress("Reading Defender, firewall, scheduled tasks, DNS cache and GPU use...")
    data: dict[str, Any] = {}
    errors: list[str] = []
    for name, collect in COLLECTORS:
        ctx.check()
        try:
            data[name] = collect()
        except Exception as e:
            errors.append(f"{name}: {wmi.com_message(e)}")
    defender = data.get("defender") or []
    route = data.get("route") or []
    info = SystemInfo(
        dns=data.get("dns", []),
        tasks=data.get("tasks", []),
        startup=data.get("startup", []),
        defender=defender[0] if defender else None,
        exclusions=data.get("exclusions", []),
        threats=data.get("threats", []),
        antivirus=data.get("antivirus", []),
        firewall=data.get("firewall", []),
        wmi=data.get("wmi", []),
        gpu=parse_gpu(data.get("gpu", [])),
        neighbors=data.get("neighbors", []),
        route=route[0] if route else None,
    )
    return info, errors


def sample_processes(ctx: Context, seconds: float = CPU_SAMPLE_SECONDS) -> list[Proc]:
    """Every process with its CPU use over ``seconds`` (percent of the whole CPU)."""
    import psutil

    ctx.progress("Sampling running programs...")
    seen: list[tuple[Any, dict[str, Any]]] = []
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]):
        try:
            p.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        seen.append((p, p.info))
    ctx.wait(seconds)
    cores = psutil.cpu_count() or 1
    procs: list[Proc] = []
    for p, info in seen:
        try:
            cpu = p.cpu_percent(None) / cores
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            cpu = 0.0
        cmdline = info.get("cmdline") or []
        procs.append(
            Proc(
                pid=int(info["pid"]),
                name=str(info.get("name") or ""),
                exe=str(info.get("exe") or ""),
                cmdline=" ".join(str(c) for c in cmdline),
                user=str(info.get("username") or ""),
                cpu=round(cpu, 1),
            )
        )
    return procs


def network_connections(procs: list[Proc]) -> tuple[list[Conn], list[Listener]]:
    import psutil

    names = {p.pid: p.name for p in procs}
    conns: list[Conn] = []
    listeners: list[Listener] = []
    for c in psutil.net_connections(kind="inet"):
        pid = int(c.pid or 0)
        name = names.get(pid, "")
        if c.status == psutil.CONN_LISTEN and c.laddr:
            listeners.append(Listener(pid, name, c.laddr.ip, c.laddr.port))
        elif c.raddr:
            conns.append(
                Conn(
                    pid,
                    name,
                    c.laddr.ip if c.laddr else "",
                    c.laddr.port if c.laddr else 0,
                    c.raddr.ip,
                    c.raddr.port,
                    str(c.status),
                )
            )
    listening = {(lst.pid, lst.port) for lst in listeners}
    for conn in conns:
        conn.inbound = (conn.pid, conn.local_port) in listening
    return conns, listeners


def _expand_env(text: str) -> str:
    return re.sub(r"%([^%]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)


_EXECUTABLE = re.compile(
    r"\.(exe|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|scr|dll|cpl|msi|lnk)$", re.I
)


def command_path(command: str) -> str:
    """The program a command line starts: quoted path, or the shortest prefix ending in
    an executable extension; bare names resolve to System32 (where Windows finds them)."""
    cmd = _expand_env(command.strip())
    if cmd.startswith("\\SystemRoot\\") or cmd.lower().startswith("\\systemroot\\"):
        cmd = str(winapi.system_root()) + cmd[len("\\SystemRoot") :]
    if cmd.startswith("\\??\\"):
        cmd = cmd[4:]
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        path = cmd[1:end] if end > 0 else cmd[1:]
    else:
        tokens = cmd.split(" ")
        path = tokens[0]
        for i in range(1, len(tokens) + 1):
            candidate = " ".join(tokens[:i]).rstrip(",")
            if _EXECUTABLE.search(candidate):
                path = candidate
                break
    if path and "\\" not in path and "/" not in path:
        path = ntpath.join(str(winapi.system_root()), "System32", path)
    return path


_HKCU, _HKLM = "HKCU", "HKLM"
RUN_KEYS = (
    (_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (_HKCU, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (_HKCU, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (_HKLM, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (_HKLM, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (_HKLM, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
    (_HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (_HKLM, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
)
WINLOGON = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
IFEO = r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
APPINIT = r"Software\Microsoft\Windows NT\CurrentVersion\Windows"
INTERNET_SETTINGS = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
TERMINAL_SERVER = r"System\CurrentControlSet\Control\Terminal Server"


def _reg_values(hive: str, key: str) -> dict[str, Any]:
    import winreg

    root = winreg.HKEY_CURRENT_USER if hive == _HKCU else winreg.HKEY_LOCAL_MACHINE
    values: dict[str, Any] = {}
    try:
        with winreg.OpenKey(root, key) as k:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(k, i)
                except OSError:
                    break
                values[name] = value
                i += 1
    except OSError:
        pass
    return values


def _reg_subkeys(hive: str, key: str) -> list[str]:
    import winreg

    root = winreg.HKEY_CURRENT_USER if hive == _HKCU else winreg.HKEY_LOCAL_MACHINE
    names: list[str] = []
    try:
        with winreg.OpenKey(root, key) as k:
            i = 0
            while True:
                try:
                    names.append(winreg.EnumKey(k, i))
                except OSError:
                    break
                i += 1
    except OSError:
        pass
    return names


def read_registry() -> dict[str, Any]:
    """Autostart keys and the settings spyware likes to change."""
    if not winapi.WINDOWS:
        return {}
    run = [
        (f"{hive}\\{key}", name, str(value))
        for hive, key in RUN_KEYS
        for name, value in _reg_values(hive, key).items()
        if value
    ]
    debuggers = []
    for sub in _reg_subkeys(_HKLM, IFEO):
        debugger = _reg_values(_HKLM, f"{IFEO}\\{sub}").get("Debugger")
        if debugger:
            debuggers.append((sub, str(debugger)))
    return {
        "run": run,
        "winlogon": _reg_values(_HKLM, WINLOGON),
        "debuggers": debuggers,
        "appinit": _reg_values(_HKLM, APPINIT),
        "proxy": _reg_values(_HKCU, INTERNET_SETTINGS),
        "rdp": _reg_values(_HKLM, TERMINAL_SERVER),
    }


def read_hosts_file(path: Path | None = None) -> tuple[list[tuple[str, str]], int]:
    """(redirects, blocked count) from the hosts file. A redirect sends a name to a real
    address (the classic hijack); a block maps it to 0.0.0.0 / loopback (ad blockers)."""
    path = path or winapi.system_root() / "System32" / "drivers" / "etc" / "hosts"
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], 0
    redirects: list[tuple[str, str]] = []
    blocks = 0
    for line in text.splitlines():
        parts = line.split("#", 1)[0].split()
        if len(parts) < 2:
            continue
        address, names = parts[0], parts[1:]
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        for name in names:
            if name.lower() in ("localhost", "localhost.localdomain", "broadcasthost"):
                continue
            if ip.is_loopback or ip.is_unspecified:
                blocks += 1
            else:
                redirects.append((name, address))
    return redirects, blocks


def autostarts(info: SystemInfo) -> list[Autostart]:
    """Programs that start by themselves: Run keys, Startup folders, scheduled tasks,
    automatic services and WMI event consumers."""
    items: list[Autostart] = []
    for key, name, value in info.registry.get("run", []):
        items.append(Autostart(key, name, _expand_env(value), command_path(value)))
    for s in info.startup:
        command = f'"{s.get("target") or s.get("file")}" {s.get("arguments") or ""}'.strip()
        items.append(
            Autostart(
                "Startup folder",
                ntpath.basename(str(s.get("file") or "")),
                command,
                str(s.get("target") or s.get("file") or ""),
            )
        )
    for t in info.tasks:
        execute = str(t.get("execute") or "")
        command = f'"{_expand_env(execute)}" {t.get("arguments") or ""}'.strip()
        items.append(
            Autostart(
                "Scheduled task",
                str(t.get("name") or ""),
                command,
                command_path(execute),
                enabled=str(t.get("state")) != "Disabled",
            )
        )
    for consumer in info.wmi:
        if consumer.get("name") == "SCM Event Log Consumer":
            continue
        command = str(consumer.get("command") or consumer.get("script") or "")
        items.append(
            Autostart(
                f"WMI {consumer.get('kind') or 'consumer'}",
                str(consumer.get("name") or ""),
                command,
                command_path(command) if consumer.get("command") else "",
            )
        )
    items.extend(services())
    return items


def services() -> list[Autostart]:
    if not winapi.WINDOWS:
        return []
    import psutil

    items: list[Autostart] = []
    for service in psutil.win_service_iter():
        try:
            s = service.as_dict()
        except Exception as e:
            logger.debug("Service %s unreadable: %s", service.name(), e)
            continue
        if s.get("start_type") != "automatic" or not s.get("binpath"):
            continue
        binpath = str(s["binpath"])
        items.append(
            Autostart(
                "Service",
                f"{s.get('display_name') or s.get('name')} ({s.get('name')})",
                binpath,
                command_path(binpath),
            )
        )
    return items


def check_signatures(file_paths: Iterable[str], ctx: Context) -> dict[str, tuple[str, str]]:
    """{lower-case path: (signed | unsigned | invalid | unknown, signer)}."""
    unique = sorted({p.lower(): p for p in file_paths if p}.values(), key=str.lower)
    unique = [p for p in unique if Path(p).is_file()][:MAX_SIGNATURE_CHECKS]
    if not unique or not winapi.WINDOWS:
        return {}
    from winsentinel import authenticode

    ctx.progress(f"Checking digital signatures of {len(unique)} programs...")
    result: dict[str, tuple[str, str]] = {}
    for i, path in enumerate(unique):
        if i % 20 == 0:
            ctx.check()
        result[path.lower()] = authenticode.verify(path)
    return result


def local_network() -> tuple[str, ipaddress.IPv4Network] | None:
    """(this PC's IPv4, its subnet) on the interface that carries the default route."""
    import psutil

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ip = str(s.getsockname()[0])
    except OSError:
        return None
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == ip and a.netmask:
                net = ipaddress.ip_network(f"{ip}/{a.netmask}", strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    return ip, net
    return None


def sweep_lan(ctx: Context) -> tuple[str, ipaddress.IPv4Network] | None:
    """Send one empty UDP packet (discard port) to each address so the ARP table lists
    every device that is up. Subnets bigger than /22 are limited to this PC's /24."""
    found = local_network()
    if found is None:
        return None
    ip, net = found
    if net.num_addresses > MAX_SWEEP_HOSTS:
        net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    ctx.progress(f"Looking for devices on {net}...")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setblocking(False)
        for host in net.hosts():
            try:
                s.sendto(b"", (str(host), 9))
            except OSError:
                continue
    return ip, net


def _reverse_names(ips: list[str], timeout: float = 3.0) -> dict[str, str]:
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)
    futures = {pool.submit(socket.gethostbyaddr, ip): ip for ip in ips}
    names: dict[str, str] = {}
    try:
        for fut in concurrent.futures.as_completed(futures, timeout=timeout):
            try:
                names[futures[fut]] = fut.result()[0]
            except OSError:
                continue
    except concurrent.futures.TimeoutError:
        pass
    pool.shutdown(wait=False, cancel_futures=True)
    return names


def normalize_mac(mac: str) -> str:
    return mac.strip().upper().replace(":", "-")


def lan_devices(
    info: SystemInfo,
    network: tuple[str, ipaddress.IPv4Network] | None,
    known: dict[str, Any] | None,
    now: dt.datetime,
    resolve: bool = True,
) -> tuple[list[Device], dict[str, Any]]:
    """Devices from the ARP table on the default-route network, marked new when their MAC
    wasn't seen before. Returns the devices and the updated known-devices table; with no
    table yet (first scan) everything is recorded as known."""
    own_ip, net = network if network else ("", None)
    interface = info.route.get("interface") if info.route else None
    gateway = str(info.route.get("gateway") or "") if info.route else ""
    devices: dict[str, Device] = {}
    for n in info.neighbors:
        ip, mac = str(n.get("ip") or ""), normalize_mac(str(n.get("mac") or ""))
        if not ip or not mac or mac in ("FF-FF-FF-FF-FF-FF", "00-00-00-00-00-00") or ip == own_ip:
            continue
        if interface is not None and n.get("interface") not in (None, interface):
            continue
        try:
            addr = ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        if addr.is_multicast or (
            net is not None and (addr not in net or addr == net.broadcast_address)
        ):
            continue
        devices[mac] = Device(ip, mac, router=ip == gateway)
    names = _reverse_names([d.ip for d in devices.values()]) if resolve and devices else {}
    first_scan = known is None
    table_ = dict(known or {})
    stamp = now.isoformat(timespec="seconds")
    for mac, device in devices.items():
        device.name = names.get(device.ip, "")
        entry = table_.get(mac)
        if isinstance(entry, dict):
            device.first_seen = str(entry.get("first_seen") or "")
        else:
            device.first_seen = stamp
            device.new = not first_scan
            entry = {"first_seen": stamp}
        entry.update(ip=device.ip, name=device.name or entry.get("name", ""), last_seen=stamp)
        table_[mac] = entry
    ordered = sorted(devices.values(), key=lambda d: ipaddress.IPv4Address(d.ip))
    return ordered, table_


def _apply_signatures(scan: SecurityScan, sigs: dict[str, tuple[str, str]]) -> None:
    for p in scan.processes:
        if p.exe and p.exe.lower() in sigs:
            p.signature, p.signer = sigs[p.exe.lower()]
    for a in scan.autostarts:
        if a.path and a.path.lower() in sigs:
            a.signature, a.signer = sigs[a.path.lower()]


def _interesting_paths(scan: SecurityScan) -> list[str]:
    from winsentinel import rules

    paths_: list[str] = []
    talking = {c.pid for c in scan.connections if c.external or c.inbound}
    exposed = {lst.pid for lst in scan.listeners if lst.exposed}
    for p in scan.processes:
        if p.exe and (p.pid in talking or p.pid in exposed or p.cpu >= 10 or p.gpu >= 10):
            paths_.append(p.exe)
    for a in scan.autostarts:
        if a.path and (a.source != "Service" or not rules.in_windows_dir(a.path)):
            paths_.append(a.path)
    return paths_


def scan(
    ctx: Context,
    *,
    capture_seconds: int | None = None,
    lan_sweep: bool = True,
) -> SecurityScan:
    """Run every check and evaluate the findings. Known network devices are updated in
    state.json; ``capture_seconds`` adds a packet capture (needs administrator)."""
    from winsentinel import rules

    result = SecurityScan()
    try:
        result.processes = sample_processes(ctx)
    except ImportError as e:
        result.errors.append(f"process list unavailable: {e}")
    try:
        result.connections, result.listeners = network_connections(result.processes)
    except Exception as e:
        result.errors.append(f"connections unavailable: {e}")
    network = None
    if lan_sweep:
        try:
            network = sweep_lan(ctx)
        except OSError as e:
            result.errors.append(f"network sweep failed: {e}")
    if winapi.WINDOWS:
        result.info, errors = collect_system(ctx)
        result.errors.extend(errors)
        result.info.registry = read_registry()
        result.info.hosts_redirects, result.info.hosts_blocks = read_hosts_file()
    ctx.check()
    for p in result.processes:
        p.gpu = result.info.gpu.get(p.pid, 0.0)
    for c in result.connections:
        c.hosts = result.info.names_for(c.remote_ip)
    try:
        result.autostarts = autostarts(result.info)
    except Exception as e:
        result.errors.append(f"autostart list incomplete: {e}")
    try:
        _apply_signatures(result, check_signatures(_interesting_paths(result), ctx))
    except Exception as e:
        result.errors.append(f"signature check failed: {e}")

    if lan_sweep:
        known = settings.load_state().get("known_devices")
        table_known = known if isinstance(known, dict) else None
        result.devices, table_ = lan_devices(result.info, network, table_known, dt.datetime.now())
        if result.devices:
            result.devices_baselined = table_known is None
            settings.save_state(known_devices=table_)

    if capture_seconds:
        found = network or local_network()
        if found is None:
            result.errors.append("packet capture: no network connection")
        else:
            result.capture = capture.capture(capture_seconds, found[0], ctx)
            if result.capture.error:
                result.errors.append(result.capture.error)

    result.findings = rules.evaluate(result, own_pid=os.getpid())
    for f in result.findings:
        ctx.item(f)
    logger.info(
        "Security scan: %d finding(s), %d connection(s), %d device(s)",
        len(result.findings),
        len(result.connections),
        len(result.devices),
    )
    return result


def report(result: SecurityScan, ignored: Iterable[str] = ()) -> Report:
    findings = sorted(result.active(ignored), key=lambda f: SEVERITY_RANK[f.severity])
    critical = sum(f.severity == CRITICAL for f in findings)
    warnings = sum(f.severity == WARNING for f in findings)
    parts: list[str] = []
    rows: list[tuple[str, ...]]
    if findings:
        rows = [(f.severity.upper(), f.category, f.title, f.detail) for f in findings]
        parts.append("Findings:\n" + table(rows, ("Level", "Area", "Finding", "Details")))
    else:
        parts.append("No findings.")
    top = sorted(result.processes, key=lambda p: p.cpu + p.gpu, reverse=True)[:10]
    if top:
        rows = [
            (p.name, str(p.pid), f"{p.cpu:.0f}%", f"{p.gpu:.0f}%", p.signature, p.exe) for p in top
        ]
        parts.append(
            "Busiest programs:\n" + table(rows, ("Program", "PID", "CPU", "GPU", "Signed", "Path"))
        )
    external = [c for c in result.connections if c.external]
    if external:
        rows = [
            (
                c.process,
                str(c.pid),
                f"{c.remote_ip}:{c.remote_port}",
                ", ".join(c.hosts[:2]),
                "in" if c.inbound else "out",
            )
            for c in external[:60]
        ]
        parts.append(
            f"Internet connections ({len(external)}):\n"
            + table(rows, ("Program", "PID", "Remote", "Name", "Dir"))
        )
    exposed = [lst for lst in result.listeners if lst.exposed]
    if exposed:
        rows = [(lst.process, str(lst.pid), str(lst.port)) for lst in exposed]
        parts.append("Open ports (all interfaces):\n" + table(rows, ("Program", "PID", "Port")))
    if result.devices:
        rows = [
            (d.ip, d.mac, d.name, "NEW" if d.new else "", "router" if d.router else "")
            for d in result.devices
        ]
        parts.append("Network devices:\n" + table(rows, ("IP", "MAC", "Name", "", "")))
        if result.devices_baselined:
            parts.append(
                f"First scan: {len(result.devices)} device(s) recorded as known; "
                "new ones will be reported from now on."
            )
    if result.capture and not result.capture.error:
        cap = result.capture
        rows = [(f"{ip}:{port}", str(n)) for ip, port, n in cap.destinations[:20]]
        parts.append(
            f"Packet capture ({cap.seconds} s, {cap.file}):\n"
            + table(rows, ("Destination", "Packets"))
        )
        rows = [(name, str(n)) for name, n in cap.dns[:20]]
        parts.append("Names looked up:\n" + table(rows, ("Name", "Queries")))
    if result.errors:
        parts.append("Checks that could not run:\n" + "\n".join(f"- {e}" for e in result.errors))
    if critical:
        severity, subject = (
            ALERT,
            f"[ALERT] Security scan: {critical} critical, {warnings} warning(s)",
        )
    elif warnings:
        severity, subject = NOTICE, f"Security scan: {warnings} warning(s)"
    else:
        severity, subject = OK, "Security scan: nothing suspicious"
    return Report("security", subject, "\n\n".join(parts), severity, result)


def end_process(pid: int) -> str:
    """Terminate a process (and wait briefly). Returns an error message or ''."""
    import psutil

    try:
        proc = psutil.Process(pid)
        proc.terminate()
        proc.wait(5)
    except psutil.NoSuchProcess:
        return ""
    except (psutil.AccessDenied, psutil.TimeoutExpired) as e:
        return str(e) or type(e).__name__
    return ""


def mpcmdrun() -> Path:
    return (
        Path(os.environ.get("ProgramFiles") or r"C:\Program Files")
        / "Windows Defender"
        / "MpCmdRun.exe"
    )


def defender_quick_scan(ctx: Context) -> Report:
    """Run a Microsoft Defender quick scan (MpCmdRun) and report what it found."""
    exe = mpcmdrun()
    if not winapi.WINDOWS or not exe.exists():
        return Report("defender", "Defender scan: Microsoft Defender not found", "", NOTICE)
    ctx.progress("Microsoft Defender quick scan running (a few minutes)...")
    started = dt.datetime.now()
    proc = subprocess.Popen(
        [str(exe), "-Scan", "-ScanType", "1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        **winapi.no_window(),
    )
    while proc.poll() is None:
        if ctx.stopped:
            proc.kill()
            ctx.check()
        time.sleep(0.5)
    try:
        found = [t for t in _threats() if t["time"] >= started.isoformat(timespec="seconds")]
    except Exception as e:
        logger.debug("Could not read Defender detections: %s", e)
        found = []
    if proc.returncode not in (0, 2):
        return Report(
            "defender", "Defender scan FAILED", f"MpCmdRun exit code {proc.returncode}", ALERT
        )
    if found or proc.returncode == 2:
        lines = [f"- {t['name'] or 'threat'}: {t['resources']}" for t in found]
        return Report(
            "defender",
            f"[ALERT] Defender found {len(found) or 'some'} threat(s)",
            "\n".join(
                lines
                + ["", "See Windows Security > Virus & threat protection > Protection history."]
            ),
            ALERT,
        )
    return Report("defender", "Defender quick scan: no threats", "", OK)
