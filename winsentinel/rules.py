"""Turn a security scan's raw data into findings. Pure functions, no system calls, so
every rule is testable with hand-made data.

Severity: critical = very likely malicious (miner running, fake system program,
encoded script at startup); warning = needs a look (remote-access tool, program
online from a temp folder, Defender exclusions); info = worth knowing.
"""

from __future__ import annotations

import hashlib
import ntpath
import re
from collections import defaultdict
from collections.abc import Iterable

from winsentinel import indicators as ind
from winsentinel import winapi
from winsentinel.security import (
    CRITICAL,
    INFO,
    SEVERITY_RANK,
    WARNING,
    Autostart,
    Conn,
    Finding,
    Proc,
    SecurityScan,
    SystemInfo,
    is_external,
)

BUSY_CPU = 30.0
BUSY_GPU = 50.0
STALE_SIGNATURE_DAYS = 7
UNTRUSTED = ("unsigned", "invalid")
IDLE_PROCESSES = {"system idle process", "idle", "system", "registry", "memory compression"}

_LOCATIONS = (
    (re.compile(r"\\appdata\\local\\temp\\", re.I), "a temp folder"),
    (re.compile(r"\\windows\\temp\\", re.I), "the Windows temp folder"),
    (re.compile(r"\\downloads\\", re.I), "the Downloads folder"),
    (re.compile(r"\\\$recycle\.bin\\", re.I), "the Recycle Bin"),
    (re.compile(r"\\users\\public\\", re.I), "the Public user folder"),
    (
        re.compile(r"\\programdata\\[^\\\"]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js)\b", re.I),
        "the top of ProgramData",
    ),
    (
        re.compile(
            r"\\appdata\\(?:roaming|local|locallow)\\[^\\\"]+\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js)\b",
            re.I,
        ),
        "the top of AppData",
    ),
)


def suspicious_location(text: str) -> str:
    """Where malware likes to live, if ``text`` (a path or command line) points there."""
    for pattern, where in _LOCATIONS:
        if pattern.search(text or ""):
            return where
    return ""


def _root() -> str:
    return ntpath.normcase(str(winapi.system_root()))


def in_windows_dir(path: str) -> bool:
    return ntpath.normcase(path).startswith(_root() + "\\")


def system_dir_ok(path: str) -> bool:
    """True for the folders the real Windows system programs run from."""
    root = _root()
    folder = ntpath.dirname(ntpath.normcase(path))
    return folder in (root, root + "\\system32", root + "\\syswow64") or folder.startswith(
        root + "\\winsxs\\"
    )


def _short(text: str, n: int = 160) -> str:
    return text if len(text) <= n else text[: n - 3] + "..."


def _digest(items: Iterable[str]) -> str:
    return hashlib.sha1("\n".join(sorted(items)).encode()).hexdigest()[:12]


def _label(p: Proc | None, conn: Conn | None = None) -> str:
    if p is not None:
        return f"{p.name} (PID {p.pid})"
    if conn is not None:
        return f"{conn.process or 'unknown program'} (PID {conn.pid})"
    return "unknown program"


def miners(procs: Iterable[Proc]) -> list[Finding]:
    out = []
    for p in procs:
        by_name = ind.program_key(p.exe or p.name) in ind.MINER_PROGRAMS
        by_cmd = bool(ind.MINER_COMMAND_LINE.search(p.cmdline))
        if not (by_name or by_cmd):
            continue
        why = "known miner program" if by_name else "mining options on its command line"
        out.append(
            Finding(
                CRITICAL,
                "Crypto-miner",
                f"Crypto-miner running: {_label(p)}",
                f"{why}; CPU {p.cpu:.0f}%, GPU {p.gpu:.0f}%; {_short(p.exe or p.cmdline)}",
                f"miner:{(p.exe or p.name).lower()}",
                p.pid,
                p.exe,
            )
        )
    return out


def pools(scan: SecurityScan, procs: dict[int, Proc]) -> list[Finding]:
    out = []
    connected: set[str] = set()
    for c in scan.connections:
        hits = [h for h in c.hosts if ind.is_pool_domain(h)]
        if not hits:
            continue
        connected.update(hits)
        p = procs.get(c.pid)
        out.append(
            Finding(
                CRITICAL,
                "Crypto-miner",
                f"Connected to a mining pool: {hits[0]}",
                f"{_label(p, c)} -> {c.remote_ip}:{c.remote_port}",
                f"pool:{hits[0]}",
                c.pid,
                p.exe if p else "",
            )
        )
    for entry in scan.info.dns:
        for name in (entry.get("entry"), entry.get("name")):
            host = str(name or "").lower().rstrip(".")
            if host and host not in connected and ind.is_pool_domain(host):
                connected.add(host)
                out.append(
                    Finding(
                        WARNING,
                        "Crypto-miner",
                        f"This PC looked up a mining pool: {host}",
                        "found in the DNS cache: a program (or a web page) contacted it recently",
                        f"pool:{host}",
                    )
                )
    return out


def ports(scan: SecurityScan, procs: dict[int, Proc]) -> list[Finding]:
    out = []
    for c in scan.connections:
        reason = ind.SUSPICIOUS_PORTS.get(c.remote_port)
        if not reason or c.inbound or not c.external:
            continue
        p = procs.get(c.pid)
        untrusted = p is not None and (p.signature in UNTRUSTED or bool(suspicious_location(p.exe)))
        hosts = f" ({', '.join(c.hosts[:2])})" if c.hosts else ""
        out.append(
            Finding(
                CRITICAL if untrusted else WARNING,
                "Network",
                f"{_label(p, c)} connects to port {c.remote_port}: {reason}",
                f"{c.remote_ip}:{c.remote_port}{hosts}",
                f"port:{ind.program_key(p.exe if p else c.process)}:{c.remote_port}",
                c.pid,
                p.exe if p else "",
            )
        )
    return out


def inbound(scan: SecurityScan, procs: dict[int, Proc]) -> list[Finding]:
    out = []
    for c in scan.connections:
        if not c.inbound or c.status != "ESTABLISHED" or c.remote_ip.startswith("127."):
            continue
        if c.remote_ip in ("::1",) or c.remote_ip.startswith("::ffff:127."):
            continue
        p = procs.get(c.pid)
        service = ind.REMOTE_ACCESS_PORTS.get(c.local_port)
        if service:
            out.append(
                Finding(
                    WARNING,
                    "Remote access",
                    f"Someone is connected to this PC by {service} from {c.remote_ip}",
                    f"{_label(p, c)} on port {c.local_port}",
                    f"session:{c.local_port}:{c.remote_ip}",
                    c.pid,
                    p.exe if p else "",
                )
            )
        elif c.external:
            out.append(
                Finding(
                    WARNING,
                    "Network",
                    f"Inbound connection from the internet to {_label(p, c)}",
                    f"{c.remote_ip}:{c.remote_port} -> port {c.local_port}",
                    f"inbound:{ind.program_key(p.exe if p else c.process)}:{c.local_port}",
                    c.pid,
                    p.exe if p else "",
                )
            )
    return out


def remote_tools(procs: Iterable[Proc]) -> list[Finding]:
    out = []
    for p in procs:
        key = ind.program_key(p.exe or p.name)
        tool = ind.REMOTE_ACCESS_TOOLS.get(key)
        if tool:
            out.append(
                Finding(
                    WARNING,
                    "Remote access",
                    f"Remote-access tool running: {tool}",
                    f"{p.exe or p.name}; fine if you installed it (Trust it to stop this warning)",
                    f"remote:{key}",
                    p.pid,
                    p.exe,
                )
            )
    return out


def masquerade(procs: Iterable[Proc]) -> list[Finding]:
    out = []
    for p in procs:
        if ind.program_key(p.name) in ind.SYSTEM_PROCESSES and p.exe and not system_dir_ok(p.exe):
            out.append(
                Finding(
                    CRITICAL,
                    "Malware",
                    f"Fake system program: {_label(p)}",
                    f"runs from {p.exe}; the real {p.name} lives in the Windows folder",
                    f"fake:{p.exe.lower()}",
                    p.pid,
                    p.exe,
                )
            )
    return out


def online_programs(scan: SecurityScan, procs: dict[int, Proc]) -> list[Finding]:
    talking: dict[int, list[Conn]] = defaultdict(list)
    for c in scan.connections:
        if c.external:
            talking[c.pid].append(c)
    out = []
    for pid, conns in talking.items():
        p = procs.get(pid)
        if p is None or not p.exe:
            continue
        remote = ", ".join(sorted({f"{c.remote_ip}:{c.remote_port}" for c in conns})[:3])
        where = suspicious_location(p.exe)
        if where:
            out.append(
                Finding(
                    CRITICAL if p.signature in UNTRUSTED else WARNING,
                    "Network",
                    f"Program running from {where} is online: {_label(p)}",
                    f"{p.exe} -> {remote}",
                    f"online:{p.exe.lower()}",
                    pid,
                    p.exe,
                )
            )
        elif p.signature == "invalid":
            out.append(
                Finding(
                    WARNING,
                    "Network",
                    f"Program with a broken signature is online: {_label(p)}",
                    f"{p.exe} -> {remote}",
                    f"online:{p.exe.lower()}",
                    pid,
                    p.exe,
                )
            )
        elif p.signature == "unsigned":
            out.append(
                Finding(
                    INFO,
                    "Network",
                    f"Unsigned program is online: {_label(p)}",
                    f"{p.exe} -> {remote}",
                    f"online:{p.exe.lower()}",
                    pid,
                    p.exe,
                )
            )
    return out


def busy_programs(procs: Iterable[Proc], own_pid: int) -> list[Finding]:
    out = []
    for p in procs:
        if p.pid in (0, 4, own_pid) or p.name.lower() in IDLE_PROCESSES or not p.exe:
            continue
        busy = []
        if p.cpu >= BUSY_CPU:
            busy.append(f"{p.cpu:.0f}% CPU")
        if p.gpu >= BUSY_GPU:
            busy.append(f"{p.gpu:.0f}% GPU")
        if not busy or p.signature == "signed":
            continue
        where = suspicious_location(p.exe)
        what = "Unsigned" if p.signature in UNTRUSTED else "Unverified"
        out.append(
            Finding(
                CRITICAL if where and p.signature in UNTRUSTED else WARNING,
                "Crypto-miner",
                f"{what} program using {' and '.join(busy)}: {_label(p)}",
                f"{p.exe}; hidden miners look like this. Make sure you know the program",
                f"busy:{p.exe.lower()}",
                p.pid,
                p.exe,
            )
        )
    return out


def listeners(scan: SecurityScan, procs: dict[int, Proc]) -> list[Finding]:
    open_ports: dict[int, set[int]] = defaultdict(set)
    for lst in scan.listeners:
        if lst.exposed and lst.pid not in (0, 4):
            open_ports[lst.pid].add(lst.port)
    out = []
    for pid, port_set in open_ports.items():
        p = procs.get(pid)
        if p is None or not p.exe:
            continue
        where = suspicious_location(p.exe)
        if not where and p.signature not in UNTRUSTED:
            continue
        why = f"runs from {where}" if where else f"is {p.signature}"
        port_list = ", ".join(str(x) for x in sorted(port_set)[:6])
        out.append(
            Finding(
                WARNING,
                "Network",
                f"Program that {why} accepts network connections: {_label(p)}",
                f"{p.exe}; listening on port(s) {port_list}",
                f"listen:{p.exe.lower()}",
                pid,
                p.exe,
            )
        )
    return out


def autostarts(items: Iterable[Autostart]) -> list[Finding]:
    out = []
    for a in items:
        if not a.enabled:
            continue
        key = f"autostart:{a.source}:{a.name}".lower()
        where_from = f"{a.source}: {_short(a.command, 200)}"
        if ind.MALICIOUS_COMMAND.search(a.command):
            out.append(
                Finding(
                    CRITICAL,
                    "Autostart",
                    f"Encoded or downloading script starts automatically: {a.name}",
                    where_from,
                    key,
                    path=a.path,
                )
            )
            continue
        if a.source.startswith("WMI"):
            out.append(
                Finding(
                    WARNING,
                    "Autostart",
                    f"WMI event consumer: {a.name}",
                    f"{where_from} (rarely used legitimately; popular with fileless malware)",
                    key,
                    path=a.path,
                )
            )
            continue
        where = suspicious_location(a.command) or suspicious_location(a.path)
        if where:
            out.append(
                Finding(
                    CRITICAL if a.signature in UNTRUSTED else WARNING,
                    "Autostart",
                    f"Starts automatically from {where}: {a.name}",
                    where_from,
                    key,
                    path=a.path,
                )
            )
        elif ind.HIDDEN_COMMAND.search(a.command):
            out.append(
                Finding(
                    WARNING,
                    "Autostart",
                    f"Hidden PowerShell window starts automatically: {a.name}",
                    where_from,
                    key,
                    path=a.path,
                )
            )
        elif a.signature == "invalid":
            out.append(
                Finding(
                    WARNING,
                    "Autostart",
                    f"Program with a broken signature starts automatically: {a.name}",
                    where_from,
                    key,
                    path=a.path,
                )
            )
        elif a.signature == "unsigned":
            out.append(
                Finding(
                    INFO,
                    "Autostart",
                    f"Unsigned program starts automatically: {a.name}",
                    where_from,
                    key,
                    path=a.path,
                )
            )
    return out


def registry(info: SystemInfo) -> list[Finding]:
    reg = info.registry
    out = []
    winlogon = reg.get("winlogon") or {}
    shell = str(winlogon.get("Shell") or "").strip()
    if shell and shell.lower() not in ("explorer.exe", r"c:\windows\explorer.exe"):
        out.append(
            Finding(
                CRITICAL,
                "Malware",
                "The Windows logon shell was changed",
                f"Winlogon Shell = {shell} (normally explorer.exe)",
                f"winlogon-shell:{shell.lower()}",
            )
        )
    userinit = str(winlogon.get("Userinit") or "").strip().rstrip(",").strip()
    if userinit and not ntpath.normcase(userinit).endswith(r"\system32\userinit.exe"):
        out.append(
            Finding(
                CRITICAL,
                "Malware",
                "Windows logon starts an extra program",
                f"Winlogon Userinit = {userinit}",
                f"winlogon-userinit:{userinit.lower()}",
            )
        )
    for image, debugger in reg.get("debuggers") or []:
        out.append(
            Finding(
                WARNING,
                "Autostart",
                f"Starting {image} runs another program instead",
                f"Image File Execution Options debugger: {debugger} "
                "(Process Explorer and debuggers set this legitimately)",
                f"ifeo:{str(image).lower()}:{str(debugger).lower()}",
            )
        )
    appinit = reg.get("appinit") or {}
    dlls = str(appinit.get("AppInit_DLLs") or "").strip()
    if dlls and appinit.get("LoadAppInit_DLLs") == 1:
        out.append(
            Finding(
                WARNING,
                "Autostart",
                "DLLs are injected into every program (AppInit_DLLs)",
                dlls,
                f"appinit:{dlls.lower()}",
            )
        )
    proxy = reg.get("proxy") or {}
    server = str(proxy.get("ProxyServer") or "").strip()
    if proxy.get("ProxyEnable") == 1 and server:
        out.append(
            Finding(
                WARNING,
                "Network",
                f"A system proxy is set: {server}",
                "web traffic goes through it; fine if it is your company's or VPN's",
                f"proxy:{server.lower()}",
            )
        )
    pac = str(proxy.get("AutoConfigURL") or "").strip()
    if pac:
        out.append(
            Finding(
                WARNING,
                "Network",
                "Web traffic is routed by a proxy script",
                f"AutoConfigURL = {pac}",
                f"pac:{pac.lower()}",
            )
        )
    rdp = reg.get("rdp") or {}
    if rdp.get("fDenyTSConnections") == 0:
        out.append(
            Finding(
                INFO,
                "Remote access",
                "Remote Desktop is enabled",
                "anyone with your password can sign in remotely; turn it off in Settings if unused",
                "rdp-enabled",
            )
        )
    return out


def _antivirus_on(state: int) -> bool:
    return bool(state & 0x1000)


def defender(info: SystemInfo) -> list[Finding]:
    out = []
    others = [
        str(a.get("name"))
        for a in info.antivirus
        if _antivirus_on(int(a.get("state") or 0)) and "defender" not in str(a.get("name")).lower()
    ]
    d = info.defender
    if d is None:
        if info.antivirus and not any(
            _antivirus_on(int(a.get("state") or 0)) for a in info.antivirus
        ):
            out.append(
                Finding(
                    WARNING,
                    "Antivirus",
                    "No active antivirus",
                    "Windows Security reports every antivirus as off",
                    "no-antivirus",
                )
            )
    else:
        if not d.get("realtime") and not others:
            out.append(
                Finding(
                    WARNING,
                    "Antivirus",
                    "Microsoft Defender real-time protection is off",
                    "turn it on in Windows Security > Virus & threat protection",
                    "defender-realtime-off",
                )
            )
        age = int(d.get("signature_age") or 0)
        if d.get("antivirus") and age > STALE_SIGNATURE_DAYS:
            out.append(
                Finding(
                    WARNING,
                    "Antivirus",
                    f"Defender's virus definitions are {age} days old",
                    "run Windows Update",
                    "defender-stale",
                )
            )
    if info.exclusions:
        out.append(
            Finding(
                WARNING,
                "Antivirus",
                f"Defender skips {len(info.exclusions)} excluded location(s) or program(s)",
                "; ".join(info.exclusions[:6])
                + ". Malware adds itself here; remove any you don't recognize",
                f"defender-exclusions:{_digest(x.lower() for x in info.exclusions)}",
            )
        )
    for t in info.threats:
        removed = bool(t.get("removed"))
        name = str(t.get("name") or "threat")
        out.append(
            Finding(
                WARNING if removed else CRITICAL,
                "Antivirus",
                f"Defender detected {name}" + ("" if removed else " (NOT removed)"),
                f"{t.get('time')}: {_short(str(t.get('resources') or ''))}",
                f"threat:{name.lower()}:{t.get('time')}",
            )
        )
    return out


def firewall(info: SystemInfo) -> list[Finding]:
    return [
        Finding(
            WARNING,
            "Network",
            f"Windows Firewall is off for the {p.get('name')} network profile",
            "turn it on in Windows Security > Firewall & network protection",
            f"firewall:{str(p.get('name')).lower()}",
        )
        for p in info.firewall
        if not p.get("enabled")
    ]


def hosts_file(info: SystemInfo) -> list[Finding]:
    out = []
    if info.hosts_redirects:
        sample = ", ".join(f"{n} -> {ip}" for n, ip in info.hosts_redirects[:5])
        out.append(
            Finding(
                WARNING,
                "Network",
                f"The hosts file redirects {len(info.hosts_redirects)} name(s)",
                f"{sample}; spyware uses this to send you to fake sites",
                f"hosts:{_digest(f'{n} {ip}' for n, ip in info.hosts_redirects)}",
            )
        )
    if info.hosts_blocks:
        out.append(
            Finding(
                INFO,
                "Network",
                f"The hosts file blocks {info.hosts_blocks} name(s)",
                "usually an ad or telemetry blocker",
                "hosts-blocks",
            )
        )
    return out


def devices(scan: SecurityScan) -> list[Finding]:
    out = []
    for d in scan.devices:
        if not d.new:
            continue
        note = "; randomized MAC (phone, tablet or laptop)" if d.random_mac else ""
        out.append(
            Finding(
                WARNING,
                "Network devices",
                f"New device on your network: {d.name or d.ip}",
                f"{d.ip}  {d.mac}{note}",
                f"device:{d.mac}",
            )
        )
    return out


def captured(scan: SecurityScan) -> list[Finding]:
    cap = scan.capture
    if cap is None or cap.error:
        return []
    out = []
    for name, count in cap.dns:
        if ind.is_pool_domain(name):
            out.append(
                Finding(
                    CRITICAL,
                    "Crypto-miner",
                    f"Mining pool looked up during the capture: {name}",
                    f"{count} quer(ies) in {cap.seconds} s",
                    f"pool:{name}",
                )
            )
    for ip, port, packets in cap.destinations:
        reason = ind.SUSPICIOUS_PORTS.get(port)
        if reason and is_external(ip):
            out.append(
                Finding(
                    WARNING,
                    "Network",
                    f"Traffic to port {port} ({reason}) during the capture",
                    f"{ip}:{port}, {packets} packet(s)",
                    f"capture-port:{ip}:{port}",
                )
            )
    return out


def evaluate(scan: SecurityScan, own_pid: int = 0) -> list[Finding]:
    """Every rule's findings, one per key (the most severe), most severe first."""
    procs = {p.pid: p for p in scan.processes}
    found = [
        *miners(scan.processes),
        *pools(scan, procs),
        *masquerade(scan.processes),
        *ports(scan, procs),
        *inbound(scan, procs),
        *remote_tools(scan.processes),
        *online_programs(scan, procs),
        *busy_programs(scan.processes, own_pid),
        *listeners(scan, procs),
        *autostarts(scan.autostarts),
        *registry(scan.info),
        *defender(scan.info),
        *firewall(scan.info),
        *hosts_file(scan.info),
        *devices(scan),
        *captured(scan),
    ]
    best: dict[str, Finding] = {}
    for f in found:
        current = best.get(f.key)
        if current is None or SEVERITY_RANK[f.severity] < SEVERITY_RANK[current.severity]:
            best[f.key] = f
    return sorted(best.values(), key=lambda f: SEVERITY_RANK[f.severity])
