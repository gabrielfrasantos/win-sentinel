from winsentinel import rules
from winsentinel.capture import CaptureSummary
from winsentinel.security import (
    Autostart,
    Conn,
    Device,
    Listener,
    Proc,
    SecurityScan,
    SystemInfo,
)

TEMP_EXE = r"C:\Users\me\AppData\Local\Temp\svc.exe"


def keys(findings):
    return {f.key.split(":")[0]: f.severity for f in findings}


def by_key(findings, prefix):
    return [f for f in findings if f.key.startswith(prefix)]


def test_clean_pc_has_no_findings():
    scan = SecurityScan(
        processes=[
            Proc(
                10,
                "chrome.exe",
                r"C:\Program Files\Google\Chrome\chrome.exe",
                cpu=12,
                signature="signed",
            ),
            Proc(11, "svchost.exe", r"C:\Windows\System32\svchost.exe", signature="signed"),
            Proc(12, "explorer.exe", r"C:\Windows\explorer.exe", signature="signed"),
        ],
        connections=[
            Conn(10, "chrome.exe", "192.168.1.10", 50000, "142.250.1.1", 443, "ESTABLISHED")
        ],
        info=SystemInfo(
            defender={"realtime": True, "antivirus": True, "signature_age": 1},
            firewall=[{"name": "Public", "enabled": True}],
            registry={
                "winlogon": {
                    "Shell": "explorer.exe",
                    "Userinit": r"C:\Windows\system32\userinit.exe,",
                }
            },
        ),
    )
    assert rules.evaluate(scan) == []


def test_miner_by_name_and_by_command_line():
    scan = SecurityScan(
        processes=[
            Proc(1, "xmrig.exe", r"C:\x\xmrig.exe", cpu=90),
            Proc(2, "notminer.exe", r"C:\x\n.exe", cmdline="n.exe -o stratum+tcp://p:3333"),
        ]
    )
    found = by_key(rules.evaluate(scan), "miner:")
    assert {f.pid for f in found} == {1, 2}
    assert all(f.severity == "critical" for f in found)


def test_pool_connection_beats_dns_only_lookup():
    scan = SecurityScan(
        processes=[Proc(5, "app.exe", r"C:\Program Files\App\app.exe", signature="signed")],
        connections=[
            Conn(
                5,
                "app.exe",
                "10.0.0.2",
                5000,
                "1.2.3.4",
                443,
                "ESTABLISHED",
                hosts=("gulf.moneroocean.stream",),
            )
        ],
        info=SystemInfo(
            dns=[
                {"entry": "gulf.moneroocean.stream", "data": "1.2.3.4"},
                {"entry": "xmr.2miners.com", "data": "5.6.7.8"},
            ]
        ),
    )
    pools = by_key(rules.evaluate(scan), "pool:")
    assert {(f.key, f.severity) for f in pools} == {
        ("pool:gulf.moneroocean.stream", "critical"),
        ("pool:xmr.2miners.com", "warning"),
    }


def test_suspicious_port_is_critical_for_untrusted_programs():
    procs = [
        Proc(1, "game.exe", r"C:\Games\game.exe", signature="signed"),
        Proc(2, "svc.exe", TEMP_EXE, signature="unsigned"),
    ]
    conns = [
        Conn(1, "game.exe", "10.0.0.2", 50000, "8.8.4.4", 4444, "ESTABLISHED"),
        Conn(2, "svc.exe", "10.0.0.2", 50001, "8.8.4.4", 14444, "ESTABLISHED"),
        Conn(2, "svc.exe", "10.0.0.2", 50002, "192.168.1.5", 14444, "ESTABLISHED"),
    ]
    found = {
        f.key: f.severity for f in rules.evaluate(SecurityScan(processes=procs, connections=conns))
    }
    assert found["port:game:4444"] == "warning"
    assert found["port:svc:14444"] == "critical"
    assert found[f"online:{TEMP_EXE.lower()}"] == "critical"


def test_fake_system_process():
    scan = SecurityScan(
        processes=[
            Proc(1, "svchost.exe", r"C:\Users\Public\svchost.exe"),
            Proc(2, "svchost.exe", r"C:\Windows\SysWOW64\svchost.exe"),
        ]
    )
    found = by_key(rules.evaluate(scan), "fake:")
    assert [f.pid for f in found] == [1]


def test_remote_tools_and_inbound_sessions():
    scan = SecurityScan(
        processes=[Proc(3, "AnyDesk.exe", r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe")],
        connections=[
            Conn(
                4,
                "svchost.exe",
                "192.168.1.10",
                3389,
                "203.0.113.9",
                51000,
                "ESTABLISHED",
                inbound=True,
            ),
            Conn(
                9,
                "web.exe",
                "192.168.1.10",
                8080,
                "45.33.32.156",
                51000,
                "ESTABLISHED",
                inbound=True,
            ),
            Conn(9, "web.exe", "127.0.0.1", 8080, "127.0.0.1", 51000, "ESTABLISHED", inbound=True),
        ],
    )
    found = {f.key: f for f in rules.evaluate(scan)}
    assert found["remote:anydesk"].severity == "warning"
    assert "Remote Desktop" in found["session:3389:203.0.113.9"].title
    assert "inbound:web:8080" in found


def test_busy_programs_only_when_not_signed():
    scan = SecurityScan(
        processes=[
            Proc(1, "render.exe", r"C:\Program Files\R\render.exe", cpu=95, signature="signed"),
            Proc(
                2,
                "helper.exe",
                r"C:\Users\me\AppData\Roaming\helper.exe",
                cpu=60,
                signature="unsigned",
            ),
            Proc(3, "tool.exe", r"C:\Tools\tool.exe", gpu=80, signature="unknown"),
            Proc(4, "idle.exe", r"C:\Tools\idle.exe", cpu=1, signature="unsigned"),
        ]
    )
    found = {f.pid: f.severity for f in by_key(rules.evaluate(scan), "busy:")}
    assert found == {2: "critical", 3: "warning"}


def test_listeners_flag_untrusted_programs_only():
    scan = SecurityScan(
        processes=[
            Proc(1, "svc.exe", TEMP_EXE),
            Proc(2, "server.exe", r"C:\Program Files\S\server.exe", signature="signed"),
        ],
        listeners=[
            Listener(1, "svc.exe", "0.0.0.0", 4444),
            Listener(1, "svc.exe", "::", 4445),
            Listener(2, "server.exe", "0.0.0.0", 80),
            Listener(1, "svc.exe", "127.0.0.1", 9),
        ],
    )
    found = by_key(rules.evaluate(scan), "listen:")
    assert len(found) == 1 and "4444, 4445" in found[0].detail


def test_autostart_rules():
    items = [
        Autostart(
            "Scheduled task",
            r"\Updater",
            "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        ),
        Autostart("Scheduled task", r"\OEM", "powershell.exe -WindowStyle Hidden -File x.ps1"),
        Autostart(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "Helper",
            f'"{TEMP_EXE}"',
            TEMP_EXE,
            signature="unsigned",
        ),
        Autostart(
            "Service",
            "Thing (thing)",
            r"C:\Program Files\T\t.exe",
            r"C:\T\t.exe",
            signature="unsigned",
        ),
        Autostart("WMI CommandLineEventConsumer", "evil", "cmd /c calc"),
        Autostart("Scheduled task", r"\Old", f'"{TEMP_EXE}"', TEMP_EXE, enabled=False),
    ]
    found = {
        f.title.split(":")[0]: f.severity for f in rules.evaluate(SecurityScan(autostarts=items))
    }
    assert found == {
        "Encoded or downloading script starts automatically": "critical",
        "Hidden PowerShell window starts automatically": "warning",
        "Starts automatically from a temp folder": "critical",
        "Unsigned program starts automatically": "info",
        "WMI event consumer": "warning",
    }


def test_registry_rules():
    info = SystemInfo(
        registry={
            "winlogon": {"Shell": "explorer.exe, evil.exe", "Userinit": r"C:\x\userinit.exe"},
            "debuggers": [("sethc.exe", r"C:\Windows\System32\cmd.exe")],
            "appinit": {"AppInit_DLLs": "x.dll", "LoadAppInit_DLLs": 1},
            "proxy": {
                "ProxyEnable": 1,
                "ProxyServer": "127.0.0.1:8888",
                "AutoConfigURL": "http://x/pac",
            },
            "rdp": {"fDenyTSConnections": 0},
        }
    )
    found = keys(rules.evaluate(SecurityScan(info=info)))
    assert found == {
        "winlogon-shell": "critical",
        "winlogon-userinit": "critical",
        "ifeo": "warning",
        "appinit": "warning",
        "proxy": "warning",
        "pac": "warning",
        "rdp-enabled": "info",
    }


def test_defender_rules():
    info = SystemInfo(
        defender={"realtime": False, "antivirus": True, "signature_age": 12},
        exclusions=[r"C:\Users\me\AppData\Roaming\x"],
        threats=[
            {
                "name": "Trojan:Win32/CoinMiner",
                "time": "2026-10-20T10:00:00",
                "resources": "file:_C:\\x.exe",
                "removed": False,
            }
        ],
    )
    found = keys(rules.evaluate(SecurityScan(info=info)))
    assert found == {
        "defender-realtime-off": "warning",
        "defender-stale": "warning",
        "defender-exclusions": "warning",
        "threat": "critical",
    }
    other_av = SystemInfo(
        defender={"realtime": False, "antivirus": False, "signature_age": 0},
        antivirus=[{"name": "ESET", "state": 0x41000}],
    )
    assert rules.evaluate(SecurityScan(info=other_av)) == []
    none_on = SystemInfo(antivirus=[{"name": "Windows Defender", "state": 0x60100}])
    assert keys(rules.evaluate(SecurityScan(info=none_on))) == {"no-antivirus": "warning"}


def test_hosts_firewall_devices_and_capture():
    scan = SecurityScan(
        info=SystemInfo(
            firewall=[{"name": "Public", "enabled": False}, {"name": "Private", "enabled": True}],
            hosts_redirects=[("bank.com", "203.0.113.5")],
            hosts_blocks=120,
        ),
        devices=[
            Device("192.168.1.37", "DA-11-22-33-44-55", new=True),
            Device("192.168.1.1", "00-11-22-33-44-55"),
        ],
        capture=CaptureSummary(
            60,
            dns=[("pool.minexmr.com", 3)],
            destinations=[("8.8.8.8", 6667, 4), ("192.168.1.1", 6667, 1)],
        ),
    )
    found = {f.key: f for f in rules.evaluate(scan)}
    assert found["firewall:public"].severity == "warning"
    assert found["hosts-blocks"].severity == "info"
    assert [k for k in found if k.startswith("hosts:")]
    assert "randomized MAC" in found["device:DA-11-22-33-44-55"].detail
    assert found["pool:pool.minexmr.com"].severity == "critical"
    assert "capture-port:8.8.8.8:6667" in found and "capture-port:192.168.1.1:6667" not in found


def test_one_finding_per_key_most_severe_first():
    scan = SecurityScan(
        processes=[Proc(1, "xmrig.exe", r"C:\x\xmrig.exe", cpu=90)],
        connections=[
            Conn(
                1,
                "xmrig.exe",
                "10.0.0.2",
                5,
                "1.2.3.4",
                3333,
                "ESTABLISHED",
                hosts=("pool.supportxmr.com",),
            )
        ],
        info=SystemInfo(
            dns=[{"entry": "pool.supportxmr.com", "data": "1.2.3.4"}],
            registry={"rdp": {"fDenyTSConnections": 0}},
        ),
    )
    found = rules.evaluate(scan)
    assert len({f.key for f in found}) == len(found)
    ranks = [{"critical": 0, "warning": 1, "info": 2}[f.severity] for f in found]
    assert ranks == sorted(ranks)


def test_suspicious_location():
    assert rules.suspicious_location(r"C:\Users\me\Downloads\setup.exe") == "the Downloads folder"
    assert rules.suspicious_location(r"C:\ProgramData\x.exe") == "the top of ProgramData"
    assert rules.suspicious_location(r"C:\ProgramData\Vendor\x.exe") == ""
    assert rules.suspicious_location(r'"C:\Users\me\AppData\Roaming\upd.exe" -s') != ""
    assert rules.suspicious_location(r"C:\Users\me\AppData\Roaming\Zoom\bin\Zoom.exe") == ""
