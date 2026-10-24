import datetime as dt
import ipaddress

import pytest

from winsentinel import security, settings
from winsentinel.report import Context
from winsentinel.security import Conn, Finding, Proc, SecurityScan, SystemInfo


@pytest.mark.parametrize(
    "command, expected",
    [
        (r'"C:\Program Files\App\app.exe" --tray', r"C:\Program Files\App\app.exe"),
        (r"C:\Program Files\App\app.exe --tray", r"C:\Program Files\App\app.exe"),
        (r"C:\Windows\system32\svchost.exe -k netsvcs -p", r"C:\Windows\system32\svchost.exe"),
        (r"\SystemRoot\System32\drivers\x.sys", r"C:\Windows\System32\drivers\x.sys"),
        ("rundll32.exe shell32.dll,Control_RunDLL", r"C:\Windows\System32\rundll32.exe"),
    ],
)
def test_command_path(command, expected, monkeypatch):
    monkeypatch.setenv("SystemRoot", r"C:\Windows")
    assert security.command_path(command) == expected


def test_parse_gpu_takes_the_busiest_engine():
    rows = [
        {"name": "pid_100_luid_0x0_0xD1_phys_0_eng_0_engtype_3D", "percent": "12"},
        {"name": "pid_100_luid_0x0_0xD1_phys_0_eng_3_engtype_Compute_0", "percent": "97"},
        {"name": "pid_7_luid_0x0_0xD1_phys_0_eng_0_engtype_3D", "percent": 3},
        {"name": "garbage", "percent": 50},
    ]
    assert security.parse_gpu(rows) == {100: 97.0, 7: 3.0}


def test_hosts_file(tmp_path):
    hosts = tmp_path / "hosts"
    hosts.write_text(
        "# comment\n127.0.0.1 localhost\n::1 localhost\n"
        "0.0.0.0 ads.example.com tracker.example.com\n"
        "203.0.113.5 bank.example.com  # redirect\n"
    )
    redirects, blocks = security.read_hosts_file(hosts)
    assert redirects == [("bank.example.com", "203.0.113.5")]
    assert blocks == 2


def test_lan_devices_baseline_then_new():
    info = SystemInfo(
        route={"interface": 7, "gateway": "192.168.1.1"},
        neighbors=[
            {"ip": "192.168.1.1", "mac": "aa-bb-cc-00-11-22", "interface": 7},
            {"ip": "192.168.1.37", "mac": "DA-11-22-33-44-55", "interface": 7},
            {"ip": "192.168.1.255", "mac": "FF-FF-FF-FF-FF-FF", "interface": 7},
            {"ip": "224.0.0.22", "mac": "01-00-5E-00-00-16", "interface": 7},
            {"ip": "10.9.9.9", "mac": "11-22-33-44-55-66", "interface": 9},
        ],
    )
    network = ("192.168.1.10", ipaddress.IPv4Network("192.168.1.0/24"))
    now = dt.datetime(2026, 10, 24, 12, 0)
    devices, known = security.lan_devices(info, network, None, now, resolve=False)
    assert [d.ip for d in devices] == ["192.168.1.1", "192.168.1.37"]
    assert not any(d.new for d in devices)
    assert devices[0].router and devices[1].random_mac

    info.neighbors.append({"ip": "192.168.1.50", "mac": "00-1A-2B-3C-4D-5E", "interface": 7})
    devices, known = security.lan_devices(info, network, known, now, resolve=False)
    assert [d.ip for d in devices if d.new] == ["192.168.1.50"]
    assert set(known) == {"AA-BB-CC-00-11-22", "DA-11-22-33-44-55", "00-1A-2B-3C-4D-5E"}


def test_names_for_uses_dns_cache():
    info = SystemInfo(dns=[{"entry": "Pool.Example.", "name": "edge.example", "data": "1.2.3.4"}])
    assert info.names_for("1.2.3.4") == ("edge.example", "pool.example")
    assert info.names_for("9.9.9.9") == ()


def test_autostarts_from_collected_info(monkeypatch):
    monkeypatch.setattr(security, "services", lambda: [])
    monkeypatch.setenv("TEMP", r"C:\Users\me\AppData\Local\Temp")
    info = SystemInfo(
        registry={"run": [(r"HKCU\Run", "Updater", r"%TEMP%\upd.exe /silent")]},
        startup=[{"file": r"C:\S\app.lnk", "target": r"C:\Apps\app.exe", "arguments": "-m"}],
        tasks=[{"name": r"\T", "state": "Disabled", "execute": "cmd.exe", "arguments": "/c x"}],
        wmi=[
            {"kind": "NTEventLogEventConsumer", "name": "SCM Event Log Consumer"},
            {"kind": "CommandLineEventConsumer", "name": "evil", "command": "calc.exe"},
        ],
    )
    items = security.autostarts(info)
    assert [(a.source, a.name) for a in items] == [
        (r"HKCU\Run", "Updater"),
        ("Startup folder", "app.lnk"),
        ("Scheduled task", r"\T"),
        ("WMI CommandLineEventConsumer", "evil"),
    ]
    assert items[0].command.startswith(r"C:\Users\me\AppData\Local\Temp\upd.exe")
    assert not items[2].enabled


def test_report_counts_and_ignored():
    scan = SecurityScan(
        findings=[
            Finding("critical", "Crypto-miner", "Miner", key="miner:x"),
            Finding("warning", "Remote access", "AnyDesk", key="remote:anydesk"),
        ],
        connections=[Conn(1, "a.exe", "10.0.0.2", 5, "8.8.8.8", 443, "ESTABLISHED")],
    )
    report = security.report(scan)
    assert report.severity == "alert" and "[ALERT]" in report.subject
    assert "8.8.8.8:443" in report.body
    quiet = security.report(scan, ignored=["miner:x", "remote:anydesk"])
    assert quiet.severity == "ok" and quiet.subject == "Security scan: nothing suspicious"
    assert security.report(scan, ignored=["miner:x"]).severity == "notice"


def test_full_scan_off_windows(monkeypatch):
    monkeypatch.setattr(security.winapi, "WINDOWS", False)
    monkeypatch.setattr(
        security,
        "sample_processes",
        lambda ctx: [Proc(4242, "xmrig.exe", "/opt/xmrig", cpu=95)],
    )
    monkeypatch.setattr(security, "network_connections", lambda procs: ([], []))
    result = security.scan(Context(), lan_sweep=False)
    assert {f.key for f in result.findings} == {"miner:/opt/xmrig", "busy:/opt/xmrig"}
    assert "known_devices" not in settings.load_state()


def test_scan_records_devices_only_when_it_sees_some(monkeypatch):
    monkeypatch.setattr(security.winapi, "WINDOWS", False)
    monkeypatch.setattr(security, "sample_processes", lambda ctx: [])
    monkeypatch.setattr(security, "network_connections", lambda procs: ([], []))
    monkeypatch.setattr(security, "sweep_lan", lambda ctx: None)
    devices = []
    monkeypatch.setattr(
        security, "lan_devices", lambda info, net, known, now: (list(devices), {"M": {}})
    )
    assert not security.scan(Context()).devices_baselined
    assert "known_devices" not in settings.load_state()
    devices.append(security.Device("192.168.1.1", "M"))
    assert security.scan(Context()).devices_baselined
    assert settings.load_state()["known_devices"] == {"M": {}}


def test_collectors_failures_become_errors(monkeypatch):
    def broken():
        raise RuntimeError("namespace missing")

    monkeypatch.setattr(
        security,
        "COLLECTORS",
        (("defender", broken), ("firewall", lambda: [{"name": "Public", "enabled": False}])),
    )
    info, errors = security.collect_system(Context())
    assert errors == ["defender: namespace missing"]
    assert info.firewall == [{"name": "Public", "enabled": False}]
    assert info.defender is None
