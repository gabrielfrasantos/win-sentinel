import datetime as dt
from types import SimpleNamespace

import pytest

from winsentinel import drivers
from winsentinel.report import Context


def com_update(uid, title, ok=True):
    """A stand-in for a WUA IWindowsDriverUpdate COM object."""
    u = SimpleNamespace(
        Identity=SimpleNamespace(UpdateID=uid),
        Title=title,
        DriverClass="Display",
        DriverProvider="Intel",
        DriverManufacturer="Intel Corporation",
        DriverModel="Iris Xe",
        DriverVerDate=dt.datetime(2026, 8, 12),
        DriverHardwareID="PCI\\VEN_8086",
        MaxDownloadSize=12345,
        EulaAccepted=False,
        ok=ok,
    )
    u.AcceptEula = lambda: setattr(u, "EulaAccepted", True)
    return u


class Collection(list):
    @property
    def Count(self):
        return len(self)

    def Item(self, i):
        return self[i]

    def Add(self, item):
        self.append(item)


class FakeSession:
    def __init__(self, offered):
        self.offered = offered
        self.installed = []

    def CreateUpdateSearcher(self):
        return SimpleNamespace(
            Search=lambda criteria: SimpleNamespace(Updates=Collection(self.offered))
        )

    def CreateUpdateDownloader(self):
        return SimpleNamespace(Updates=None, Download=lambda: None)

    def CreateUpdateInstaller(self):
        installer = SimpleNamespace(Updates=None)

        def install():
            u = installer.Updates[0]
            self.installed.append(u.Identity.UpdateID)
            one = SimpleNamespace(ResultCode=2 if u.ok else 4, HResult=0 if u.ok else -2145124329)
            return SimpleNamespace(GetUpdateResult=lambda i: one, RebootRequired=u.ok)

        installer.Install = install
        return installer


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(drivers.winapi, "WINDOWS", True)
    monkeypatch.setattr(drivers.winapi, "is_admin", lambda: True)


def test_to_update_reads_driver_fields():
    u = drivers.to_update(com_update("id-1", "Intel - Display - 31.0"))
    assert u == drivers.DriverUpdate(
        "id-1",
        "Intel - Display - 31.0",
        "Display",
        "Intel",
        "Intel Corporation",
        "Iris Xe",
        "2026-08-12",
        "PCI\\VEN_8086",
        12345,
    )


def test_problem_devices_skip_disconnected():
    rows = [
        {
            "Name": "USB thing",
            "PNPClass": "USB",
            "DeviceID": "USB\\1",
            "ConfigManagerErrorCode": 43,
        },
        {"Name": "Old phone", "PNPClass": "WPD", "DeviceID": "X", "ConfigManagerErrorCode": 45},
        {"Name": None, "PNPClass": None, "DeviceID": "ACPI\\X", "ConfigManagerErrorCode": 28},
    ]
    found = drivers.parse_problems(rows)
    assert [(d.name, d.code) for d in found] == [("USB thing", 43), ("ACPI\\X", 28)]
    assert found[1].problem == "code 28: drivers not installed"


def test_search_collects_updates_and_problems(windows, monkeypatch):
    session = FakeSession([com_update("a", "Driver A"), com_update("b", "Driver B")])
    monkeypatch.setattr(drivers, "_session", lambda: session)
    monkeypatch.setattr(drivers.wmi, "query", lambda q, ns=None: [])
    items = []
    scan = drivers.search(Context(on_item=items.append))
    assert [u.id for u in scan.updates] == ["a", "b"] == [u.id for u in items]
    assert scan.error == ""
    report = drivers.scan_report(scan)
    assert report.severity == "notice" and "2 update(s) available" in report.subject


def test_install_one_by_one_and_report(windows, monkeypatch):
    offered = [com_update("a", "Driver A"), com_update("b", "Driver B", ok=False)]
    session = FakeSession(offered)
    monkeypatch.setattr(drivers, "_session", lambda: session)
    monkeypatch.setattr(drivers.wmi, "dispatch", lambda progid: Collection())
    updates = [drivers.to_update(u) for u in offered] + [drivers.DriverUpdate("gone", "Gone")]
    result = drivers.install(updates, Context())
    assert session.installed == ["a", "b"]
    assert [(o.update.id, o.result) for o in result.outcomes] == [
        ("a", "Succeeded"),
        ("b", "Failed"),
        ("gone", "Failed"),
    ]
    assert result.outcomes[1].hresult == 0x80240017
    assert result.reboot_required
    report = drivers.scan_report(drivers.DriverScan(updates=updates), result)
    assert report.severity == "alert" and "2 install(s) failed" in report.subject
    assert "restart is needed" in report.body


def test_install_needs_admin(windows, monkeypatch):
    monkeypatch.setattr(drivers.winapi, "is_admin", lambda: False)
    result = drivers.install([drivers.DriverUpdate("a", "A")], Context())
    assert result.outcomes[0].error == "needs administrator"


def test_stop_between_drivers(windows, monkeypatch):
    offered = [com_update("a", "A"), com_update("b", "B")]
    session = FakeSession(offered)
    monkeypatch.setattr(drivers, "_session", lambda: session)
    monkeypatch.setattr(drivers.wmi, "dispatch", lambda progid: Collection())
    ctx = Context()
    ctx.item = lambda outcome: ctx.stop.set()
    result = drivers.install([drivers.to_update(u) for u in offered], ctx)
    assert session.installed == ["a"]
    assert result.outcomes[1].result == "NotStarted"


def test_search_off_windows():
    scan = drivers.search(Context())
    if not drivers.winapi.WINDOWS:
        assert scan.error == "driver updates need Windows"
        assert drivers.scan_report(scan).severity == "error"
