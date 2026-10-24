"""Integration tests against the real Windows APIs (WMI, COM, WinVerifyTrust, Task
Scheduler). They run on the Windows CI runners and are skipped elsewhere."""

import os
import sys
from pathlib import Path

import pytest

from winsentinel import authenticode, cleanup, drivers, security, startup, temperature, winapi, wmi
from winsentinel.report import Context

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")

needs_admin = pytest.mark.skipif(
    sys.platform != "win32" or not winapi.is_admin(), reason="needs administrator"
)


def test_wmi_query_and_errors():
    rows = wmi.query("SELECT Caption, Version FROM Win32_OperatingSystem")
    assert rows and "Windows" in rows[0]["Caption"]
    assert rows[0]["__CLASS"] == "Win32_OperatingSystem"
    with pytest.raises(wmi.WmiError):
        wmi.query("SELECT * FROM Sensor", r"root\NoSuchNamespaceHere")


def test_signatures():
    explorer = str(winapi.system_root() / "explorer.exe")
    status, signer = authenticode.verify(explorer)
    assert status == "signed" and "Microsoft" in signer


def test_unsigned_file(tmp_path):
    fake = tmp_path / "fake.exe"
    fake.write_bytes(b"MZ" + b"\x00" * 1022)
    assert authenticode.verify(str(fake))[0] in ("unsigned", "unknown")


def test_device_problems_and_rescan():
    assert isinstance(drivers.problem_devices(), list)
    drivers.rescan_devices()


def test_sensors_read_without_error():
    sample = temperature.read_sensors()
    assert isinstance(sample.sensors, list)


def test_system_collectors(tmp_path):
    info, errors = security.collect_system(Context())
    assert info.route is not None or errors
    assert isinstance(info.tasks, list) and info.tasks
    assert all(isinstance(e, str) for e in errors)
    assert security.read_registry()["winlogon"]


def test_recycle_bin_size():
    size, items = cleanup.recycle_bin_size()
    assert size >= 0 and items >= 0


def test_dns_flush():
    cleanup.flush_dns()


@needs_admin
def test_startup_task_round_trip(monkeypatch):
    monkeypatch.setattr(startup, "TASK_NAME", f"win-sentinel-test-{os.getpid()}")
    startup.enable()
    try:
        assert startup.is_enabled()
    finally:
        startup.disable()
    assert not startup.is_enabled()


@needs_admin
def test_short_capture(monkeypatch):
    from winsentinel import capture

    found = security.local_network()
    if found is None:
        pytest.skip("no network")
    summary = capture.capture(2, found[0], Context())
    assert summary.error == "" and Path(summary.file).exists()
