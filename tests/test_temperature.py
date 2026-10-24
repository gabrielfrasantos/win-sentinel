import datetime as dt

import pytest

from winsentinel import temperature
from winsentinel.temperature import OverheatGuard, Sample, Sensor


def test_parse_monitor_sensors():
    rows = [
        {"Name": "CPU Package", "Identifier": "/intelcpu/0/temperature/8", "Value": 71.25},
        {
            "Name": "CPU Core #1 Distance to TjMax",
            "Identifier": "/intelcpu/0/temperature/9",
            "Value": 29.0,
        },
        {"Name": "GPU Core", "Identifier": "/gpu-nvidia/0/temperature/0", "Value": 55.0},
        {"Name": "Temperature #1", "Identifier": "/lpc/nct6798d/temperature/0", "Value": 33.0},
        {"Name": "Core (Tctl/Tdie)", "Identifier": "/amdcpu/0/temperature/2", "Value": "64.5"},
        {"Name": "Broken", "Identifier": "x", "Value": None},
    ]
    sensors = temperature.parse_monitor(rows)
    assert [(s.name, s.kind) for s in sensors] == [
        ("CPU Package", "cpu"),
        ("GPU Core", "gpu"),
        ("Temperature #1", "other"),
        ("Core (Tctl/Tdie)", "cpu"),
    ]
    assert Sample(dt.datetime.now(), "LHM", sensors).cpu_max == 71.2


def test_parse_acpi_tenths_of_kelvin():
    sensors = temperature.parse_acpi([{"CurrentTemperature": 3232}, {"CurrentTemperature": 0}])
    assert [(s.name, s.kind) for s in sensors] == [("ThermalZone0", "cpu")]
    assert sensors[0].celsius == pytest.approx(50.05, abs=0.06)


def test_overheat_guard_cooldown():
    guard = OverheatGuard(90, cooldown_min=30)
    t0 = dt.datetime(2026, 10, 24, 12, 0)

    def sample(minutes, celsius):
        return Sample(t0 + dt.timedelta(minutes=minutes), "x", [Sensor("CPU", celsius, "cpu")])

    assert not guard.check(sample(0, 89.9))
    assert guard.check(sample(1, 90))
    assert not guard.check(sample(10, 95))
    assert guard.check(sample(31, 92))
    assert not guard.check(Sample(t0, "x", [Sensor("GPU", 99, "gpu")]))


def test_log_alert_and_prune(home):
    when = dt.datetime(2026, 10, 24, 12, 0, 5)
    sample = Sample(when, "LibreHardwareMonitor", [Sensor("CPU, Package", 93.0, "cpu")])
    path = temperature.log_sample(sample)
    temperature.log_sample(sample)
    lines = path.read_text().splitlines()
    assert lines == [
        "timestamp,sensor,tempC",
        "2026-10-24T12:00:05,CPU  Package,93.0",
        "2026-10-24T12:00:05,CPU  Package,93.0",
    ]
    report = temperature.alert_report(sample, 90)
    assert report.severity == "alert" and report.subject.startswith("[OVERHEAT] CPU 93.0")
    assert "2026-10-24T12:00:05" in report.body

    old = temperature.csv_path(dt.date(2026, 8, 1))
    old.write_text("timestamp,sensor,tempC\n")
    temperature.prune_logs(when)
    assert not old.exists() and path.exists()


def test_monitor_tick_logs_reports_and_alerts(monkeypatch):
    hot = Sample(dt.datetime.now(), "LibreHardwareMonitor", [Sensor("CPU Package", 97, "cpu")])
    monkeypatch.setattr(temperature, "read_sensors", lambda: hot)
    samples, alerts = [], []
    monitor = temperature.TempMonitor(15, 90, 30, samples.append, alerts.append)
    monitor.tick()
    monitor.tick()
    assert len(samples) == 2 and len(alerts) == 1
    assert temperature.csv_path(hot.time.date()).exists()


def test_monitor_thread_starts_and_stops(monkeypatch):
    monkeypatch.setattr(temperature, "read_sensors", lambda: Sample(dt.datetime.now()))
    seen = []
    monitor = temperature.TempMonitor(0.05, 90, 30, seen.append, lambda r: None)
    monitor.start()
    for _ in range(100):
        if len(seen) >= 2:
            break
        import time

        time.sleep(0.02)
    monitor.stop()
    assert not monitor.running and len(seen) >= 2
