"""CPU temperature watch: samples the sensors, logs them to a daily CSV and raises an
overheat alert (rate-limited) when the CPU crosses the threshold. Built to diagnose
overheat crashes: the CSV holds the readings up to the moment the PC died.

Sensors, best first (all through WMI):
  1. LibreHardwareMonitor (root\\LibreHardwareMonitor) - real per-core temperatures;
     the app must be running: ``winget install LibreHardwareMonitor.LibreHardwareMonitor``
  2. OpenHardwareMonitor (root\\OpenHardwareMonitor)
  3. ACPI thermal zones (root\\WMI) - built in, but on many boards a slow board sensor
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from winsentinel import paths, winapi, wmi
from winsentinel.report import ALERT, Report

logger = logging.getLogger(__name__)

HW_MONITORS = (
    ("LibreHardwareMonitor", r"root\LibreHardwareMonitor"),
    ("OpenHardwareMonitor", r"root\OpenHardwareMonitor"),
)
SENSOR_QUERY = "SELECT Name, Identifier, Value FROM Sensor WHERE SensorType = 'Temperature'"
ACPI_QUERY = "SELECT InstanceName, CurrentTemperature FROM MSAcpi_ThermalZoneTemperature"
ACPI_SOURCE = "ACPI thermal zone"
CSV_HEADER = "timestamp,sensor,tempC"
RETENTION = dt.timedelta(days=30)
_CPU_NAME = re.compile(r"cpu|core|package|tctl|tdie|ccd", re.IGNORECASE)


@dataclass(frozen=True)
class Sensor:
    name: str
    celsius: float
    kind: str = "other"


@dataclass
class Sample:
    time: dt.datetime
    source: str = ""
    sensors: list[Sensor] = field(default_factory=list)

    @property
    def cpu_max(self) -> float | None:
        values = [s.celsius for s in self.sensors if s.kind == "cpu"]
        return max(values) if values else None


def classify(name: str, identifier: str) -> str:
    ident = identifier.lower()
    if "gpu" in ident:
        return "gpu"
    if "cpu" in ident or _CPU_NAME.search(name):
        return "cpu"
    return "other"


def parse_monitor(rows: list[dict[str, object]]) -> list[Sensor]:
    """Temperature sensors from (Libre|Open)HardwareMonitor's Sensor class."""
    sensors = []
    for r in rows:
        name = str(r.get("Name") or "")
        if "distance" in name.lower():
            continue
        try:
            value = float(r.get("Value") or 0)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if value <= 0:
            continue
        sensors.append(
            Sensor(name, round(value, 1), classify(name, str(r.get("Identifier") or "")))
        )
    return sensors


def parse_acpi(rows: list[dict[str, object]]) -> list[Sensor]:
    """ACPI zones report tenths of a kelvin."""
    sensors = []
    for i, r in enumerate(rows):
        try:
            kelvin10 = float(r.get("CurrentTemperature") or 0)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if kelvin10 > 0:
            sensors.append(Sensor(f"ThermalZone{i}", round(kelvin10 / 10 - 273.15, 1), "cpu"))
    return sensors


def read_sensors(now: dt.datetime | None = None) -> Sample:
    now = now or dt.datetime.now()
    if not winapi.WINDOWS:
        return Sample(now)
    for source, namespace in HW_MONITORS:
        try:
            sensors = parse_monitor(wmi.query(SENSOR_QUERY, namespace))
        except wmi.WmiError:
            continue
        if sensors:
            return Sample(now, source, sensors)
    try:
        sensors = parse_acpi(wmi.query(ACPI_QUERY, r"root\WMI"))
    except wmi.WmiError:
        sensors = []
    return Sample(now, ACPI_SOURCE if sensors else "", sensors)


def csv_path(day: dt.date) -> Path:
    return paths.temperature_dir() / f"temp_{day:%Y%m%d}.csv"


def log_sample(sample: Sample) -> Path:
    path = csv_path(sample.time.date())
    new = not path.exists()
    with path.open("a", encoding="utf-8") as f:
        if new:
            f.write(CSV_HEADER + "\n")
        stamp = sample.time.isoformat(timespec="seconds")
        for s in sample.sensors:
            f.write(f"{stamp},{s.name.replace(',', ' ')},{s.celsius}\n")
    return path


def prune_logs(now: dt.datetime) -> None:
    cutoff = (now - RETENTION).date()
    for old in paths.temperature_dir().glob("temp_*.csv"):
        try:
            if dt.datetime.strptime(old.stem[5:], "%Y%m%d").date() < cutoff:
                old.unlink()
        except (ValueError, OSError):
            continue


def recent_lines(day: dt.date, n: int = 40) -> list[str]:
    path = csv_path(day)
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8").splitlines()[-n:]


class OverheatGuard:
    """Alert when the CPU reaches the threshold, at most once per cooldown."""

    def __init__(self, threshold: float, cooldown_min: float) -> None:
        self.threshold = threshold
        self.cooldown = dt.timedelta(minutes=cooldown_min)
        self.last_alert: dt.datetime | None = None

    def check(self, sample: Sample) -> bool:
        hot = sample.cpu_max
        if hot is None or hot < self.threshold:
            return False
        if self.last_alert is not None and sample.time - self.last_alert < self.cooldown:
            return False
        self.last_alert = sample.time
        return True


def alert_report(sample: Sample, threshold: float) -> Report:
    hot = [s for s in sample.sensors if s.kind == "cpu" and s.celsius >= threshold]
    lines = [
        f"CPU at {sample.cpu_max} °C (alert threshold {threshold} °C), source: {sample.source}",
        "",
        "Hot sensors:",
        *(f"  {s.name}: {s.celsius} °C" for s in hot),
        "",
        "Last readings:",
        *recent_lines(sample.time.date()),
    ]
    return Report(
        "temperature",
        f"[OVERHEAT] CPU {sample.cpu_max} °C on {winapi.computer_name()}",
        "\n".join(lines),
        ALERT,
        sample,
        sample.time,
    )


class TempMonitor:
    """Samples every ``interval`` seconds in a daemon thread. ``on_sample`` and
    ``on_alert`` run on that thread."""

    def __init__(
        self,
        interval: float,
        threshold: float,
        cooldown_min: float,
        on_sample: Callable[[Sample], None],
        on_alert: Callable[[Report], None],
    ) -> None:
        self.interval = interval
        self.guard = OverheatGuard(threshold, cooldown_min)
        self._on_sample = on_sample
        self._on_alert = on_alert
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._warned = False

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def configure(self, interval: float, threshold: float, cooldown_min: float) -> None:
        self.interval = interval
        self.guard.threshold = threshold
        self.guard.cooldown = dt.timedelta(minutes=cooldown_min)

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True, name="temperature")
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def tick(self) -> Sample:
        """One reading: log it, report it, alert if hot."""
        sample = read_sensors()
        if not sample.sensors:
            if not self._warned:
                self._warned = True
                logger.warning(
                    "No temperature sensors readable; run LibreHardwareMonitor for real readings."
                )
        else:
            log_sample(sample)
        self._on_sample(sample)
        if self.guard.check(sample):
            logger.warning("Overheat: CPU %s °C", sample.cpu_max)
            self._on_alert(alert_report(sample, self.guard.threshold))
        return sample

    def _run(self) -> None:
        logger.info(
            "Temperature watch on (every %s s, alert at %s °C)", self.interval, self.guard.threshold
        )
        prune_logs(dt.datetime.now())
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("Temperature reading failed")
            self._stop.wait(self.interval)
