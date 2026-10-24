"""Saved settings (settings.json), app bookkeeping (state.json) and the schedule rules.

``load_settings()`` always returns every key of ``DEFAULTS``: a missing or invalid
value in the file falls back to its default, so a hand-edited file can't break a run.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from winsentinel import paths

logger = logging.getLogger(__name__)

JOBS = ("clean", "drivers", "security")
JOB_LABELS = {"clean": "Cleanup", "drivers": "Driver check", "security": "Security scan"}
FREQUENCIES = ("off", "daily", "weekly", "monthly")
WEEKDAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
EMAIL_WHEN = ("always", "problems", "never")


@dataclass(frozen=True)
class Schedule:
    """When a job runs: off, daily, weekly (on ``weekday``, Monday = 0) or monthly
    (on ``monthday``, 1-28 so every month has it), at ``time`` (HH:MM, local)."""

    frequency: str = "off"
    time: str = "03:00"
    weekday: int = 6
    monthday: int = 1

    @classmethod
    def from_value(cls, value: object, default: Schedule) -> Schedule:
        if not isinstance(value, dict):
            return default
        try:
            s = cls(
                frequency=str(value.get("frequency", default.frequency)),
                time=str(value.get("time", default.time)),
                weekday=int(value.get("weekday", default.weekday)),
                monthday=int(value.get("monthday", default.monthday)),
            )
            s.at()
        except (TypeError, ValueError):
            return default
        if s.frequency not in FREQUENCIES or not 0 <= s.weekday <= 6 or not 1 <= s.monthday <= 28:
            return default
        return s

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def at(self) -> dt.time:
        hours, _, minutes = self.time.partition(":")
        return dt.time(int(hours), int(minutes))

    def fires_on(self, day: dt.date) -> bool:
        if self.frequency == "daily":
            return True
        if self.frequency == "weekly":
            return day.weekday() == self.weekday
        if self.frequency == "monthly":
            return day.day == self.monthday
        return False

    def latest_slot(self, now: dt.datetime) -> dt.datetime | None:
        """The most recent scheduled moment at or before ``now``."""
        for back in range(32):
            day = now.date() - dt.timedelta(days=back)
            slot = dt.datetime.combine(day, self.at())
            if self.fires_on(day) and slot <= now:
                return slot
        return None

    def next_slot(self, now: dt.datetime) -> dt.datetime | None:
        for ahead in range(32):
            day = now.date() + dt.timedelta(days=ahead)
            slot = dt.datetime.combine(day, self.at())
            if self.fires_on(day) and slot > now:
                return slot
        return None

    def describe(self) -> str:
        if self.frequency == "daily":
            return f"daily at {self.time}"
        if self.frequency == "weekly":
            return f"every {WEEKDAYS[self.weekday]} at {self.time}"
        if self.frequency == "monthly":
            return f"monthly on day {self.monthday} at {self.time}"
        return "off"


def due_slot(schedule: Schedule, now: dt.datetime, since: dt.datetime | None) -> dt.datetime | None:
    """The slot to run now, if one passed after ``since`` (the last run, or when the
    schedule was set). A PC that was off at the slot catches up once, at the next tick."""
    slot = schedule.latest_slot(now)
    if slot is None or since is None or since >= slot:
        return None
    return slot


DEFAULT_SCHEDULES = {
    "clean": Schedule("monthly", "03:00", 2, 15),
    "drivers": Schedule("weekly", "03:00", 6, 1),
    "security": Schedule("daily", "01:00", 0, 1),
}

DEFAULTS: dict[str, Any] = {
    "clean_schedule": DEFAULT_SCHEDULES["clean"].to_dict(),
    "drivers_schedule": DEFAULT_SCHEDULES["drivers"].to_dict(),
    "security_schedule": DEFAULT_SCHEDULES["security"].to_dict(),
    "clean_targets": None,
    "clean_min_age_hours": 24,
    "drivers_auto_install": False,
    "security_capture": True,
    "capture_seconds": 120,
    "lan_sweep": True,
    "ignored_findings": [],
    "temp_enabled": True,
    "temp_interval": 15,
    "temp_threshold": 90,
    "temp_cooldown_min": 30,
    "email_when": "problems",
    "email_user": "",
    "email_recipient": "",
    "email_host": "smtp.gmail.com",
    "email_port": 465,
    "check_updates": True,
}


def _int_in(low: int, high: int) -> Callable[[object], bool]:
    return lambda v: isinstance(v, int) and not isinstance(v, bool) and low <= v <= high


def _str_list(v: object) -> bool:
    return isinstance(v, list) and all(isinstance(x, str) for x in v)


_VALID: dict[str, Callable[[object], bool]] = {
    "clean_targets": lambda v: v is None or _str_list(v),
    "clean_min_age_hours": _int_in(0, 24 * 30),
    "drivers_auto_install": lambda v: isinstance(v, bool),
    "security_capture": lambda v: isinstance(v, bool),
    "capture_seconds": _int_in(10, 3600),
    "lan_sweep": lambda v: isinstance(v, bool),
    "ignored_findings": _str_list,
    "temp_enabled": lambda v: isinstance(v, bool),
    "temp_interval": _int_in(2, 3600),
    "temp_threshold": _int_in(40, 120),
    "temp_cooldown_min": _int_in(1, 24 * 60),
    "email_when": lambda v: v in EMAIL_WHEN,
    "email_user": lambda v: isinstance(v, str),
    "email_recipient": lambda v: isinstance(v, str),
    "email_host": lambda v: isinstance(v, str) and bool(v),
    "email_port": _int_in(1, 65535),
    "check_updates": lambda v: isinstance(v, bool),
}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        logger.warning("Ignoring %s: %s", path.name, e)
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    tmp.replace(path)


def load_settings() -> dict[str, Any]:
    """DEFAULTS overlaid with the valid values of settings.json."""
    saved = _read_json(paths.settings_file())
    settings = dict(DEFAULTS)
    for key, value in saved.items():
        if key not in DEFAULTS:
            continue
        if key.endswith("_schedule"):
            job = key.removesuffix("_schedule")
            settings[key] = Schedule.from_value(value, DEFAULT_SCHEDULES[job]).to_dict()
        elif _VALID[key](value):
            settings[key] = value
        else:
            logger.warning("Bad %s in settings.json (%r); using the default.", key, value)
    return settings


def save_settings(values: dict[str, Any]) -> None:
    """Update the given keys in settings.json, keeping the others."""
    current = _read_json(paths.settings_file())
    current.update({k: values[k] for k in DEFAULTS if k in values})
    _write_json(paths.settings_file(), current)


def schedule_of(settings: dict[str, Any], job: str) -> Schedule:
    return Schedule.from_value(settings[f"{job}_schedule"], DEFAULT_SCHEDULES[job])


def load_state() -> dict[str, Any]:
    return _read_json(paths.state_file())


def save_state(**values: Any) -> None:
    state = load_state()
    state.update(values)
    _write_json(paths.state_file(), state)


def _parse_time(value: object) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def job_times(job: str) -> tuple[dt.datetime | None, dt.datetime | None]:
    """(last run, when its schedule was set) for a job, from state.json."""
    state = load_state()
    last = state.get("last_run", {})
    since = state.get("schedule_since", {})
    return (
        _parse_time(last.get(job) if isinstance(last, dict) else None),
        _parse_time(since.get(job) if isinstance(since, dict) else None),
    )


def mark_job(job: str, key: str, when: dt.datetime) -> None:
    """Record ``when`` under ``state[key][job]`` (key: last_run or schedule_since)."""
    state = load_state()
    table = state.get(key)
    if not isinstance(table, dict):
        table = {}
    table[job] = when.isoformat(timespec="seconds")
    save_state(**{key: table})
