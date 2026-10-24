import datetime as dt
import json

import pytest

from winsentinel import paths, settings
from winsentinel.settings import DEFAULTS, Schedule, due_slot


def at(text):
    return dt.datetime.fromisoformat(text)


def test_defaults_when_no_file():
    assert settings.load_settings() == DEFAULTS


def test_bad_values_fall_back_per_key():
    paths.settings_file().parent.mkdir(parents=True)
    paths.settings_file().write_text(
        json.dumps(
            {
                "temp_threshold": "hot",
                "temp_interval": 30,
                "email_when": "sometimes",
                "clean_schedule": {"frequency": "hourly"},
                "security_schedule": {"frequency": "weekly", "time": "22:15", "weekday": 2},
                "unknown": 1,
            }
        )
    )
    s = settings.load_settings()
    assert s["temp_threshold"] == DEFAULTS["temp_threshold"]
    assert s["temp_interval"] == 30
    assert s["email_when"] == DEFAULTS["email_when"]
    assert s["clean_schedule"] == DEFAULTS["clean_schedule"]
    assert settings.schedule_of(s, "security") == Schedule("weekly", "22:15", 2, 1)
    assert "unknown" not in s


def test_unreadable_file_is_ignored():
    paths.settings_file().parent.mkdir(parents=True)
    paths.settings_file().write_text("{not json")
    assert settings.load_settings() == DEFAULTS


def test_save_updates_only_given_keys():
    settings.save_settings({"temp_threshold": 85})
    settings.save_settings({"email_when": "always", "not_a_setting": 1})
    saved = json.loads(paths.settings_file().read_text())
    assert saved == {"temp_threshold": 85, "email_when": "always"}


@pytest.mark.parametrize(
    "schedule, now, latest, nxt",
    [
        (Schedule("daily", "01:00"), "2026-10-24 12:00", "2026-10-24 01:00", "2026-10-25 01:00"),
        (Schedule("daily", "13:00"), "2026-10-24 12:00", "2026-10-23 13:00", "2026-10-24 13:00"),
        (
            Schedule("weekly", "03:00", weekday=6),
            "2026-10-24 12:00",
            "2026-10-18 03:00",
            "2026-10-25 03:00",
        ),
        (
            Schedule("monthly", "03:00", monthday=15),
            "2026-10-24 12:00",
            "2026-10-15 03:00",
            "2026-11-15 03:00",
        ),
        (Schedule("off"), "2026-10-24 12:00", None, None),
    ],
)
def test_slots(schedule, now, latest, nxt):
    assert schedule.latest_slot(at(now)) == (at(latest) if latest else None)
    assert schedule.next_slot(at(now)) == (at(nxt) if nxt else None)


def test_due_slot_runs_once_and_catches_up():
    daily = Schedule("daily", "01:00")
    assert due_slot(daily, at("2026-10-24 12:00"), at("2026-10-23 01:05")) == at("2026-10-24 01:00")
    assert due_slot(daily, at("2026-10-24 12:00"), at("2026-10-24 01:00")) is None
    assert due_slot(daily, at("2026-10-24 12:00"), None) is None
    monthly = Schedule("monthly", "03:00", monthday=15)
    assert due_slot(monthly, at("2026-10-24 09:00"), at("2026-09-20 03:00")) == at(
        "2026-10-15 03:00"
    )


def test_schedule_from_bad_values():
    default = Schedule("daily", "01:00")
    assert Schedule.from_value({"frequency": "daily", "time": "25:00"}, default) == default
    assert Schedule.from_value({"frequency": "monthly", "monthday": 31}, default) == default
    assert Schedule.from_value("daily", default) == default
    assert Schedule("weekly", "03:00", 6).describe() == "every Sunday at 03:00"


def test_job_times_round_trip():
    when = dt.datetime(2026, 10, 24, 1, 0, 3)
    settings.mark_job("security", "last_run", when)
    settings.mark_job("security", "schedule_since", when - dt.timedelta(days=1))
    last, since = settings.job_times("security")
    assert last == when and since == when - dt.timedelta(days=1)
    assert settings.job_times("clean") == (None, None)
