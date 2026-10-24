"""Where win-sentinel keeps its files, and logging setup.

Everything lives in one per-user folder, ``%APPDATA%\\win-sentinel`` on Windows
(``$XDG_DATA_HOME/win-sentinel`` elsewhere); ``WIN_SENTINEL_HOME`` overrides it.
The install folder is never written to.

    settings.json        what the GUI saves (schedules, email account, thresholds)
    state.json           bookkeeping (last runs, known network devices)
    win-sentinel.log     rotating log
    reports/             one text report per run
    temperature/         temp_YYYYMMDD.csv sensor log
    captures/            packet captures (tshark)
    updates/             downloaded installers
"""

from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from winsentinel import APP_NAME

FROZEN = bool(getattr(sys, "frozen", False))
HOME_ENV = "WIN_SENTINEL_HOME"

logger = logging.getLogger("winsentinel")

_home: Path | None = None


def app_home() -> Path:
    """The data folder for this user, honoring ``WIN_SENTINEL_HOME``."""
    if os.environ.get(HOME_ENV):
        return Path(os.environ[HOME_ENV]).expanduser()
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / APP_NAME


def home() -> Path:
    global _home
    if _home is None:
        _home = app_home()
    return _home


def set_home(path: Path | None) -> None:
    """Point every data file somewhere else (tests); None goes back to ``app_home()``."""
    global _home
    _home = path


def _dir(name: str) -> Path:
    d = home() / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def settings_file() -> Path:
    return home() / "settings.json"


def state_file() -> Path:
    return home() / "state.json"


def log_file() -> Path:
    return home() / f"{APP_NAME}.log"


def reports_dir() -> Path:
    return _dir("reports")


def temperature_dir() -> Path:
    return _dir("temperature")


def captures_dir() -> Path:
    return _dir("captures")


def updates_dir() -> Path:
    return _dir("updates")


def setup_logging(level: int = logging.INFO) -> Path:
    """Rotating log file plus the console when there is one (the windowed exe has none)."""
    path = log_file()
    if logger.handlers:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S")
    handlers: list[logging.Handler] = [
        RotatingFileHandler(path, maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    ]
    if sys.stdout is not None:
        handlers.append(logging.StreamHandler(sys.stdout))
    for handler in handlers:
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    logger.setLevel(level)
    return path
