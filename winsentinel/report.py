"""What every job shares: the run context it reports progress through, and the
``Report`` it produces (saved to reports/, emailed, shown in the tray)."""

from __future__ import annotations

import datetime as dt
import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from winsentinel import paths

logger = logging.getLogger(__name__)

OK, NOTICE, ALERT, ERROR = "ok", "notice", "alert", "error"
SEVERITY_ORDER = {OK: 0, NOTICE: 1, ALERT: 2, ERROR: 3}
REPORT_RETENTION = dt.timedelta(days=180)


class Cancelled(Exception):
    """The user (or shutdown) asked the running job to stop."""


class Context:
    """Handed to every job: a stop flag plus progress / item callbacks.

    The GUI's worker thread routes the callbacks to Qt; the CLI and tests use the
    defaults, which only log.
    """

    def __init__(
        self,
        stop: threading.Event | None = None,
        on_progress: Callable[[str, float | None], None] | None = None,
        on_item: Callable[[Any], None] | None = None,
    ) -> None:
        self.stop = stop or threading.Event()
        self._on_progress = on_progress
        self._on_item = on_item

    @property
    def stopped(self) -> bool:
        return self.stop.is_set()

    def check(self) -> None:
        if self.stop.is_set():
            raise Cancelled

    def wait(self, seconds: float) -> None:
        """Sleep, but wake (and raise Cancelled) as soon as stop is set."""
        if self.stop.wait(seconds):
            raise Cancelled

    def progress(self, text: str, fraction: float | None = None) -> None:
        logger.info(text)
        if self._on_progress is not None:
            self._on_progress(text, fraction)

    def item(self, payload: Any) -> None:
        if self._on_item is not None:
            self._on_item(payload)


@dataclass
class Report:
    """A finished run, ready to save and email. ``data`` carries the job's own result."""

    job: str
    subject: str
    body: str
    severity: str = OK
    data: Any = None
    created: dt.datetime = field(default_factory=dt.datetime.now)

    @property
    def problem(self) -> bool:
        return self.severity != OK

    def text(self) -> str:
        return f"{self.subject}\n{self.created:%Y-%m-%d %H:%M:%S}\n\n{self.body}\n"


def error_report(job: str, label: str, error: BaseException) -> Report:
    return Report(job, f"{label} FAILED", f"Error: {error}", ERROR)


def save_report(report: Report) -> Path:
    """Write the report to reports/ and drop reports older than REPORT_RETENTION."""
    folder = paths.reports_dir()
    path = folder / f"{report.created:%Y%m%d-%H%M%S}-{report.job}.txt"
    path.write_text(report.text(), encoding="utf-8")
    cutoff = (dt.datetime.now() - REPORT_RETENTION).timestamp()
    for old in folder.glob("*.txt"):
        try:
            if old.stat().st_mtime < cutoff:
                old.unlink()
        except OSError as e:
            logger.debug("Could not prune %s: %s", old, e)
    return path


def human_size(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if abs(n) < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def table(rows: Sequence[Sequence[str]], headers: Sequence[str] | None = None) -> str:
    """Plain-text table for reports and email bodies."""
    all_rows = [headers, *rows] if headers else list(rows)
    if not all_rows:
        return ""
    widths = [max(len(r[i]) for r in all_rows) for i in range(len(all_rows[0]))]
    lines = [
        "  ".join(c.ljust(w) for c, w in zip(r, widths, strict=False)).rstrip() for r in all_rows
    ]
    if headers:
        lines.insert(1, "  ".join("-" * w for w in widths))
    return "\n".join(lines)
