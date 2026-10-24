"""Background work for the GUI, as in port-bridge and flight-monitor: Qt owns the main
thread; jobs run in a daemon thread and post their events (log records, progress,
streamed items, the result) to a ``queue.SimpleQueue`` that a 100 ms QTimer drains on
the Qt thread. No widget is touched from a worker.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections.abc import Callable
from typing import Any

from PySide6.QtCore import QObject, QTimer, Signal

from winsentinel import jobs, settings, temperature
from winsentinel.report import Cancelled, Context, Report

logger = logging.getLogger("winsentinel")

DRAIN_MS = 100

DoneCallback = Callable[[Any, BaseException | None], None]


class _QueueHandler(logging.Handler):
    def __init__(self, events: queue.SimpleQueue[tuple[str, Any]]) -> None:
        super().__init__(logging.INFO)
        self._events = events

    def emit(self, record: logging.LogRecord) -> None:
        self._events.put_nowait(("log", record))


class JobController(QObject):
    """Runs one job at a time. ``start(label, fn, on_done, on_item)`` calls
    ``fn(ctx)`` in a worker thread; ``on_item`` gets each ``ctx.item()`` and
    ``on_done(result, error)`` the outcome (error is a Cancelled when stopped), both on
    the Qt thread. Also relays every log record of the app to ``log_record``."""

    busy_changed = Signal(bool)
    progress = Signal(str, object)
    log_record = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._events: queue.SimpleQueue[tuple[str, Any]] = queue.SimpleQueue()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._on_done: DoneCallback | None = None
        self._on_item: Callable[[Any], None] | None = None
        self.label = ""
        self._handler = _QueueHandler(self._events)
        logger.addHandler(self._handler)
        self._timer = QTimer(self)
        self._timer.setInterval(DRAIN_MS)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    @property
    def busy(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(
        self,
        label: str,
        fn: Callable[[Context], Any],
        on_done: DoneCallback,
        on_item: Callable[[Any], None] | None = None,
    ) -> bool:
        if self.busy:
            return False
        self.label = label
        self._stop.clear()
        self._on_done, self._on_item = on_done, on_item
        put = self._events.put_nowait
        ctx = Context(
            self._stop,
            on_progress=lambda text, fraction: put(("progress", (text, fraction))),
            on_item=lambda item: put(("item", item)),
        )
        self._thread = threading.Thread(
            target=self._run, args=(fn, ctx), daemon=True, name=f"job-{label}"
        )
        self._thread.start()
        self.busy_changed.emit(True)
        return True

    def stop(self) -> None:
        self._stop.set()

    def shutdown(self, timeout: float = 10.0) -> None:
        self.stop()
        if self._thread is not None:
            self._thread.join(timeout)
        self._timer.stop()
        logger.removeHandler(self._handler)

    def _run(self, fn: Callable[[Context], Any], ctx: Context) -> None:
        result: Any = None
        error: BaseException | None = None
        try:
            result = fn(ctx)
        except Cancelled as e:
            logger.info("%s stopped.", self.label)
            error = e
        except Exception as e:
            logger.exception("%s failed", self.label)
            error = e
        self._events.put_nowait(("done", (result, error)))

    def drain(self) -> None:
        self._drain()

    def _drain(self) -> None:
        while True:
            try:
                kind, payload = self._events.get_nowait()
            except queue.Empty:
                return
            if kind == "log":
                self.log_record.emit(payload)
            elif kind == "progress":
                self.progress.emit(*payload)
            elif kind == "item" and self._on_item is not None:
                self._on_item(payload)
            elif kind == "done":
                if self._thread is not None:
                    self._thread.join(1)
                callback, self._on_done, self._on_item = self._on_done, None, None
                self.busy_changed.emit(False)
                if callback is not None:
                    callback(*payload)


class TempController(QObject):
    """Owns the temperature monitor thread; re-emits its readings and alerts on Qt's
    thread. Alerts are saved and emailed from the monitor thread (SMTP can be slow)."""

    sample = Signal(object)
    alert = Signal(object)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._events: queue.SimpleQueue[tuple[str, Any]] = queue.SimpleQueue()
        self._monitor: temperature.TempMonitor | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(DRAIN_MS * 5)
        self._timer.timeout.connect(self._drain)
        self._timer.start()

    @property
    def running(self) -> bool:
        return self._monitor is not None and self._monitor.running

    def apply(self, s: dict[str, Any] | None = None) -> None:
        """Start, reconfigure or stop the monitor to match the settings."""
        s = s or settings.load_settings()
        interval = int(s["temp_interval"])
        threshold = int(s["temp_threshold"])
        cooldown = int(s["temp_cooldown_min"])
        if not s["temp_enabled"]:
            self.stop()
            return
        if self._monitor is None:
            self._monitor = temperature.TempMonitor(
                interval,
                threshold,
                cooldown,
                on_sample=lambda smp: self._events.put_nowait(("sample", smp)),
                on_alert=self._on_alert,
            )
        else:
            self._monitor.configure(interval, threshold, cooldown)
        self._monitor.start()

    def stop(self) -> None:
        if self._monitor is not None:
            self._monitor.stop()
            self._monitor = None

    def _on_alert(self, report: Report) -> None:
        jobs.deliver(report)
        self._events.put_nowait(("alert", report))

    def _drain(self) -> None:
        while True:
            try:
                kind, payload = self._events.get_nowait()
            except queue.Empty:
                return
            (self.sample if kind == "sample" else self.alert).emit(payload)
