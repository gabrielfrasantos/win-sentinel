"""Main window: one tab per job, a shared progress row (one job runs at a time), the
log, and the scheduler that runs due jobs by itself.

┌ win-sentinel 0.1.0 ─────────────────────────────────────────────────────────┐
│ [Cleanup] [Drivers] [Security] [Temperature] [Schedule & email]              │
│  ...tab...                                                                   │
│ ● Security scan: checking signatures...      [=====------]           [Stop] │
│ ┌ log ────────────────────────────────────────────────────────────────────┐ │
│ └─────────────────────────────────────────────────────────────────────────┘ │
│ Data: %APPDATA%\\win-sentinel          Open data folder · Check for updates  │
└──────────────────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path
from typing import Any

from PySide6.QtCore import QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QStatusBar,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from winsentinel import APP_NAME, __version__, jobs, paths, settings, updater, winapi
from winsentinel.gui import widgets
from winsentinel.gui.cleanup_tab import CleanupTab
from winsentinel.gui.desktop import SystemTrayIcon, app_icon
from winsentinel.gui.drivers_tab import DriversTab
from winsentinel.gui.schedule_tab import ScheduleTab
from winsentinel.gui.security_tab import SecurityTab
from winsentinel.gui.temperature_tab import TemperatureTab
from winsentinel.gui.update import UpdateChecker, UpdateDialog, download_with_progress
from winsentinel.gui.worker import JobController, TempController
from winsentinel.report import Cancelled, Report, error_report
from winsentinel.settings import JOB_LABELS, JOBS

logger = logging.getLogger("winsentinel")

SCHEDULE_TICK_MS = 30_000
FIRST_TICK_MS = 90_000
UPDATE_INTERVAL_MS = 24 * 3600 * 1000


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} {__version__}")
        self.setWindowIcon(app_icon())
        self.resize(1000, 760)

        self.tray: SystemTrayIcon | None = None
        self.checker: UpdateChecker | None = None
        self._told_about_tray = False
        self._manual_update_check = False
        self._update_dialog_open = False
        self._pending_installer: Path | None = None

        self.controller = JobController(self)
        self.controller.log_record.connect(self._on_log_record)
        self.controller.progress.connect(self._on_progress)
        self.controller.busy_changed.connect(self._on_busy_changed)
        self.temp = TempController(self)

        self.cleanup_tab = CleanupTab(self)
        self.drivers_tab = DriversTab(self)
        self.security_tab = SecurityTab(self)
        self.temperature_tab = TemperatureTab(self)
        self.schedule_tab = ScheduleTab(self)
        self.temp.sample.connect(self.temperature_tab.show_sample)
        self.temp.alert.connect(self._on_overheat)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.cleanup_tab, "Cleanup")
        self.tabs.addTab(self.drivers_tab, "Drivers")
        self.tabs.addTab(self.security_tab, "Security")
        self.tabs.addTab(self.temperature_tab, "Temperature")
        self.tabs.addTab(self.schedule_tab, "Schedule && email")

        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        if not winapi.is_admin():
            layout.addWidget(self._admin_banner())
        layout.addWidget(self.tabs, stretch=3)
        layout.addWidget(self._status_row())
        layout.addWidget(self._log_panel(), stretch=1)
        self._status_bar()

        self._schedule_timer = QTimer(self)
        self._schedule_timer.setInterval(SCHEDULE_TICK_MS)
        self._schedule_timer.timeout.connect(self.tick_schedule)
        self._schedule_timer.start()
        QTimer.singleShot(FIRST_TICK_MS, self.tick_schedule)
        self.temp.apply()

    def _admin_banner(self) -> QWidget:
        frame = QFrame()
        frame.setStyleSheet("QFrame { background: #5a4500; border-radius: 4px; }")
        row = QHBoxLayout(frame)
        text = QLabel(
            "Running without administrator rights: system cleanup, driver installs, "
            "packet capture and Start with Windows are unavailable."
        )
        text.setWordWrap(True)
        row.addWidget(text, stretch=1)
        if winapi.WINDOWS:
            btn = QPushButton("Restart as administrator")
            btn.clicked.connect(self._restart_elevated)
            row.addWidget(btn)
        return frame

    def _status_row(self) -> QWidget:
        widget = QWidget()
        row = QHBoxLayout(widget)
        row.setContentsMargins(0, 0, 0, 0)
        self._dot = widgets.status_dot(widgets.IDLE)
        self._status = QLabel("Ready.")
        self._progress = QProgressBar()
        self._progress.setMaximumWidth(240)
        self._progress.setVisible(False)
        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self.controller.stop)
        row.addWidget(self._dot)
        row.addWidget(self._status, stretch=1)
        row.addWidget(self._progress)
        row.addWidget(self._stop_btn)
        return widget

    def _log_panel(self) -> QPlainTextEdit:
        self._log_view = QPlainTextEdit()
        self._log_view.setReadOnly(True)
        self._log_view.setMaximumBlockCount(3000)
        self._log_view.setStyleSheet(
            "QPlainTextEdit { background: #1e1e1e; color: #dddddd;"
            " font-family: Consolas, monospace; font-size: 11px; }"
        )
        return self._log_view

    def _status_bar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        where = QLabel(f"Data: {paths.home()}")
        where.setStyleSheet(widgets.MUTED + " font-size: 10px;")
        bar.addWidget(where, 1)
        bar.addPermanentWidget(widgets.link_button("Open data folder", self.open_data_dir))
        self._check_updates_btn = widgets.link_button("Check for updates", self.check_for_updates)
        bar.addPermanentWidget(self._check_updates_btn)

    def set_tray(self, tray: SystemTrayIcon) -> None:
        self.tray = tray
        tray.messageClicked.connect(self.bring_to_front)
        self._refresh_tooltip()

    def set_checker(self, checker: UpdateChecker, automatic: bool) -> None:
        self.checker = checker
        checker.update_available.connect(self._on_update_available)
        checker.check_done.connect(self._on_update_check_done)
        if automatic:
            self._update_timer = QTimer(self)
            self._update_timer.setInterval(UPDATE_INTERVAL_MS)
            self._update_timer.timeout.connect(self._automatic_update_check)
            self._update_timer.start()
            QTimer.singleShot(5000, self._automatic_update_check)

    def shutdown(self) -> None:
        self._schedule_timer.stop()
        self.temp.stop()
        self.controller.shutdown()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.tray is not None:
            event.ignore()
            self.hide()
            self.tray.sync_menu()
            if not self._told_about_tray:
                self._told_about_tray = True
                self.tray.notify(
                    APP_NAME,
                    "Still running in the tray: scheduled runs and the temperature watch "
                    "continue. Right-click the icon to quit.",
                )
            return
        self.shutdown()
        event.accept()

    def bring_to_front(self) -> None:
        if self.tray is not None:
            self.tray.show_window()
        else:
            self.showNormal()
            self.raise_()
            self.activateWindow()

    def notify(self, message: str, warning: bool = False) -> None:
        """Tray balloon (when the window isn't in front) plus the status line."""
        self.statusBar().showMessage(message, 10_000)
        if self.tray is not None and (warning or not self.isActiveWindow()):
            self.tray.notify(APP_NAME, message, warning)

    def log_line(self, text: str) -> None:
        self._log_view.appendPlainText(f"[{dt.datetime.now():%H:%M:%S}] {text}")

    def _on_log_record(self, record: logging.LogRecord) -> None:
        when = dt.datetime.fromtimestamp(record.created)
        self._log_view.appendPlainText(f"[{when:%H:%M:%S}] {record.getMessage()}")

    def _on_progress(self, text: str, fraction: Any) -> None:
        self._status.setText(f"{self.controller.label}: {text}")
        if isinstance(fraction, float):
            self._progress.setRange(0, 100)
            self._progress.setValue(int(fraction * 100))
        else:
            self._progress.setRange(0, 0)

    def _on_busy_changed(self, busy: bool) -> None:
        widgets.set_dot(self._dot, widgets.RUNNING if busy else widgets.IDLE)
        self._progress.setVisible(busy)
        self._progress.setRange(0, 0)
        self._stop_btn.setEnabled(busy)
        if busy:
            self._status.setText(f"{self.controller.label}...")
        else:
            self._status.setText("Ready.")
        for tab in (self.cleanup_tab, self.drivers_tab, self.security_tab, self.schedule_tab):
            tab.set_busy(busy)
        if self.tray is not None:
            self.tray.set_busy(busy)
        if not busy:
            self.schedule_tab.refresh()
            if self._pending_installer is not None:
                QTimer.singleShot(500, lambda: self.install_update(self._pending_installer))

    def run_job(self, job: str) -> bool:
        """Run a job like the schedule does: saved settings, report saved and emailed."""
        if self.controller.busy:
            self.notify(f"{self.controller.label} is still running; try again when it ends.")
            return False
        s = settings.load_settings()
        runner = jobs.RUNNERS[job]

        def work(ctx: Any) -> Report:
            report = runner(ctx, s)
            jobs.deliver(report, s)
            return report

        settings.mark_job(job, "last_run", dt.datetime.now())
        return self.controller.start(
            JOB_LABELS[job], work, lambda report, error: self._on_job_done(job, report, error)
        )

    def _on_job_done(self, job: str, report: Report | None, error: BaseException | None) -> None:
        if error is not None:
            if not isinstance(error, Cancelled):
                failed = error_report(job, JOB_LABELS[job], error)
                jobs.deliver(failed)
                self.notify(failed.subject, warning=True)
            return
        assert report is not None
        if job == "clean":
            self.cleanup_tab.show_result(report.data)
        elif job == "drivers":
            scan, installed = report.data
            self.drivers_tab.show_scan(scan, installed)
        elif job == "security":
            self.security_tab.show_scan(report.data)
        self.notify(report.subject, warning=report.severity in ("alert", "error"))

    def tick_schedule(self) -> None:
        """Start the first job whose slot has passed since it last ran (one per tick)."""
        self._refresh_tooltip()
        if self.controller.busy:
            return
        now = dt.datetime.now()
        s = settings.load_settings()
        for job in JOBS:
            schedule = settings.schedule_of(s, job)
            last, since = settings.job_times(job)
            if since is None:
                settings.mark_job(job, "schedule_since", now)
                continue
            slot = settings.due_slot(schedule, now, max(t for t in (last, since) if t is not None))
            if slot is not None:
                logger.info("Scheduled %s (%s).", JOB_LABELS[job].lower(), f"{slot:%a %H:%M}")
                self.run_job(job)
                return

    def _refresh_tooltip(self) -> None:
        if self.tray is None:
            return
        now = dt.datetime.now()
        s = settings.load_settings()
        lines = [f"{APP_NAME} {__version__}"]
        for job in JOBS:
            nxt = settings.schedule_of(s, job).next_slot(now)
            if nxt:
                lines.append(f"{JOB_LABELS[job]}: {nxt:%a %H:%M}")
        self.tray.setToolTip("\n".join(lines))

    def _on_overheat(self, report: Report) -> None:
        self.notify(report.subject, warning=True)

    def open_data_dir(self) -> None:
        winapi.open_path(paths.home())

    def _restart_elevated(self) -> None:
        if winapi.relaunch_as_admin(["--handover"]):
            QApplication.quit()

    def check_for_updates(self) -> None:
        if self.checker is None:
            return
        self._manual_update_check = True
        self._check_updates_btn.setEnabled(False)
        self._check_updates_btn.setText("Checking...")
        self.checker.check_in_background()

    def _automatic_update_check(self) -> None:
        if self.checker is not None and settings.load_settings()["check_updates"]:
            self.checker.check_in_background()

    def _on_update_check_done(self, found: bool, error: str) -> None:
        self._check_updates_btn.setEnabled(True)
        self._check_updates_btn.setText("Check for updates")
        if self._manual_update_check and not found:
            message = (
                f"Update check failed: {error}"
                if error
                else f"{APP_NAME} {__version__} is up to date."
            )
            self.statusBar().showMessage(message, 8000)
        self._manual_update_check = False

    def _on_update_available(self, release: updater.Release) -> None:
        if self._update_dialog_open or self._pending_installer is not None:
            return
        self._update_dialog_open = True
        try:
            dialog = UpdateDialog(release, paths.FROZEN, self)
            if dialog.exec() != UpdateDialog.DialogCode.Accepted:
                return
            installer = download_with_progress(release, self)
        finally:
            self._update_dialog_open = False
        if installer is not None:
            self.install_update(installer)

    def install_update(self, installer: Path | None) -> None:
        """Run the verified installer and quit; waits for a running job to end first."""
        if installer is None:
            return
        if self.controller.busy:
            self._pending_installer = installer
            self.notify(f"The update installs when {self.controller.label.lower()} finishes.")
            return
        self._pending_installer = None
        try:
            updater.launch_installer(installer)
        except OSError as e:
            QMessageBox.warning(self, "Update", f"Could not start the installer:\n{e}")
            return
        QApplication.quit()
