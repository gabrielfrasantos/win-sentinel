"""Schedule & email tab: when each job runs by itself, where reports go, and the app
options (start with Windows, automatic update checks)."""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from PySide6.QtCore import QTime
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

from winsentinel import paths, settings, startup, winapi, wmi
from winsentinel.gui import widgets
from winsentinel.gui.email_dialog import EmailDialog
from winsentinel.settings import FREQUENCIES, JOB_LABELS, JOBS, WEEKDAYS, Schedule

if TYPE_CHECKING:
    from winsentinel.gui.window import MainWindow

EMAIL_WHEN = (
    ("Every run", "always"),
    ("Only problems: findings, failures, overheating", "problems"),
    ("Never", "never"),
)


class _JobRow:
    def __init__(self, tab: ScheduleTab, job: str, schedule: Schedule) -> None:
        self.job = job
        self.frequency = QComboBox()
        for f in FREQUENCIES:
            self.frequency.addItem(f.capitalize(), f)
        self.frequency.setCurrentIndex(FREQUENCIES.index(schedule.frequency))
        self.weekday = QComboBox()
        self.weekday.addItems(list(WEEKDAYS))
        self.weekday.setCurrentIndex(schedule.weekday)
        self.monthday = QSpinBox()
        self.monthday.setRange(1, 28)
        self.monthday.setPrefix("day ")
        self.monthday.setValue(schedule.monthday)
        self.time = QTimeEdit(QTime(schedule.at().hour, schedule.at().minute))
        self.time.setDisplayFormat("HH:mm")
        self.info = QLabel()
        self.info.setStyleSheet(widgets.MUTED)
        self.run_now = QPushButton("Run now")
        self.run_now.clicked.connect(lambda: tab.main.run_job(job))
        for signal in (
            self.frequency.currentIndexChanged,
            self.weekday.currentIndexChanged,
            self.monthday.valueChanged,
            self.time.timeChanged,
        ):
            signal.connect(lambda *_: tab.save_schedule(self))
        self.sync()

    def schedule(self) -> Schedule:
        return Schedule(
            frequency=str(self.frequency.currentData()),
            time=self.time.time().toString("HH:mm"),
            weekday=self.weekday.currentIndex(),
            monthday=self.monthday.value(),
        )

    def sync(self) -> None:
        f = self.frequency.currentData()
        self.weekday.setVisible(f == "weekly")
        self.monthday.setVisible(f == "monthly")
        self.time.setEnabled(f != "off")


class ScheduleTab(QWidget):
    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self.main = window
        s = settings.load_settings()

        runs = QGroupBox("Automatic runs")
        grid = QGridLayout(runs)
        self.rows: dict[str, _JobRow] = {}
        for i, job in enumerate(JOBS):
            row = _JobRow(self, job, settings.schedule_of(s, job))
            self.rows[job] = row
            grid.addWidget(QLabel(f"<b>{JOB_LABELS[job]}</b>"), i, 0)
            grid.addWidget(row.frequency, i, 1)
            grid.addWidget(row.weekday, i, 2)
            grid.addWidget(row.monthday, i, 2)
            grid.addWidget(row.time, i, 3)
            grid.addWidget(row.info, i, 4)
            grid.addWidget(row.run_now, i, 5)
        grid.setColumnStretch(4, 1)
        self.auto_install = QCheckBox("Install the driver updates a scheduled check finds")
        self.auto_install.setChecked(bool(s["drivers_auto_install"]))
        self.auto_install.toggled.connect(
            lambda on: settings.save_settings({"drivers_auto_install": bool(on)})
        )
        grid.addWidget(self.auto_install, len(JOBS), 0, 1, 6)
        grid.addWidget(
            widgets.note(
                "Runs happen while win-sentinel is running (it starts with Windows and stays "
                "in the tray). A run missed while the PC was off happens at the next start. "
                "Scheduled cleanups clean the items ticked on the Cleanup tab; scheduled "
                "scans use the Security tab's options."
            ),
            len(JOBS) + 1,
            0,
            1,
            6,
        )

        mail = QGroupBox("Email reports")
        mail_row = QHBoxLayout(mail)
        self.email_info = QLabel()
        self.when = QComboBox()
        for label, value in EMAIL_WHEN:
            self.when.addItem(label, value)
        self.when.setCurrentIndex(max(0, self.when.findData(s["email_when"])))
        self.when.currentIndexChanged.connect(
            lambda: settings.save_settings({"email_when": self.when.currentData()})
        )
        email_btn = QPushButton("Email settings…")
        email_btn.clicked.connect(self._edit_email)
        mail_row.addWidget(self.email_info, stretch=1)
        mail_row.addWidget(QLabel("Send:"))
        mail_row.addWidget(self.when)
        mail_row.addWidget(email_btn)

        app = QGroupBox("App")
        app_box = QVBoxLayout(app)
        self.startup_check = QCheckBox(
            "Start with Windows (in the tray, as administrator, without a UAC prompt)"
        )
        self.startup_check.setEnabled(winapi.WINDOWS and winapi.is_admin())
        self.startup_check.setChecked(startup.is_enabled())
        self.startup_check.toggled.connect(self._toggle_startup)
        self.updates_check = QCheckBox("Check for new versions automatically (every day)")
        self.updates_check.setChecked(bool(s["check_updates"]))
        self.updates_check.toggled.connect(
            lambda on: settings.save_settings({"check_updates": bool(on)})
        )
        folders = QHBoxLayout()
        data_btn = QPushButton("Open data folder")
        data_btn.clicked.connect(lambda: winapi.open_path(paths.home()))
        reports_btn = QPushButton("Open reports")
        reports_btn.clicked.connect(lambda: winapi.open_path(paths.reports_dir()))
        folders.addWidget(data_btn)
        folders.addWidget(reports_btn)
        folders.addStretch(1)
        app_box.addWidget(self.startup_check)
        app_box.addWidget(self.updates_check)
        app_box.addLayout(folders)

        layout = QVBoxLayout(self)
        layout.addWidget(runs)
        layout.addWidget(mail)
        layout.addWidget(app)
        layout.addStretch(1)
        self.refresh()

    def set_busy(self, busy: bool) -> None:
        for row in self.rows.values():
            row.run_now.setEnabled(not busy)

    def save_schedule(self, row: _JobRow) -> None:
        row.sync()
        settings.save_settings({f"{row.job}_schedule": row.schedule().to_dict()})
        settings.mark_job(row.job, "schedule_since", dt.datetime.now())
        self.refresh()

    def refresh(self) -> None:
        now = dt.datetime.now()
        s = settings.load_settings()
        for job, row in self.rows.items():
            schedule = settings.schedule_of(s, job)
            last, _ = settings.job_times(job)
            nxt = schedule.next_slot(now)
            parts = [f"next {nxt:%a %d %b %H:%M}" if nxt else "not scheduled"]
            parts.append(f"last {last:%a %d %b %H:%M}" if last else "never ran")
            row.info.setText(" · ".join(parts))
        user = s["email_user"]
        if user:
            self.email_info.setText(f"From {user} to {s['email_recipient'] or user}")
        else:
            self.email_info.setText("No email account set: reports are only saved to disk.")

    def _edit_email(self) -> None:
        if EmailDialog(self).exec():
            self.refresh()

    def _toggle_startup(self, on: bool) -> None:
        try:
            if on:
                startup.enable()
            else:
                startup.disable()
        except wmi.WmiError as e:
            QMessageBox.warning(self, "Start with Windows", str(e))
            self.startup_check.blockSignals(True)
            self.startup_check.setChecked(startup.is_enabled())
            self.startup_check.blockSignals(False)
