"""Drivers tab: search Windows Update for driver updates, install the ticked ones, and
list devices Device Manager reports a problem for."""

from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING, Any

from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from winsentinel import drivers, winapi
from winsentinel.gui import widgets
from winsentinel.report import Cancelled, human_size, save_report

if TYPE_CHECKING:
    from winsentinel.gui.window import MainWindow

UPDATE_COLUMNS = ("Driver", "Class", "Provider", "Date", "Size", "Status")
PROBLEM_COLUMNS = ("Device", "Class", "Problem")


class DriversTab(QWidget):
    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self._window = window
        self._scan = drivers.DriverScan()
        self.updates = widgets.make_table(UPDATE_COLUMNS, stretch=0)
        self.problems = widgets.make_table(PROBLEM_COLUMNS, stretch=2)
        self.status = QLabel("Search to see which drivers Windows Update has for this PC.")

        self.search_btn = QPushButton("Search for driver updates")
        self.search_btn.setDefault(True)
        self.search_btn.clicked.connect(self.search)
        self.install_btn = QPushButton("Install selected")
        self.install_btn.setEnabled(False)
        self.install_btn.clicked.connect(self.install)
        manager_btn = QPushButton("Device Manager")
        manager_btn.clicked.connect(drivers.open_device_manager)
        rescan_btn = QPushButton("Scan for hardware changes")
        rescan_btn.clicked.connect(self._rescan)

        top = QHBoxLayout()
        top.addWidget(self.search_btn)
        top.addWidget(self.install_btn)
        top.addStretch(1)
        top.addWidget(manager_btn)
        top.addWidget(rescan_btn)

        updates_box = QGroupBox("Driver updates from Windows Update")
        box = QVBoxLayout(updates_box)
        box.addWidget(self.updates)
        problems_box = QGroupBox("Devices with problems")
        box2 = QVBoxLayout(problems_box)
        box2.addWidget(self.problems)

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.status)
        layout.addWidget(updates_box, stretch=3)
        layout.addWidget(problems_box, stretch=2)
        layout.addWidget(
            widgets.note(
                "The search takes a few minutes. Drivers install one by one and never restart "
                "the PC; if a new driver misbehaves, roll it back in Device Manager "
                "(device > Properties > Driver > Roll Back Driver)."
            )
        )

    def set_busy(self, busy: bool) -> None:
        self.search_btn.setEnabled(not busy)
        self.install_btn.setEnabled(not busy and self.updates.rowCount() > 0)

    def search(self) -> None:
        self.status.setText("Searching Windows Update...")
        self._window.controller.start("Driver search", drivers.search, self._on_searched)

    def _on_searched(self, scan: Any, error: BaseException | None) -> None:
        if error is not None:
            stopped = isinstance(error, Cancelled)
            self.status.setText("Search stopped." if stopped else f"Search failed: {error}")
            return
        self.show_scan(scan)
        save_report(drivers.scan_report(scan))

    def show_scan(
        self, scan: drivers.DriverScan, installed: drivers.InstallResult | None = None
    ) -> None:
        done = {o.update.id: o for o in installed.outcomes} if installed else {}
        self.updates.setRowCount(0)
        for u in scan.updates:
            outcome = done.get(u.id)
            status = ""
            if outcome is not None:
                status = outcome.result + (f": {outcome.error}" if outcome.error else "")
            widgets.add_row(
                self.updates,
                [u.title, u.driver_class, u.provider, u.date, human_size(u.size), status],
                u,
                checkable=outcome is None or not outcome.ok,
                checked=outcome is None,
                tooltip=f"{u.title}\n{u.manufacturer} {u.model}\n{u.hardware_id}",
            )
        self.problems.setRowCount(0)
        for d in scan.problems:
            widgets.add_row(
                self.problems, [d.name, d.device_class, d.problem], d, tooltip=d.device_id
            )
        text = (
            f"{len(scan.updates)} driver update(s), {len(scan.problems)} device problem(s). "
            f"Checked {dt.datetime.now():%H:%M}."
        )
        if scan.error:
            text = f"{text}  Error: {scan.error}"
        if installed and installed.reboot_required:
            text += "  Restart the PC to finish installing."
        self.status.setText(text)
        self.install_btn.setEnabled(bool(scan.updates) and not self._window.controller.busy)
        self._scan = scan

    def install(self) -> None:
        chosen = widgets.checked_data(self.updates)
        if not chosen:
            QMessageBox.information(self, "Install drivers", "Tick the drivers to install.")
            return
        if not winapi.is_admin():
            QMessageBox.warning(
                self, "Install drivers", "Installing drivers needs administrator rights."
            )
            return
        names = "\n".join(f"• {u.title}" for u in chosen)
        answer = QMessageBox.question(
            self,
            "Install drivers",
            f"Download and install these drivers?\n\n{names}\n\nThe PC will not restart by itself.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.status.setText("Installing...")
        self._window.controller.start(
            "Driver install", lambda ctx: drivers.install(chosen, ctx), self._on_installed
        )

    def _on_installed(self, result: Any, error: BaseException | None) -> None:
        if error is not None:
            self.status.setText(f"Install failed: {error}")
            return
        self.show_scan(self._scan, result)
        report = drivers.scan_report(self._scan, result)
        save_report(report)
        self._window.notify(report.subject, warning=report.severity != "notice")

    def _rescan(self) -> None:
        drivers.rescan_devices()
        self.status.setText("Asked Windows to scan for hardware changes.")
