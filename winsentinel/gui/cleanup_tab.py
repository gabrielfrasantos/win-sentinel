"""Cleanup tab: tick what to clean, Analyze to see the sizes, Clean to free the space.
The ticks are the selection scheduled cleanups use too."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from winsentinel import cleanup, settings, winapi
from winsentinel.gui import widgets
from winsentinel.report import Cancelled, human_size, save_report

if TYPE_CHECKING:
    from winsentinel.gui.window import MainWindow

COLUMNS = ("Item", "Size", "Files", "Notes")


class CleanupTab(QWidget):
    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self._window = window
        self._rows: dict[str, int] = {}
        s = settings.load_settings()

        self.table = widgets.make_table(COLUMNS, stretch=3)
        selected = {t.id for t in cleanup.selected_targets(s["clean_targets"])}
        admin = winapi.is_admin()
        for target in cleanup.TARGETS:
            notes = target.description
            if target.admin and not admin:
                notes = f"needs administrator; {notes}"
            row = widgets.add_row(
                self.table,
                [target.label, "", "", notes],
                target.id,
                checkable=True,
                checked=target.id in selected,
            )
            self._rows[target.id] = row
        self.table.itemChanged.connect(self._on_item_changed)

        self.min_age = QSpinBox()
        self.min_age.setRange(0, 24 * 30)
        self.min_age.setSuffix(" h")
        self.min_age.setValue(int(s["clean_min_age_hours"]))
        self.min_age.setToolTip(
            "Temp files changed more recently stay: an installer may need them."
        )
        self.min_age.valueChanged.connect(
            lambda v: settings.save_settings({"clean_min_age_hours": int(v)})
        )
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.analyze)
        self.clean_btn = QPushButton("Clean selected")
        self.clean_btn.setDefault(True)
        self.clean_btn.clicked.connect(self.clean)
        self.summary = QLabel("Analyze to see how much space can be freed.")

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Keep temp files newer than"))
        controls.addWidget(self.min_age)
        controls.addStretch(1)
        controls.addWidget(self.analyze_btn)
        controls.addWidget(self.clean_btn)

        layout = QVBoxLayout(self)
        layout.addWidget(
            widgets.note(
                "Only caches and leftovers are removed, never documents, settings or the "
                "registry. Files in use are skipped. The ticked items are also what the "
                "scheduled cleanup removes."
            )
        )
        layout.addWidget(self.table, stretch=1)
        layout.addWidget(self.summary)
        layout.addLayout(controls)

    def set_busy(self, busy: bool) -> None:
        self.analyze_btn.setEnabled(not busy)
        self.clean_btn.setEnabled(not busy)

    def _selected(self) -> list[cleanup.Target]:
        ids = set(widgets.checked_data(self.table))
        return [t for t in cleanup.TARGETS if t.id in ids]

    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() == 0:
            settings.save_settings({"clean_targets": [t.id for t in self._selected()]})

    def _set(self, target_id: str, size: str, files: str, notes: str | None = None) -> None:
        row = self._rows[target_id]
        widgets.set_cell(self.table, row, 1, size)
        widgets.set_cell(self.table, row, 2, files)
        if notes is not None:
            widgets.set_cell(self.table, row, 3, notes)

    def analyze(self) -> None:
        targets = list(cleanup.TARGETS)
        age = self.min_age.value()
        self.summary.setText("Analyzing...")
        self._window.controller.start(
            "Cleanup analysis",
            lambda ctx: cleanup.analyze(targets, age, ctx),
            self._on_analyzed,
            self._on_scan_item,
        )

    def _on_scan_item(self, scan: cleanup.TargetScan) -> None:
        if scan.target.kind in ("dns", "dism"):
            self._set(scan.target.id, "-", "-")
            return
        self._set(scan.target.id, human_size(scan.bytes), str(scan.files))
        if scan.note:
            self._set(scan.target.id, human_size(scan.bytes), str(scan.files), scan.note)

    def _on_analyzed(self, scans: Any, error: BaseException | None) -> None:
        if error is not None:
            stopped = isinstance(error, Cancelled)
            self.summary.setText("Analysis stopped." if stopped else f"Analysis failed: {error}")
            return
        chosen = {t.id for t in self._selected()}
        total = sum(s.bytes for s in scans if s.target.id in chosen)
        self.summary.setText(f"{human_size(total)} can be freed from the selected items.")

    def clean(self) -> None:
        targets = self._selected()
        if not targets:
            QMessageBox.information(self, "Cleanup", "Tick at least one item.")
            return
        names = "\n".join(f"• {t.label}" for t in targets)
        answer = QMessageBox.question(self, "Clean up", f"Clean these items?\n\n{names}")
        if answer != QMessageBox.StandardButton.Yes:
            return
        age = self.min_age.value()
        self.summary.setText("Cleaning...")
        self._window.controller.start(
            "Cleanup",
            lambda ctx: cleanup.clean(targets, age, ctx),
            self._on_cleaned,
            self._on_clean_item,
        )

    def _on_clean_item(self, item: cleanup.TargetResult) -> None:
        note = item.error or (f"{item.skipped} in use" if item.skipped else "cleaned")
        files = str(item.files) if item.target.kind not in ("dns", "dism") else "-"
        self._set(item.target.id, human_size(item.bytes), files, note)

    def _on_cleaned(self, result: Any, error: BaseException | None) -> None:
        if error is not None:
            self.summary.setText(f"Cleanup failed: {error}")
            return
        self.show_result(result)
        report = cleanup.report(result)
        save_report(report)
        self._window.notify(report.subject)

    def show_result(self, result: cleanup.CleanResult) -> None:
        for item in result.results:
            self._on_clean_item(item)
        text = f"Freed {human_size(result.total_bytes)} in {result.total_files} files."
        if result.cancelled:
            text += " (stopped before the end)"
        self.summary.setText(text)
