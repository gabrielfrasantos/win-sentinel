"""Small widgets and table helpers shared by the tabs."""

from __future__ import annotations

import datetime as dt
from collections import deque
from collections.abc import Callable, Sequence
from typing import Any

from PySide6.QtCore import QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPaintEvent, QPen
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QWidget,
)

IDLE, RUNNING, FAILED, GOOD = "#666666", "#5aa0ff", "#ff5555", "#44cc66"
SEVERITY_COLORS = {
    "critical": QColor(255, 80, 80, 70),
    "warning": QColor(255, 190, 60, 60),
    "info": QColor(90, 160, 255, 40),
}
MUTED = "color: #888888;"


def status_dot(color: str) -> QLabel:
    label = QLabel("●")
    set_dot(label, color)
    return label


def set_dot(label: QLabel, color: str) -> None:
    label.setStyleSheet(f"color: {color}; font-size: 18px;")


def note(text: str = "") -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(MUTED)
    label.setWordWrap(True)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextBrowserInteraction)
    label.setOpenExternalLinks(True)
    return label


def link_button(text: str, slot: Callable[[], None]) -> QPushButton:
    btn = QPushButton(text)
    btn.setFlat(True)
    btn.setStyleSheet("color: #8fa8ff; font-size: 10px;")
    btn.clicked.connect(slot)
    return btn


def make_table(headers: Sequence[str], stretch: int = -1) -> QTableWidget:
    """Read-only, row-selecting table; column ``stretch`` takes the spare width."""
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(list(headers))
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.verticalHeader().setVisible(False)
    table.setWordWrap(False)
    header = table.horizontalHeader()
    header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
    if stretch >= 0:
        header.setSectionResizeMode(stretch, QHeaderView.ResizeMode.Stretch)
    else:
        header.setStretchLastSection(True)
    return table


def add_row(
    table: QTableWidget,
    values: Sequence[str],
    data: Any = None,
    *,
    checkable: bool = False,
    checked: bool = False,
    color: QColor | None = None,
    tooltip: str = "",
) -> int:
    row = table.rowCount()
    table.insertRow(row)
    for col, value in enumerate(values):
        item = QTableWidgetItem(value)
        if col == 0:
            item.setData(Qt.ItemDataRole.UserRole, data)
            if checkable:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        if color is not None:
            item.setBackground(color)
        if tooltip or len(value) > 60:
            item.setToolTip(tooltip or value)
        table.setItem(row, col, item)
    return row


def row_data(table: QTableWidget, row: int) -> Any:
    item = table.item(row, 0)
    return item.data(Qt.ItemDataRole.UserRole) if item is not None else None


def selected_data(table: QTableWidget) -> Any:
    rows = table.selectionModel().selectedRows()
    return row_data(table, rows[0].row()) if rows else None


def checked_data(table: QTableWidget) -> list[Any]:
    out = []
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is not None and item.checkState() == Qt.CheckState.Checked:
            out.append(item.data(Qt.ItemDataRole.UserRole))
    return out


def set_cell(table: QTableWidget, row: int, col: int, text: str) -> None:
    item = table.item(row, col)
    if item is None:
        table.setItem(row, col, QTableWidgetItem(text))
    else:
        item.setText(text)


class TempChart(QWidget):
    """Line chart of the hottest CPU sensor over the last ``minutes``, with the alert
    threshold as a dashed line."""

    def __init__(self, minutes: int = 60, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.minutes = minutes
        self.threshold = 90.0
        self.points: deque[tuple[dt.datetime, float]] = deque(maxlen=minutes * 60)
        self.setMinimumHeight(140)

    def add(self, when: dt.datetime, celsius: float) -> None:
        self.points.append((when, celsius))
        cutoff = when - dt.timedelta(minutes=self.minutes)
        while self.points and self.points[0][0] < cutoff:
            self.points.popleft()
        self.update()

    def paintEvent(self, event: QPaintEvent) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(36, 8, -8, -18)
        p.fillRect(self.rect(), QColor("#1e1e1e"))
        low, high = 20.0, max(100.0, self.threshold + 5)
        span = high - low

        def y(value: float) -> float:
            return rect.bottom() - (min(max(value, low), high) - low) / span * rect.height()

        p.setPen(QColor("#555555"))
        for mark in range(30, int(high) + 1, 20):
            p.drawLine(rect.left(), int(y(mark)), rect.right(), int(y(mark)))
            p.drawText(2, int(y(mark)) + 4, f"{mark}°")
        dash = QPen(QColor("#ff5555"))
        dash.setStyle(Qt.PenStyle.DashLine)
        p.setPen(dash)
        p.drawLine(rect.left(), int(y(self.threshold)), rect.right(), int(y(self.threshold)))
        p.setPen(QColor("#888888"))
        p.drawText(rect.left(), self.height() - 4, f"last {self.minutes} min")
        if len(self.points) >= 2:
            end = self.points[-1][0]
            start = end - dt.timedelta(minutes=self.minutes)
            total = (end - start).total_seconds()
            line = [
                QPointF(
                    rect.left() + (t - start).total_seconds() / total * rect.width(),
                    y(v),
                )
                for t, v in self.points
            ]
            p.setPen(QPen(QColor("#5aa0ff"), 2))
            p.drawPolyline(line)
        p.end()
