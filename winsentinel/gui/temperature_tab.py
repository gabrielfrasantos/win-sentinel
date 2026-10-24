"""Temperature tab: live CPU temperature, a one-hour chart, every sensor, and the
watch settings (interval, alert threshold, time between alerts)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from winsentinel import paths, settings, temperature, winapi
from winsentinel.gui import widgets

if TYPE_CHECKING:
    from winsentinel.gui.window import MainWindow

SENSOR_COLUMNS = ("Sensor", "°C", "Type")
LHM_HINT = (
    "For real per-core temperatures install LibreHardwareMonitor and keep it running "
    "(Options: Run On Windows Startup, Start Minimized): "
    "<code>winget install LibreHardwareMonitor.LibreHardwareMonitor</code>"
)


def _spin(low: int, high: int, value: int, suffix: str) -> QSpinBox:
    spin = QSpinBox()
    spin.setRange(low, high)
    spin.setValue(value)
    spin.setSuffix(suffix)
    return spin


class TemperatureTab(QWidget):
    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self._window = window
        s = settings.load_settings()

        self.enabled = QCheckBox("Watch the CPU temperature every")
        self.enabled.setChecked(bool(s["temp_enabled"]))
        self.interval = _spin(2, 3600, int(s["temp_interval"]), " s")
        self.threshold = _spin(40, 120, int(s["temp_threshold"]), " °C")
        self.cooldown = _spin(1, 24 * 60, int(s["temp_cooldown_min"]), " min")
        for widget in (self.interval, self.threshold, self.cooldown):
            widget.valueChanged.connect(self._save)
        self.enabled.toggled.connect(self._save)

        row = QHBoxLayout()
        row.addWidget(self.enabled)
        row.addWidget(self.interval)
        row.addWidget(QLabel("alert at"))
        row.addWidget(self.threshold)
        row.addWidget(QLabel("at most every"))
        row.addWidget(self.cooldown)
        row.addStretch(1)

        self.current = QLabel("-")
        big = QFont()
        big.setPointSize(22)
        big.setBold(True)
        self.current.setFont(big)
        self.source = QLabel("")
        self.source.setStyleSheet(widgets.MUTED)
        self.hint = widgets.note(LHM_HINT)
        self.hint.setVisible(winapi.WINDOWS)
        self.chart = widgets.TempChart()
        self.chart.threshold = float(s["temp_threshold"])
        self.sensors = widgets.make_table(SENSOR_COLUMNS, stretch=0)
        logs_btn = QPushButton("Open temperature logs")
        logs_btn.clicked.connect(lambda: winapi.open_path(paths.temperature_dir()))

        head = QHBoxLayout()
        head.addWidget(self.current)
        head.addWidget(self.source, stretch=1)
        head.addWidget(logs_btn)

        layout = QVBoxLayout(self)
        layout.addLayout(row)
        layout.addLayout(head)
        layout.addWidget(self.chart)
        layout.addWidget(self.sensors, stretch=1)
        layout.addWidget(self.hint)
        layout.addWidget(
            widgets.note(
                "Readings are logged to a daily CSV (kept 30 days) so the last values before "
                "a crash survive it. Alerts go to the tray and to your email."
            )
        )

    def _save(self) -> None:
        values = {
            "temp_enabled": self.enabled.isChecked(),
            "temp_interval": self.interval.value(),
            "temp_threshold": self.threshold.value(),
            "temp_cooldown_min": self.cooldown.value(),
        }
        settings.save_settings(values)
        self.chart.threshold = float(self.threshold.value())
        self.chart.update()
        self._window.temp.apply()
        if not self.enabled.isChecked():
            self.current.setText("off")

    def show_sample(self, sample: temperature.Sample) -> None:
        hot = sample.cpu_max
        if hot is None:
            self.current.setText("no sensor")
            self.source.setText("No CPU temperature sensor is readable.")
        else:
            self.current.setText(f"CPU {hot:.0f} °C")
            color = "#ff5555" if hot >= self.threshold.value() else ""
            self.current.setStyleSheet(f"color: {color};" if color else "")
            note = "  (coarse board sensor)" if sample.source == temperature.ACPI_SOURCE else ""
            self.source.setText(f"{sample.source}{note}, {sample.time:%H:%M:%S}")
            self.chart.add(sample.time, hot)
        self.hint.setVisible(
            winapi.WINDOWS and sample.source not in (h for h, _ in temperature.HW_MONITORS)
        )
        self.sensors.setRowCount(0)
        for s in sorted(sample.sensors, key=lambda s: (s.kind != "cpu", s.name)):
            widgets.add_row(self.sensors, [s.name, f"{s.celsius:.1f}", s.kind.upper()], s)
