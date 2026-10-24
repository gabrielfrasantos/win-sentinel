"""Security tab: scan for crypto-miners, spyware and strangers on the network, review the
findings (trust the ones you know, end a process, open its folder), and run a
Microsoft Defender quick scan."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from winsentinel import security, settings, winapi
from winsentinel.gui import widgets
from winsentinel.report import Cancelled, save_report

if TYPE_CHECKING:
    from winsentinel.gui.window import MainWindow

FINDING_COLUMNS = ("Level", "Area", "Finding", "Details")
CONNECTION_COLUMNS = ("Program", "PID", "Remote address", "Port", "Name", "Direction", "Signature")
DEVICE_COLUMNS = ("IP", "MAC", "Name", "First seen", "")
AUTOSTART_COLUMNS = ("Source", "Name", "Signature", "Command")
TRUSTED = QColor(128, 128, 128, 40)


class SecurityTab(QWidget):
    def __init__(self, window: MainWindow) -> None:
        super().__init__()
        self._window = window
        self._scan = security.SecurityScan()
        s = settings.load_settings()

        self.scan_btn = QPushButton("Scan now")
        self.scan_btn.setDefault(True)
        self.scan_btn.clicked.connect(self.scan)
        self.capture_check = QCheckBox("Packet capture for")
        self.capture_check.setChecked(bool(s["security_capture"]))
        self.capture_check.setToolTip(
            "Records which internet hosts this PC sends traffic to and which names it\n"
            "looks up (needs administrator). Saved as a .pcap Wireshark can open."
        )
        self.capture_check.toggled.connect(self._save_options)
        self.capture_seconds = QSpinBox()
        self.capture_seconds.setRange(10, 3600)
        self.capture_seconds.setSuffix(" s")
        self.capture_seconds.setValue(int(s["capture_seconds"]))
        self.capture_seconds.valueChanged.connect(self._save_options)
        self.lan_check = QCheckBox("Look for devices on my network")
        self.lan_check.setChecked(bool(s["lan_sweep"]))
        self.lan_check.toggled.connect(self._save_options)
        self.defender_btn = QPushButton("Defender quick scan")
        self.defender_btn.clicked.connect(self.defender_scan)
        self.summary = QLabel("Scan to check for crypto-miners, spyware and remote access.")

        top = QHBoxLayout()
        top.addWidget(self.scan_btn)
        top.addWidget(self.capture_check)
        top.addWidget(self.capture_seconds)
        top.addWidget(self.lan_check)
        top.addStretch(1)
        top.addWidget(self.defender_btn)

        self.findings = widgets.make_table(FINDING_COLUMNS, stretch=3)
        self.findings.itemSelectionChanged.connect(self._sync_actions)
        self.trust_btn = QPushButton("Trust")
        self.trust_btn.setToolTip("Stop reporting this finding (until you untrust it).")
        self.trust_btn.clicked.connect(self._toggle_trust)
        self.kill_btn = QPushButton("End process")
        self.kill_btn.clicked.connect(self._end_process)
        self.reveal_btn = QPushButton("Open file location")
        self.reveal_btn.clicked.connect(self._reveal)
        actions = QHBoxLayout()
        actions.addStretch(1)
        actions.addWidget(self.trust_btn)
        actions.addWidget(self.kill_btn)
        actions.addWidget(self.reveal_btn)
        findings_page = QWidget()
        page = QVBoxLayout(findings_page)
        page.setContentsMargins(0, 0, 0, 0)
        page.addWidget(self.findings)
        page.addLayout(actions)

        self.connections = widgets.make_table(CONNECTION_COLUMNS, stretch=4)
        self.devices = widgets.make_table(DEVICE_COLUMNS, stretch=2)
        self.autostarts = widgets.make_table(AUTOSTART_COLUMNS, stretch=3)
        self.pages = QTabWidget()
        self.pages.addTab(findings_page, "Findings")
        self.pages.addTab(self.connections, "Internet connections")
        self.pages.addTab(self.devices, "Network devices")
        self.pages.addTab(self.autostarts, "Starts with Windows")

        layout = QVBoxLayout(self)
        layout.addLayout(top)
        layout.addWidget(self.summary)
        layout.addWidget(self.pages, stretch=1)
        layout.addWidget(
            widgets.note(
                "Findings are leads, not verdicts: a remote-access tool you installed is fine. "
                "Trust it once and it is no longer reported or emailed."
            )
        )
        self._sync_actions()

    def set_busy(self, busy: bool) -> None:
        self.scan_btn.setEnabled(not busy)
        self.defender_btn.setEnabled(not busy)
        self._sync_actions()

    def _save_options(self) -> None:
        settings.save_settings(
            {
                "security_capture": self.capture_check.isChecked(),
                "capture_seconds": self.capture_seconds.value(),
                "lan_sweep": self.lan_check.isChecked(),
            }
        )

    def scan(self) -> None:
        seconds = self.capture_seconds.value() if self.capture_check.isChecked() else None
        if seconds and not winapi.is_admin():
            seconds = None
        lan = self.lan_check.isChecked()
        self.summary.setText("Scanning...")
        self._window.controller.start(
            "Security scan",
            lambda ctx: security.scan(ctx, capture_seconds=seconds, lan_sweep=lan),
            self._on_scanned,
        )

    def _on_scanned(self, result: Any, error: BaseException | None) -> None:
        if error is not None:
            stopped = isinstance(error, Cancelled)
            self.summary.setText("Scan stopped." if stopped else f"Scan failed: {error}")
            return
        self.show_scan(result)
        report = security.report(result, settings.load_settings()["ignored_findings"])
        save_report(report)
        self._window.notify(report.subject, warning=report.problem)

    def show_scan(self, result: security.SecurityScan) -> None:
        self._scan = result
        for e in result.errors:
            self._window.log_line(f"Security check skipped: {e}")
        self._fill_findings()
        self.connections.setRowCount(0)
        sigs = {p.pid: p.signature for p in result.processes}
        for c in sorted(result.connections, key=lambda c: (c.process.lower(), c.remote_ip)):
            if not c.external:
                continue
            widgets.add_row(
                self.connections,
                [
                    c.process,
                    str(c.pid),
                    c.remote_ip,
                    str(c.remote_port),
                    ", ".join(c.hosts[:2]),
                    "inbound" if c.inbound else "outbound",
                    sigs.get(c.pid, ""),
                ],
                c,
            )
        self.devices.setRowCount(0)
        for d in result.devices:
            tags = ["NEW"] if d.new else []
            if d.router:
                tags.append("router")
            widgets.add_row(
                self.devices,
                [d.ip, d.mac, d.name, d.first_seen.replace("T", " "), " ".join(tags)],
                d,
                color=widgets.SEVERITY_COLORS["warning"] if d.new else None,
            )
        self.autostarts.setRowCount(0)
        for a in result.autostarts:
            if not a.enabled or (a.source == "Service" and a.signature in ("", "signed")):
                continue
            widgets.add_row(self.autostarts, [a.source, a.name, a.signature, a.command], a)

    def _fill_findings(self) -> None:
        ignored = set(settings.load_settings()["ignored_findings"])
        self.findings.setRowCount(0)
        for f in self._scan.findings:
            trusted = f.key in ignored
            level = f.severity.upper() + (" (trusted)" if trusted else "")
            widgets.add_row(
                self.findings,
                [level, f.category, f.title, f.detail],
                f,
                color=TRUSTED if trusted else widgets.SEVERITY_COLORS.get(f.severity),
                tooltip=f"{f.title}\n{f.detail}",
            )
        active = self._scan.active(ignored)
        counts = {sev: sum(f.severity == sev for f in active) for sev in widgets.SEVERITY_COLORS}
        text = (
            f"{counts['critical']} critical, {counts['warning']} warning(s), "
            f"{counts['info']} note(s); {len(self._scan.findings) - len(active)} trusted."
        )
        if self._scan.errors:
            text += f"  {len(self._scan.errors)} check(s) could not run (see the log)."
        self.summary.setText(text)
        self._sync_actions()

    def _selected(self) -> security.Finding | None:
        found = widgets.selected_data(self.findings)
        return found if isinstance(found, security.Finding) else None

    def _sync_actions(self) -> None:
        f = self._selected()
        busy = self._window.controller.busy if hasattr(self._window, "controller") else False
        ignored = set(settings.load_settings()["ignored_findings"])
        self.trust_btn.setEnabled(f is not None and bool(f.key))
        self.trust_btn.setText("Untrust" if f is not None and f.key in ignored else "Trust")
        self.kill_btn.setEnabled(f is not None and f.pid is not None and not busy)
        self.reveal_btn.setEnabled(f is not None and bool(f.path))

    def _toggle_trust(self) -> None:
        f = self._selected()
        if f is None or not f.key:
            return
        ignored = list(settings.load_settings()["ignored_findings"])
        if f.key in ignored:
            ignored.remove(f.key)
        else:
            ignored.append(f.key)
        settings.save_settings({"ignored_findings": ignored})
        self._fill_findings()

    def _end_process(self) -> None:
        f = self._selected()
        if f is None or f.pid is None:
            return
        answer = QMessageBox.question(
            self,
            "End process",
            f"End process {f.pid}?\n\n{f.title}\n{f.path}\n\nUnsaved work in it is lost.",
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        error = security.end_process(f.pid)
        if error:
            QMessageBox.warning(self, "End process", f"Could not end it: {error}")
        else:
            self._window.log_line(f"Ended process {f.pid} ({f.title}).")

    def _reveal(self) -> None:
        f = self._selected()
        if f is not None and f.path:
            winapi.reveal(f.path)

    def defender_scan(self) -> None:
        self.summary.setText("Microsoft Defender quick scan running...")
        self._window.controller.start(
            "Defender quick scan", security.defender_quick_scan, self._on_defender_done
        )

    def _on_defender_done(self, report: Any, error: BaseException | None) -> None:
        if error is not None:
            self.summary.setText(f"Defender scan did not finish: {error}")
            return
        save_report(report)
        self.summary.setText(report.subject)
        self._window.notify(report.subject, warning=report.problem)
