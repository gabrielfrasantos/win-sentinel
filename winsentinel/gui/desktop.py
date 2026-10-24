"""Desktop integration, as in port-bridge and flight-monitor: app icon, tray icon and a
single-instance guard (which also lets the installer ask the running copy to quit)."""

from __future__ import annotations

import logging
from collections.abc import Callable

from PySide6.QtCore import QObject, QPointF, Qt, Signal
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import QApplication, QMenu, QSystemTrayIcon, QWidget

from winsentinel import APP_NAME

logger = logging.getLogger("winsentinel")

INSTANCE_KEY = f"{APP_NAME}-gui"


def render_icon(size: int) -> QPixmap:
    """Teal rounded square with a white shield and check mark."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    margin = max(1, size // 16)
    radius = max(3, size // 5)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#00796B"))
    p.drawRoundedRect(margin, margin, size - 2 * margin, size - 2 * margin, radius, radius)

    p.scale(size / 100, size / 100)
    shield = QPainterPath()
    shield.moveTo(50, 16)
    shield.lineTo(78, 27)
    shield.cubicTo(78, 55, 68, 74, 50, 86)
    shield.cubicTo(32, 74, 22, 55, 22, 27)
    shield.closeSubpath()
    p.setBrush(QColor("white"))
    p.drawPath(shield)
    pen = QPen(QColor("#00796B"), 8)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolyline([QPointF(37, 50), QPointF(47, 60), QPointF(64, 41)])
    p.end()
    return px


def app_icon() -> QIcon:
    icon = QIcon()
    for size in (16, 24, 32, 48, 64, 128, 256):
        icon.addPixmap(render_icon(size))
    return icon


class SingleInstance(QObject):
    """One app per user: a second launch asks the first to show its window and exits.

    Two copies would run every scheduled job twice. The same channel lets the
    installer ask the running copy to quit before it replaces the files.
    """

    activated = Signal()
    quit_requested = Signal()

    def __init__(self, key: str = INSTANCE_KEY, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._key = key
        self._server: QLocalServer | None = None

    def send(self, message: bytes) -> bool:
        """Deliver message to the running instance; False if there is none.

        Waits for the acknowledgement before hanging up: on Windows a named pipe
        closed right after writing can lose the data unread.
        """
        socket = QLocalSocket()
        socket.connectToServer(self._key)
        if not socket.waitForConnected(1000):
            return False
        socket.write(message)
        socket.flush()
        socket.waitForBytesWritten(1000)
        socket.waitForReadyRead(2000)
        socket.disconnectFromServer()
        return True

    def is_running(self) -> bool:
        """Whether another instance is up (without asking it anything)."""
        socket = QLocalSocket()
        socket.connectToServer(self._key)
        if not socket.waitForConnected(500):
            return False
        socket.disconnectFromServer()
        return True

    def already_running(self) -> bool:
        """True (after asking it to show itself) if another instance is up; else become it."""
        if self.send(b"show"):
            return True
        QLocalServer.removeServer(self._key)
        self._server = QLocalServer(self)
        self._server.newConnection.connect(self._on_connection)
        if not self._server.listen(self._key):
            logger.info("Single-instance guard unavailable: %s", self._server.errorString())
        return False

    def _on_connection(self) -> None:
        assert self._server is not None
        while (conn := self._server.nextPendingConnection()) is not None:
            if not conn.bytesAvailable():
                conn.waitForReadyRead(1000)
            message = bytes(conn.readAll().data()).strip()
            conn.write(b"ok")
            conn.flush()
            conn.waitForBytesWritten(1000)
            conn.disconnectFromServer()
            conn.deleteLater()
            if message == b"quit":
                self.quit_requested.emit()
            elif message:
                self.activated.emit()


class SystemTrayIcon(QSystemTrayIcon):
    """Keeps the app (and its schedule and temperature watch) reachable from the
    notification area. Click toggles the window."""

    def __init__(
        self,
        window: QWidget,
        *,
        run_job: Callable[[str], None],
        check_updates: Callable[[], None],
        open_data: Callable[[], None],
        parent: QObject | None = None,
    ) -> None:
        super().__init__(app_icon(), parent)
        self._window = window
        menu = QMenu()
        self._toggle_action = menu.addAction("Hide window")
        self._toggle_action.triggered.connect(self.toggle_window)
        menu.addSeparator()
        self.job_actions = {}
        for job, text in (
            ("clean", "Clean up now"),
            ("drivers", "Check drivers now"),
            ("security", "Security scan now"),
        ):
            action = menu.addAction(text)
            action.triggered.connect(lambda _=False, j=job: run_job(j))
            self.job_actions[job] = action
        menu.addSeparator()
        self.check_updates_action = menu.addAction("Check for updates")
        self.check_updates_action.triggered.connect(check_updates)
        menu.addAction("Open data folder").triggered.connect(open_data)
        menu.addSeparator()
        menu.addAction("Quit").triggered.connect(QApplication.quit)
        self._menu = menu
        self.setContextMenu(menu)
        self.setToolTip(APP_NAME)
        self.activated.connect(self._on_activated)

    def set_busy(self, busy: bool) -> None:
        for action in self.job_actions.values():
            action.setEnabled(not busy)

    def _on_activated(self, reason: QSystemTrayIcon.ActivationReason) -> None:
        if reason in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.DoubleClick,
        ):
            self.toggle_window()

    def toggle_window(self) -> None:
        if self._window.isVisible():
            self._window.hide()
            self.sync_menu()
        else:
            self.show_window()

    def show_window(self) -> None:
        self._window.showNormal()
        self._window.raise_()
        self._window.activateWindow()
        self.sync_menu()

    def sync_menu(self) -> None:
        self._toggle_action.setText("Hide window" if self._window.isVisible() else "Show window")

    def notify(self, title: str, message: str, warning: bool = False) -> None:
        icon = (
            QSystemTrayIcon.MessageIcon.Warning
            if warning
            else QSystemTrayIcon.MessageIcon.Information
        )
        self.showMessage(title, message, icon, 8000)
