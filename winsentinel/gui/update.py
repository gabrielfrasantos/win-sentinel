"""Update UI: a background check against GitHub Releases, a dialog that asks before
installing, and a download dialog that verifies the installer before handing it on."""

from __future__ import annotations

import logging
import threading
import webbrowser
from pathlib import Path

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QLabel,
    QProgressDialog,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from winsentinel import APP_NAME, __version__, paths, updater
from winsentinel.report import Cancelled, human_size

logger = logging.getLogger("winsentinel")


class UpdateChecker(QObject):
    """Checks for a newer release in a daemon thread. Signals arrive on Qt's thread:
    ``update_available(Release)`` for a newer release, ``check_done(found, error)``
    after every check (so a manual check can report "up to date")."""

    update_available = Signal(object)
    check_done = Signal(bool, str)

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._running = threading.Lock()

    def check_in_background(self) -> None:
        if self._running.acquire(blocking=False):
            threading.Thread(target=self._check, daemon=True, name="update-check").start()

    def _check(self) -> None:
        found, error = False, ""
        try:
            release = updater.latest_release()
            if release is not None and updater.is_newer(release):
                logger.info(
                    "Update available: %s %s (running %s)", APP_NAME, release.version, __version__
                )
                found = True
                self.update_available.emit(release)
        except (OSError, ValueError) as e:
            error = str(e)
            logger.debug("Update check failed: %s", e)
        finally:
            self._running.release()
            self.check_done.emit(found, error)


class UpdateDialog(QDialog):
    """Asks before updating: Install now (download, verify, install, restart),
    the release page, or Later."""

    def __init__(
        self, release: updater.Release, can_install: bool, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.release = release
        self.setWindowTitle("Update available")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"<b>{APP_NAME} {release.version}</b> is available."))
        layout.addWidget(QLabel(f"You are running version {__version__}."))
        if release.notes:
            notes = QTextBrowser()
            notes.setMarkdown(release.notes)
            notes.setOpenExternalLinks(True)
            notes.setMaximumHeight(220)
            layout.addWidget(notes)
        buttons = QDialogButtonBox()
        if can_install and release.installable:
            size = f" ({human_size(release.size)})" if release.size else ""
            layout.addWidget(
                QLabel(
                    f"Install now downloads the installer{size}, checks it and restarts {APP_NAME}."
                )
            )
            install = buttons.addButton("Install now", QDialogButtonBox.ButtonRole.AcceptRole)
            install.setDefault(True)
        page = buttons.addButton("Release page", QDialogButtonBox.ButtonRole.HelpRole)
        page.clicked.connect(lambda: webbrowser.open(release.page_url))
        buttons.addButton("Later", QDialogButtonBox.ButtonRole.RejectRole)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


class _Download(QObject):
    progress = Signal(int, int)
    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, release: updater.Release) -> None:
        super().__init__()
        self.release = release
        self.stop = threading.Event()

    def run(self) -> None:
        try:
            path = updater.download(
                self.release, lambda done, total: self.progress.emit(done, total), self.stop
            )
        except Cancelled:
            self.failed.emit("")
        except (updater.UpdateError, OSError, ValueError) as e:
            logger.error("Update download failed: %s", e)
            self.failed.emit(str(e))
        else:
            self.finished.emit(path)


def download_with_progress(release: updater.Release, parent: QWidget | None) -> Path | None:
    """Download and verify with a cancellable progress dialog; the installer path, or
    None (cancelled or failed; failures are explained in the dialog's label)."""
    dialog = QProgressDialog(
        f"Downloading {APP_NAME} {release.version}...", "Cancel", 0, 100, parent
    )
    dialog.setWindowTitle("Updating")
    dialog.setWindowModality(Qt.WindowModality.ApplicationModal)
    dialog.setAutoClose(False)
    dialog.setAutoReset(False)
    dialog.setMinimumDuration(0)
    job = _Download(release)
    result: dict[str, object] = {}

    def on_progress(done: int, total: int) -> None:
        if total:
            dialog.setValue(int(done * 100 / total))
        dialog.setLabelText(f"Downloading {APP_NAME} {release.version}... {human_size(done)}")

    def on_finished(path: Path) -> None:
        result["path"] = path
        dialog.accept()

    def on_failed(message: str) -> None:
        result["error"] = message
        dialog.reject()

    job.progress.connect(on_progress, Qt.ConnectionType.QueuedConnection)
    job.finished.connect(on_finished, Qt.ConnectionType.QueuedConnection)
    job.failed.connect(on_failed, Qt.ConnectionType.QueuedConnection)
    dialog.canceled.connect(job.stop.set)
    threading.Thread(target=job.run, daemon=True, name="update-download").start()
    dialog.exec()
    job.stop.set()
    path = result.get("path")
    if isinstance(path, Path):
        return path
    error = result.get("error")
    if error:
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.warning(
            parent,
            "Update failed",
            f"The update was not installed:\n{error}\n\nLog: {paths.log_file()}",
        )
    return None
