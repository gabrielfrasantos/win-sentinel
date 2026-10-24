"""Email settings: sending account (Gmail App Password by default), recipient, server,
with a test send. The password goes to Windows Credential Manager."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from winsentinel import APP_NAME, emailer
from winsentinel.gui import widgets


class EmailDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Email settings")
        self.setMinimumWidth(460)
        cfg = emailer.load_config()

        self.user = QLineEdit(cfg.user)
        self.user.setPlaceholderText("you@gmail.com")
        self.password = QLineEdit(cfg.password)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("Gmail: a 16-letter App Password")
        self.recipient = QLineEdit(cfg.recipient if cfg.recipient != cfg.user else "")
        self.recipient.setPlaceholderText("default: the sending account")
        self.host = QLineEdit(cfg.host)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(cfg.port)
        self.port.setToolTip("465 = SSL; 587 (or any other) = STARTTLS")
        help_link = QLabel(
            '<a href="https://myaccount.google.com/apppasswords">Create a Gmail App Password</a>'
            " (needs 2-Step Verification)"
        )
        help_link.setOpenExternalLinks(True)

        form = QFormLayout()
        form.addRow("From account:", self.user)
        form.addRow("Password:", self.password)
        form.addRow("", help_link)
        form.addRow("Send reports to:", self.recipient)
        server = QHBoxLayout()
        server.addWidget(self.host, stretch=1)
        server.addWidget(QLabel("Port:"))
        server.addWidget(self.port)
        form.addRow("SMTP server:", server)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel
        )
        test = buttons.addButton("Send test email", QDialogButtonBox.ButtonRole.ActionRole)
        test.clicked.connect(self._send_test)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addLayout(form)
        layout.addWidget(
            widgets.note(
                "The password is kept in Windows Credential Manager, never in a file; the "
                "other settings in settings.json."
            )
        )
        layout.addWidget(buttons)

    def config(self) -> emailer.EmailConfig:
        user = self.user.text().strip()
        return emailer.EmailConfig(
            user=user,
            password=self.password.text().strip(),
            recipient=self.recipient.text().strip() or user,
            host=self.host.text().strip() or "smtp.gmail.com",
            port=self.port.value(),
        )

    def _send_test(self) -> None:
        cfg = self.config()
        if not cfg.complete:
            QMessageBox.warning(self, "Email settings", "Enter the sending account and password.")
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            emailer.send(
                f"{APP_NAME} test email",
                f"Email settings work. Reports will come from {cfg.user} via {cfg.host}.",
                cfg,
            )
        except Exception as e:
            QApplication.restoreOverrideCursor()
            QMessageBox.warning(self, "Test email failed", f"Could not send:\n{e}")
            return
        QApplication.restoreOverrideCursor()
        QMessageBox.information(self, "Test email", f"Sent to {cfg.recipient}.")

    def accept(self) -> None:
        cfg = self.config()
        for address in (cfg.user, cfg.recipient):
            if address and "@" not in address:
                QMessageBox.warning(self, "Email settings", f"{address!r} is not an email address.")
                return
        try:
            emailer.save_config(cfg)
        except Exception as e:
            QMessageBox.warning(
                self, "Email settings", f"Could not store the password securely:\n{e}"
            )
            return
        super().accept()
