"""Email reports over SMTP (Gmail by default: an App Password, SSL on port 465).

The account, recipient and server live in settings.json; the password goes to the
OS credential store (Windows Credential Manager, through ``keyring``), never to a file.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from dataclasses import dataclass
from email.mime.text import MIMEText
from typing import Any

from winsentinel import APP_NAME, settings, winapi
from winsentinel.report import Report

logger = logging.getLogger(__name__)

KEYRING_SERVICE = APP_NAME


@dataclass
class EmailConfig:
    user: str = ""
    password: str = ""
    recipient: str = ""
    host: str = "smtp.gmail.com"
    port: int = 465

    @property
    def complete(self) -> bool:
        return bool(self.user and self.password)


def _keyring() -> Any:
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def stored_password(user: str) -> str:
    kr = _keyring()
    if not user or kr is None:
        return ""
    try:
        return str(kr.get_password(KEYRING_SERVICE, user) or "")
    except Exception as e:
        logger.debug("Credential store unavailable: %s", e)
        return ""


def load_config(values: dict[str, Any] | None = None) -> EmailConfig:
    s = values or settings.load_settings()
    user = str(s["email_user"])
    return EmailConfig(
        user=user,
        password=stored_password(user),
        recipient=str(s["email_recipient"]) or user,
        host=str(s["email_host"]),
        port=int(s["email_port"]),
    )


def save_config(cfg: EmailConfig) -> None:
    """Password to the credential store, the rest to settings.json. Raises (saving
    nothing) when there is no usable credential store."""
    kr = _keyring()
    if kr is None:
        raise RuntimeError("the keyring package is missing")
    if cfg.password:
        kr.set_password(KEYRING_SERVICE, cfg.user, cfg.password)
    else:
        try:
            kr.delete_password(KEYRING_SERVICE, cfg.user)
        except Exception as e:
            logger.debug("No stored password to delete: %s", e)
    settings.save_settings(
        {
            "email_user": cfg.user,
            "email_recipient": cfg.recipient,
            "email_host": cfg.host,
            "email_port": cfg.port,
        }
    )


def send(subject: str, body: str, cfg: EmailConfig | None = None) -> bool:
    """Send one message; False (logged) when no account is set. Raises on SMTP errors."""
    cfg = cfg or load_config()
    if not cfg.complete:
        logger.info("Email skipped: no email account set (Schedule & email > Email settings).")
        return False
    to_addr = cfg.recipient or cfg.user
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = cfg.user
    msg["To"] = to_addr
    ctx = ssl.create_default_context()
    password = cfg.password.replace(" ", "")
    if cfg.port == 465:
        with smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx, timeout=30) as smtp:
            smtp.login(cfg.user, password)
            smtp.sendmail(cfg.user, [to_addr], msg.as_string())
    else:
        with smtplib.SMTP(cfg.host, cfg.port, timeout=30) as smtp:
            smtp.starttls(context=ctx)
            smtp.login(cfg.user, password)
            smtp.sendmail(cfg.user, [to_addr], msg.as_string())
    logger.info("Email sent to %s: %s", to_addr, subject)
    return True


def wants_email(report: Report, when: str) -> bool:
    """always / problems (anything not OK) / never."""
    if when == "never":
        return False
    if when == "problems":
        return report.problem
    return True


def send_report(report: Report, when: str) -> None:
    """Email a report if the policy wants it; SMTP failures are logged, never raised."""
    if not wants_email(report, when):
        return
    try:
        send(f"{report.subject} - {winapi.computer_name()}", report.text())
    except Exception as e:
        logger.error("Email FAILED: %s", e)
