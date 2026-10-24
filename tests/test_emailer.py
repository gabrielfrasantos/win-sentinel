import json

import pytest

from winsentinel import emailer, paths
from winsentinel.report import Report


class FakeSMTP:
    sent = []

    def __init__(self, host, port, **kwargs):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self, context=None):
        self.tls = True

    def login(self, user, password):
        self.login_args = (user, password)

    def sendmail(self, sender, to, message):
        FakeSMTP.sent.append((self.host, self.port, sender, to, message, self.login_args))


@pytest.fixture
def smtp(monkeypatch):
    FakeSMTP.sent = []
    monkeypatch.setattr(emailer.smtplib, "SMTP_SSL", FakeSMTP)
    monkeypatch.setattr(emailer.smtplib, "SMTP", FakeSMTP)
    return FakeSMTP.sent


def test_config_round_trip_keeps_password_out_of_files():
    emailer.save_config(emailer.EmailConfig("me@gmail.com", "abcd efgh ijkl mnop", "you@x.com"))
    cfg = emailer.load_config()
    assert (cfg.user, cfg.password, cfg.recipient, cfg.port) == (
        "me@gmail.com",
        "abcd efgh ijkl mnop",
        "you@x.com",
        465,
    )
    assert "abcd" not in paths.settings_file().read_text()
    assert json.loads(paths.settings_file().read_text())["email_user"] == "me@gmail.com"


def test_send_uses_ssl_or_starttls(smtp):
    cfg = emailer.EmailConfig("me@gmail.com", "abcd efgh", "")
    assert emailer.send("Subject", "Body", cfg)
    host, port, sender, to, message, login = smtp[-1]
    assert (host, port, sender, to, login) == (
        "smtp.gmail.com",
        465,
        "me@gmail.com",
        ["me@gmail.com"],
        ("me@gmail.com", "abcdefgh"),
    )
    assert "Subject: Subject" in message
    cfg.port = 587
    emailer.send("S", "B", cfg)
    assert smtp[-1][1] == 587


def test_no_account_skips(smtp):
    assert not emailer.send("S", "B")
    assert smtp == []


@pytest.mark.parametrize(
    "severity, when, expected",
    [
        ("ok", "always", True),
        ("ok", "problems", False),
        ("notice", "problems", True),
        ("alert", "never", False),
    ],
)
def test_policy(severity, when, expected):
    assert emailer.wants_email(Report("x", "s", "b", severity), when) is expected


def test_send_report_never_raises(monkeypatch):
    def boom(*a, **k):
        raise OSError("smtp down")

    monkeypatch.setattr(emailer, "send", boom)
    emailer.send_report(Report("x", "s", "b", "alert"), "always")
