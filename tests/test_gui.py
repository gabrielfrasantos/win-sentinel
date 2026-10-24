import datetime as dt

import pytest

pytest.importorskip("PySide6.QtWidgets")

from winsentinel import jobs, security, settings  # noqa: E402
from winsentinel.gui import window as window_module  # noqa: E402
from winsentinel.gui.window import MainWindow  # noqa: E402
from winsentinel.report import Report  # noqa: E402


@pytest.fixture
def window(qapp, monkeypatch):
    monkeypatch.setattr(settings, "DEFAULTS", {**settings.DEFAULTS, "temp_enabled": False})
    w = MainWindow()
    yield w
    w.shutdown()
    w.deleteLater()
    qapp.processEvents()


def wait_idle(window, qapp, seconds=5.0):
    deadline = dt.datetime.now() + dt.timedelta(seconds=seconds)
    while window.controller.busy and dt.datetime.now() < deadline:
        qapp.processEvents()
    window.controller.drain()
    qapp.processEvents()


def test_window_builds_with_all_tabs(window):
    titles = [window.tabs.tabText(i) for i in range(window.tabs.count())]
    assert titles == ["Cleanup", "Drivers", "Security", "Temperature", "Schedule && email"]


def test_cleanup_selection_is_saved(window):
    table = window.cleanup_tab.table
    from PySide6.QtCore import Qt

    table.item(0, 0).setCheckState(Qt.CheckState.Unchecked)
    saved = settings.load_settings()["clean_targets"]
    assert "user-temp" not in saved and "windows-temp" in saved


def test_run_job_delivers_and_shows_result(window, qapp, monkeypatch):
    delivered = []
    monkeypatch.setattr(jobs, "deliver", lambda report, s=None: delivered.append(report))
    finding = security.Finding("warning", "Remote access", "AnyDesk", key="remote:anydesk")
    monkeypatch.setitem(
        jobs.RUNNERS,
        "security",
        lambda ctx, s: Report(
            "security",
            "Security scan: 1 warning(s)",
            "",
            "notice",
            security.SecurityScan(findings=[finding]),
        ),
    )
    assert window.run_job("security")
    wait_idle(window, qapp)
    assert [r.subject for r in delivered] == ["Security scan: 1 warning(s)"]
    assert window.security_tab.findings.rowCount() == 1
    last, _ = settings.job_times("security")
    assert last is not None


def test_schedule_tick_runs_a_due_job_once(window, qapp, monkeypatch):
    ran = []
    monkeypatch.setattr(jobs, "deliver", lambda report, s=None: None)
    for job in settings.JOBS:
        monkeypatch.setitem(
            jobs.RUNNERS, job, lambda ctx, s, j=job: ran.append(j) or Report(j, j, "", "ok")
        )
    monkeypatch.setattr(window, "_on_job_done", lambda *a: None)
    settings.save_settings({"security_schedule": {"frequency": "daily", "time": "00:00"}})
    for job in settings.JOBS:
        settings.mark_job(job, "schedule_since", dt.datetime.now() - dt.timedelta(days=40))
        settings.mark_job(job, "last_run", dt.datetime.now())
    settings.mark_job("security", "last_run", dt.datetime.now() - dt.timedelta(days=2))
    window.tick_schedule()
    wait_idle(window, qapp)
    window.tick_schedule()
    wait_idle(window, qapp)
    assert ran == ["security"]


def test_first_tick_only_records_when_schedules_start(window):
    window.tick_schedule()
    for job in settings.JOBS:
        last, since = settings.job_times(job)
        assert last is None and since is not None
    assert not window.controller.busy


def test_trusting_a_finding_hides_it_from_the_report(window):
    finding = security.Finding("warning", "Remote access", "AnyDesk", key="remote:anydesk", pid=1)
    tab = window.security_tab
    tab.show_scan(security.SecurityScan(findings=[finding]))
    tab.findings.selectRow(0)
    tab._toggle_trust()
    assert settings.load_settings()["ignored_findings"] == ["remote:anydesk"]
    assert "(trusted)" in tab.findings.item(0, 0).text()
    assert security.report(tab._scan, settings.load_settings()["ignored_findings"]).severity == "ok"


def test_update_flow_waits_for_running_job(window, qapp, monkeypatch, tmp_path):
    from winsentinel import updater

    launched = []
    monkeypatch.setattr(updater, "launch_installer", launched.append)
    monkeypatch.setattr(window_module.QApplication, "quit", lambda: launched.append("quit"))
    installer = tmp_path / "win-sentinel-9.9.9-windows-setup.exe"
    window.controller.start("Slow job", lambda ctx: ctx.wait(0.3), lambda r, e: None)
    window.install_update(installer)
    assert launched == []
    wait_idle(window, qapp)
    deadline = dt.datetime.now() + dt.timedelta(seconds=3)
    while not launched and dt.datetime.now() < deadline:
        qapp.processEvents()
    assert launched == [installer, "quit"]


def test_update_dialog_offers_install_only_when_installable(qapp):
    from PySide6.QtWidgets import QDialogButtonBox

    from winsentinel import updater
    from winsentinel.gui.update import UpdateDialog

    release = updater.Release(
        "9.9.9", "https://x", "notes", "a.exe", "https://x/a.exe", 10, "f" * 64
    )

    def labels(can_install):
        dialog = UpdateDialog(release, can_install)
        return [b.text() for b in dialog.findChildren(QDialogButtonBox)[0].buttons()]

    assert "Install now" in labels(True)
    assert "Install now" not in labels(False) and "Release page" in labels(False)


def test_email_dialog_saves(qapp, monkeypatch):
    from winsentinel import emailer
    from winsentinel.gui.email_dialog import EmailDialog

    dialog = EmailDialog()
    dialog.user.setText("me@gmail.com")
    dialog.password.setText("abcd efgh ijkl mnop")
    dialog.accept()
    cfg = emailer.load_config()
    assert cfg.user == "me@gmail.com" and cfg.password == "abcd efgh ijkl mnop"
