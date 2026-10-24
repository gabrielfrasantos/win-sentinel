import xml.dom.minidom

from winsentinel import jobs, paths, settings, startup
from winsentinel.report import Context, Report


def test_deliver_saves_and_emails_per_policy(monkeypatch):
    sent = []
    monkeypatch.setattr(jobs.emailer, "send", lambda subject, body: sent.append(subject) or True)
    settings.save_settings({"email_when": "problems"})
    jobs.deliver(Report("clean", "Cleanup: 1 GB freed", "body"))
    jobs.deliver(Report("security", "[ALERT] Security scan", "body", "alert"))
    assert len(list(paths.reports_dir().glob("*.txt"))) >= 1
    assert len(sent) == 1 and sent[0].startswith("[ALERT] Security scan")


def test_run_drivers_auto_install(monkeypatch):
    from winsentinel import drivers

    update = drivers.DriverUpdate("a", "A")
    monkeypatch.setattr(drivers, "search", lambda ctx: drivers.DriverScan(updates=[update]))
    installed = []
    monkeypatch.setattr(
        drivers,
        "install",
        lambda ups, ctx: (
            installed.extend(ups)
            or drivers.InstallResult([drivers.InstallOutcome(update, "Succeeded")])
        ),
    )
    s = settings.load_settings()
    assert jobs.run_drivers(Context(), s).subject.startswith("Drivers: 1 update(s) available")
    assert installed == []
    s["drivers_auto_install"] = True
    assert jobs.run_drivers(Context(), s).subject == "Drivers: 1 installed"
    assert installed == [update]


def test_run_security_uses_saved_options(monkeypatch):
    from winsentinel import security

    seen = {}

    def fake_scan(ctx, capture_seconds=None, lan_sweep=True):
        seen.update(capture=capture_seconds, lan=lan_sweep)
        return security.SecurityScan()

    monkeypatch.setattr(security, "scan", fake_scan)
    s = settings.load_settings()
    s.update(security_capture=False, lan_sweep=False)
    assert jobs.run_security(Context(), s).severity == "ok"
    assert seen == {"capture": None, "lan": False}


def test_startup_task_xml_is_valid_and_escaped():
    text = startup.task_xml(
        r"C:\Program Files\win-sentinel\win-sentinel.exe", "--minimized", "PC\\A&B"
    )
    doc = xml.dom.minidom.parseString(text.replace('encoding="UTF-16"', 'encoding="UTF-8"'))
    assert doc.getElementsByTagName("Command")[0].firstChild.data.endswith("win-sentinel.exe")
    assert doc.getElementsByTagName("UserId")[0].firstChild.data == "PC\\A&B"
    assert doc.getElementsByTagName("RunLevel")[0].firstChild.data == "HighestAvailable"
    assert doc.getElementsByTagName("ExecutionTimeLimit")[0].firstChild.data == "PT0S"
