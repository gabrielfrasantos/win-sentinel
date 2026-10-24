"""The three scheduled jobs, run the same way from the tray app's schedule, its
"Run now" buttons and the CLI: each takes the saved settings and returns a Report.
``deliver()`` then saves the report and emails it per the email policy."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from winsentinel import cleanup, drivers, emailer, security, settings
from winsentinel.report import Context, Report, save_report

logger = logging.getLogger(__name__)


def run_clean(ctx: Context, s: dict[str, Any]) -> Report:
    targets = cleanup.selected_targets(s["clean_targets"])
    return cleanup.report(cleanup.clean(targets, int(s["clean_min_age_hours"]), ctx))


def run_drivers(ctx: Context, s: dict[str, Any]) -> Report:
    scan = drivers.search(ctx)
    installed = None
    if s["drivers_auto_install"] and scan.updates and not scan.error:
        installed = drivers.install(scan.updates, ctx)
    return drivers.scan_report(scan, installed)


def run_security(ctx: Context, s: dict[str, Any]) -> Report:
    seconds = int(s["capture_seconds"]) if s["security_capture"] else None
    result = security.scan(ctx, capture_seconds=seconds, lan_sweep=bool(s["lan_sweep"]))
    return security.report(result, s["ignored_findings"])


RUNNERS: dict[str, Callable[[Context, dict[str, Any]], Report]] = {
    "clean": run_clean,
    "drivers": run_drivers,
    "security": run_security,
}


def deliver(report: Report, s: dict[str, Any] | None = None) -> None:
    """Save the report to reports/ and email it if the policy says so."""
    s = s or settings.load_settings()
    try:
        path = save_report(report)
        logger.info("%s (report: %s)", report.subject, path.name)
    except OSError as e:
        logger.error("Could not save the report: %s", e)
    emailer.send_report(report, str(s["email_when"]))
