"""Command line: run one job with the saved settings and print its report.

    python -m winsentinel clean          clean the saved selection
    python -m winsentinel analyze        size up the cleanup without deleting
    python -m winsentinel drivers        search for driver updates (and install them
                                         if "install automatically" is on)
    python -m winsentinel security       security scan
    python -m winsentinel temperature    one sensor reading
Add --email to send the report per the email policy, as a scheduled run does.
Exit codes: 0 ok, 1 something needs attention, 2 the job failed.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from winsentinel import __version__, cleanup, jobs, paths, settings, temperature
from winsentinel.report import ERROR, OK, Context, Report, human_size, table


def _analyze(s: dict[str, Any]) -> Report:
    targets = cleanup.selected_targets(s["clean_targets"])
    scans = cleanup.analyze(targets, int(s["clean_min_age_hours"]), Context())
    rows = [(sc.target.label, human_size(sc.bytes), str(sc.files), sc.note) for sc in scans]
    total = sum(sc.bytes for sc in scans)
    body = table(rows, ("Item", "Size", "Files", "Note")) + f"\n\nTotal: {human_size(total)}"
    return Report("clean", f"Cleanup analysis: {human_size(total)} can be freed", body)


def _temperature() -> Report:
    sample = temperature.read_sensors()
    if not sample.sensors:
        return Report("temperature", "No temperature sensors readable", "", ERROR)
    rows = [(s.name, f"{s.celsius} °C", s.kind) for s in sample.sensors]
    return Report("temperature", f"CPU {sample.cpu_max} °C ({sample.source})", table(rows), OK)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="win-sentinel-cli", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("job", choices=["clean", "analyze", "drivers", "security", "temperature"])
    parser.add_argument("--email", action="store_true", help="email the report per the policy")
    args = parser.parse_args(argv)

    paths.setup_logging()
    s = settings.load_settings()
    if args.job == "analyze":
        report = _analyze(s)
    elif args.job == "temperature":
        report = _temperature()
    else:
        try:
            report = jobs.RUNNERS[args.job](Context(), s)
        except KeyboardInterrupt:
            return 2
    if args.email:
        jobs.deliver(report, s)
    if sys.stdout is not None:
        print(report.text())
    return {OK: 0, ERROR: 2}.get(report.severity, 1)


if __name__ == "__main__":
    sys.exit(main())
