# win-sentinel — Agent Rules (canonical)

Single source of truth for **Claude, Copilot, and sub-agents**. `CLAUDE.md` and `.github/copilot-instructions.md` point here.

Windows tray app: disk cleanup, driver updates through Windows Update, a security scan (crypto-miners, spyware, remote access, new network devices, optional packet capture) and a CPU temperature watch. Runs the jobs on its own schedule, emails reports, and updates itself from GitHub Releases (asks first, verifies the installer's SHA-256). Ships as a PyInstaller + Inno Setup Windows installer; runs elevated; not a PyPI package.

## Architecture

```
winsentinel/
  __init__.py      — __version__ (release-please), APP_NAME, REPO
  __main__.py      — CLI: run one job with the saved settings, print the report
  paths.py         — data folder (%APPDATA%\win-sentinel, WIN_SENTINEL_HOME), logging
  settings.py      — settings.json (validated per key) / state.json, Schedule + due_slot()
  report.py        — Context (stop flag, progress, items), Report, save_report(), table()
  jobs.py          — RUNNERS for the scheduled jobs + deliver() (save + email)
  cleanup.py       — Target list, analyze() / clean(); Recycle Bin + DNS via ctypes, DISM
  drivers.py       — Windows Update Agent COM (search / install one by one), device problems (WMI)
  security.py      — collectors (psutil, WMI, Task Scheduler COM, winreg, hosts) -> SecurityScan
  rules.py         — pure functions: SecurityScan -> findings (critical / warning / info)
  indicators.py    — miner names, pool domains, ports, remote-access tools, suspicious commands
  capture.py       — raw-socket packet capture (SIO_RCVALL), DNS question parsing, .pcap writer
  temperature.py   — WMI sensors (LibreHardwareMonitor > OpenHardwareMonitor > ACPI), CSV, alerts
  emailer.py       — SMTP send, password in Windows Credential Manager (keyring)
  startup.py       — "Start with Windows": Task Scheduler logon task (XML), elevated, no time limit
  updater.py       — GitHub release lookup, verified download, silent installer launch
  wmi.py           — WMI queries / late-bound COM through pywin32 (plain dicts out)
  authenticode.py  — WinVerifyTrust (embedded + catalog signatures) via ctypes
  winapi.py        — admin check, elevation, hidden subprocesses, open / reveal paths
  gui/
    __main__.py    — GUI entry: single instance, tray, --minimized, --quit, --smoke-test,
                     --enable-startup / --disable-startup (used by the installer)
    window.py      — MainWindow: tabs, shared progress row, log, scheduler tick, update flow
    worker.py      — JobController (one job at a time) and TempController (sensor thread)
    *_tab.py       — Cleanup, Drivers, Security, Temperature, Schedule & email
    update.py      — UpdateChecker, UpdateDialog (asks first), verified download dialog
    desktop.py     — icon, tray icon, SingleInstance (QLocalServer)
win-sentinel.spec  — PyInstaller one-folder build, windowed, uac_admin
installer/windows/ — Inno Setup (admin install, logon task, silent update + /RELAUNCH=1)
scripts/generate_icon.py — assets/icon.ico + icon.png from desktop.render_icon()
```

## Windows APIs: Python only

- No PowerShell, batch or VBScript anywhere in the app. Use psutil, pywin32 (`wmi.query()`, `wmi.dispatch()`), ctypes, winreg or the stdlib. Native programs only where no API exists (`dism.exe`, `MpCmdRun.exe`).
- COM is per thread: `wmi.ensure_com()` (called by `query()`/`dispatch()`). Never pass COM objects between threads; convert to dataclasses / dicts in the thread that made them.
- Late-bound COM only (`win32com.client.dynamic`): the frozen app can't generate makepy wrappers.
- Windows paths in pure code: `ntpath`, not `pathlib` (tests run on Linux too).
- Windows-only calls stay behind `winapi.WINDOWS` checks and degrade to empty results / a clear error, so the pure logic stays testable with mocks.

## Jobs and threads

- A job is `fn(ctx: Context) -> result`; long loops call `ctx.check()` / `ctx.wait()` so Stop works. `Cancelled` ends a job cleanly.
- GUI: Qt owns the main thread; `JobController` runs one job in a daemon thread; events go through a `queue.SimpleQueue` drained by a 100 ms `QTimer` (as in port-bridge / flight-monitor). No `qasync`, no widget access from workers.
- Scheduled runs use the **saved** settings, save the report, and email per `email_when`; manual runs from a tab only save the report.
- The temperature monitor is its own thread; alerts are saved and emailed from that thread.
- A schedule only catches up on slots after `schedule_since` (set the first time the app sees the job, and whenever the schedule changes), so changing a schedule never triggers an immediate run.

## Security scan rules

- Collectors gather data; `rules.py` decides. Keep rules pure and tested with hand-made `SecurityScan`s.
- Every finding has a stable `key` (no PIDs) so users can trust (ignore) it; `evaluate()` keeps one finding per key, the most severe.
- Severity: critical = very likely malicious; warning = needs a look; info = worth knowing. Report severity: alert if any critical, notice if any warning.
- Heuristics must stay cheap to override: anything that can be legitimate is a warning, not critical.

## Updates and installer

- The updater only installs a file whose SHA-256 matches the asset's GitHub `digest` or the `.sha256` asset; a mismatch is deleted. It always asks first.
- Inno Setup: admin install to Program Files, `CloseApplications=yes`, `[InstallDelete]` of `_internal`, the app's `--quit` before files are replaced. Keep `AppId` stable. `/RELAUNCH=1` (passed by the updater) restarts the app after a silent install and skips re-creating the logon task.
- `win-sentinel.exe --smoke-test` must exit 0: CI runs it on the built folder and after a silent install.

## Data

- `settings.json` keys are validated one by one (`_VALID`); add a validator with every new key. `save_settings()` updates only the keys it is given.
- The email password lives only in Windows Credential Manager. Never log it or write it to a file.
- `state.json` holds `last_run`, `schedule_since`, `known_devices`.

## Python and platform

- Windows only: CI, CodeQL and releases all run on `windows-latest`. Python 3.12+ (the installer bundles 3.12): PySide6 over-releases `None`/`True`/`False` on signal emits and `processEvents()`, which aborts 3.10/3.11 after a few thousand calls and is harmless on 3.12's immortal objects.

## Style

- PEP 8, line length 100, `ruff` (lint + format) authoritative, `mypy --strict` (typed as `platform = "win32"`; `gui/` excluded).
- `from __future__ import annotations` in every module; type annotations on public functions; docstrings for modules and public functions; comments only for a non-obvious *why*. No `TODO`/`FIXME`.
- `logging` (`winsentinel` logger), not `print`, except CLI output.

## Testing

- `python -m pytest`. The autouse `home` fixture redirects the data folder and fakes the credential store.
- Mock Windows APIs at the module boundary (`wmi.query`, `wmi.dispatch`, `drivers._session`, `security.sample_processes`, ...). No network: patch `updater._urlopen`.
- `tests/test_windows.py` runs against the real APIs (WMI, COM, WinVerifyTrust, Task Scheduler, packet capture); CI runners are elevated, so the admin-only tests run too.
- GUI tests run with `QT_QPA_PLATFORM=offscreen`.

## Release

- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs:`, `ci:`, ...).
- `release-please` bumps `pyproject.toml`, `winsentinel/__init__.py` and the manifest, writes `CHANGELOG.md` and publishes the release; `build-installers.yml` attaches the installer and its `.sha256`.

## Assistant behavior

- Minimal prose. Report file paths + pass/fail.
- Never commit anything from the data folder (settings, reports, captures, logs).
