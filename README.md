# win-sentinel

[![CI](https://github.com/gabrielfrasantos/win-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/gabrielfrasantos/win-sentinel/actions/workflows/ci.yml)
[![CodeQL](https://github.com/gabrielfrasantos/win-sentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/gabrielfrasantos/win-sentinel/actions/workflows/codeql.yml)

A Windows tray app that keeps a PC tidy and keeps an eye on it:

- **Cleanup**: temp folders, Windows Update and Delivery Optimization caches, logs,
  crash reports, browser caches, Recycle Bin, DNS cache, and the Windows component
  store (DISM). Analyze first to see the sizes, then clean what you tick.
- **Drivers**: asks Windows Update for driver updates for this PC and installs the
  ones you pick (one at a time, never restarts by itself), and lists devices
  Device Manager reports a problem for.
- **Security**: looks for crypto-miners (known miner programs, mining options, mining
  pools, unsigned programs burning CPU/GPU), spyware and remote access (remote-access
  tools, inbound sessions, programs online from temp folders, fake system programs,
  encoded scripts at startup, proxy and hosts-file hijacks, Defender exclusions and
  detections, firewall off) and **new devices on your network**. An optional packet
  capture records which hosts the PC talks to and which names it looks up.
- **CPU temperature**: watches the sensors, logs them to a daily CSV (so the readings
  before a crash survive it) and alerts when the CPU gets too hot.

It runs those jobs **on a schedule**, **emails reports** (Gmail by default), and
**updates itself**: when a new release is out it asks, then downloads the installer,
checks its SHA-256 and installs it.

Everything is Python (PySide6, psutil, pywin32, ctypes): no PowerShell scripts and
no extra tools to install.

## Install

Download `win-sentinel-<version>-windows-setup.exe` from the
[latest release](https://github.com/gabrielfrasantos/win-sentinel/releases/latest)
and run it. It installs for all users and needs administrator rights: cleaning
system folders, installing drivers and capturing packets all need them, so the app
always runs elevated.

- **Start with Windows** (on by default) registers a Task Scheduler task that starts
  win-sentinel minimized in the tray at logon, elevated, without a UAC prompt. You
  can switch it off later in *Schedule & email*.
- Closing the window keeps it in the tray (scheduled runs and the temperature watch
  continue). Quit from the tray icon's menu.
- Your data lives in `%APPDATA%\win-sentinel`. Uninstalling keeps it.

### First steps

1. **Schedule & email > Email settings…**: enter your Gmail address and a
   [Gmail App Password](https://myaccount.google.com/apppasswords) (needs 2-Step
   Verification), then **Send test email**. The password goes to Windows Credential
   Manager, never to a file.
2. **Cleanup**: untick anything you want to keep, then **Analyze**.
3. **Security > Scan now**. Look through the findings; **Trust** the ones you know
   (a remote-access tool you installed yourself, a hosts-file ad blocker) and they
   stop being reported.
4. **Temperature**: install LibreHardwareMonitor for real per-core readings and
   leave it running (Options: *Run On Windows Startup*, *Start Minimized*):
   ```
   winget install LibreHardwareMonitor.LibreHardwareMonitor
   ```
   Without it the app falls back to the ACPI thermal zone, which on many boards is a
   slow board sensor rather than the CPU.

### Default schedule

| Job | When | Email |
|---|---|---|
| Cleanup | monthly, day 15, 03:00 | |
| Driver check | weekly, Sunday 03:00 (updates are listed, not installed, unless you tick *Install automatically*) | per policy |
| Security scan | daily, 01:00 | per policy |
| Temperature | every 15 s; alert at 90 °C, at most every 30 min | on alert |

The email policy (*Send*) is *every run*, *only problems* (default: findings,
failures, available drivers, overheating) or *never*. Every run also writes a text
report to `%APPDATA%\win-sentinel\reports`.

Runs happen while the app is running. A run missed while the PC was off happens at
the next start (once, about 90 s after the app starts).

### Updates

The app checks GitHub Releases at start and once a day (*Check for updates* any time,
from the status bar or the tray). When there is a newer version it **asks first**;
*Install now* downloads the installer, verifies its SHA-256 against the checksum
published with the release (a mismatch is deleted, never run), installs it silently
and restarts the app. A running job finishes first.

## Coming from the PowerShell scripts

The app replaces `Clean-System.ps1`, `Update-Drivers.ps1`, `Network-Spy.ps1` and
`Monitor-Temp.ps1`. Remove their scheduled tasks, or every job runs (and emails)
twice. In a terminal opened as administrator:

```
schtasks /Delete /TN "Maintenance\Update-Drivers" /F
schtasks /Delete /TN "Maintenance\Clean-System" /F
schtasks /Delete /TN "Maintenance\Network-Spy" /F
schtasks /Delete /TN "Maintenance\Monitor-Temp" /F
```

Then enter the Gmail account again in *Email settings* (the old `gmail.cred.xml` and
`config.json` are not read) and delete the old scripts folder. Wireshark is no longer
needed: the packet capture is built in.

## What each check means

Findings are leads, not verdicts. Levels:

- **critical**: very likely malicious. A known miner running or mining options on a
  command line, a connection to a mining pool, a program named like a Windows system
  program running from elsewhere, an encoded/downloading script that starts with
  Windows, a changed Windows logon shell, a Defender detection that wasn't removed.
- **warning**: needs a look. A remote-access or tunnel tool running, someone connected
  by Remote Desktop/VNC, an unsigned program online from a temp or Downloads folder or
  using lots of CPU/GPU, a suspicious port, a system proxy, hosts-file redirects,
  Defender exclusions or real-time protection off, a firewall profile off, a new
  device on the network.
- **info**: worth knowing. Unsigned programs that are online or start with Windows,
  Remote Desktop enabled, hosts-file blocks.

The **first** scan records every device on the network as known; later scans report
devices they haven't seen before. Phones and laptops often use a randomized MAC per
network, which the finding points out.

The **packet capture** (Security tab, on by default for 120 s) needs administrator. It
uses a raw socket, so it sees IPv4 traffic only, and DNS lookups only when they go
over plain DNS (not a browser's DNS-over-HTTPS). Captures are saved as `.pcap` in
`%APPDATA%\win-sentinel\captures` for 14 days; Wireshark opens them.

## Files

`%APPDATA%\win-sentinel` (or `WIN_SENTINEL_HOME`):

| File | What |
|---|---|
| `settings.json` | everything the GUI saves (schedules, email account without the password, thresholds, trusted findings) |
| `state.json` | last runs, known network devices |
| `win-sentinel.log` | the log (rotated, 3 × 2 MB) |
| `reports/` | one text report per run (180 days) |
| `temperature/` | `temp_YYYYMMDD.csv` (30 days) |
| `captures/` | packet captures (14 days) |
| `updates/` | the downloaded installer and its log |

## Development

Needs Python 3.12+ on Windows (PySide6 mishandles reference counts in ways only
3.12's immortal objects absorb; on 3.10/3.11 the GUI aborts after a while).

```
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
python -m winsentinel.gui            # the app (run the terminal as admin for everything)
python -m winsentinel security       # one job from the command line; --help for all
python -m pytest                     # tests, including the real Windows API tests
ruff check . && ruff format --check . && mypy
```

Build the installer like CI does (needs [Inno Setup](https://jrsoftware.org/isinfo.php)):

```
python scripts/generate_icon.py
pyinstaller --noconfirm win-sentinel.spec
dist\win-sentinel\win-sentinel.exe --smoke-test
iscc installer\windows\setup.iss /DAppVersion=0.1.0
```

Releases: commit with [Conventional Commits](https://www.conventionalcommits.org/)
(`feat:`, `fix:`, ...). `release-please` opens a release PR; merging it tags the
release, and `build-installers.yml` attaches the installer and its `.sha256`, which
is what the app's updater downloads. See [AGENTS.md](AGENTS.md) for the code layout
and rules.
