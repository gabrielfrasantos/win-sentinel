# Maintenance scripts

Three scheduled PowerShell maintenance tasks for this PC. All mail a report to
`gabriel.fra.santos@gmail.com`.

| Script | What | Schedule | Needs |
|--------|------|----------|-------|
| `Update-Drivers.ps1` | Auto-install Windows driver updates (PSWindowsUpdate), no reboot | Weekly, Sunday 03:00 | admin, internet |
| `Clean-System.ps1` | CCleaner-style cleanup: temp/caches/recycle bin/update cache/DISM | 3rd Wednesday monthly, 03:00 | admin |
| `Network-Spy.ps1` | Real packet capture (tshark), flags suspicious ports/DNS/listeners | Daily, 01:00 | admin, Wireshark+Npcap |
| `Monitor-Temp.ps1` | Continuous CPU temp logger; emails alert if ≥90°C. Diagnoses overheat crashes | At startup, runs forever | admin, LibreHardwareMonitor running |

## Setup (do once, in order)

1. **Gmail app password** — needs 2-Step Verification on.
   - https://myaccount.google.com/security  → enable 2FA
   - https://myaccount.google.com/apppasswords → create, copy 16 chars

1b. **Install LibreHardwareMonitor** (for real CPU core temps):
   ```powershell
   winget install LibreHardwareMonitor.LibreHardwareMonitor
   ```
   Must run elevated and stay running so it publishes the `root/LibreHardwareMonitor`
   WMI namespace. Without it the script falls back to ACPI thermal zone, which on
   many boards reports an ambient/board sensor (~25°C), not the CPU — useless for
   overheat diagnosis. Set it to start with Windows (Options → Run On Windows Startup +
   Start Minimized).

2. **Install Wireshark + Npcap** (for the network watch):
   ```powershell
   winget install WiresharkFoundation.Wireshark
   ```
   Keep "WinPcap API compatible" checked during Npcap install.

3. **Store creds + config** — run as your normal user (NOT admin), interactive:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Users\Gabriel\Scripts\Maintenance\Setup-Credentials.ps1"
   ```
   Sends a test mail; only saves if it succeeds. Password stored DPAPI-encrypted
   in `gmail.cred.xml` — readable only by your Windows user on this PC.

4. **Schedule** — run as Administrator:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "C:\Users\Gabriel\Scripts\Maintenance\Register-Tasks.ps1"
   ```
   Prompts once for your Windows password (Task Scheduler stores it so tasks run
   while logged off, with admin rights, as YOU — required for DPAPI decrypt).

## Test without waiting for the schedule
```powershell
schtasks /Run /TN Maintenance\Network-Spy
schtasks /Run /TN Maintenance\Clean-System
schtasks /Run /TN Maintenance\Update-Drivers
```

## Files
- `Common.ps1` — shared logging + `Send-Report` (Gmail SMTP 587 STARTTLS)
- `config.json` — from/to addresses (created by setup)
- `gmail.cred.xml` — DPAPI-encrypted credential (created by setup)
- `logs\*.log` — per-component logs

## Notes / caveats
- **`Send-MailMessage` is deprecated** by Microsoft but still works for Gmail. If
  Google later blocks it, swap to MailKit — `Send-Report` in `Common.ps1` is the
  one place to change.
- Tasks run **as your user** (not SYSTEM) on purpose: DPAPI credential is per-user.
- `Network-Spy.ps1` captures interface index `-i 1`. If wrong NIC, list them:
  `& 'C:\Program Files\Wireshark\tshark.exe' -D` and edit the `-i` value.
- Cleanup only touches caches/temp/recycle bin — never documents, registry, or
  app settings.
- Driver auto-install can occasionally regress a driver. Reports list what changed;
  roll back via Device Manager if needed. Switch to download-only by removing
  `-Install -AcceptAll` in `Update-Drivers.ps1`.
