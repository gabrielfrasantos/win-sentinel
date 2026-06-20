# Register-Tasks.ps1 — create the 3 scheduled tasks. RUN AS ADMINISTRATOR.
# Tasks run as YOUR user with highest privileges, whether logged on or not.
# Running as your user (not SYSTEM) is required so DPAPI can decrypt the Gmail credential.
# You will be prompted ONCE for your Windows account password (stored by Task Scheduler).

#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'
$dir   = $PSScriptRoot
$ps    = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$user  = "$env:USERDOMAIN\$env:USERNAME"

Write-Host "Tasks will run as: $user" -ForegroundColor Cyan
$pw = Read-Host "Enter Windows password for $user" -AsSecureString
$pwPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pw))

function New-Task {
    param([string]$Name, [string]$Script, [string[]]$ScheduleArgs)
    $tr = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dir\$Script`""
    $args = @(
        '/Create','/F',
        '/TN', $Name,
        '/TR', $tr,
        '/RU', $user,
        '/RP', $pwPlain,
        '/RL','HIGHEST'
    ) + $ScheduleArgs
    schtasks.exe @args
    if ($LASTEXITCODE -eq 0) { Write-Host "  OK: $Name" -ForegroundColor Green }
    else { Write-Host "  FAILED: $Name (exit $LASTEXITCODE)" -ForegroundColor Red }
}

Write-Host "`nCreating tasks..." -ForegroundColor Cyan

# 1. Drivers — weekly, Sunday 03:00
New-Task -Name 'Maintenance\Update-Drivers' -Script 'Update-Drivers.ps1' `
    -ScheduleArgs @('/SC','WEEKLY','/D','SUN','/ST','03:00')

# 2. Cleanup — 3rd Wednesday each month, 03:00
New-Task -Name 'Maintenance\Clean-System' -Script 'Clean-System.ps1' `
    -ScheduleArgs @('/SC','MONTHLY','/MO','THIRD','/D','WED','/ST','03:00')

# 3. Network watch — daily, 01:00
New-Task -Name 'Maintenance\Network-Spy' -Script 'Network-Spy.ps1' `
    -ScheduleArgs @('/SC','DAILY','/ST','01:00')

# 4. Temp monitor — continuous, starts at boot (and now)
New-Task -Name 'Maintenance\Monitor-Temp' -Script 'Monitor-Temp.ps1' `
    -ScheduleArgs @('/SC','ONSTART','/DELAY','0001:00')

# scrub plaintext password from memory
$pwPlain = $null; [GC]::Collect()

Write-Host "`nDone. Verify: schtasks /Query /TN Maintenance\Update-Drivers /V /FO LIST" -ForegroundColor Cyan
Write-Host "Run one now to test: schtasks /Run /TN Maintenance\Network-Spy" -ForegroundColor Cyan
