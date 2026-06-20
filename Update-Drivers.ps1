# Update-Drivers.ps1 — auto-install Windows driver updates. Weekly, 3am. Needs admin.
# Uses PSWindowsUpdate module (auto-installed on first run). Reboot suppressed; reports result.

. "$PSScriptRoot\Common.ps1"
$comp = 'drivers'

try {
    Write-Log "Driver update run start" $comp

    # Ensure NuGet provider + module present.
    if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
        Write-Log "Installing PSWindowsUpdate module" $comp
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Get-PackageProvider -Name NuGet -ForceBootstrap -ErrorAction Stop | Out-Null
        Install-Module PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
    }
    Import-Module PSWindowsUpdate -ErrorAction Stop

    # Snapshot drivers available (driver-category only).
    $available = Get-WindowsUpdate -MicrosoftUpdate -UpdateType Driver -ErrorAction SilentlyContinue

    if (-not $available) {
        $body = "No driver updates available.`nChecked: $(Get-Date)"
        Write-Log "No driver updates" $comp
        Send-Report -Subject "Driver update: nothing to do" -Body $body
        return
    }

    Write-Log ("{0} driver update(s) found, installing" -f $available.Count) $comp

    # Install drivers only, do not auto-reboot.
    $result = Get-WindowsUpdate -MicrosoftUpdate -UpdateType Driver -Install -AcceptAll -IgnoreReboot -Verbose 4>&1

    $installed = Get-WUHistory -Last 25 | Where-Object {
        $_.Date -ge (Get-Date).AddHours(-1)
    } | Select-Object Date, Result, Title

    $lines = @("Driver update run $(Get-Date)`n")
    $lines += "Found: $($available.Count)"
    if ($installed) {
        $lines += "`nRecent results:"
        $lines += ($installed | Format-Table -AutoSize | Out-String)
    }
    $reboot = (Get-WURebootStatus -Silent)
    $lines += "Reboot required: $reboot"

    $body = $lines -join "`n"
    Write-Log "Driver update done. Reboot required: $reboot" $comp
    Send-Report -Subject "Driver update report ($($available.Count) found)" -Body $body
}
catch {
    $err = $_.Exception.Message
    Write-Log "ERROR: $err" $comp
    try { Send-Report -Subject "Driver update FAILED" -Body "Error:`n$err`n`n$($_.ScriptStackTrace)" } catch {}
}
