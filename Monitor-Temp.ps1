# Monitor-Temp.ps1 — continuous CPU temperature logger + overheat alert.
# Runs forever (scheduled At-Startup). Samples every $IntervalSec, logs CSV daily,
# mails an alert if temp crosses $ThreshC (rate-limited). Built to diagnose
# suspected overheat crashes: the CSV holds the last readings before a crash.
#
# TEMP SOURCE: tries accurate sensors first, falls back to ACPI thermal zone.
#   For real per-core temps install LibreHardwareMonitor and leave it running:
#       winget install LibreHardwareMonitor.LibreHardwareMonitor
#   (its app must run so it publishes the root/LibreHardwareMonitor WMI namespace)
#   Without it, MSAcpi_ThermalZoneTemperature is used (coarser, sometimes unsupported).

$IntervalSec     = 15      # sample period
$ThreshC         = 90      # alert threshold °C (CPU throttle danger zone)
$AlertCooldownMin= 30      # min minutes between alert emails
$RetainDays      = 30      # CSV retention

. "$PSScriptRoot\Common.ps1"
$comp = 'temp'

function Get-CpuTemps {
    # Returns array of [pscustomobject]@{ Name; TempC }
    $out = @()

    # 1. LibreHardwareMonitor (accurate, if app running)
    try {
        $s = Get-CimInstance -Namespace 'root/LibreHardwareMonitor' -ClassName Sensor -ErrorAction Stop |
             Where-Object { $_.SensorType -eq 'Temperature' -and $_.Name -match 'CPU|Core|Package|Tctl|Tdie' }
        foreach ($x in $s) { $out += [pscustomobject]@{ Name = $x.Name; TempC = [math]::Round($x.Value,1) } }
        if ($out) { return $out }
    } catch {}

    # 2. OpenHardwareMonitor (accurate, if app running)
    try {
        $s = Get-CimInstance -Namespace 'root/OpenHardwareMonitor' -ClassName Sensor -ErrorAction Stop |
             Where-Object { $_.SensorType -eq 'Temperature' -and $_.Name -match 'CPU|Core|Package' }
        foreach ($x in $s) { $out += [pscustomobject]@{ Name = $x.Name; TempC = [math]::Round($x.Value,1) } }
        if ($out) { return $out }
    } catch {}

    # 3. ACPI thermal zone (no install; tenths of Kelvin)
    try {
        $tz = Get-CimInstance -Namespace 'root/WMI' -ClassName MSAcpi_ThermalZoneTemperature -ErrorAction Stop
        $i = 0
        foreach ($z in $tz) {
            $c = [math]::Round(($z.CurrentTemperature / 10) - 273.15, 1)
            $out += [pscustomobject]@{ Name = "ThermalZone$i"; TempC = $c }
            $i++
        }
    } catch {}

    return $out
}

Write-Log "Temp monitor start (interval ${IntervalSec}s, threshold ${ThreshC}C)" $comp
$lastAlert = [datetime]::MinValue
$warned    = $false

while ($true) {
    try {
        $temps = Get-CpuTemps
        if (-not $temps -or $temps.Count -eq 0) {
            if (-not $warned) {
                Write-Log "No temp sensors readable. Install LibreHardwareMonitor for real readings." $comp
                $warned = $true
            }
            Start-Sleep -Seconds $IntervalSec
            continue
        }

        $now = Get-Date
        $csv = Join-Path $LogDir ("temp_{0}.csv" -f $now.ToString('yyyyMMdd'))
        if (-not (Test-Path $csv)) { Add-Content $csv "timestamp,sensor,tempC" }
        foreach ($t in $temps) {
            Add-Content $csv ("{0},{1},{2}" -f $now.ToString('s'), $t.Name, $t.TempC)
        }

        $max = ($temps | Measure-Object TempC -Maximum).Maximum
        $hot = $temps | Where-Object { $_.TempC -ge $ThreshC }

        if ($hot -and ($now - $lastAlert).TotalMinutes -ge $AlertCooldownMin) {
            $recent = if (Test-Path $csv) { Get-Content $csv -Tail 40 } else { @() }
            $body = @(
                "OVERHEAT ALERT $now",
                "Max temp: $max C  (threshold $ThreshC C)",
                "",
                "Hot sensors:",
                ($hot | ForEach-Object { "  {0}: {1} C" -f $_.Name, $_.TempC }),
                "",
                "Last readings (this sensor log):",
                $recent
            ) -join "`n"
            try {
                Send-Report -Subject ("[OVERHEAT] CPU {0}C on $env:COMPUTERNAME" -f $max) -Body $body
                $lastAlert = $now
                Write-Log "ALERT sent: max $max C" $comp
            } catch { Write-Log "Alert mail failed: $($_.Exception.Message)" $comp }
        }

        # prune old CSVs
        Get-ChildItem (Join-Path $LogDir 'temp_*.csv') -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$RetainDays) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-Log "Loop error: $($_.Exception.Message)" $comp
    }
    Start-Sleep -Seconds $IntervalSec
}
