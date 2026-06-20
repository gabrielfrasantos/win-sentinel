# Clean-System.ps1 — CCleaner-style cleanup. 3rd Wednesday monthly, 3am. Needs admin.
# Clears temp, caches, recycle bin, update cache, logs, thumbnails. Reports space freed.
# Safe targets only — does NOT touch documents, registry, or app settings.

. "$PSScriptRoot\Common.ps1"
$comp = 'clean'

function Get-FolderSize {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    try {
        (Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
            Measure-Object -Property Length -Sum).Sum
    } catch { 0 }
}

function Clear-PathContents {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return 0 }
    $before = Get-FolderSize $Path
    Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        ForEach-Object {
            try { Remove-Item -LiteralPath $_.FullName -Force -Recurse -ErrorAction SilentlyContinue } catch {}
        }
    $after = Get-FolderSize $Path
    [math]::Max(0, $before - $after)
}

try {
    Write-Log "Cleanup run start" $comp
    $freed = [ordered]@{}

    $targets = [ordered]@{
        'User temp'        = $env:TEMP
        'Windows temp'     = 'C:\Windows\Temp'
        'Prefetch'         = 'C:\Windows\Prefetch'
        'CBS logs'         = 'C:\Windows\Logs\CBS'
        'Windows Update DL'= 'C:\Windows\SoftwareDistribution\Download'
        'Thumbnail cache'  = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer')
        'INetCache'        = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\INetCache')
        'Chrome cache'     = (Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Cache')
        'Edge cache'       = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\User Data\Default\Cache')
        'Firefox cache'    = (Join-Path $env:LOCALAPPDATA 'Mozilla\Firefox\Profiles')
        'CrashDumps'       = (Join-Path $env:LOCALAPPDATA 'CrashDumps')
        'Delivery Opt'     = 'C:\Windows\SoftwareDistribution\DeliveryOptimization'
    }

    foreach ($name in $targets.Keys) {
        $p = $targets[$name]
        $b = Clear-PathContents $p
        $freed[$name] = $b
        Write-Log ("{0}: freed {1:N1} MB" -f $name, ($b/1MB)) $comp
    }

    # Recycle Bin (all drives).
    $rbBefore = 0
    try {
        $shell = New-Object -ComObject Shell.Application
        $bin = $shell.NameSpace(0xA)
        $rbBefore = ($bin.Items() | ForEach-Object { $_.Size } | Measure-Object -Sum).Sum
    } catch {}
    try { Clear-RecycleBin -Force -ErrorAction SilentlyContinue } catch {}
    $freed['Recycle Bin'] = [int64]$rbBefore
    Write-Log ("Recycle Bin: freed {0:N1} MB" -f ($rbBefore/1MB)) $comp

    # DNS cache flush (no size, hygiene).
    try { Clear-DnsClientCache; Write-Log "DNS cache flushed" $comp } catch {}

    # Component store cleanup (WinSxS) — slow but big wins.
    try {
        Write-Log "Running DISM component cleanup" $comp
        Start-Process dism.exe -ArgumentList '/Online','/Cleanup-Image','/StartComponentCleanup','/Quiet' -Wait -NoNewWindow
    } catch { Write-Log "DISM cleanup skipped: $($_.Exception.Message)" $comp }

    $total = ($freed.Values | Measure-Object -Sum).Sum
    $lines = @("System cleanup $(Get-Date)`n")
    foreach ($k in $freed.Keys) { $lines += ("{0,-22} {1,10:N1} MB" -f $k, ($freed[$k]/1MB)) }
    $lines += ("-" * 36)
    $lines += ("{0,-22} {1,10:N1} MB" -f 'TOTAL FREED', ($total/1MB))

    $body = $lines -join "`n"
    Write-Log ("Cleanup done. Total freed {0:N1} MB" -f ($total/1MB)) $comp
    Send-Report -Subject ("System cleanup: {0:N0} MB freed" -f ($total/1MB)) -Body $body
}
catch {
    $err = $_.Exception.Message
    Write-Log "ERROR: $err" $comp
    try { Send-Report -Subject "System cleanup FAILED" -Body "Error:`n$err`n`n$($_.ScriptStackTrace)" } catch {}
}
