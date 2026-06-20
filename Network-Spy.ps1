# Network-Spy.ps1 — daily packet-capture watch for suspicious network activity. 1am. Needs admin.
# Real capture via tshark (Wireshark/Npcap). Captures a window, flags indicators, mails report.
#
# PREREQ: install Wireshark + Npcap.  winget install WiresharkFoundation.Wireshark
#   During Npcap install, leave "WinPcap API compatible" checked.
# Tunables:
$CaptureSeconds = 120          # how long to sniff
$TopN           = 20           # rows per table in report

. "$PSScriptRoot\Common.ps1"
$comp = 'spy'

function Find-TShark {
    $cmd = Get-Command tshark.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in 'C:\Program Files\Wireshark\tshark.exe','C:\Program Files (x86)\Wireshark\tshark.exe') {
        if (Test-Path $p) { return $p }
    }
    return $null
}

function Get-CaptureInterface {
    param([string]$TShark)
    # Pick the active adapter carrying the default route (lowest metric, Up).
    # Map its InterfaceGuid to a tshark device path (\Device\NPF_{GUID}).
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object RouteMetric, ifMetric | Select-Object -First 1
        $ad = Get-NetAdapter -InterfaceIndex $route.ifIndex -ErrorAction Stop
        if ($ad.Status -eq 'Up' -and $ad.InterfaceGuid) {
            return "\Device\NPF_$($ad.InterfaceGuid)"
        }
    } catch {}
    # Fallback: first Up adapter's GUID.
    try {
        $ad = Get-NetAdapter | Where-Object Status -eq 'Up' |
            Sort-Object InterfaceMetric | Select-Object -First 1
        if ($ad.InterfaceGuid) { return "\Device\NPF_$($ad.InterfaceGuid)" }
    } catch {}
    return $null
}

try {
    Write-Log "Network capture start ($CaptureSeconds s)" $comp
    $tshark = Find-TShark
    if (-not $tshark) {
        throw "tshark not found. Install Wireshark+Npcap: winget install WiresharkFoundation.Wireshark"
    }

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $pcap  = Join-Path $env:TEMP "spy_$stamp.pcapng"

    # Auto-pick active NIC (default-route adapter); fall back to index 1.
    $iface = Get-CaptureInterface -TShark $tshark
    if (-not $iface) { $iface = '1' }
    Write-Log "Capturing on interface: $iface" $comp
    & $tshark -i $iface -a duration:$CaptureSeconds -w $pcap -q 2>$null
    if (-not (Test-Path $pcap)) { throw "Capture produced no file (interface '$iface' / Npcap issue)." }

    # --- Analysis via tshark read filters / fields ---

    # 1. Established TCP/UDP conversations: remote IP, packets, bytes.
    $convRaw = & $tshark -r $pcap -q -z conv,tcp 2>$null
    $convUdp = & $tshark -r $pcap -q -z conv,udp 2>$null

    # 2. All unique remote (non-private) IPv4 destinations with port + count.
    $flows = & $tshark -r $pcap -T fields -e ip.dst -e tcp.dstport -e udp.dstport 2>$null `
        -Y "ip.dst and not (ip.dst==10.0.0.0/8 or ip.dst==192.168.0.0/16 or ip.dst==172.16.0.0/12 or ip.dst==224.0.0.0/4 or ip.dst==255.255.255.255)"

    $remote = @{}
    foreach ($l in $flows) {
        $f = $l -split "`t"
        $ip = $f[0]; if (-not $ip) { continue }
        $port = if ($f[1]) { $f[1] } elseif ($f[2]) { $f[2] } else { '?' }
        $key = "$ip`:$port"
        $remote[$key] = ($remote[$key] + 1)
    }

    # 3. DNS queries (domains being resolved) — beaconing / odd domains.
    $dns = & $tshark -r $pcap -T fields -e dns.qry.name -Y "dns.flags.response==0" 2>$null |
        Where-Object { $_ } | Group-Object | Sort-Object Count -Descending

    # 4. Suspicious-port heuristic: common C2 / RAT / backdoor ports.
    $susPorts = '4444','1337','31337','5555','6667','6666','9001','8080','8443','1080','3389','5900','23','2323'
    $flagged = @()
    foreach ($k in $remote.Keys) {
        $port = ($k -split ':')[-1]
        if ($susPorts -contains $port) { $flagged += "$k  count=$($remote[$k])" }
    }

    # 5. Local listeners that accept remote (exposed surface) — netstat cross-check.
    $listen = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalAddress -in '0.0.0.0','::' } |
        ForEach-Object {
            $p = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue)
            "{0}:{1}  <- {2} (pid {3})" -f $_.LocalAddress, $_.LocalPort, $p.ProcessName, $_.OwningProcess
        } | Sort-Object -Unique

    # --- Build report ---
    $topRemote = $remote.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First $TopN
    $lines = @()
    $lines += "Network watch report — $(Get-Date)"
    $lines += "Capture window: $CaptureSeconds s   File: $pcap"
    $lines += ""
    if ($flagged.Count) {
        $lines += "!!! SUSPICIOUS PORTS SEEN ($($flagged.Count)) !!!"
        $lines += $flagged
        $lines += ""
    } else {
        $lines += "No known-bad ports observed."
        $lines += ""
    }
    $lines += "== Top external destinations (ip:port -> packets) =="
    foreach ($r in $topRemote) { $lines += ("{0,-28} {1}" -f $r.Key, $r.Value) }
    $lines += ""
    $lines += "== Top DNS queries =="
    foreach ($d in ($dns | Select-Object -First $TopN)) { $lines += ("{0,-5} {1}" -f $d.Count, $d.Name) }
    $lines += ""
    $lines += "== Local listening ports (exposed surface) =="
    $lines += $listen
    $lines += ""
    $lines += "== TCP conversations (tshark) =="
    $lines += ($convRaw -join "`n")

    $body = $lines -join "`n"

    # Keep pcap as evidence; attach if small (<10MB).
    $attach = @()
    if ((Get-Item $pcap).Length -lt 10MB) { $attach = @($pcap) }

    $subjFlag = if ($flagged.Count) { "[ALERT] " } else { "" }
    Write-Log ("Capture done. Remote endpoints: {0}, flagged: {1}" -f $remote.Count, $flagged.Count) $comp
    Send-Report -Subject "${subjFlag}Network watch — $(Get-Date -Format 'yyyy-MM-dd')" -Body $body -Attachments $attach

    # Retain pcaps 14 days, prune older.
    Get-ChildItem (Join-Path $env:TEMP 'spy_*.pcapng') -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-14) } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}
catch {
    $err = $_.Exception.Message
    Write-Log "ERROR: $err" $comp
    try { Send-Report -Subject "Network watch FAILED" -Body "Error:`n$err`n`n$($_.ScriptStackTrace)" } catch {}
}
