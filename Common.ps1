# Common.ps1 — shared helpers for maintenance scripts.
# Dot-source this at top of each task script:  . "$PSScriptRoot\Common.ps1"

$script:Root      = $PSScriptRoot
$script:LogDir    = Join-Path $Root 'logs'
$script:ConfigPath= Join-Path $Root 'config.json'
$script:CredPath  = Join-Path $Root 'gmail.cred.xml'   # DPAPI-encrypted, per Windows user

if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }

function Write-Log {
    param([string]$Message, [string]$Component = 'general')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Component, $Message
    $file = Join-Path $LogDir ("{0}.log" -f $Component)
    Add-Content -Path $file -Value $line
    Write-Host $line
}

function Get-Config {
    if (-not (Test-Path $ConfigPath)) {
        throw "Config missing: $ConfigPath. Run Setup-Credentials.ps1 first."
    }
    Get-Content $ConfigPath -Raw | ConvertFrom-Json
}

function Get-GmailCredential {
    if (-not (Test-Path $CredPath)) {
        throw "Gmail credential missing: $CredPath. Run Setup-Credentials.ps1 first."
    }
    # DPAPI decrypt — only works as the same Windows user that created it.
    Import-Clixml $CredPath
}

function Send-Report {
    param(
        [Parameter(Mandatory)] [string]$Subject,
        [Parameter(Mandatory)] [string]$Body,
        [string[]]$Attachments,
        [switch]$Html
    )
    $cfg  = Get-Config
    $cred = Get-GmailCredential
    $params = @{
        From       = $cfg.from
        To         = $cfg.to
        Subject    = $Subject
        Body       = $Body
        SmtpServer = 'smtp.gmail.com'
        Port       = 587
        UseSsl     = $true
        Credential = $cred
        BodyAsHtml = [bool]$Html
    }
    if ($Attachments) {
        $exist = $Attachments | Where-Object { $_ -and (Test-Path $_) }
        if ($exist) { $params.Attachments = $exist }
    }
    # Send-MailMessage is deprecated by MS but still functional for Gmail STARTTLS:587.
    Send-MailMessage @params
    Write-Log "Report mailed to $($cfg.to): $Subject" 'email'
}
