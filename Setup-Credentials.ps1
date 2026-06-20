# Setup-Credentials.ps1 — run ONCE, interactively, as your own Windows user.
# Stores Gmail app password encrypted with DPAPI (only this Windows user on this PC can read it)
# and writes config.json with from/to addresses.
#
# PREREQ: Gmail App Password (NOT your normal password).
#   1. Enable 2-Step Verification: https://myaccount.google.com/security
#   2. Create app password:        https://myaccount.google.com/apppasswords
#   3. Use the 16-char value below when prompted for "password".

. "$PSScriptRoot\Common.ps1"

Write-Host "=== Gmail report setup ===" -ForegroundColor Cyan

$email = 'gabriel.fra.santos@gmail.com'
Write-Host "Enter Gmail address as USERNAME and the 16-char APP PASSWORD as password."
$cred = Get-Credential -UserName $email -Message "Gmail app password for sending reports"

# Quick auth test before saving.
Write-Host "Testing SMTP login..." -ForegroundColor Yellow
try {
    Send-MailMessage -From $cred.UserName -To $email -Subject 'Maintenance scripts: setup test' `
        -Body "Setup OK at $(Get-Date). Scripts can now mail you." `
        -SmtpServer 'smtp.gmail.com' -Port 587 -UseSsl -Credential $cred -ErrorAction Stop
    Write-Host "Test mail sent. Check inbox." -ForegroundColor Green
} catch {
    Write-Host "SMTP test FAILED: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Fix app password / 2FA, then re-run. Not saving." -ForegroundColor Red
    return
}

$cred | Export-Clixml -Path $script:CredPath
Write-Host "Credential saved (DPAPI): $script:CredPath" -ForegroundColor Green

$config = [ordered]@{
    from = $cred.UserName
    to   = $email
}
$config | ConvertTo-Json | Set-Content -Path $script:ConfigPath -Encoding UTF8
Write-Host "Config saved: $script:ConfigPath" -ForegroundColor Green
Write-Host "Done. Next: run Register-Tasks.ps1 (as admin) to schedule." -ForegroundColor Cyan
