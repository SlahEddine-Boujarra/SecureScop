$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

$Python = $VenvPython
if (-not (Test-Path $Python)) { $Python = "python.exe" }

Write-Host "SecureScope OpenVAS Doctor" -ForegroundColor Cyan
Write-Host "1. Read-only diagnostic"
Write-Host "2. Diagnose and start exact Greenbone tasks that are still New"
$choice = Read-Host "Choose 1 or 2"

if ($choice -eq "2") {
    & $Python -m securescope.scanners.openvas.openvas_live_doctor --repair-new
} else {
    & $Python -m securescope.scanners.openvas.openvas_live_doctor
}

Write-Host "Upload the generated openvas_doctor_batch_*.json file for analysis." -ForegroundColor Yellow
