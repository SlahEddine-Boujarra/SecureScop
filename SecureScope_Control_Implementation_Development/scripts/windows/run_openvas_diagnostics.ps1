$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

if (-not (Test-Path ".env")) {
    Write-Host "Create and configure .env first." -ForegroundColor Red
    exit 1
}

$python = $VenvPython
if (-not (Test-Path $python)) {
    $python = "py"
    & $python -3.11 -m securescope.scanners.openvas.openvas_diagnostics
}
else {
    & $python -m securescope.scanners.openvas.openvas_diagnostics
}
