$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

if (-not (Test-Path $VenvPython)) {
    Write-Host "SecureScope virtual environment is missing. Run start_securescope.ps1 once." -ForegroundColor Red
    exit 1
}

& $VenvPython -m securescope.scanners.openvas.openvas_task_start_diagnostics --start-next
exit $LASTEXITCODE
