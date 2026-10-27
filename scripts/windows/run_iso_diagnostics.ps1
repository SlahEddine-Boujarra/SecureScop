$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython
if (-not (Test-Path $Python)) {
    Write-Host "Run start_securescope.ps1 once to create .venv." -ForegroundColor Yellow
    exit 1
}
& $Python -m securescope.compliance.iso_diagnostics
exit $LASTEXITCODE
