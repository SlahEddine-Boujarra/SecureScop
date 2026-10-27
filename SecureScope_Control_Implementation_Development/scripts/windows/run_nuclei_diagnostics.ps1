$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython
if (-not (Test-Path $Python)) { $Python = "python.exe" }
& $Python -m securescope.scanners.nuclei.nuclei_diagnostics
exit $LASTEXITCODE
