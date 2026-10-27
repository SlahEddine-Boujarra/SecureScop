$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython
if (-not (Test-Path $Python)) { $Python = "python.exe" }
& $Python -c "from securescope.scanners.nuclei.nuclei_client import NucleiClient; print(NucleiClient().update_templates())"
exit $LASTEXITCODE
