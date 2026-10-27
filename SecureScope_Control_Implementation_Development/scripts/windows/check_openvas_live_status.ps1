$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

if (Test-Path $VenvPython) {
    & $VenvPython -m securescope.scanners.openvas.check_openvas_live_status
}
else {
    & py -3.11 -m securescope.scanners.openvas.check_openvas_live_status
}
