param()

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython

if (-not (Test-Path $Python)) {
    throw "SecureScope virtual environment not found. Run start_securescope.ps1 first."
}

Set-Location $ProjectRoot
& $Python -m securescope.compliance.remediation_worker_runner
