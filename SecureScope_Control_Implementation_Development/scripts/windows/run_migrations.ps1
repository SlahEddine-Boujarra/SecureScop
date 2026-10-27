$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

$python = $VenvPython
if (-not (Test-Path $python)) {
    throw "Python environment not found. Run start_securescope.ps1 first."
}

& $python -m securescope.cli.run_migrations
if ($LASTEXITCODE -ne 0) {
    throw "SecureScope database migration failed."
}
