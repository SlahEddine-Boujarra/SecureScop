param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8765
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    throw "SecureScope virtual environment not found. Run start_securescope.ps1 first."
}

$env:PYTHONPATH = Join-Path $ProjectRoot "src"
Set-Location $ProjectRoot
& $Python -m uvicorn securescope.api.app:app --host $HostAddress --port $Port
