$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython

if (-not (Test-Path $Python)) {
    Write-Host "The SecureScope virtual environment does not exist." -ForegroundColor Red
    Write-Host "Run .\start_securescope.ps1 once, then retry." -ForegroundColor Yellow
    exit 1
}

& $Python -c "import pytest" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Install development dependencies first:" -ForegroundColor Yellow
    Write-Host "  .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt"
    exit 1
}

Push-Location $ProjectRoot
try {
    & $Python -m compileall -q src tests
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    & $Python -m pytest -q
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
