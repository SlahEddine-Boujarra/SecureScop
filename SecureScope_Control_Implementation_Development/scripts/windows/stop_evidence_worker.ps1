param()

$ProjectRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$PidFile = Join-Path $ProjectRoot "logs\evidence_worker.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "No ISO evidence worker PID file exists."
    exit 0
}

$StoredPid = (Get-Content $PidFile -Raw).Trim()
if ($StoredPid -match '^\d+$') {
    Stop-Process -Id ([int]$StoredPid) -ErrorAction SilentlyContinue
}
Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
Write-Host "ISO evidence worker stopped."
