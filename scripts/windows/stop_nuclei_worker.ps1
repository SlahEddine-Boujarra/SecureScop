$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$PidFile = Join-Path $ProjectRoot "logs\nuclei_worker.pid"

if (-not (Test-Path $PidFile)) {
    Write-Host "No Nuclei worker PID file exists."
    exit 0
}

$WorkerPid = (Get-Content $PidFile -Raw).Trim()
if ($WorkerPid -notmatch '^\d+$') {
    Remove-Item $PidFile -Force
    throw "Invalid Nuclei worker PID file."
}

$Process = Get-Process -Id ([int]$WorkerPid) -ErrorAction SilentlyContinue
if ($Process) {
    Stop-Process -Id ([int]$WorkerPid) -Force
    Write-Host "Stopped Nuclei worker PID $WorkerPid." -ForegroundColor Green
}
else {
    Write-Host "Nuclei worker PID $WorkerPid is no longer running."
}
Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
