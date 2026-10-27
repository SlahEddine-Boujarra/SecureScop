param(
    [switch]$Foreground
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

$Python = $VenvPython
if (-not (Test-Path $Python)) {
    if (Get-Command py.exe -ErrorAction SilentlyContinue) {
        $Python = "py.exe"
    }
    elseif (Get-Command python.exe -ErrorAction SilentlyContinue) {
        $Python = "python.exe"
    }
    else {
        throw "Python was not found. Run start_securescope.ps1 first."
    }
}

$PidFile = Join-Path $ProjectRoot "logs\nuclei_worker.pid"
$StdoutLog = Join-Path $ProjectRoot "logs\nuclei_worker_stdout.log"
$StderrLog = Join-Path $ProjectRoot "logs\nuclei_worker_stderr.log"
New-Item -ItemType Directory -Force (Split-Path $PidFile) | Out-Null

if (Test-Path $PidFile) {
    $ExistingPid = (Get-Content $PidFile -Raw).Trim()
    if ($ExistingPid -match '^\d+$') {
        $ExistingProcess = Get-Process -Id ([int]$ExistingPid) -ErrorAction SilentlyContinue
        if ($ExistingProcess) {
            Write-Host "Nuclei worker is already running with PID $ExistingPid." -ForegroundColor Green
            exit 0
        }
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

if ($Foreground) {
    & $Python -m securescope.scanners.nuclei.nuclei_worker_runner
    exit $LASTEXITCODE
}

$Process = Start-Process `
    -FilePath $Python `
    -ArgumentList @("-m", "securescope.scanners.nuclei.nuclei_worker_runner") `
    -WorkingDirectory $ProjectRoot `
    -RedirectStandardOutput $StdoutLog `
    -RedirectStandardError $StderrLog `
    -WindowStyle Hidden `
    -PassThru

Set-Content -Path $PidFile -Value $Process.Id -Encoding ascii
Start-Sleep -Seconds 3

& $Python -m securescope.scanners.nuclei.nuclei_worker_probe --max-age 30
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Nuclei worker started with PID $($Process.Id), but its heartbeat is not healthy yet. Review $StderrLog."
    exit 2
}

Write-Host "Nuclei worker started with PID $($Process.Id)." -ForegroundColor Green
