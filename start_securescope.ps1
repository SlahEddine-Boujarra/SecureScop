$ErrorActionPreference = "Stop"
$env:PYTHONUTF8 = "1"
$ProjectRoot = $PSScriptRoot
$SourceRoot = Join-Path $ProjectRoot "src"
$PackageRoot = Join-Path $SourceRoot "securescope"
Set-Location $ProjectRoot

$env:SECURESCOPE_ENV_FILE = Join-Path $ProjectRoot ".env"
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$SourceRoot;$($env:PYTHONPATH)"
}
else {
    $env:PYTHONPATH = $SourceRoot
}

function Get-DotEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [string]$Default = ""
    )

    if (-not (Test-Path ".env")) { return $Default }
    $pattern = "^\s*" + [regex]::Escape($Name) + "\s*="
    $line = Get-Content ".env" |
        Where-Object { $_ -match $pattern } |
        Select-Object -Last 1
    if (-not $line) { return $Default }
    $value = ($line -split "=", 2)[1].Trim()
    if (
        ($value.StartsWith('"') -and $value.EndsWith('"')) -or
        ($value.StartsWith("'") -and $value.EndsWith("'"))
    ) {
        $value = $value.Substring(1, $value.Length - 2)
    }
    return $value
}

function Test-EnvTrue {
    param([string]$Value)
    return $Value.Trim().ToLowerInvariant() -in @("1", "true", "yes", "on")
}

function Test-EngineEnabled {
    param(
        [Parameter(Mandatory = $true)][string]$Engine,
        [Parameter(Mandatory = $true)][string]$RawEngines
    )

    $tokens = $RawEngines.ToLowerInvariant().Replace(";", ",").Split(",") |
        ForEach-Object { $_.Trim() }
    if ($Engine -eq "OpenVAS") {
        return ($tokens -contains "openvas") -or
            ($tokens -contains "greenbone") -or
            ($tokens -contains "gvm")
    }
    return ($tokens -contains "nuclei") -or
        ($tokens -contains "projectdiscovery") -or
        ($tokens -contains "project discovery")
}

function Test-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$HostName,
        [Parameter(Mandatory = $true)][int]$Port,
        [int]$TimeoutMilliseconds = 1000
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMilliseconds, $false)) {
            return $false
        }
        $client.EndConnect($async)
        return $true
    }
    catch { return $false }
    finally { $client.Close() }
}

function Start-OpenVasTunnelIfNeeded {
    param([bool]$Enabled)

    if (-not $Enabled) {
        $env:SECURESCOPE_OPENVAS_RUNTIME_READY = "false"
        Write-Host "OpenVAS engine is disabled." -ForegroundColor DarkGray
        return
    }

    $localHost = Get-DotEnvValue "LOCAL_TUNNEL_HOST" "127.0.0.1"
    $localPort = [int](Get-DotEnvValue "LOCAL_TUNNEL_PORT" "19390")
    $sshAutostart = Get-DotEnvValue "OPENVAS_SSH_AUTOSTART" "false"
    $sshHost = Get-DotEnvValue "OPENVAS_SSH_HOST" ""
    $sshUser = Get-DotEnvValue "OPENVAS_SSH_USER" "openvas"
    $sshKeyPath = Get-DotEnvValue "OPENVAS_SSH_KEY_PATH" ""
    $remoteSocket = Get-DotEnvValue "OPENVAS_GVMD_SOCKET" "/run/gvmd/gvmd.sock"
    $timeout = [int](Get-DotEnvValue "OPENVAS_TUNNEL_START_TIMEOUT_SECONDS" "30")

    $ready = Test-TcpEndpoint -HostName $localHost -Port $localPort
    if (-not $ready -and (Test-EnvTrue $sshAutostart)) {
        if (-not $sshHost) {
            Write-Warning "OPENVAS_SSH_AUTOSTART=true but OPENVAS_SSH_HOST is empty."
        }
        else {
            $ssh = Get-Command "ssh.exe" -ErrorAction SilentlyContinue
            if (-not $ssh) {
                Write-Warning "Windows OpenSSH client is unavailable."
            }
            else {
                $forward = "${localHost}:${localPort}:${remoteSocket}"
                $arguments = @(
                    "-N", "-T",
                    "-o", "ExitOnForwardFailure=yes",
                    "-o", "ServerAliveInterval=30",
                    "-o", "ServerAliveCountMax=3",
                    "-L", $forward
                )
                if ($sshKeyPath) { $arguments += @("-i", $sshKeyPath) }
                $arguments += "${sshUser}@${sshHost}"
                Write-Host "Starting the OpenVAS SSH tunnel..." -ForegroundColor Cyan
                Start-Process -FilePath $ssh.Source -ArgumentList $arguments | Out-Null
                $deadline = (Get-Date).AddSeconds([Math]::Max(5, $timeout))
                do {
                    Start-Sleep -Milliseconds 750
                    $ready = Test-TcpEndpoint -HostName $localHost -Port $localPort
                } while (-not $ready -and (Get-Date) -lt $deadline)
            }
        }
    }

    $env:SECURESCOPE_OPENVAS_RUNTIME_READY = if ($ready) { "true" } else { "false" }
    if ($ready) {
        Write-Host "OpenVAS tunnel ready at ${localHost}:${localPort}." -ForegroundColor Green
    }
    else {
        Write-Warning "OpenVAS is offline at ${localHost}:${localPort}. Nuclei can still be used."
    }
}

function Start-NucleiWorkerIfNeeded {
    param(
        [bool]$Enabled,
        [Parameter(Mandatory = $true)][string]$PythonPath
    )

    if (-not $Enabled) {
        $env:SECURESCOPE_NUCLEI_RUNTIME_READY = "false"
        Write-Host "Nuclei engine is disabled." -ForegroundColor DarkGray
        return
    }

    New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    $diagnosticLog = Join-Path $PSScriptRoot "logs\nuclei_startup_diagnostic.log"
    Write-Host "Checking the Nuclei CLI and templates..." -ForegroundColor Cyan
    & $PythonPath -m securescope.scanners.nuclei.nuclei_diagnostics *> $diagnosticLog
    if ($LASTEXITCODE -ne 0) {
        $env:SECURESCOPE_NUCLEI_RUNTIME_READY = "false"
        Write-Warning "Nuclei diagnostics failed. Review $diagnosticLog."
        return
    }

    $autostart = Get-DotEnvValue "NUCLEI_WORKER_AUTOSTART" "true"
    if (-not (Test-EnvTrue $autostart)) {
        $env:SECURESCOPE_NUCLEI_RUNTIME_READY = "true"
        Write-Host "Nuclei CLI ready; worker autostart is disabled." -ForegroundColor Green
        return
    }

    $pidFile = Join-Path $PSScriptRoot "logs\nuclei_worker.pid"
    $workerPid = 0
    $probeOutput = & $PythonPath -m securescope.scanners.nuclei.nuclei_worker_probe --max-age 45 2>$null
    if ($LASTEXITCODE -eq 0 -and $probeOutput) {
        try {
            $probeState = ($probeOutput -join "`n") | ConvertFrom-Json
            $probePid = [int]$probeState.pid
            if ($probePid -gt 0 -and (Get-Process -Id $probePid -ErrorAction SilentlyContinue)) {
                $workerPid = $probePid
                Set-Content -Path $pidFile -Value $workerPid -Encoding ASCII
                Write-Host "Reusing healthy Nuclei worker PID $workerPid." -ForegroundColor Green
            }
        }
        catch { $workerPid = 0 }
    }

    if ($workerPid -eq 0 -and (Test-Path $pidFile)) {
        $storedPid = (Get-Content $pidFile -Raw).Trim()
        if ($storedPid -match '^\d+$' -and (Get-Process -Id ([int]$storedPid) -ErrorAction SilentlyContinue)) {
            $workerPid = [int]$storedPid
        }
        else {
            Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        }
    }

    if ($workerPid -eq 0) {
        $stdoutLog = Join-Path $PSScriptRoot "logs\nuclei_worker_stdout.log"
        $stderrLog = Join-Path $PSScriptRoot "logs\nuclei_worker_stderr.log"
        Write-Host "Starting the standalone Nuclei worker..." -ForegroundColor Cyan
        $process = Start-Process `
            -FilePath $PythonPath `
            -ArgumentList @("-m", "securescope.scanners.nuclei.nuclei_worker_runner") `
            -WorkingDirectory $PSScriptRoot `
            -WindowStyle Hidden `
            -RedirectStandardOutput $stdoutLog `
            -RedirectStandardError $stderrLog `
            -PassThru
        $workerPid = $process.Id
        Set-Content -Path $pidFile -Value $workerPid -Encoding ASCII
    }

    $deadline = (Get-Date).AddSeconds(20)
    $workerReady = $false
    do {
        Start-Sleep -Seconds 1
        & $PythonPath -m securescope.scanners.nuclei.nuclei_worker_probe --max-age 45 *> $null
        $workerReady = ($LASTEXITCODE -eq 0)
    } while (-not $workerReady -and (Get-Date) -lt $deadline)

    $env:SECURESCOPE_NUCLEI_RUNTIME_READY = if ($workerReady) { "true" } else { "false" }
    if ($workerReady) {
        Write-Host "Nuclei worker ready (PID $workerPid)." -ForegroundColor Green
    }
    else {
        Write-Warning "Nuclei CLI is available, but the worker heartbeat is not healthy. Review logs\nuclei_worker_stderr.log."
    }
}

function Start-RemediationWorkerIfEnabled {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $autostart = Get-DotEnvValue "REMEDIATION_WORKER_AUTOSTART" "false"
    $executionEnabled = Get-DotEnvValue `
        "WAZUH_REMEDIATION_EXECUTION_ENABLED" `
        "false"
    if (-not (Test-EnvTrue $autostart) -or -not (Test-EnvTrue $executionEnabled)) {
        Write-Host "Approved remediation execution is disabled." -ForegroundColor DarkGray
        return
    }

    New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    $pidFile = Join-Path $PSScriptRoot "logs\remediation_worker.pid"
    if (Test-Path $pidFile) {
        $storedPid = (Get-Content $pidFile -Raw).Trim()
        if ($storedPid -match '^\d+$' -and (Get-Process -Id ([int]$storedPid) -ErrorAction SilentlyContinue)) {
            Write-Host "Reusing approved remediation worker PID $storedPid." -ForegroundColor Green
            return
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
    $stdoutLog = Join-Path $PSScriptRoot "logs\remediation_worker_stdout.log"
    $stderrLog = Join-Path $PSScriptRoot "logs\remediation_worker_stderr.log"
    Write-Host "Starting the approved remediation worker..." -ForegroundColor Cyan
    $process = Start-Process `
        -FilePath $PythonPath `
        -ArgumentList @("-m", "securescope.compliance.remediation_worker_runner") `
        -WorkingDirectory $PSScriptRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -PassThru
    Set-Content -Path $pidFile -Value $process.Id -Encoding ASCII
}

function Start-EvidenceWorkerIfEnabled {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    $autostart = Get-DotEnvValue "EVIDENCE_WORKER_AUTOSTART" "false"
    if (-not (Test-EnvTrue $autostart)) {
        Write-Host "ISO evidence collector worker autostart is disabled." -ForegroundColor DarkGray
        return
    }

    New-Item -ItemType Directory -Path "logs" -Force | Out-Null
    $pidFile = Join-Path $PSScriptRoot "logs\evidence_worker.pid"
    if (Test-Path $pidFile) {
        $storedPid = (Get-Content $pidFile -Raw).Trim()
        if ($storedPid -match '^\d+$' -and (Get-Process -Id ([int]$storedPid) -ErrorAction SilentlyContinue)) {
            Write-Host "Reusing ISO evidence worker PID $storedPid." -ForegroundColor Green
            return
        }
        Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    }
    $stdoutLog = Join-Path $PSScriptRoot "logs\evidence_worker_stdout.log"
    $stderrLog = Join-Path $PSScriptRoot "logs\evidence_worker_stderr.log"
    Write-Host "Starting the independent ISO evidence collector worker..." -ForegroundColor Cyan
    $process = Start-Process `
        -FilePath $PythonPath `
        -ArgumentList @("-m", "securescope.evidence.evidence_worker") `
        -WorkingDirectory $PSScriptRoot `
        -WindowStyle Hidden `
        -RedirectStandardOutput $stdoutLog `
        -RedirectStandardError $stderrLog `
        -PassThru
    Set-Content -Path $pidFile -Value $process.Id -Encoding ASCII
}

try { py -3.11 --version | Out-Null }
catch {
    Write-Host "Python 3.11 is required." -ForegroundColor Red
    exit 1
}

if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
    Write-Host "A .env file was created. Configure PostgreSQL and at least one scanner engine." -ForegroundColor Yellow
    notepad .env
    exit 0
}

if (-not (Test-Path ".venv")) {
    Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
    py -3.11 -m venv .venv
}

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$requirementsHash = (Get-FileHash requirements.txt -Algorithm SHA256).Hash
$marker = Join-Path $PSScriptRoot ".venv\.requirements-$requirementsHash"
if (-not (Test-Path $marker)) {
    Write-Host "Installing SecureScope dependencies..." -ForegroundColor Cyan
    & $python -m pip install --upgrade pip
    & $python -m pip install -r requirements.txt
    if ($LASTEXITCODE -ne 0) { exit 1 }
    Get-ChildItem ".venv\.requirements-*" -ErrorAction SilentlyContinue | Remove-Item -Force
    New-Item $marker -ItemType File -Force | Out-Null
}

Write-Host "Applying backward-compatible SecureScope migrations..." -ForegroundColor Cyan
& $python -m securescope.cli.run_migrations
if ($LASTEXITCODE -ne 0) {
    Write-Host "Database migration failed. Scanner workers were not started." -ForegroundColor Red
    exit 1
}

$rawEngines = Get-DotEnvValue "SECURESCOPE_ENABLED_SCAN_ENGINES" "OpenVAS,Nuclei"
$openvasEnabled = Test-EngineEnabled -Engine "OpenVAS" -RawEngines $rawEngines
$nucleiEnabled = Test-EngineEnabled -Engine "Nuclei" -RawEngines $rawEngines
if (-not $openvasEnabled -and -not $nucleiEnabled) {
    Write-Host "No supported scan engine is enabled." -ForegroundColor Red
    exit 1
}

Start-OpenVasTunnelIfNeeded -Enabled $openvasEnabled
Start-NucleiWorkerIfNeeded -Enabled $nucleiEnabled -PythonPath $python
Start-RemediationWorkerIfEnabled -PythonPath $python
Start-EvidenceWorkerIfEnabled -PythonPath $python

# A fresh, process-local proof of host access; never stored in browser markup.
$setupBytes = New-Object byte[] 32
$setupRng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $setupRng.GetBytes($setupBytes) } finally { $setupRng.Dispose() }
$env:SECURESCOPE_LOCAL_SETUP_CODE = [Convert]::ToBase64String($setupBytes)
Write-Host "Private local setup code (keep in this launcher window):" -ForegroundColor Yellow
Write-Host $env:SECURESCOPE_LOCAL_SETUP_CODE -ForegroundColor Yellow
Write-Host "Use Programme Foundation > Administrator setup / local sign-in."

Write-Host "Starting SecureScope OpenVAS/Nuclei dashboard..." -ForegroundColor Green
Write-Host "Enabled engines: $rawEngines" -ForegroundColor Green
& $python -m streamlit run "src\securescope\app.py"
