# Run as Administrator on a Windows endpoint with the Wazuh agent installed.
param(
    [string]$WazuhHome = "C:\Program Files (x86)\ossec-agent"
)

$ErrorActionPreference = "Stop"
$Source = Join-Path $PSScriptRoot "securescope_time_sync.ps1"
$Destination = Join-Path $WazuhHome "securescope_time_sync.ps1"

if (-not (Test-Path $Source)) {
    throw "Probe script not found: $Source"
}
if (-not (Test-Path $WazuhHome)) {
    throw "Wazuh agent directory not found: $WazuhHome"
}

Copy-Item $Source $Destination -Force
$Hash = (Get-FileHash $Destination -Algorithm SHA256).Hash
Write-Host "Installed: $Destination" -ForegroundColor Green
Write-Host "SHA-256:  $Hash"
Write-Host "Test output:" -ForegroundColor Cyan
& PowerShell.exe -NoProfile -ExecutionPolicy Bypass -File $Destination

$Service = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($Service) {
    Restart-Service -Name WazuhSvc
    Write-Host "Wazuh agent restarted." -ForegroundColor Green
}
else {
    Write-Host "WazuhSvc was not found; restart the Wazuh agent manually." -ForegroundColor Yellow
}
