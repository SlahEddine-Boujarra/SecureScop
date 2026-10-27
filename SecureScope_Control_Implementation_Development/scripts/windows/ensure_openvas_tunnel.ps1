$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"

Write-Host "Use start_securescope.ps1. It now validates and optionally starts the OpenVAS SSH tunnel before Streamlit." -ForegroundColor Cyan
& "$ProjectRoot\start_securescope.ps1"
