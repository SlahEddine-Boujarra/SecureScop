param(
    [ValidateSet("amd64", "arm64")]
    [string]$Architecture = "amd64"
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$ToolsDir = Join-Path $ProjectRoot "tools\nuclei"
$DownloadDir = Join-Path $env:TEMP "securescope-nuclei-install"
$ArchivePath = Join-Path $DownloadDir "nuclei.zip"

New-Item -ItemType Directory -Force $ToolsDir | Out-Null
New-Item -ItemType Directory -Force $DownloadDir | Out-Null

Write-Host "Reading the latest official ProjectDiscovery release..." -ForegroundColor Cyan
$Headers = @{
    "User-Agent" = "SecureScope-Nuclei-Installer"
    "Accept" = "application/vnd.github+json"
}
$Release = Invoke-RestMethod `
    -Uri "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest" `
    -Headers $Headers

$Pattern = "windows_${Architecture}\.zip$"
$Asset = $Release.assets |
    Where-Object { $_.name -match $Pattern } |
    Select-Object -First 1

if (-not $Asset) {
    throw "The official release does not contain a Windows $Architecture archive."
}

Write-Host "Downloading $($Asset.name)..." -ForegroundColor Cyan
Invoke-WebRequest `
    -Uri $Asset.browser_download_url `
    -Headers $Headers `
    -OutFile $ArchivePath

$ExtractDir = Join-Path $DownloadDir "extracted"
Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive -Path $ArchivePath -DestinationPath $ExtractDir -Force
$Binary = Get-ChildItem $ExtractDir -Recurse -Filter "nuclei.exe" |
    Select-Object -First 1
if (-not $Binary) {
    throw "nuclei.exe was not found in the downloaded official archive."
}

$Destination = Join-Path $ToolsDir "nuclei.exe"
Copy-Item $Binary.FullName $Destination -Force

Write-Host "Installed: $Destination" -ForegroundColor Green
& $Destination -version
Write-Host "Installing/updating the community templates..." -ForegroundColor Cyan
& $Destination -update-templates
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Nuclei was installed, but the template update returned an error."
    exit $LASTEXITCODE
}

Write-Host "Set NUCLEI_BINARY=tools\nuclei\nuclei.exe in .env." -ForegroundColor Green
