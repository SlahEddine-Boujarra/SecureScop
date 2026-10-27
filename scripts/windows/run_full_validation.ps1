param(
    [switch]$Strict
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\_bootstrap.ps1"
$Python = $VenvPython

if (-not (Test-Path $Python)) {
    Write-Host "The SecureScope virtual environment does not exist." -ForegroundColor Red
    Write-Host "Run .\start_securescope.ps1 once, then retry." -ForegroundColor Yellow
    exit 1
}

$Arguments = @("-m", "securescope.validation.full_stack_validation")
if ($Strict) {
    $Arguments += "--strict"
}

& $Python @Arguments
exit $LASTEXITCODE
