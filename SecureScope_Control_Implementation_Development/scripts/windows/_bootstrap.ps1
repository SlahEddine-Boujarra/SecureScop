$ProjectRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $PSScriptRoot "..\..")
)
$SourceRoot = Join-Path $ProjectRoot "src"
$PackageRoot = Join-Path $SourceRoot "securescope"
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

$env:SECURESCOPE_ENV_FILE = Join-Path $ProjectRoot ".env"
if ($env:PYTHONPATH) {
    $env:PYTHONPATH = "$SourceRoot;$($env:PYTHONPATH)"
}
else {
    $env:PYTHONPATH = $SourceRoot
}

Set-Location $ProjectRoot

