$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$secureScopePython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $secureScopePython)) {
    throw "Run the SecureScope setup first to create .venv."
}
$env:PYTHONPATH = Join-Path $PSScriptRoot "src"
& $secureScopePython -m securescope.cli.configure_identity
if ($LASTEXITCODE -ne 0) { throw "Workspace identity setup did not complete." }
