@echo off
setlocal
set "SCRIPT=%~dp0securescope_security_updates.ps1"
set "EXPECTED=bfc56c31c23e9cb7a0e8d69f2e6148254a1b3371cd67ab89c034e80e56ae136c"

if not exist "%SCRIPT%" exit /b 96
for /f "usebackq delims=" %%H in (`powershell.exe -NoProfile -NonInteractive -Command "(Get-FileHash -LiteralPath '%SCRIPT%' -Algorithm SHA256).Hash.ToLowerInvariant()"`) do set "ACTUAL=%%H"
if /i not "%ACTUAL%"=="%EXPECTED%" exit /b 97

powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File "%SCRIPT%"
exit /b %ERRORLEVEL%
