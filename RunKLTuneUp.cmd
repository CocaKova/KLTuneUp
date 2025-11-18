@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if not exist "%SCRIPT_DIR%KLTuneUp.ps1" (
    echo KLTuneUp.ps1 not found next to this launcher.
    pause
    exit /b 1
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%KLTuneUp.ps1" %*
endlocal
