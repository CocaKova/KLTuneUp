@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
if not exist "%SCRIPT_DIR%KLTuneUp.ps1" (
    echo KLTuneUp.ps1 not found next to this launcher.
    pause
    exit /b 1
)
:: Pass -LaunchedFromScript so the PowerShell script prompts before exiting.
:: Also add -NoExit so that the PowerShell host remains open even if the script calls exit.
powershell.exe -NoLogo -NoProfile -NoExit -ExecutionPolicy Bypass -File "%SCRIPT_DIR%KLTuneUp.ps1" -LaunchedFromScript %*
endlocal
