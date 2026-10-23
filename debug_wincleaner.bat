@echo off
rem WinCleaner debug launcher - keeps the console open so errors are visible
setlocal
cd /d "%~dp0"

set "PY=%~dp0.venv\Scripts\python.exe"

if not exist "%PY%" (
  echo [ERROR] venv missing: %~dp0.venv
  pause
  exit /b 1
)

"%PY%" "%~dp0main.py"
echo.
echo ---- exit code: %ERRORLEVEL% ----
pause
