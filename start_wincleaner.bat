@echo off
rem WinCleaner launcher - double click to start (no console window)
setlocal
cd /d "%~dp0"

set "PYW=%~dp0.venv\Scripts\pythonw.exe"
set "PY=%~dp0.venv\Scripts\python.exe"

if not exist "%PYW%" goto noenv
if not exist "%~dp0main.py" goto nomain

"%PY%" -c "import PyQt6, psutil" >nul 2>&1
if errorlevel 1 goto nodeps

start "" "%PYW%" "%~dp0main.py"
exit /b 0

:noenv
echo.
echo  [ERROR] Virtual environment not found: %~dp0.venv
echo.
echo  Fix it with:
echo      py -3.12 -m venv .venv
echo      .venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
pause
exit /b 1

:nodeps
echo.
echo  [ERROR] Missing runtime dependencies (PyQt6 / psutil).
echo.
echo  Fix it with:
echo      .venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
pause
exit /b 1

:nomain
echo.
echo  [ERROR] main.py not found next to this launcher.
echo.
pause
exit /b 1
