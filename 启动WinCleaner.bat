@echo off
rem WinCleaner 启动器 —— 双击即可运行（无控制台窗口）
setlocal
cd /d "%~dp0"

set "PYW=%~dp0.venv\Scripts\pythonw.exe"
set "PY=%~dp0.venv\Scripts\python.exe"

if not exist "%PYW%" goto noenv
if not exist "%~dp0main.py" goto nomain

rem 依赖自检：缺 PyQt6 就直接给出可执行的修复命令
"%PY%" -c "import PyQt6, psutil" >nul 2>&1
if errorlevel 1 goto nodeps

start "" "%PYW%" "%~dp0main.py"
exit /b 0

:noenv
echo.
echo  [ERROR] 找不到虚拟环境：
echo          %~dp0.venv
echo.
echo  请在项目根目录执行以下命令重建：
echo      py -3.12 -m venv .venv
echo      .venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
pause
exit /b 1

:nodeps
echo.
echo  [ERROR] 运行依赖缺失（PyQt6 / psutil）。
echo.
echo  请执行：
echo      .venv\Scripts\python.exe -m pip install -r requirements.txt
echo.
pause
exit /b 1

:nomain
echo.
echo  [ERROR] 未找到 main.py（应在启动器同级目录）。
echo.
pause
exit /b 1
