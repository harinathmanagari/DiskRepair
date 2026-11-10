@echo off
rem Starts DiskRepair. Windows will ask for administrator rights - raw disk access needs them.
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
    echo Python 3 was not found on PATH. Install it from https://www.python.org/ and try again.
    pause
    exit /b 1
)
start "" pythonw "%~dp0DiskRepair.pyw"
