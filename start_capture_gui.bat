@echo off
echo Starting Network Capture Launcher (GUI)...
cd /d "%~dp0"
python launcher_gui.py
if errorlevel 1 (
    echo.
    echo Error: Could not start GUI launcher.
    echo Make sure Python and tkinter are installed.
    pause
)


