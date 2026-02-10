@echo off
echo Starting Network Capture and Prediction Tool...
echo.
echo Note: This may require administrator privileges for packet capture.
echo.
cd /d "%~dp0"
python capture_predict_live.py
pause


