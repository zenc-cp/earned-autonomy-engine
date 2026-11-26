@echo off
setlocal
cd /d "%~dp0"
python -B live_desk.py --port 8790 --open
if errorlevel 1 pause
