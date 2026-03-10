@echo off
setlocal
cd /d "%~dp0"
start "" cmd /k "cd /d %~dp0 && python -m banking_system.main"
timeout /t 3 /nobreak >nul
start "" http://127.0.0.1:8080/admin/logs
start "" http://127.0.0.1:8080/admin/oversight
