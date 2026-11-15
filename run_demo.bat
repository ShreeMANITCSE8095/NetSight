@echo off
setlocal
cd /d "%~dp0"

echo ==========================================================
echo   NetSight: Network Telemetry ^& DPI Engine Launcher
echo ==========================================================

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_demo.ps1" %*

