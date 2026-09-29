@echo off
rem ProxyDirector watchdog: relaunch the app if it is not running.
rem Skips when stop.flag exists (user exited via tray on purpose).
set DIR=%~dp0
if exist "%DIR%runtime\stop.flag" exit /b 0
tasklist /FI "IMAGENAME eq ProxyDirector.exe" 2>nul | find /I "ProxyDirector.exe" >nul
if errorlevel 1 (
  start "" "%DIR%dist\ProxyDirector.exe"
)
