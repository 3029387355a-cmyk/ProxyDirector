@echo off
rem Remove the watchdog scheduled task and autostart entry.
schtasks /Delete /F /TN "ProxyDirector Watchdog"
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ProxyDirector /f
echo.
echo Uninstalled.
pause
