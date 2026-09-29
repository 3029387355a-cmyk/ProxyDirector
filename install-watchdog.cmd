@echo off
rem Register the per-minute watchdog scheduled task and HKCU autostart. No admin rights needed.
set DIR=%~dp0
schtasks /Create /F /TN "ProxyDirector Watchdog" /SC MINUTE /MO 1 /TR "\"%DIR%watchdog.cmd\""
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v ProxyDirector /t REG_SZ /d "\"%DIR%dist\ProxyDirector.exe\"" /f
echo.
echo Done. Watchdog checks every minute; app also starts at login.
pause
