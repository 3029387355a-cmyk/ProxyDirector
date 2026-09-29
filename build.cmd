@echo off
rem Build ProxyDirector with the Windows built-in .NET Framework 4.8 compiler (csc). No SDK needed.
setlocal
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
set OUT=%~dp0dist
if not exist "%OUT%" mkdir "%OUT%"

"%CSC%" /nologo /target:winexe /optimize+ /out:"%OUT%\ProxyDirector.exe" ^
  /r:System.Windows.Forms.dll ^
  /r:System.Drawing.dll ^
  /r:System.Net.Http.dll ^
  /r:System.Web.Extensions.dll ^
  "%~dp0src\ProxyDirector.cs"

if errorlevel 1 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK: %OUT%\ProxyDirector.exe
