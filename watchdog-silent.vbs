' Launch watchdog.cmd fully hidden (no console flash).
' Task Scheduler runs this via wscript.exe, which creates no window.
Dim fso, sh, dir
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run """" & dir & "\watchdog.cmd""", 0, False
