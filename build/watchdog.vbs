' Arrabona Guard orkutya - 2 percenkent ellenorzi, fut-e a Guard; ha nem (es nem
' te leptel ki), ujrainditja. A telepito masolja ide es o hozza letre a feladatot is.
Option Explicit
Dim fso, sh, wmi, procs, dir, exe, flag
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")
dir = fso.GetParentFolderName(fso.GetParentFolderName(WScript.ScriptFullName))
exe = dir & "\Arrabona Guard.exe"
flag = sh.ExpandEnvironmentStrings("%APPDATA%") & "\ArrabonaGuard\kilepes.flag"
If fso.FileExists(flag) Then WScript.Quit 0
If Not fso.FileExists(exe) Then WScript.Quit 0
Set wmi = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set procs = wmi.ExecQuery("SELECT ProcessId FROM Win32_Process WHERE Name = 'Arrabona Guard.exe'")
If procs.Count = 0 Then
  sh.Run """" & exe & """ --watchdog", 7, False
End If
