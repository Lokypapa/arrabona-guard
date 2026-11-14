# Arrabona Guard - automatikus inditas beallitasa (a telepito futtatja)
# Utemezett feladat: bejelentkezeskor indul, rendszergazdai joggal (UAC-ablak nelkul),
# akkumulatorrol is, es nincs futasi idokorlat (az alapertelmezett 3 nap utan leallitana).
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$User
)
$ErrorActionPreference = 'Stop'
$nev = 'ArrabonaGuard AutoStart'
$action    = New-ScheduledTaskAction -Execute $Exe -WorkingDirectory (Split-Path $Exe)
$trigger   = New-ScheduledTaskTrigger -AtLogOn -User $User
$trigger.Delay = 'PT20S'
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName $nev -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description 'Arrabona Guard inditasa bejelentkezeskor' -Force | Out-Null
