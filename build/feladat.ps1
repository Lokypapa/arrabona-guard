# Arrabona Guard - utemezett feladatok beallitasa (a telepito futtatja)
#  - "ArrabonaGuard AutoStart": bejelentkezeskor inditja a Guardot (rendszergazdai joggal,
#    UAC-ablak nelkul, akkumulatorrol is, futasi idokorlat nelkul)
#  - "ArrabonaGuard Watchdog": 2 percenkent ellenorzi, fut-e (tools\watchdog.vbs)
# A Guard maga ezeket nem hozza letre, csak a telepito (a Defender a programtol
# "megkapaszkodasnak" nezne).
param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$User,
    [int]$AutoStart = 1
)
$ErrorActionPreference = 'Stop'
$dir = Split-Path $Exe
$principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Highest

# --- AutoStart ---
$action   = New-ScheduledTaskAction -Execute $Exe -WorkingDirectory $dir
$trigger  = New-ScheduledTaskTrigger -AtLogOn -User $User
$trigger.Delay = 'PT20S'
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
            -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable
Register-ScheduledTask -TaskName 'ArrabonaGuard AutoStart' -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Description 'Arrabona Guard inditasa bejelentkezeskor' -Force | Out-Null
if ($AutoStart -eq 0) { Disable-ScheduledTask -TaskName 'ArrabonaGuard AutoStart' | Out-Null }

# --- Watchdog ---
$vbs = Join-Path $dir 'tools\watchdog.vbs'
$waction   = New-ScheduledTaskAction -Execute 'wscript.exe' -Argument ('//B //Nologo "' + $vbs + '"')
$wtrigger  = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(2) `
             -RepetitionInterval (New-TimeSpan -Minutes 2) -RepetitionDuration (New-TimeSpan -Days 9999)
$wsettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
             -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -MultipleInstances IgnoreNew -StartWhenAvailable -Hidden
Register-ScheduledTask -TaskName 'ArrabonaGuard Watchdog' -Action $waction -Trigger $wtrigger `
    -Principal $principal -Settings $wsettings -Description 'Arrabona Guard orkutya' -Force | Out-Null

# regi (v2.18.1 elotti) orkutya-szkript takaritasa
Remove-Item (Join-Path $env:APPDATA 'ArrabonaGuard\watchdog.vbs') -ErrorAction SilentlyContinue
