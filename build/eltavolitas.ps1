# Arrabona Guard - takaritas eltavolitaskor (a telepito futtatja)
# Leallitja a Guardot, torli az utemezett feladatokat, az automatikus inditast es a
# Guard altal letrehozott tuzfal-szabalyokat. A beallitasok es naplok
# (%APPDATA%\ArrabonaGuard) megmaradnak - kezzel torolheted, ha mar nem kellenek.
$ErrorActionPreference = 'SilentlyContinue'
Get-Process -Name 'Arrabona Guard' | Stop-Process -Force
foreach ($t in 'ArrabonaGuard AutoStart', 'ArrabonaGuard Watchdog') {
    Unregister-ScheduledTask -TaskName $t -Confirm:$false
}
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'ArrabonaGuard'
Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Arrabona*' } | Remove-NetFirewallRule
