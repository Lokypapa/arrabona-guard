; ============================================================
;  Arrabona Guard - telepito (Inno Setup 6)
;  Nem kezzel kell futtatni: a build\build.bat forditja le, a verziot is az adja at.
; ============================================================

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppName   "Arrabona Guard"
#define AppExe    "Arrabona Guard.exe"
#define AppRepo   "https://github.com/Lokypapa/arrabona-guard"

[Setup]
AppId={{1DF0463A-EE22-447A-80B8-E809C6136803}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} v{#AppVersion}
AppPublisher=Lokypapa
AppPublisherURL={#AppRepo}
AppSupportURL={#AppRepo}/issues
AppUpdatesURL={#AppRepo}/releases
DefaultDirName={autopf}\Arrabona Guard
DefaultGroupName=Arrabona Guard
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
OutputDir=..\release
OutputBaseFilename=ArrabonaGuard_Setup_{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
LicenseFile=..\LICENSE
UninstallDisplayIcon={app}\{#AppExe}
UninstallDisplayName={#AppName}
CloseApplications=no
SetupLogging=yes
VersionInfoVersion={#AppVersion}

[Languages]
Name: "hungarian"; MessagesFile: "compiler:Languages\Hungarian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "autostart"; Description: "Indítás automatikusan bejelentkezéskor, rendszergazdai joggal (ajánlott)"; GroupDescription: "Indítás:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[InstallDelete]
; [v2.18.2] mappas build: a regi verzio konyvtarai ne keveredjenek az ujakkal
Type: filesandordirs; Name: "{app}\_internal"

[Files]
; [v2.18.2] "onedir" build: Arrabona Guard.exe + _internal mappa (a vírusirtók kevésbé gyanakszanak rá)
Source: "..\dist\Arrabona Guard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\assets\logo_tray.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\assets\logo_zold_uj.png"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "feladat.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion
Source: "eltavolitas.ps1"; DestDir: "{app}\tools"; Flags: ignoreversion
Source: "watchdog.vbs"; DestDir: "{app}\tools"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
; Utemezett feladatok: AutoStart (bejelentkezeskor, rendszergazdai joggal, UAC nelkul) + Watchdog (orkutya).
; [v2.18.2] Mindig letrejonnek (csak a telepito hozza letre oket); ha az automatikus inditas nincs
; bejelolve, az AutoStart kikapcsolt allapotban jon letre - a Guardban a pipa be tudja kapcsolni.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\feladat.ps1"" -Exe ""{app}\{#AppExe}"" -User ""{username}"" -AutoStart 1"; Flags: runhidden waituntilterminated; Tasks: autostart; StatusMsg: "Ütemezett feladatok beállítása..."
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\feladat.ps1"" -Exe ""{app}\{#AppExe}"" -User ""{username}"" -AutoStart 0"; Flags: runhidden waituntilterminated; Tasks: not autostart; StatusMsg: "Ütemezett feladatok beállítása..."
; A Guard inditasa a telepites vegen (csendes frissiteskor is)
Filename: "{app}\{#AppExe}"; Description: "Arrabona Guard indítása"; Flags: nowait postinstall

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\tools\eltavolitas.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "ArrabonaCleanup"

[Code]
procedure GuardLeallitasa();
var
  RC: Integer;
  Flag: String;
begin
  // kilepes.flag: az orkutya ne inditsa ujra a Guardot, amig a fajlokat csereljuk
  Flag := ExpandConstant('{userappdata}\ArrabonaGuard\kilepes.flag');
  ForceDirectories(ExtractFileDir(Flag));
  SaveStringToFile(Flag, 'telepito', False);
  // onfrissiteskor a Guard magatol kilep - adunk neki par masodpercet, utana leallitjuk
  Sleep(3000);
  Exec(ExpandConstant('{sys}\taskkill.exe'), '/f /im "{#AppExe}"', '', SW_HIDE, ewWaitUntilTerminated, RC);
  Sleep(1000);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  GuardLeallitasa();
  Result := '';
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
    GuardLeallitasa();
end;
