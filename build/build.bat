@echo off
rem ============================================================
rem  Arrabona Guard - kiadas keszitese
rem    1) PyInstaller: dist\Arrabona Guard.exe
rem    2) Inno Setup:  release\ArrabonaGuard_Setup_VERZIO.exe
rem    3) release\SHA256SUMS.txt  (a frissito ezzel ellenoriz)
rem  Futtatas: dupla kattintas, vagy a repo mappajabol:  build\build.bat
rem  Kell hozza: Python 3.11+  es  Inno Setup 6  (https://jrsoftware.org/isdl.php)
rem ============================================================
setlocal
cd /d "%~dp0.."

set VER=
for /f "delims=" %%v in ('python build\verzio.py') do set VER=%%v
if "%VER%"=="" (
    echo [HIBA] Nem talalom a Pythont vagy a verziot az arrabona\common.py-ban.
    goto :hiba
)
echo.
echo === Arrabona Guard v%VER% kiadas keszitese ===
echo.

echo [1/4] Python-csomagok...
python -m pip install --upgrade --quiet -r requirements.txt pyinstaller || goto :hiba

echo [2/4] PyInstaller...
set ICON=
if exist "assets\logo_zold_uj.png" set ICON=--icon "assets\logo_zold_uj.png"
if exist "assets\logo_zold.ico" set ICON=--icon "assets\logo_zold.ico"
if not exist "assets\logo_tray.png" echo [FIGYELEM] assets\logo_tray.png hianyzik - a tartalek logot hasznalja.
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
    --name "Arrabona Guard" %ICON% ^
    --hidden-import pystray._win32 ^
    arrabona_guard.py || goto :hiba

echo [3/4] Inno Setup...
set ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" set ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" set ISCC=%LocalAppData%\Programs\Inno Setup 6\ISCC.exe
if not exist "%ISCC%" (
    echo [HIBA] Nincs telepitve az Inno Setup 6: https://jrsoftware.org/isdl.php
    goto :hiba
)
if exist release rmdir /s /q release
"%ISCC%" /Q /DAppVersion=%VER% build\installer.iss || goto :hiba

echo [4/4] SHA256SUMS.txt...
python build\release_hash.py release || goto :hiba

echo.
echo ============================================================
echo  KESZ: release\ArrabonaGuard_Setup_%VER%.exe + SHA256SUMS.txt
echo  GitHub: Releases - Draft a new release - tag: v%VER%
echo  Mindket fajlt huzd be az "Attach binaries" mezobe!
echo ============================================================
explorer release
pause
exit /b 0

:hiba
echo.
echo *** A build megszakadt (lasd a hibat fent). ***
pause
exit /b 1
