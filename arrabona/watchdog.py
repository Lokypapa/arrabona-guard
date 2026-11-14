# -*- coding: utf-8 -*-
"""Arrabona Guard - Orkutya: utemezett feladat + VBS, ami ujrainditja a Guardot, ha leall."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import datetime
import os
import subprocess
import sys
import time
from .common import (
    APPDATA_DIR,
    HEARTBEAT_FILE,
    QUIT_FLAG,
    WATCHDOG_TASK,
    WATCHDOG_VBS,
    log_line,
)

# ----------------------- [v1.9.5] Orkutya (watchdog) -----------------------
# Egy utemezett feladat 2 percenkent lefuttat egy apro VBS-t (wscript: nincs
# felvillano ablak). Ha a Guard nem fut, es NEM a felhasznalo lepett ki
# (kilepes.flag), ujrainditja "--watchdog" kapcsoloval. Az igy indult Guard
# Telegramon jelzi, hogy le volt allva. Exe nelkul (sima .py futtatas) inaktiv.

def _vbs_str(x):
    return '"' + str(x).replace('"', '""') + '"'


def watchdog_vbs_text(exe):
    import ntpath
    nev = ntpath.basename(exe).replace("\\", "").replace("'", "\\'")
    return "\r\n".join([
        "' Arrabona Guard orkutya - 2 percenkent ellenorzi, fut-e a Guard.",
        "' Automatikusan generalt fajl, a Guard minden inditaskor ujrairja.",
        "Option Explicit",
        "Dim fso, sh, wmi, procs, exe, flag",
        "exe = " + _vbs_str(exe),
        "flag = " + _vbs_str(QUIT_FLAG),
        "Set fso = CreateObject(\"Scripting.FileSystemObject\")",
        "If fso.FileExists(flag) Then WScript.Quit 0",
        "If Not fso.FileExists(exe) Then WScript.Quit 0",
        "Set wmi = GetObject(\"winmgmts:{impersonationLevel=impersonate}!\\\\.\\root\\cimv2\")",
        "Set procs = wmi.ExecQuery(\"SELECT ProcessId FROM Win32_Process WHERE Name = '" + nev + "'\")",
        "If procs.Count = 0 Then",
        "  Set sh = CreateObject(\"WScript.Shell\")",
        "  sh.Run \"\"\"\" & exe & \"\"\" --watchdog\", 7, False",
        "End If",
        ""])


def _schtasks(args, timeout=20):
    return subprocess.run(["schtasks"] + args, capture_output=True, timeout=timeout,
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def watchdog_task_exists():
    try:
        return _schtasks(["/query", "/tn", WATCHDOG_TASK]).returncode == 0
    except Exception:
        return False


def watchdog_install(exe=None):
    """[v2.18.2] Az orkutya feladatat es a watchdog.vbs-t a TELEPITO hozza letre
    (tools\\watchdog.vbs). A Guard maga mar nem ir feladatot / VBS-t: aláíratlan programtol
    ez a Defender szemeben "megkapaszkodas" (Behavior:Win32/Persistence), es torli az exe-t.
    Visszateres: (megvan_a_feladat, False)."""
    return (watchdog_task_exists(), False)


def quit_flag_set():
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
        with open(QUIT_FLAG, "w", encoding="utf-8") as f:
            f.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    except Exception:
        pass


def quit_flag_clear():
    try:
        if os.path.exists(QUIT_FLAG):
            os.remove(QUIT_FLAG)
    except Exception:
        pass


def heartbeat_write():
    try:
        with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except Exception:
        pass


def heartbeat_read():
    try:
        with open(HEARTBEAT_FILE, "r", encoding="utf-8") as f:
            return float(f.read().strip() or 0)
    except Exception:
        return 0.0


class WatchdogMixin(object):
    """Orkutya-ellenorzes a fo ciklusbol.
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""

    def _watchdog_check(self):
        """[v1.9.5 / v2.18.2] Az orkutya feladat meglete. A feladatot a telepito hozza letre;
        ha hianyzik (vagy kesobb eltunik - valaki torolte), riaszt, es a telepito
        ujrafuttatasat keri (maga nem allitja vissza, lasd watchdog_install)."""
        if not getattr(sys, "frozen", False):
            self.wd_status = "inaktív (nem exe-ből fut)"
            return
        try:
            van, _ = watchdog_install(sys.executable)
        except Exception as e:
            van = False
            log_line("[ORKUTYA] ellenorzesi hiba: %s" % e)
        elso = not getattr(self, "_wd_checked", False)
        self._wd_checked = True
        if van:
            self._wd_volt = True
            self._wd_hiany_jelezve = False
            self.wd_status = "aktív (2 percenként ellenőriz)"
            if elso:
                log_line("[ORKUTYA] feladat rendben: %s" % WATCHDOG_TASK)
            return
        self.wd_status = "NINCS BEÁLLÍTVA - futtasd újra a telepítőt"
        if elso:
            log_line("[ORKUTYA] a(z) '%s' feladat hianyzik - a telepito ujrafuttatasa letrehozza" % WATCHDOG_TASK)
        if getattr(self, "_wd_volt", False) and not getattr(self, "_wd_hiany_jelezve", False):
            self._wd_hiany_jelezve = True
            msg = ("[ORKUTYA] Az orkutya utemezett feladata ELTUNT (valaki torolte?). "
                   "Visszaallitas: futtasd ujra az Arrabona Guard telepitojet.")
            log_line(msg)
            self.alert("127.0.0.1", msg, always=True)
