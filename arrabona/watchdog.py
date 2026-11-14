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
    """VBS (ujra)irasa + az utemezett feladat letrehozasa, ha hianyzik.
    Visszateres: (ok, uj_feladat_jott_letre)."""
    exe = exe or sys.executable
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
        tartalom = watchdog_vbs_text(exe)
        regi = ""
        try:
            with open(WATCHDOG_VBS, "r", encoding="utf-8", errors="ignore") as f:
                regi = f.read()
        except OSError:
            pass
        if regi.replace("\r\n", "\n") != tartalom.replace("\r\n", "\n"):
            # ANSI (cp1250) kodolas: a wscript nem szereti a BOM nelkuli UTF-8-at
            with open(WATCHDOG_VBS, "w", encoding="cp1250", errors="replace", newline="") as f:
                f.write(tartalom)
    except Exception as e:
        log_line("[ORKUTYA] VBS irasi hiba: %s" % e)
        return (False, False)
    if watchdog_task_exists():
        return (True, False)
    try:
        r = _schtasks(["/create", "/tn", WATCHDOG_TASK,
                       "/tr", 'wscript.exe //B //Nologo "%s"' % WATCHDOG_VBS,
                       "/sc", "minute", "/mo", "2", "/rl", "highest", "/f"])
        if r.returncode == 0:
            return (True, True)
        log_line("[ORKUTYA] feladat letrehozasa SIKERTELEN (kod %s)" % r.returncode)
    except Exception as e:
        log_line("[ORKUTYA] schtasks hiba: %s" % e)
    return (False, False)


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
        """[v1.9.5] Az orkutya feladat meglete. Elso alkalommal csendben
        telepiti; ha kesobb hianyzik (valaki torolte), riaszt es visszaallitja."""
        if not getattr(sys, "frozen", False):
            self.wd_status = "inaktív (nem exe-ből fut)"
            return
        if not self.admin:
            self.wd_status = "nincs admin jog"
            return
        elso = not getattr(self, "_wd_checked", False)
        self._wd_checked = True
        try:
            ok, uj = watchdog_install(sys.executable)
        except Exception as e:
            ok, uj = False, False
            log_line("[ORKUTYA] ellenorzesi hiba: %s" % e)
        if not ok:
            self.wd_status = "HIBA (lásd napló)"
            return
        self.wd_status = "aktív (2 percenként ellenőriz)"
        if elso:
            log_line("[ORKUTYA] %s: %s" % ("feladat letrehozva" if uj else "feladat rendben",
                                           WATCHDOG_TASK))
        elif uj:
            msg = ("[ORKUTYA] Az orkutya utemezett feladata HIANYZOTT (valaki torolte?) "
                   "- visszaallitva.")
            log_line(msg)
            self.alert("127.0.0.1", msg, always=True)
