# -*- coding: utf-8 -*-
"""Arrabona Guard - INDITOPULT-figyeles (GuardCore mixin). [v2.2.0]

A kartevok legtobbje ugy marad a gepen ujrainditas utan, hogy beirja magat
az indulo programok koze. A Guard 15 mp-enkent atnezi:
  - Run / RunOnce kulcsok (HKCU, HKLM, HKLM 32 bites ag) + Policies\\Explorer\\Run,
  - Winlogon Shell / Userinit (ha ez valtozik, az nagyon gyanus),
  - Indito (Startup) mappak (sajat + minden felhasznaloe).
Minden uj / modosult bejegyzesrol riaszt (a Guard leallasa alatt tortentrol is),
a gyanus mintakat kiemeli (Temp / Letoltesek mappa, rejtett PowerShell, mshta,
script-futtatok, internetes cim a parancsban), es az uj program fajljat
automatikusan atvizsgaltatja a Defenderrel (indulo.txt: AUTOSCAN BE / KI).
Az utemezett feladatokat es szolgaltatasokat a 4698/7045 figyeles mar latja.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import re
import subprocess
import threading
import time
import winreg
from .common import (APPDATA_DIR, REG_NAME, WINDIR, autostart_cmd, log_line)
from .alairas import (sig_check, sig_one, sig_szoveg, sig_veszely)

STARTUP_STATE_FILE = os.path.join(APPDATA_DIR, "indulo_ismert.json")
STARTUP_CFG_FILE = os.path.join(APPDATA_DIR, "indulo.txt")
STARTUP_POLL = 15.0

_W64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
_HKCU, _HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
# (kulcs-nev a riasztashoz, gyoker, ut, csak ezek az ertekek (None = mind))
_REG_HELYEK = (
    ("HKCU\\Run", _HKCU, r"Software\Microsoft\Windows\CurrentVersion\Run", None),
    ("HKCU\\RunOnce", _HKCU, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", None),
    ("HKCU\\Policies\\Run", _HKCU, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", None),
    ("HKLM\\Run", _HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", None),
    ("HKLM\\RunOnce", _HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", None),
    ("HKLM\\Run (32 bit)", _HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", None),
    ("HKLM\\RunOnce (32 bit)", _HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", None),
    ("HKLM\\Policies\\Run", _HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", None),
    ("HKLM\\Winlogon", _HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", ("Shell", "Userinit")),
    ("HKCU\\Winlogon", _HKCU, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ("Shell", "Userinit")),
)
_MAPPAK = (
    ("Indító mappa (saját)", os.path.join(os.environ.get("APPDATA", ""),
                                          r"Microsoft\Windows\Start Menu\Programs\Startup")),
    ("Indító mappa (közös)", os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                                          r"Microsoft\Windows\Start Menu\Programs\StartUp")),
)

# gyanus mintak a parancssorban -> magyar indoklas
_GYANUS = (
    (re.compile(r"\\(temp|tmp)\\", re.I), "Temp mappából indul"),
    (re.compile(r"\\downloads\\|\\letöltések\\", re.I), "a Letöltések mappából indul"),
    (re.compile(r"\\users\\public\\", re.I), "a Public (közös) mappából indul"),
    (re.compile(r"\\programdata\\[^\\]+\.(exe|dll|bat|cmd|vbs|js|ps1|scr)\b", re.I),
     "közvetlenül a ProgramData-ból indul"),
    (re.compile(r"\\appdata\\roaming\\[^\\]+\.(exe|scr|bat|cmd|vbs|js)\b", re.I),
     "közvetlenül az AppData\\Roaming-ból indul"),
    (re.compile(r"powershell[^\n]*\s-(e|en|enc|encodedcommand)\s", re.I), "kódolt PowerShell-parancs"),
    (re.compile(r"powershell[^\n]*-w(indowstyle)?\s+h(idden)?\b", re.I), "rejtett PowerShell-ablak"),
    (re.compile(r"\b(mshta|wscript|cscript|regsvr32|certutil|bitsadmin)(\.exe)?\b", re.I),
     "script-/letöltő Windows-eszközzel indul"),
    (re.compile(r"\brundll32(\.exe)?\b[^\n]*(javascript:|http|\\appdata\\|\\temp\\)", re.I),
     "rundll32 gyanús paraméterrel"),
    (re.compile(r"https?://", re.I), "internetes címet tartalmaz"),
    (re.compile(r"\bcmd(\.exe)?\s+/c\b", re.I), "cmd /c parancsot futtat"),
)
_FAJL = re.compile(r"[A-Za-z]:\\[^\"<>|*?\r\n,]*?\.(exe|dll|sys|bat|cmd|vbs|vbe|js|jse|ps1|scr|com|hta|pif)\b", re.I)
# az alapertelmezett Winlogon-ertekek: ezektol elteres = nagyon gyanus
_WINLOGON_ALAP = {"shell": ("explorer.exe",),
                  "userinit": (os.path.join(WINDIR, "system32", "userinit.exe").lower() + ",",
                               os.path.join(WINDIR, "system32", "userinit.exe").lower(),
                               "userinit.exe,", "userinit.exe")}


def startup_cfg():
    """indulo.txt: AUTOSCAN BE (alap) / KI."""
    mod = "BE"
    try:
        if not os.path.exists(STARTUP_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(STARTUP_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - inditopult-figyeles\n"
                        "# AUTOSCAN BE = az uj indulo program fajljat a Defender azonnal atvizsgalja (ajanlott)\n"
                        "# AUTOSCAN KI = csak riasztas, vizsgalat nincs\n"
                        "AUTOSCAN BE\n")
        with open(STARTUP_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip().upper()
                if ln.startswith("AUTOSCAN"):
                    r = ln.split(None, 1)
                    v = r[1].strip() if len(r) > 1 else "BE"
                    if v in ("BE", "KI", "ON", "OFF"):
                        mod = "KI" if v in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return mod


def _reg_values(gyoker, ut, csak=None):
    """{ertek_nev: szoveg}. None, ha a kulcs nem letezik."""
    try:
        k = winreg.OpenKey(gyoker, ut, 0, winreg.KEY_READ | _W64)
    except OSError:
        return None
    out = {}
    try:
        i = 0
        while True:
            try:
                nev, adat, _t = winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1
            if csak is not None and nev not in csak:
                continue
            if isinstance(adat, (list, tuple)):
                adat = " ".join(str(x) for x in adat)
            elif isinstance(adat, bytes):
                # pl. StartupApproved-szeru binaris: rovid hex
                adat = adat[:32].hex()
            out[nev or "(alapértelmezett)"] = str(adat)
    finally:
        winreg.CloseKey(k)
    return out


def startup_snapshot():
    """{kulcs: {"hely": ..., "nev": ..., "cmd": ...}} - a jelenlegi inditopult."""
    snap = {}
    for hely, gy, ut, csak in _REG_HELYEK:
        vals = _reg_values(gy, ut, csak)
        for nev, cmd in (vals or {}).items():
            snap["%s|%s" % (hely, nev)] = {"hely": hely, "nev": nev, "cmd": cmd}
    for hely, mappa in _MAPPAK:
        try:
            nevek = os.listdir(mappa)
        except OSError:
            continue
        for n in nevek:
            if n.lower() == "desktop.ini":
                continue
            p = os.path.join(mappa, n)
            try:
                s = os.stat(p)
                azon = "%d|%d" % (int(s.st_mtime), s.st_size)
            except OSError:
                azon = "?"
            snap["%s|%s" % (hely, n)] = {"hely": hely, "nev": n, "cmd": p, "azon": azon}
    return snap


def lnk_target(p):
    """Parancsikon celja (PowerShell / WScript.Shell). '' ha nem sikerult."""
    try:
        ut = p.replace("'", "''")
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                            "$s=(New-Object -ComObject WScript.Shell).CreateShortcut('%s');"
                            "$s.TargetPath + ' ' + $s.Arguments" % ut],
                           capture_output=True, timeout=20)
        return (r.stdout or b"").decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def gyanus_okok(cmd):
    okok = []
    for rx, ok in _GYANUS:
        if rx.search(cmd or "") and ok not in okok:
            okok.append(ok)
    return okok


def bejegyzes_okok(e, cel=""):
    """Gyanus jelek egy indulo bejegyzesben (+ Winlogon elteres az alapertelmezettol)."""
    cmd = e.get("cmd") or ""
    okok = gyanus_okok(cel or cmd)
    if e.get("hely", "").endswith("Winlogon"):
        v = cmd.strip().lower()
        alap = _WINLOGON_ALAP.get((e.get("nev") or "").lower(), ())
        if v not in alap and not v.endswith(alap):
            okok.insert(0, "a Winlogon %s értéke eltér az alapértelmezettől" % e.get("nev"))
    return okok


def fajl_a_parancsban(cmd):
    """Az elso vizsgalhato fajl a parancssorban (a Windows sajat futtatoit
    - powershell, rundll32, wscript... - atugorja, ha utana van masik fajl)."""
    cmd = os.path.expandvars(cmd or "")
    jeloltek = [m.group(0).strip() for m in _FAJL.finditer(cmd)]
    rendszer = _norm_dir(os.path.join(WINDIR, "System32")), _norm_dir(os.path.join(WINDIR, "SysWOW64"))
    nem_rendszer = [j for j in jeloltek if not os.path.normcase(j).startswith(rendszer)]
    for j in nem_rendszer + jeloltek:
        if os.path.isfile(j):
            return j
    return None


def _norm_dir(p):
    return os.path.normcase(os.path.normpath(p)) + "\\"


class StartupMixin(object):
    """Inditopult-figyeles. A GuardCore resze (mixin)."""

    def _startup_load(self):
        try:
            with open(STARTUP_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _startup_save(self, d):
        try:
            tmp = STARTUP_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(d, f, ensure_ascii=False, indent=1)
            os.replace(tmp, STARTUP_STATE_FILE)
        except OSError as e:
            log_line("[INDITOPULT] mentesi hiba: %s" % e)

    @staticmethod
    def _startup_sajat(e):
        """A Guard sajat 'Automatikus inditas' bejegyzese (a felulet kapcsoloja allitja)."""
        return e.get("hely") == "HKCU\\Run" and e.get("nev") == REG_NAME and \
            (e.get("cmd") or "").strip().lower() == autostart_cmd().strip().lower()

    def _startup_check(self, indulas=False):
        most = startup_snapshot()
        regi = self._startup_known
        if regi is None:
            self._startup_known = most
            self._startup_save(most)
            log_line("[INDITOPULT] alapallapot: %d indulo bejegyzes ismertnek jelolve" % len(most))
            # az alapallapotban is szolunk, ha mar most gyanus a Winlogon / egy bejegyzes
            try:
                sigs = self.startup_signatures()
            except Exception:
                sigs = {}
            for k0, e in most.items():
                okok = bejegyzes_okok(e)
                s0 = sigs.get(k0)
                if sig_veszely(s0) == 2:
                    okok.insert(0, "ÉRVÉNYTELEN aláírás - a fájlt aláírás után módosították")
                elif okok and s0:
                    okok.append(sig_szoveg(s0, ekezet=False))
                if okok:
                    self.alert("127.0.0.1", "[INDITOPULT] Mar most is GYANUS indulo bejegyzes: %s / %s = %s"
                               " | Gyanus: %s" % (e["hely"], e["nev"], (e.get("cmd") or "")[:300],
                                                  "; ".join(okok)), always=True)
            self.startup_status = "aktív"
            return
        if most == regi:
            self.startup_status = "aktív"
            return
        uj = [k for k in most if k not in regi]
        modosult = [k for k in most if k in regi and (most[k].get("cmd") != regi[k].get("cmd")
                                                       or most[k].get("azon") != regi[k].get("azon"))]
        torolt = [k for k in regi if k not in most]
        self._startup_known = most
        self._startup_save(most)
        for k in uj:
            self._startup_alert("UJ", most[k], None, indulas)
        for k in modosult:
            self._startup_alert("MODOSULT", most[k], regi[k], indulas)
        for k in torolt:
            e = regi[k]
            if "RunOnce" in e["hely"] or (e["hely"] == "HKCU\\Run" and e["nev"] == REG_NAME):
                # a RunOnce bejegyzes lefutas utan magatol torlodik; a sajat kapcsolo sem riasztas
                log_line("[INDITOPULT] torolve: %s / %s" % (e["hely"], e["nev"]))
                continue
            log_line("[INDITOPULT] Indulo bejegyzes TOROLVE: %s / %s (%s)" % (e["hely"], e["nev"], e["cmd"][:200]))
            if e["hely"].endswith("Winlogon") or e["nev"].lower() in ("securityhealth", "windowsdefender"):
                self.alert("127.0.0.1", "[INDITOPULT] FONTOS INDULO BEJEGYZES TOROLVE: %s / %s - "
                           "ha nem te voltal, kartevo kapcsolhatta ki a vedelmet!" % (e["hely"], e["nev"]),
                           always=True)
        self.startup_status = "aktív"

    def _startup_alert(self, mi, e, regi_e, indulas):
        if self._startup_sajat(e):
            log_line("[INDITOPULT] a Guard sajat automatikus inditasa %s" % ("bekapcsolva" if mi == "UJ" else "frissitve"))
            return
        cmd = e.get("cmd") or ""
        cel = ""
        if cmd.lower().endswith(".lnk") and os.path.isfile(cmd):
            cel = lnk_target(cmd)
        teljes = (cmd + (" -> " + cel if cel else ""))
        okok = bejegyzes_okok(e, cel)
        # [v2.4.0] digitalis alairas
        fajl = fajl_a_parancsban(cel or cmd)
        sig = sig_one(fajl) if fajl else None
        veszely = sig_veszely(sig)
        self.startup_changes = getattr(self, "startup_changes", 0) + 1
        self._startup_recent = ([{"ts": time.time(), "mi": mi, "hely": e["hely"], "nev": e["nev"],
                                  "cmd": teljes[:200],
                                  "okok": okok + (["érvénytelen aláírás"] if veszely == 2 else []),
                                  "sig": sig_szoveg(sig, ekezet=False) if sig else ""}]
                                + list(getattr(self, "_startup_recent", [])))[:20]
        fej = "UJ INDULO PROGRAM" if mi == "UJ" else "INDULO BEJEGYZES MODOSULT"
        if veszely == 2 or (okok and veszely >= 1):
            fej = "NAGYON GYANUS " + fej   # gyanus hely/minta + alairatlan / ervenytelen
        elif okok:
            fej = "GYANUS " + fej
        msg = "[INDITOPULT] %s%s: %s / %s = %s" % (
            fej, " (a Guard leallasa alatt)" if indulas else "", e["hely"], e["nev"], teljes[:300])
        if regi_e and regi_e.get("cmd") != cmd:
            msg += " (elotte: %s)" % (regi_e.get("cmd") or "")[:150]
        if sig:
            msg += " | Alairas: %s" % sig_szoveg(sig, ekezet=False)
        if okok:
            msg += " | Gyanus: %s" % "; ".join(okok)
        msg += " | Ha nem te telepitettel most valamit, nezd meg!"
        # automatikus Defender-vizsgalat az uj program fajljara
        if fajl and startup_cfg() == "BE":
            lepesek = [("%s indítópult-bejegyzés: %s (%s)" % ("Új" if mi == "UJ" else "Módosult",
                                                              e["nev"][:40], e["hely"]), time.time()),
                       ("Fájl: %s" % fajl[-70:], time.time())]
            if sig:
                lepesek.append(("Aláírás: %s" % sig_szoveg(sig), time.time()))
            try:
                ok = self.defender_scan("custom", fajl, elozmeny=lepesek,
                                        cimke="Indítópult: %s" % os.path.basename(fajl)[:40])
            except Exception as ex:
                ok = False
                log_line("[INDITOPULT] vizsgalat inditasi hiba: %s" % ex)
            from .defender import scan_allapot
            msg += " | Defender-vizsgalat %s" % scan_allapot(ok)
        if fajl and (veszely >= 1 or okok) and hasattr(self, "vt_kerd"):
            self.vt_kerd(fajl, "Indítópult: %s" % e["nev"][:40])   # [v2.11.0]
        # [v2.10.0] Telegram-gomb: karanten + futo peldany leallitasa
        gombok = None
        try:
            from .telegram import tg_action
            gombok = [[("🗄 Karanténba + leállítás", tg_action("q", "%s|%s" % (e["hely"], e["nev"])))]]
        except Exception:
            pass
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)

    def _startup_loop(self):
        elso = True
        while not self._startup_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    # [v2.3.0] a javitas (karanten) kozben ne fusson: a sajat lepesunkre ne riasszon
                    lk = self._fix_lock() if hasattr(self, "_fix_lock") else None
                    if lk:
                        with lk:
                            self._startup_check(indulas=elso)
                    else:
                        self._startup_check(indulas=elso)
                    elso = False
            except Exception as ex:
                log_line("[INDITOPULT] figyelo hiba: %s" % ex)
            self._startup_stop_ev.wait(STARTUP_POLL)

    def _startup_start(self):
        if getattr(self, "_startup_thread", None) and self._startup_thread.is_alive():
            return
        self._startup_known = self._startup_load()
        self.startup_changes = getattr(self, "startup_changes", 0)
        self.startup_status = "indulás…"
        self._startup_recent = getattr(self, "_startup_recent", [])
        self._startup_started = time.time()
        startup_cfg()
        self._startup_stop_ev = threading.Event()
        self._startup_thread = threading.Thread(target=self._startup_loop, name="startup", daemon=True)
        self._startup_thread.start()
        log_line("[INDITOPULT] figyeles aktiv: Run/RunOnce, Winlogon, Indito mappak (autoscan: %s)" % startup_cfg())

    def _startup_stop(self):
        ev = getattr(self, "_startup_stop_ev", None)
        if ev is not None:
            ev.set()

    def startup_signatures(self):
        """[v2.4.0] {kulcs: alairas-info} az osszes indulo bejegyzesre (kotegelt ellenorzes)."""
        known = getattr(self, "_startup_known", None) or {}
        fajlok = {}
        for k, e in known.items():
            cmd = e.get("cmd") or ""
            cel = lnk_target(cmd) if cmd.lower().endswith(".lnk") and os.path.isfile(cmd) else ""
            fajlok[k] = fajl_a_parancsban(cel or cmd) or (cmd if os.path.isfile(cmd) else None)
        sigs = sig_check([f for f in fajlok.values() if f])
        return {k: (sigs.get(f) if f else None) for k, f in fajlok.items()}

    def startup_summary(self):
        known = getattr(self, "_startup_known", None) or {}
        reszek = ["Indulók: %d" % len(known),
                  "Változás (futam): %d" % getattr(self, "startup_changes", 0)]
        rec = getattr(self, "_startup_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s%s" % (rec[0]["nev"][:24],
                                               time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"])),
                                               " ⚠" if rec[0]["okok"] else ""))
        return " | ".join(reszek)

    def startup_text(self):
        known = getattr(self, "_startup_known", None) or {}
        sorok = ["INDITOPULT: %d bejegyzes (letiltas: /indulotiltas <szam> [kill])" % len(known)]
        hely = None
        try:
            sigs = self.startup_signatures()
        except Exception:
            sigs = {}
        for i, _k, e, okok in self.startup_entries():
            s = sigs.get(_k)
            if sig_veszely(s) == 2:
                okok = okok + ["ervenytelen alairas"]
            elif sig_veszely(s) == 1 and okok:
                okok = okok + ["alairatlan"]
            if e["hely"] != hely:
                hely = e["hely"]
                sorok.append("[%s]" % hely)
            sorok.append("  %d. %s = %s [%s]%s" % (i, e["nev"][:30], (e["cmd"] or "")[:80],
                                                  sig_szoveg(s, ekezet=False) if s else "-",
                                                  "  <-- GYANUS" if okok else ""))
        rec = getattr(self, "_startup_recent", [])
        if rec:
            sorok.append("Legutobbi valtozasok:")
            for r in rec[:5]:
                sorok.append("  %s %s %s / %s%s" % (time.strftime("%m-%d %H:%M", time.localtime(r["ts"])),
                                                    r["mi"], r["hely"], r["nev"][:30],
                                                    "  <-- GYANUS" if r["okok"] else ""))
        return "\n".join(sorok)
