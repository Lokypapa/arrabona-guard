# -*- coding: utf-8 -*-
"""Arrabona Guard - Egykattintasos javitas (GuardCore mixin). [v2.3.0]

  - INDITOPULT: barmely bejegyzes KARANTENBA teheto (letiltas). Semmi nem vesz el:
      * registry-ertek -> elmentjuk (nev, tipus, ertek), majd toroljuk,
      * Indito mappa fajlja -> a karanten mappaba kerul (.karanten vegzodessel),
      * HKLM Winlogon Shell / Userinit -> visszaall az alapertelmezettre
        (ezt TOROLNI tilos, a Windows nem indulna el rendesen).
    Kerheto a futo peldany leallitasa is (Windows-mappabeli programot soha).
    Barmikor visszaallithato: quarantine_restore().
  - HOSTS: visszaallitas az elozo valtozatra vagy a Windows alapertelmezettjere.
    Csere tortenik: a mostani tartalom lesz az "elozo", igy a visszaallitas is
    visszacsinalhato. Atiranyitott DataBasePath eseten azt is helyreallitja.
Karanten: %APPDATA%\\ArrabonaGuard\\karanten\\ (karanten.json + fajlok)
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import shutil
import stat
import subprocess
import threading
import time
import winreg
from .common import (APPDATA_DIR, WINDIR, log_line)
from .startup import (_REG_HELYEK, _W64, bejegyzes_okok, fajl_a_parancsban, lnk_target,
                      startup_snapshot)
from .hosts import (HOSTS_BACKUP_FILE, HOSTS_COPY_FILE, _DEFAULT_DB, _TCPIP_KEY, _norm,
                    hosts_dir, hosts_parse)

KARANTEN_DIR = os.path.join(APPDATA_DIR, "karanten")
KARANTEN_FILE = os.path.join(KARANTEN_DIR, "karanten.json")

_HOSTS_ALAP = (
    "# Copyright (c) 1993-2009 Microsoft Corp.\r\n"
    "#\r\n"
    "# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n"
    "#\r\n"
    "# (Arrabona Guard: visszaallitva az alapertelmezett allapotra)\r\n"
    "#\r\n"
    "# localhost name resolution is handled within DNS itself.\r\n"
    "#\t127.0.0.1       localhost\r\n"
    "#\t::1             localhost\r\n").encode("ascii")
_WINLOGON_ALAPERTEK = {"Shell": "explorer.exe",
                       "Userinit": os.path.join(WINDIR, "system32", "userinit.exe") + ","}
_VEDETT_NEVEK = ("securityhealth", "windowsdefender")


def _hely_reg(hely):
    for h, gy, ut, _csak in _REG_HELYEK:
        if h == hely:
            return gy, ut
    return None, None


def _windows_fajl(p):
    w = os.path.normcase(os.path.normpath(WINDIR)) + os.sep
    return os.path.normcase(os.path.normpath(p or "")).startswith(w)


def stop_processes(exe):
    """A megadott exe minden futo peldanyanak leallitasa. Visszaad: leallitott db (-1 = hiba)."""
    if not exe or _windows_fajl(exe):
        return 0
    ut = exe.replace("'", "''")
    ps = ("$n=0; Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.Path -ieq '%s' } | "
          "ForEach-Object { try { Stop-Process -Id $_.Id -Force -ErrorAction Stop; $n++ } catch {} }; $n" % ut)
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                           capture_output=True, timeout=30)
        return int(((r.stdout or b"").decode("utf-8", errors="ignore").strip().splitlines() or ["0"])[-1])
    except Exception:
        return -1


class FixMixin(object):
    """Karanten + hosts-visszaallitas. A GuardCore resze (mixin)."""

    def _fix_lock(self):
        lk = getattr(self, "_fix_lock_obj", None)
        if lk is None:
            lk = self._fix_lock_obj = threading.RLock()
        return lk

    # ------------------------------------------------------------ karanten-nyilvantartas
    def quarantine_list(self):
        try:
            with open(KARANTEN_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, list) else []
        except (OSError, ValueError):
            return []

    def _quarantine_save(self, lst):
        os.makedirs(KARANTEN_DIR, exist_ok=True)
        tmp = KARANTEN_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(lst, f, ensure_ascii=False, indent=1)
        os.replace(tmp, KARANTEN_FILE)

    def _startup_resync(self):
        """A sajat modositas utan az ismert allapot frissitese (ne riasszon a sajat lepesunkre)."""
        try:
            most = startup_snapshot()
            self._startup_known = most
            self._startup_save(most)
        except Exception as e:
            log_line("[JAVITAS] inditopult-ujraolvasasi hiba: %s" % e)

    # ------------------------------------------------------------ inditopult
    def startup_entries(self):
        """A mostani inditopult rendezett listaja: [(sorszam, kulcs, bejegyzes, okok)].
        Ugyanez a sorszam szerepel a Telegram /indulo listajaban."""
        known = getattr(self, "_startup_known", None) or {}
        out = []
        for i, k in enumerate(sorted(known, key=lambda x: (known[x]["hely"], known[x]["nev"].lower())), 1):
            out.append((i, k, known[k], bejegyzes_okok(known[k])))
        return out

    def startup_find(self, mi):
        """Sorszam vagy nev (kis/nagybetu mindegy) -> kulcs. None, ha nincs / tobb is van."""
        mi = (mi or "").strip()
        lst = self.startup_entries()
        if mi.isdigit():
            for i, k, _e, _o in lst:
                if i == int(mi):
                    return k
            return None
        talalat = [k for _i, k, e, _o in lst if e["nev"].lower() == mi.lower()]
        return talalat[0] if len(talalat) == 1 else None

    def startup_disable(self, kulcs, leallit=False, ki="felulet"):
        """Bejegyzes karantenba tetele. Visszaad: (ok, szoveg)."""
        with self._fix_lock():
            known = getattr(self, "_startup_known", None) or {}
            e = known.get(kulcs)
            if not e:
                return False, "Nincs ilyen indulo bejegyzes (kozben megvaltozhatott - frissits)."
            hely, nev, cmd = e["hely"], e["nev"], e.get("cmd") or ""
            if nev.lower() in _VEDETT_NEVEK:
                return False, "A(z) %s a Windows biztonsagi osszetevoje - ezt a Guard nem tiltja le." % nev
            lst = self.quarantine_list()
            # rovid, egyedi azonosito (Telegramon is kenyelmes): HHNNoopp-n
            alap = time.strftime("%m%d%H%M")
            letezo = {r.get("id") for r in lst}
            n = 1
            while "%s-%d" % (alap, n) in letezo:
                n += 1
            rec = {"id": "%s-%d" % (alap, n),
                   "ts": time.time(), "hely": hely, "nev": nev, "cmd": cmd, "ki": ki}
            # a futo peldany fajlja (a parancsikon celjabol is)
            cel = lnk_target(cmd) if cmd.lower().endswith(".lnk") and os.path.isfile(cmd) else ""
            exe = fajl_a_parancsban(cel or cmd)
            try:
                if hely.startswith("Indító mappa"):
                    os.makedirs(KARANTEN_DIR, exist_ok=True)
                    cel_ut = os.path.join(KARANTEN_DIR, "%s_%s.karanten" % (rec["id"], os.path.basename(cmd)))
                    shutil.move(cmd, cel_ut)
                    rec.update({"tipus": "fajl", "eredeti": cmd, "karanten": cel_ut})
                    muvelet = "athelyezve a karantenba"
                else:
                    gy, ut = _hely_reg(hely)
                    if gy is None:
                        return False, "Ismeretlen hely: %s" % hely
                    with winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE | _W64) as k:
                        vnev = "" if nev == "(alapértelmezett)" else nev
                        ertek, tipus = winreg.QueryValueEx(k, vnev)
                        rec.update({"tipus": "reg", "regtipus": tipus, "ertek": ertek, "vnev": vnev})
                        if hely == "HKLM\\Winlogon" and nev in _WINLOGON_ALAPERTEK:
                            winreg.SetValueEx(k, vnev, 0, winreg.REG_SZ, _WINLOGON_ALAPERTEK[nev])
                            rec["tipus"] = "winlogon"
                            muvelet = "visszaallitva az alapertelmezettre (%s)" % _WINLOGON_ALAPERTEK[nev]
                        else:
                            winreg.DeleteValue(k, vnev)
                            muvelet = "torolve a registrybol (mentve a karantenba)"
            except PermissionError:
                return False, ("Nincs jogosultsag (%s). A HKLM-es bejegyzesekhez es a kozos Indito mappahoz "
                               "rendszergazdakent kell futnia a Guardnak." % hely)
            except OSError as ex:
                return False, "Nem sikerult: %s" % ex
            lst.insert(0, rec)
            try:
                self._quarantine_save(lst)
            except OSError as ex:
                log_line("[JAVITAS] karanten-mentesi hiba: %s" % ex)
            self._startup_resync()
            szoveg = "%s / %s %s." % (hely, nev, muvelet)
            if leallit and exe:
                if _windows_fajl(exe):
                    szoveg += " A futo peldanyt nem allitottam le (Windows-program: %s)." % os.path.basename(exe)
                else:
                    n = stop_processes(exe)
                    szoveg += (" Futo peldany leallitva: %d db." % n if n > 0 else
                               " Nem futott belole peldany." if n == 0 else " A leallitas nem sikerult.")
            log_line("[JAVITAS] INDITOPULT KARANTEN (%s): %s | parancs: %s" % (ki, szoveg, cmd[:200]))
            self.alert("127.0.0.1", "[JAVITAS] Indulo bejegyzes karantenba teve (%s): %s Visszaallitas: "
                       "Javitas ablak / Telegram /visszaallit %s" % (ki, szoveg, rec["id"]), always=True)
            return True, szoveg

    def quarantine_restore(self, qid, ki="felulet"):
        with self._fix_lock():
            lst = self.quarantine_list()
            rec = next((r for r in lst if r.get("id") == str(qid)), None)
            if not rec:
                return False, "Nincs ilyen karanten-tetel: %s" % qid
            try:
                if rec["tipus"] == "fajl":
                    if os.path.exists(rec["eredeti"]):
                        return False, "Az eredeti helyen mar van fajl: %s" % rec["eredeti"]
                    os.makedirs(os.path.dirname(rec["eredeti"]), exist_ok=True)
                    shutil.move(rec["karanten"], rec["eredeti"])
                else:
                    gy, ut = _hely_reg(rec["hely"])
                    if gy is None:
                        return False, "Ismeretlen hely: %s" % rec["hely"]
                    with winreg.CreateKeyEx(gy, ut, 0, winreg.KEY_SET_VALUE | _W64) as k:
                        winreg.SetValueEx(k, rec.get("vnev", rec["nev"]), 0, int(rec.get("regtipus", winreg.REG_SZ)),
                                          rec["ertek"])
            except PermissionError:
                return False, "Nincs jogosultsag - rendszergazdakent kell futnia a Guardnak."
            except (OSError, KeyError) as ex:
                return False, "Nem sikerult: %s" % ex
            lst = [r for r in lst if r.get("id") != rec["id"]]
            try:
                self._quarantine_save(lst)
            except OSError:
                pass
            self._startup_resync()
            szoveg = "%s / %s visszaallitva." % (rec["hely"], rec["nev"])
            log_line("[JAVITAS] KARANTENBOL VISSZAALLITVA (%s): %s" % (ki, szoveg))
            self.out.put(("status", szoveg))
            return True, szoveg

    def quarantine_text(self):
        lst = self.quarantine_list()
        if not lst:
            return "A karanten ures."
        sorok = ["Karanten (%d tetel) - visszaallitas: /visszaallit <azonosito>" % len(lst)]
        for r in lst[:20]:
            sorok.append("%s  %s  %s / %s" % (r["id"], time.strftime("%m-%d %H:%M", time.localtime(r["ts"])),
                                              r["hely"], r["nev"][:40]))
        return "\n".join(sorok)

    # ------------------------------------------------------------ hosts
    def hosts_restore(self, mod="elozo", ki="felulet"):
        """mod: "elozo" (hosts_elozo.txt) vagy "alap" (Windows alapertelmezett). (ok, szoveg)"""
        with self._fix_lock():
            if mod == "alap":
                uj = _HOSTS_ALAP
                honnan = "a Windows alapertelmezett hosts fajljara"
            else:
                try:
                    with open(HOSTS_BACKUP_FILE, "rb") as f:
                        uj = f.read()
                except OSError:
                    return False, "Nincs elmentett elozo valtozat (hosts_elozo.txt). Hasznald az alapertelmezettet."
                honnan = "az elozo valtozatra"
            reszek = []
            # atiranyitott hosts-hely helyreallitasa
            if _norm(hosts_dir()) != _norm(_DEFAULT_DB):
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_KEY, 0,
                                        winreg.KEY_SET_VALUE | _W64) as k:
                        winreg.SetValueEx(k, "DataBasePath", 0, winreg.REG_EXPAND_SZ,
                                          r"%SystemRoot%\System32\drivers\etc")
                    reszek.append("a hosts HELYE (DataBasePath) visszaallitva")
                except OSError as ex:
                    return False, "A hosts helyet nem sikerult visszaallitani: %s" % ex
            ut = os.path.join(_DEFAULT_DB, "hosts")
            try:
                with open(ut, "rb") as f:
                    regi = f.read()
            except OSError:
                regi = b""
            try:
                if os.path.exists(ut):
                    os.chmod(ut, stat.S_IREAD | stat.S_IWRITE)   # irasvedett attributum le
                with open(ut, "wb") as f:
                    f.write(uj)
            except PermissionError:
                return False, ("Nincs jogosultsag a hosts irasahoz - rendszergazdakent kell futnia a Guardnak "
                               "(vagy a Defender / egy masik program zarolja).")
            except OSError as ex:
                return False, "A hosts irasa nem sikerult: %s" % ex
            # csere: a mostani (rossz) lesz az elozo -> a visszaallitas is visszacsinalhato
            try:
                with open(HOSTS_BACKUP_FILE, "wb") as f:
                    f.write(regi)
                with open(HOSTS_COPY_FILE, "wb") as f:
                    f.write(uj)
            except OSError:
                pass
            self._hosts_state = {"hash": hashlib.sha256(uj).hexdigest(), "entries": hosts_parse(uj),
                                 "exists": True, "path": ut, "ts": time.time()}
            self._hosts_save_state(self._hosts_state)
            try:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=20)
                reszek.append("DNS-gyorsitotar uritve")
            except Exception:
                pass
            szoveg = "Hosts visszaallitva %s (%d bejegyzes)%s." % (
                honnan, len(self._hosts_state["entries"]), ("; " + ", ".join(reszek)) if reszek else "")
            log_line("[JAVITAS] HOSTS VISSZAALLITVA (%s): %s" % (ki, szoveg))
            self.alert("127.0.0.1", "[JAVITAS] %s Visszacsinalas: ujra 'elozo valtozat' visszaallitas." % szoveg,
                       always=True)
            return True, szoveg
