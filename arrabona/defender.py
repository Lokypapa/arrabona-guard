# -*- coding: utf-8 -*-
"""Arrabona Guard - Windows Defender integracio (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import subprocess
import re
import threading
import time
from .common import (DEF_SIG_MAX_AGE, log_line)


def _mmss(mp):
    """[v2.1.3] 75 -> '01:15', 3725 -> '1:02:05'."""
    mp = max(0, int(mp))
    o, m, s = mp // 3600, (mp % 3600) // 60, mp % 60
    return ("%d:%02d:%02d" % (o, m, s)) if o else ("%02d:%02d" % (m, s))

def scan_allapot(ok):
    """[v2.9.0] defender_scan visszateresi ertekebol riasztas-szoveg."""
    if ok == "HALASZTVA":
        return "a jatek vegeig ELHALASZTVA"
    return "ELINDITVA" if ok else "nem indult (mar fut egy)"


class DefenderMixin(object):
    """Windows Defender integracio.
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""

    # ================= [v1.9.6] WINDOWS DEFENDER INTEGRACIO =================
    _DEF_PS_STATUS = (
        "$ErrorActionPreference='Stop';"
        "$o=@{};"
        "try{$m=Get-MpComputerStatus;"
        "$o.mode=[string]$m.AMRunningMode;$o.av=[bool]$m.AntivirusEnabled;"
        "$o.rt=[bool]$m.RealTimeProtectionEnabled;$o.bm=[bool]$m.BehaviorMonitorEnabled;"
        "$o.tamper=[bool]$m.IsTamperProtected;$o.sigage=[int]$m.AntivirusSignatureAge;"
        "$o.sigver=[string]$m.AntivirusSignatureVersion;"
        "$o.qage=[long]$m.QuickScanAge;$o.fage=[long]$m.FullScanAge}catch{$o.err=$_.Exception.Message};"
        "try{$d=Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard;"
        "$o.hvci=[bool](@($d.SecurityServicesRunning) -contains 2)}catch{$o.hvci=$null};"
        "$o|ConvertTo-Json -Compress")

    def _defender_query(self):
        """Defender + Memoriaintegritas allapota szotarban (hiba eseten 'err')."""
        import json as _json
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                self._DEF_PS_STATUS],
                               capture_output=True, timeout=60,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            txt = (r.stdout or b"").decode("utf-8", errors="ignore").strip()
            i = txt.find("{")
            return _json.loads(txt[i:]) if i >= 0 else {"err": "ures valasz"}
        except Exception as e:
            return {"err": str(e)}

    def _defender_status_check(self):
        st = self._defender_query()
        st["ts"] = time.time()
        elozo = getattr(self, "def_status", None) or {}
        self.def_status = st
        if st.get("err") and "rt" not in st:
            self.def_rt_off = False
            if not elozo.get("err"):
                log_line("[DEFENDER] allapot nem kerdezheto le: %s" % st.get("err"))
            return st
        mode = (st.get("mode") or "").lower()
        aktiv = mode in ("normal", "") or "edr" in mode
        if not aktiv:
            # masik virusirto fut, a Defender passziv: ez nem hiba
            self.def_rt_off = False
            if (elozo.get("mode") or "").lower() != mode:
                log_line("[DEFENDER] passziv mod (%s) - valoszinuleg masik virusirto vedi a gepet" % st.get("mode"))
            return st
        rt = bool(st.get("rt")) and bool(st.get("av", True))
        self.def_rt_off = not rt
        if not rt and (not elozo or elozo.get("rt", True)):
            self.alert("127.0.0.1", "[DEFENDER] A VALOS IDEJU VEDELEM KI VAN KAPCSOLVA! "
                       "Ha nem te kapcsoltad ki, kartevo is lehet mogotte.", always=True)
        elif rt and elozo and elozo.get("rt") is False:
            self.alert("127.0.0.1", "[DEFENDER] A valos ideju vedelem ujra BEKAPCSOLVA.", always=True)
        kor = st.get("sigage")
        if isinstance(kor, int) and kor >= DEF_SIG_MAX_AGE:
            ma = time.strftime("%Y-%m-%d")
            if getattr(self, "_def_sig_alert_day", "") != ma:
                self._def_sig_alert_day = ma
                self.alert("127.0.0.1", "[DEFENDER] A virusdefiniciok %d naposak - frissites ajanlott "
                           "(Telegram: /defupdate)." % kor, always=True)
        if elozo.get("tamper") is True and st.get("tamper") is False:
            self.alert("127.0.0.1", "[DEFENDER] A SZABOTAZSVEDELEM (Tamper Protection) KIKAPCSOLT!", always=True)
        if elozo.get("hvci") is True and st.get("hvci") is False:
            self.alert("127.0.0.1", "[DEFENDER] A MEMORIAINTEGRITAS (HVCI) KIKAPCSOLT!", always=True)
        return st

    @staticmethod
    def _def_path(p):
        """'file:_C:\\x.exe;containerfile:_...' -> 'C:\\x.exe' (tobb ut eseten az elso + db)."""
        if not p:
            return "?"
        darabok = [x for x in p.split(";") if x.strip()]
        tiszta = []
        for d in darabok:
            if ":_" in d:
                d = d.split(":_", 1)[1]
            tiszta.append(d.strip())
        if not tiszta:
            return "?"
        return tiszta[0] + (" (+%d tovabbi)" % (len(tiszta) - 1) if len(tiszta) > 1 else "")

    def _defender_event(self, eid, ev):
        d = self._ev_data(ev)
        fenyegetes = d.get("Threat Name") or "?"
        sulyossag = d.get("Severity Name") or ""
        ut = self._def_path(d.get("Path"))
        folyamat = d.get("Process Name") or ""
        muvelet = d.get("Action Name") or ""
        if eid == "1116":
            self.def_detections = getattr(self, "def_detections", 0) + 1
            msg = "[DEFENDER] KARTEVO ESZLELVE: %s%s - %s%s" % (
                fenyegetes, " (%s)" % sulyossag if sulyossag else "", ut,
                " | folyamat: %s" % folyamat if folyamat and folyamat != "Unknown" else "")
        elif eid == "1117":
            msg = "[DEFENDER] Kartevo kezelve (%s): %s - %s" % (muvelet or "muvelet", fenyegetes, ut)
        elif eid in ("1118", "1119"):
            msg = ("[DEFENDER] A KARTEVOT NEM SIKERULT ELTAVOLITANI! %s - %s (%s). "
                   "Teljes vizsgalat ajanlott: /scanfull" % (fenyegetes, ut, d.get("Error Description") or muvelet or "hiba"))
        elif eid == "5001":
            msg = "[DEFENDER] VALOS IDEJU VEDELEM KIKAPCSOLVA (esemenynaplo 5001)!"
        elif eid in ("5010", "5012"):
            msg = "[DEFENDER] A %s KIKAPCSOLVA (esemeny %s)!" % (
                "KARTEVO-VIZSGALAT" if eid == "5010" else "VIRUSVIZSGALAT", eid)
        elif eid == "5007":
            uj = d.get("New Value") or ""
            if "\\Exclusions\\" not in uj:
                return False   # egyeb beallitas-valtozas: nem riasztunk
            kivetel = uj.split("\\Exclusions\\", 1)[1]
            kivetel = kivetel.rsplit(" = ", 1)[0].strip()
            msg = ("[DEFENDER] UJ KIVETEL A DEFENDERBEN: %s - ha nem te adtad hozza, "
                   "kartevo rejtozkodhet!" % kivetel)
        else:
            return False
        self.alert("127.0.0.1", msg, always=True)
        return True

    def defender_scan(self, tipus="quick", utvonal=None, elozmeny=None, cimke=None, auto=None):
        """Vizsgalat inditasa hatterszalon. False, ha mar fut egy.
        tipus: "quick" / "full" / "custom" (v2.1.0: utvonal, pl. egy pendrive "E:\\").
        elozmeny (v2.1.3): a folyamatpanel korabbi lepesei, pl.
        [("Uj USB-tarolo eszlelve: Kingston", ido), ("Meghajto csatlakoztatva: G:", ido)].
        cimke (v2.2.0): sajat nev a panelre (pl. "Indítópult: valami.exe").
        [v2.2.0] A vizsgalat megszakithato: defender_scan_cancel().
        auto (v2.9.0): automatikus vizsgalat (USB, inditopult...) - jatek mod alatt a
        jatek vegeig var ("HALASZTVA"). Alapbol: custom + elozmeny = automatikus."""
        if auto is None:
            auto = (tipus == "custom" and elozmeny is not None)
        if auto and hasattr(self, "game_active") and self.game_active():
            self.game_defer_scan((tipus, utvonal), {"elozmeny": elozmeny, "cimke": cimke})
            return "HALASZTVA"
        if getattr(self, "def_scan_running", None):
            return False
        if tipus == "custom":
            # csak egyszeru meghajto-/mappa-/fajlutat engedunk (PowerShell-injekcio ellen)
            if not utvonal or not re.match(r"^[A-Za-z]:\\[^'\"`$;|&<>]*$", utvonal):
                return False
            if len(utvonal) <= 3:
                nev = "Meghajtó (%s)" % utvonal.rstrip("\\")
            else:
                nev = "Fájl / mappa (%s)" % utvonal.rstrip("\\").rsplit("\\", 1)[-1][:40]
            parancs = "Start-MpScan -ScanType CustomScan -ScanPath '%s'" % utvonal
            idokorlat = 6 * 3600
        elif tipus == "full":
            nev, parancs, idokorlat = "Teljes", "Start-MpScan -ScanType FullScan", 12 * 3600
        else:
            nev, parancs, idokorlat = "Gyors", "Start-MpScan -ScanType QuickScan", 3 * 3600
        if cimke:
            nev = cimke
        self.def_scan_running = nev
        det0 = getattr(self, "def_detections", 0)
        # [v2.1.3] folyamat-nyilvantartas a felulet folyamatpaneljehez
        t_start = time.time()
        self._def_scan_seq = getattr(self, "_def_scan_seq", 0) + 1
        scan_id = self._def_scan_seq
        self.def_scan_info = {"id": scan_id, "name": nev, "start": t_start, "end": None,
                              "result": None, "ok": None, "steps": list(elozmeny or []),
                              "cancel": False}

        def _kesz(eredm, ok):
            inf = getattr(self, "def_scan_info", None)
            if inf is not None and inf.get("id") == scan_id:
                inf["end"] = time.time(); inf["result"] = eredm; inf["ok"] = ok

        def _fut():
            t0 = t_start
            p = None
            try:
                # [v2.2.0] Popen: a megszakitas le tudja allitani a PowerShellt
                p = subprocess.Popen(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                      parancs],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000))
                self._def_scan_proc = p
                try:
                    _out, err = p.communicate(timeout=idokorlat)
                except subprocess.TimeoutExpired:
                    p.kill()
                    _out, err = p.communicate()
                    err = ("idokorlat (%s) lejart" % _mmss(idokorlat)).encode()
                ido = _mmss(time.time() - t0)
                megszakitva = bool((getattr(self, "def_scan_info", None) or {}).get("cancel"))
                # a vizsgalat soran keletkezett 1116-os esemenyek beolvasasa
                try:
                    self._persist_check()
                except Exception:
                    pass
                uj = getattr(self, "def_detections", 0) - det0
                if megszakitva:
                    eredm = "MEGSZAKITVA (%s utan)" % ido
                    if uj > 0:
                        eredm += ", addig %d ESZLELES - lasd a riasztasokat!" % uj
                    _kesz("Megszakítva %s után%s" % (ido, (" — addig %d ÉSZLELÉS!" % uj) if uj > 0 else
                                                     " — a már átnézett részben nem volt kártevő"),
                          False if uj > 0 else None)
                    self.alert("127.0.0.1", "[DEFENDER] %s vizsgalat %s" % (nev, eredm), always=True)
                elif p.returncode == 0:
                    eredm = ("NINCS uj eszleles" if uj <= 0 else "%d UJ ESZLELES - lasd a riasztasokat!" % uj)
                    _kesz("Nincs kártevő — tiszta" if uj <= 0 else "%d ÉSZLELÉS — lásd a riasztásokat!" % uj, uj <= 0)
                    self.alert("127.0.0.1", "[DEFENDER] %s vizsgalat kesz (%s): %s" % (nev, ido, eredm), always=True)
                else:
                    hiba = (err or b"").decode("utf-8", errors="ignore").strip().splitlines()
                    hiba_txt = (hiba[0] if hiba else "kod %s" % p.returncode)[:200]
                    _kesz("Hiba: " + hiba_txt, None)
                    self.alert("127.0.0.1", "[DEFENDER] %s vizsgalat HIBA: %s" % (nev, hiba_txt), always=True)
            except Exception as e:
                _kesz("Nem futott: %s" % e, None)
                self.alert("127.0.0.1", "[DEFENDER] %s vizsgalat nem futott: %s" % (nev, e), always=True)
            finally:
                self._def_scan_proc = None
                self.def_scan_running = None
                try:
                    self._defender_status_check()
                except Exception:
                    pass
        threading.Thread(target=_fut, name="defender-scan", daemon=True).start()
        log_line("[DEFENDER] %s vizsgalat elinditva" % nev)
        return True

    @staticmethod
    def _mpcmdrun_path():
        """[v2.2.0] A legujabb MpCmdRun.exe (Platform mappa), kulonben a Program Files-beli."""
        import glob
        import os
        jeloltek = []
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        for d in glob.glob(os.path.join(pd, "Microsoft", "Windows Defender", "Platform", "*")):
            exe = os.path.join(d, "MpCmdRun.exe")
            if os.path.isfile(exe):
                jeloltek.append(exe)
        if jeloltek:
            def _ver(x):
                try:
                    return tuple(int(n) for n in os.path.basename(os.path.dirname(x)).split("-")[0].split("."))
                except ValueError:
                    return (0,)
            return max(jeloltek, key=_ver)
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        exe = os.path.join(pf, "Windows Defender", "MpCmdRun.exe")
        return exe if os.path.isfile(exe) else None

    def defender_scan_cancel(self, ki="felulet"):
        """[v2.2.0] A futo vizsgalat megszakitasa. A Defender PowerShell-modulnak
        nincs Stop-MpScan parancsa, ezert: 1) MpCmdRun -Scan -Cancel (ez allitja le
        a Defender motorjaban futo vizsgalatot), 2) a varakozo PowerShell leallitasa.
        Visszaad: (ok, szoveg)."""
        inf = getattr(self, "def_scan_info", None)
        if not getattr(self, "def_scan_running", None) or not inf or inf.get("end"):
            return False, "Nem fut Defender-vizsgálat."
        if inf.get("cancel"):
            return False, "A megszakítás már folyamatban van."
        inf["cancel"] = True
        inf.setdefault("steps", []).append(("Megszakítás kérve (%s)" % ki, time.time()))
        log_line("[DEFENDER] %s vizsgalat megszakitasa kerve (%s)" % (self.def_scan_running, ki))
        mp = self._mpcmdrun_path()
        motor_ok = False
        if mp:
            try:
                r = subprocess.run([mp, "-Scan", "-Cancel"], capture_output=True, timeout=60)
                motor_ok = (r.returncode == 0)
                if not motor_ok:
                    log_line("[DEFENDER] MpCmdRun -Cancel kod: %s %s" % (
                        r.returncode, (r.stdout or b"").decode("utf-8", errors="ignore").strip()[:200]))
            except Exception as e:
                log_line("[DEFENDER] MpCmdRun -Cancel hiba: %s" % e)
        else:
            log_line("[DEFENDER] MpCmdRun.exe nem talalhato - csak a PowerShell all le")
        # ha a Start-MpScan a motor leallitasa utan magatol nem tert vissza, leallitjuk
        p = getattr(self, "_def_scan_proc", None)
        for _ in range(20):
            if p is None or p.poll() is not None:
                break
            time.sleep(0.5)
        if p is not None and p.poll() is None:
            try:
                p.kill()
            except Exception:
                pass
        if motor_ok:
            return True, "Vizsgálat megszakítva."
        return True, ("A Guard leállította a vizsgálat figyelését, de a Defender lehet, hogy "
                      "a háttérben még befejezi (MpCmdRun -Cancel nem sikerült).")

    def defender_update(self):
        if getattr(self, "def_updating", False):
            return False
        self.def_updating = True

        def _fut():
            try:
                r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                                    "Update-MpSignature"], capture_output=True, timeout=1800,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                st = self._defender_status_check()
                if r.returncode == 0:
                    self.alert("127.0.0.1", "[DEFENDER] Definiciofrissites kesz. Verzio: %s, kor: %s nap" % (
                        st.get("sigver", "?"), st.get("sigage", "?")), always=True)
                else:
                    hiba = (r.stderr or b"").decode("utf-8", errors="ignore").strip().splitlines()
                    self.alert("127.0.0.1", "[DEFENDER] Definiciofrissites HIBA: %s" % (
                        (hiba[0] if hiba else "kod %s" % r.returncode)[:200]), always=True)
            except Exception as e:
                self.alert("127.0.0.1", "[DEFENDER] Definiciofrissites nem futott: %s" % e, always=True)
            finally:
                self.def_updating = False
        threading.Thread(target=_fut, name="defender-update", daemon=True).start()
        return True

    def scan_progress(self, latszik=120.0):
        """[v2.1.3] A folyamatpanel adatai: a futo vizsgalat, vagy a legutobbi
        (a vege utan meg 'latszik' mp-ig). None, ha nincs mit mutatni."""
        inf = getattr(self, "def_scan_info", None)
        if not inf:
            return None
        if inf.get("end") and time.time() - inf["end"] > latszik:
            return None
        most = time.time()
        return {"name": inf["name"], "steps": list(inf.get("steps") or []),
                "start": inf["start"], "running": not inf.get("end"),
                "elapsed": _mmss((inf.get("end") or most) - inf["start"]),
                "result": inf.get("result"), "ok": inf.get("ok"),
                "cancel": bool(inf.get("cancel"))}

    def defender_summary(self, rovid=False):
        """Rovid szoveges allapot a kartyara / Telegramra."""
        st = getattr(self, "def_status", None)
        if not st:
            return "lekérdezés…"
        if st.get("err") and "rt" not in st:
            return "nem kérdezhető le (%s)" % str(st.get("err"))[:60]

        def be(x):
            return "?" if x is None else ("BE" if x else "KI")

        def napja(x):
            try:
                x = int(x)
            except (TypeError, ValueError):
                return "?"
            if x >= 100000:
                return "még soha"
            return "ma" if x == 0 else "%d napja" % x
        mode = st.get("mode") or ""
        if mode and mode.lower() not in ("normal",) and "edr" not in mode.lower():
            fej = "Passzív (%s)" % mode
        else:
            fej = "Valós idejű: %s" % be(st.get("rt"))
        reszek = [fej,
                  "Definíciók: %s" % napja(st.get("sigage")),
                  "Memóriaintegritás: %s" % be(st.get("hvci")),
                  "Szabotázsvédelem: %s" % be(st.get("tamper")),
                  "Gyors vizsgálat: %s" % napja(st.get("qage"))]
        if not rovid:
            reszek.append("Teljes vizsgálat: %s" % napja(st.get("fage")))
        if getattr(self, "def_scan_running", None):
            inf = getattr(self, "def_scan_info", None) or {}
            reszek.append("%s vizsgálat FUT… (%s)" % (
                self.def_scan_running, _mmss(time.time() - inf.get("start", time.time()))))
        return " | ".join(reszek)
