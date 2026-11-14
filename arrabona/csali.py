# -*- coding: utf-8 -*-
"""Arrabona Guard - RANSOMWARE-CSAPDA (GuardCore mixin). [v2.5.0]

Csalifajlok ("Jelszavak.xlsx", "Bankszamla_kivonat.pdf"...) kerulnek egy rejtett
"!Arrabona_csali" mappaba a Dokumentumok / Asztal / Kepek / Letoltesek alatt, es
(keresre) a tobbi belso lemez gyokerebe. A "!" miatt a betusorrendben ELSOKENT
kerul sorra, igy a zsarolovirus jellemzoen eloszor ezekhez nyul.
Ember ezekhez nem er hozza - barmilyen modositas / atnevezes / torles / uj fajl
a mappaban = szinte biztosan titkosito kartevo.

Ilyenkor (csali.txt AKCIO):
  FELFUGGESZT (alap) - a gyanus folyamatot MEGALLITJA (szuneteltetes, nem oli meg):
                       te dontesz: Leallitas vagy Folytatas (ablak / Telegram)
  LEALLIT            - azonnal leallitja
  RIASZT             - csak riaszt
A gyanusitott: az a folyamat, amelyik az utolso 2 mp-ben a legtobbet irt a lemezre
(a Windows-alapfolyamatokat, az Intezot es a Defendert soha nem allitja meg).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import hashlib
import json as _json
import os
import random
import threading
import time
import winreg
from .common import (APPDATA_DIR, log_line)

CSALI_CFG_FILE = os.path.join(APPDATA_DIR, "csali.txt")
CSALI_STATE_FILE = os.path.join(APPDATA_DIR, "csali_allapot.json")
CSALI_MAPPA = "!Arrabona_csali"
CSALI_POLL = 2.0

# nev -> (fejlec-bajtok, meret KB)  - valodinak latszo fajlok
_CSALIK = (
    ("Jelszavak_2025.xlsx", b"PK\x03\x04\x14\x00\x06\x00", 38),
    ("Bankszamla_kivonat_2025.pdf", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n", 64),
    ("Szerzodes_vegleges.docx", b"PK\x03\x04\x14\x00\x06\x00", 27),
    ("Csaladi_fotok_001.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", 92),
)
# ezeket SOHA nem allitjuk meg (csak riasztunk)
_VEDETT = {"system", "registry", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
           "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "msmpeng.exe",
           "mpdefendercoreservice.exe", "nissrv.exe", "searchindexer.exe", "searchprotocolhost.exe",
           "searchfilterhost.exe", "onedrive.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
           "runtimebroker.exe", "audiodg.exe", "memory compression", "securityhealthservice.exe"}


def csali_cfg():
    """{"CSAPDA": "BE"/"KI", "AKCIO": "FELFUGGESZT"/"LEALLIT"/"RIASZT", "MEGHAJTOK": "BE"/"KI"}"""
    cfg = {"CSAPDA": "BE", "AKCIO": "FELFUGGESZT", "MEGHAJTOK": "BE"}
    try:
        if not os.path.exists(CSALI_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(CSALI_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - ransomware-csapda\n"
                        "# CSAPDA BE / KI   (KI: a csalimappak is torlodnek a Guard ujrainditasakor)\n"
                        "CSAPDA BE\n"
                        "# AKCIO FELFUGGESZT = a gyanus folyamat megall, te dontesz (ajanlott)\n"
                        "# AKCIO LEALLIT     = azonnali leallitas\n"
                        "# AKCIO RIASZT      = csak riasztas\n"
                        "AKCIO FELFUGGESZT\n"
                        "# MEGHAJTOK BE = a tobbi belso lemez (D:, E:, F:...) gyokerebe is kerul csali\n"
                        "MEGHAJTOK BE\n")
        with open(CSALI_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                r = ln.strip().upper().split()
                if len(r) >= 2 and r[0] in cfg:
                    cfg[r[0]] = r[1]
    except Exception:
        pass
    if cfg["AKCIO"] not in ("FELFUGGESZT", "LEALLIT", "RIASZT"):
        cfg["AKCIO"] = "FELFUGGESZT"
    return cfg


def _shell_folder(nev, alap):
    """A Dokumentumok / Asztal stb. VALODI helye (OneDrive-ra atiranyitva is)."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders") as k:
            v, _t = winreg.QueryValueEx(k, nev)
            v = os.path.expandvars(str(v))
            if v and os.path.isdir(v):
                return v
    except OSError:
        pass
    p = os.path.join(os.path.expanduser("~"), alap)
    return p if os.path.isdir(p) else None


def csali_helyek(meghajtok=True):
    helyek = []
    for nev, alap in (("Personal", "Documents"), ("Desktop", "Desktop"), ("My Pictures", "Pictures"),
                      ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads")):
        p = _shell_folder(nev, alap)
        if p and p not in helyek:
            helyek.append(p)
    if meghajtok:
        try:
            k32 = ctypes.WinDLL("kernel32")
            mask = k32.GetLogicalDrives()
            for i in range(26):
                if (mask >> i) & 1:
                    b = "%s:\\" % chr(65 + i)
                    if b.upper() != "C:\\" and k32.GetDriveTypeW(b) == 3:   # 3 = belso/fix lemez
                        helyek.append(b)
        except Exception:
            pass
    return [os.path.join(h, CSALI_MAPPA) for h in helyek]


def _tartalom(nev, fej, kb):
    """Determinisztikus, valodinak latszo tartalom (a fajlnevbol szamolt magbol)."""
    rnd = random.Random(hashlib.sha256(nev.encode("utf-8")).digest())
    return fej + bytes(rnd.getrandbits(8) for _ in range(kb * 1024 - len(fej)))


def _rejt(p):
    try:
        ctypes.windll.kernel32.SetFileAttributesW(p, 0x02)   # FILE_ATTRIBUTE_HIDDEN
    except Exception:
        pass


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for blokk in iter(lambda: f.read(65536), b""):
            h.update(blokk)
    return h.hexdigest()


class CsaliMixin(object):
    """Ransomware-csapda. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ csalik letrehozasa
    def _csali_telepit(self):
        """Letrehozza / helyreallitja a csalifajlokat. Visszaad: {mappa: {fajl: (hash, meret, mtime)}}."""
        cfg = csali_cfg()
        allapot = {}
        for mappa in csali_helyek(cfg["MEGHAJTOK"] == "BE"):
            try:
                os.makedirs(mappa, exist_ok=True)
                _rejt(mappa)
                fajlok = {}
                for nev, fej, kb in _CSALIK:
                    p = os.path.join(mappa, nev)
                    adat = _tartalom(nev, fej, kb)
                    h = hashlib.sha256(adat).hexdigest()
                    try:
                        jo = os.path.getsize(p) == len(adat) and _sha(p) == h
                    except OSError:
                        jo = False
                    if not jo:
                        with open(p, "wb") as f:
                            f.write(adat)
                    s = os.stat(p)
                    fajlok[nev] = [h, s.st_size, s.st_mtime_ns]
                # a mappaban levo minden mas fajl (pl. korabbi riasztas maradeka) ismertnek szamit
                extra = sorted(set(os.listdir(mappa)) - set(fajlok))
                allapot[mappa] = {"fajlok": fajlok, "extra": extra}
            except OSError as e:
                # pl. Defender "Vezerelt mappahozzaferes" vagy irasvedett lemez
                log_line("[CSAPDA] nem hozhato letre: %s (%s)" % (mappa, e))
        return allapot

    def _csali_torol(self):
        import shutil
        for mappa in csali_helyek(True):
            if os.path.isdir(mappa):
                try:
                    shutil.rmtree(mappa)
                    log_line("[CSAPDA] csalimappa torolve: %s" % mappa)
                except OSError:
                    pass

    # ------------------------------------------------------------ figyeles
    def _csali_valtozas(self):
        """[(mappa, fajl, mi)] - mi: "modositva" / "torolve" / "uj fajl" / "mappa torolve"."""
        talalat = []
        for mappa, a in (self._csali_allapot or {}).items():
            try:
                most = set(os.listdir(mappa))
            except OSError:
                talalat.append((mappa, "", "mappa torolve"))
                continue
            for nev, (h, meret, mt) in a["fajlok"].items():
                p = os.path.join(mappa, nev)
                try:
                    s = os.stat(p)
                except OSError:
                    talalat.append((mappa, nev, "torolve / atnevezve"))
                    continue
                if s.st_size != meret or s.st_mtime_ns != mt:
                    try:
                        if _sha(p) != h:
                            talalat.append((mappa, nev, "MODOSITVA (titkositva?)"))
                    except OSError:
                        talalat.append((mappa, nev, "zarolva / nem olvashato"))
            for uj in sorted(most - set(a["fajlok"]) - set(a.get("extra") or [])):
                talalat.append((mappa, uj, "UJ FAJL (atnevezett csali / valtsagdij-uzenet?)"))
        return talalat

    def _csali_io_pillanat(self):
        """{pid: (irt bajtok, nev, exe)}"""
        try:
            import psutil
        except ImportError:
            return {}
        out = {}
        for p in psutil.process_iter(["pid", "name", "exe", "io_counters"]):
            io = p.info.get("io_counters")
            if io is None:
                continue
            out[p.info["pid"]] = (getattr(io, "write_bytes", 0), p.info.get("name") or "?", p.info.get("exe") or "")
        return out

    def _csali_gyanusitott(self, elozo, most):
        """A ket pillanatkep kozott legtobbet iro folyamatok (csokkeno sorrendben)."""
        sajat = os.getpid()
        lista = []
        for pid, (wb, nev, exe) in most.items():
            if pid in (0, 4, sajat):
                continue
            regi = elozo.get(pid)
            d = (wb - regi[0]) if regi else wb   # uj folyamat: az eddigi osszes irasa
            if d > 0:
                lista.append((d, pid, nev, exe))
        lista.sort(reverse=True)
        return lista[:3]

    def _csali_riaszt(self, talalat):
        cfg = csali_cfg()
        most_io = self._csali_io_pillanat()
        gyanus = self._csali_gyanusitott(self._csali_io or {}, most_io)
        self._csali_io = most_io
        self.csali_hits = getattr(self, "csali_hits", 0) + 1
        helyek = self._csali_osszegzes(talalat)
        akcio_txt = "nincs gyanusitott (nem latszott iras)"
        lepes = None
        if gyanus:
            d, pid, nev, exe = gyanus[0]
            akcio_txt = "Gyanusitott: %s (PID %d, %s) - %.1f MB iras 2 mp alatt" % (
                nev, pid, exe or "?", d / 1048576.0)
            try:
                from .alairas import sig_one, sig_szoveg
                si = sig_one(exe) if exe else None
                if si:
                    akcio_txt += " | Alairas: %s" % sig_szoveg(si, ekezet=False)
            except Exception:
                pass
            if nev.lower() in _VEDETT:
                akcio_txt += " | Windows-/vedett folyamat: NEM allitottam meg"
            elif cfg["AKCIO"] == "RIASZT":
                akcio_txt += " | (csali.txt: AKCIO RIASZT - nem allitottam meg)"
            else:
                lepes = "LEALLIT" if cfg["AKCIO"] == "LEALLIT" else "FELFUGGESZT"
                ok, uz = (self.csali_kill(pid, "automatikus") if lepes == "LEALLIT"
                          else self._csali_suspend(pid, nev, exe))
                akcio_txt += " | %s" % uz
                if not ok:
                    lepes = None
            if len(gyanus) > 1:
                akcio_txt += " | Tovabbi irok: %s" % ", ".join("%s (PID %d, %.1f MB)" % (n, p, dd / 1048576.0)
                                                              for dd, p, n, _e in gyanus[1:])
        msg = ("[CSAPDA] ZSAROLOVIRUS-GYANU! A csalifajlokhoz hozzanyult valami: %s | %s | "
               "Ha nem te voltal: Leallitas (ablak / Telegram /leallit <PID>), utana /scanfull." % (helyek, akcio_txt))
        self.alert("127.0.0.1", msg, always=True)
        self._csali_recent = ([{"ts": time.time(), "hely": helyek, "akcio": akcio_txt}]
                              + list(getattr(self, "_csali_recent", [])))[:10]
        if lepes == "FELFUGGESZT" and gyanus:
            d, pid, nev, exe = gyanus[0]
            try:
                self.out.put(("ransom", {"pid": pid, "name": nev, "exe": exe, "where": helyek, "ts": time.time()}))
            except Exception:
                pass
        # a csapda ujraelesitese (a maradek fajlok bizonyitekkent maradnak: "extra" lesz)
        self._csali_allapot = self._csali_telepit()
        self._csali_save()

    @staticmethod
    def _csali_osszegzes(talalat):
        """Rovid osszegzes: hol, mi tortent, peldak az uj fajlokra (pl. .locked, README...)."""
        def _rov(m):
            r = m.replace("/", "\\").rstrip("\\").rsplit("\\", 2)
            return r[-2] if len(r) >= 2 else m
        mappak = []
        for m, _f, _mi in talalat:
            if _rov(m) not in mappak:
                mappak.append(_rov(m))
        db = {"mod": 0, "tor": 0, "uj": 0, "mappa": 0}
        ujak = []
        for _m, f, mi in talalat:
            if mi.startswith("MODOSITVA") or mi.startswith("zarolva"):
                db["mod"] += 1
            elif mi.startswith("torolve"):
                db["tor"] += 1
            elif mi.startswith("UJ"):
                db["uj"] += 1
                if f not in ujak:
                    ujak.append(f)
            else:
                db["mappa"] += 1
        reszek = []
        if db["mod"]:
            reszek.append("%d csali MODOSITVA" % db["mod"])
        if db["tor"]:
            reszek.append("%d torolve/atnevezve" % db["tor"])
        if db["uj"]:
            reszek.append("%d uj fajl (pl. %s)" % (db["uj"], ", ".join(ujak[:3])))
        if db["mappa"]:
            reszek.append("%d csalimappa torolve" % db["mappa"])
        return "%s - hely: %s" % (", ".join(reszek), ", ".join(mappak[:5]))

    def _csali_suspend(self, pid, nev, exe):
        try:
            import psutil
            psutil.Process(pid).suspend()
        except Exception as e:
            return False, "MEGALLITAS NEM SIKERULT: %s" % e
        sp = getattr(self, "_csali_suspended", None)
        if sp is None:
            sp = self._csali_suspended = {}
        sp[pid] = {"name": nev, "exe": exe, "ts": time.time()}
        log_line("[CSAPDA] folyamat FELFUGGESZTVE: %s (PID %d)" % (nev, pid))
        return True, "FOLYAMAT MEGALLITVA (felfuggesztve) - dontes: Leallitas / Folytatas"

    def csali_kill(self, pid, ki="felulet"):
        """(ok, szoveg)"""
        try:
            import psutil
            pr = psutil.Process(int(pid))
            nev = pr.name()
            if nev.lower() in _VEDETT:
                return False, "%s Windows-folyamat - nem allitom le." % nev
            pr.kill()
        except Exception as e:
            return False, "Leallitas nem sikerult (PID %s): %s" % (pid, e)
        (getattr(self, "_csali_suspended", None) or {}).pop(int(pid), None)
        log_line("[CSAPDA] folyamat LEALLITVA (%s): %s (PID %s)" % (ki, nev, pid))
        return True, "LEALLITVA: %s (PID %s). Ajanlott: teljes Defender-vizsgalat (/scanfull)." % (nev, pid)

    def csali_resume(self, pid, ki="felulet"):
        try:
            import psutil
            pr = psutil.Process(int(pid))
            nev = pr.name()
            pr.resume()
        except Exception as e:
            return False, "Folytatas nem sikerult (PID %s): %s" % (pid, e)
        (getattr(self, "_csali_suspended", None) or {}).pop(int(pid), None)
        log_line("[CSAPDA] folyamat FOLYTATVA (%s): %s (PID %s)" % (ki, nev, pid))
        return True, "Folytatva: %s (PID %s)." % (nev, pid)

    # ------------------------------------------------------------ allapot / ciklus
    def _csali_save(self):
        try:
            tmp = CSALI_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._csali_allapot, f, ensure_ascii=False)
            os.replace(tmp, CSALI_STATE_FILE)
        except OSError:
            pass

    def _csali_loop(self):
        while not self._csali_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    talalat = self._csali_valtozas()
                    if talalat:
                        self._csali_riaszt(talalat)
                    else:
                        # irasi pillanatkep a kovetkezo korhoz (a gyanusitott kivalasztasahoz)
                        self._csali_io = self._csali_io_pillanat()
            except Exception as e:
                log_line("[CSAPDA] figyelo hiba: %s" % e)
            self._csali_stop_ev.wait(CSALI_POLL)

    def _csali_start(self):
        if getattr(self, "_csali_thread", None) and self._csali_thread.is_alive():
            return
        cfg = csali_cfg()
        self.csali_hits = getattr(self, "csali_hits", 0)
        self._csali_recent = getattr(self, "_csali_recent", [])
        self._csali_io = {}
        if cfg["CSAPDA"] != "BE":
            self._csali_torol()
            self.csali_status = "kikapcsolva"
            self._csali_allapot = {}
            log_line("[CSAPDA] kikapcsolva (csali.txt)")
            return
        # a Guard leallasa alatti valtozas: riasztas (de NEM allitunk meg semmit - nem tudni, ki volt)
        try:
            with open(CSALI_STATE_FILE, "r", encoding="utf-8") as f:
                regi = _json.load(f)
            self._csali_allapot = regi if isinstance(regi, dict) else {}
            elozo = self._csali_valtozas()
            if elozo:
                self.alert("127.0.0.1", "[CSAPDA] A Guard leallasa alatt valami hozzanyult a csalifajlokhoz: %s - "
                           "ha nem te voltal, futtass teljes vizsgalatot (/scanfull)!" % "; ".join(
                               "%s: %s" % (f or m, mi) for m, f, mi in elozo[:5]), always=True)
        except (OSError, ValueError):
            pass
        self._csali_allapot = self._csali_telepit()
        self._csali_save()
        self.csali_status = "aktív"
        self._csali_started = time.time()
        self._csali_stop_ev = threading.Event()
        self._csali_thread = threading.Thread(target=self._csali_loop, name="csapda", daemon=True)
        self._csali_thread.start()
        log_line("[CSAPDA] aktiv: %d csalimappa, akcio: %s" % (len(self._csali_allapot), cfg["AKCIO"]))

    def _csali_stop(self):
        ev = getattr(self, "_csali_stop_ev", None)
        if ev is not None:
            ev.set()

    def csali_summary(self):
        if getattr(self, "csali_status", "") == "kikapcsolva":
            return "Kikapcsolva (csali.txt)"
        a = getattr(self, "_csali_allapot", None) or {}
        reszek = ["%d hely, %d csalifájl" % (len(a), sum(len(x["fajlok"]) for x in a.values())),
                  "Akció: %s" % {"FELFUGGESZT": "megállít", "LEALLIT": "leállít", "RIASZT": "csak riaszt"}.get(
                      csali_cfg()["AKCIO"], "?"),
                  "Riasztás: %d" % getattr(self, "csali_hits", 0)]
        sp = getattr(self, "_csali_suspended", None) or {}
        if sp:
            reszek.append("⏸ MEGÁLLÍTVA: %s" % ", ".join("%s (%d)" % (v["name"], p) for p, v in sp.items()))
        return " | ".join(reszek)

    def csali_text(self):
        a = getattr(self, "_csali_allapot", None) or {}
        sorok = ["Ransomware-csapda: %s, akcio: %s" % (getattr(self, "csali_status", "?"), csali_cfg()["AKCIO"])]
        for m in a:
            sorok.append("  %s" % m)
        sp = getattr(self, "_csali_suspended", None) or {}
        for p, v in sp.items():
            sorok.append("MEGALLITVA: %s (PID %d) - /leallit %d vagy /folytat %d" % (v["name"], p, p, p))
        for r in getattr(self, "_csali_recent", [])[:3]:
            sorok.append("%s  %s" % (time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), r["hely"][:150]))
        return "\n".join(sorok)
