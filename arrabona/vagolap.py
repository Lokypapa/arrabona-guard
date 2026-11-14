# -*- coding: utf-8 -*-
"""Arrabona Guard - VAGOLAP-VEDELEM ("clipper" kartevok ellen) (GuardCore mixin). [v2.14.0]

A "clipper" kartevo a hatterben figyeli a vagolapot: ha kriptotarca-cimet vagy
bankszamlaszamot (IBAN) masolsz, egy pillanat alatt kicsereli a SAJATJARA, es
a beillesztett cimre kuldott penz a csalohoz megy.

A Guard 0,25 mp-enkent nezi a vagolap valtozas-szamlalojat (ez szinte semmi
terhelest nem jelent). Ha egy masolt cim / IBAN 3 mp-en belul egy MASIK cimre
cserelodik, es ezt nem az az ablak tette, amelyikbol masoltal:
  - az EREDETI cimet azonnal visszaallitja a vagolapra,
  - a cserelo folyamatot (ha azonosithato) megallitja - te dontesz,
  - riaszt (ablak + Telegram).
Felismert cimek: Bitcoin, Ethereum / BSC / Polygon (0x...), Litecoin, Dogecoin,
Tron, Monero, Bitcoin Cash, Solana (+ egyeb base58), IBAN (ellenorzo osszeggel).
A vagolap tartalmat SEHOVA nem kuldi el es nem menti: a riasztasban is csak
a cim eleje-vege szerepel.

vagolap.txt: FIGYELES BE/KI, VISSZAALLIT BE/KI, AKCIO FELFUGGESZT/LEALLIT/RIASZT,
KIVETEL <program.exe> (pl. vagolap-kezelo).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import os
import re
import threading
import time
from .common import (APPDATA_DIR, log_line)

VAGOLAP_CFG_FILE = os.path.join(APPDATA_DIR, "vagolap.txt")
POLL = 0.25
ABLAK = 3.0                    # ennyi mp-en belul tortent csere szamit gyanusnak
CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002

_B58 = "1-9A-HJ-NP-Za-km-z"
_TIPUSOK = (
    ("Bitcoin", re.compile(r"^(bc1[ac-hj-np-z02-9]{11,71}|[13][%s]{25,34})$" % _B58)),
    ("Ethereum/BSC (0x)", re.compile(r"^0x[a-fA-F0-9]{40}$")),
    ("Litecoin", re.compile(r"^(ltc1[ac-hj-np-z02-9]{11,71}|[LM][%s]{26,33})$" % _B58)),
    ("Dogecoin", re.compile(r"^D[5-9A-HJ-NP-U][%s]{32}$" % _B58)),
    ("Tron", re.compile(r"^T[%s]{33}$" % _B58)),
    ("Monero", re.compile(r"^[48][0-9AB][%s]{93}$" % _B58)),
    ("Bitcoin Cash", re.compile(r"^(bitcoincash:)?[qp][a-z0-9]{41}$")),
    ("Solana / base58", re.compile(r"^[%s]{32,44}$" % _B58)),
)
_IBAN = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$")
# vagolap-kezelok, jelszokezelok, tavoli asztal / virtualis gep: ezek legitim modon irjak at
_KIVETEL = {"ditto.exe", "clipboardfusion.exe", "clipclip.exe", "clipx.exe", "textinputhost.exe",
            "rdpclip.exe", "vmtoolsd.exe", "vboxtray.exe", "keepass.exe", "keepassxc.exe", "bitwarden.exe",
            "1password.exe", "dashlane.exe", "nordpass.exe", "teamviewer.exe", "anydesk.exe", "parsec.exe"}


def iban_ok(s):
    s = s.replace(" ", "").upper()
    if not _IBAN.match(s):
        return False
    t = s[4:] + s[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in t)) % 97 == 1
    except ValueError:
        return False


def cim_tipus(szoveg):
    """A vagolap szovegebol: (tipus, normalt_cim) vagy None."""
    if not szoveg:
        return None
    t = szoveg.strip()
    if len(t) > 120 or len(t) < 15 or "\n" in t:
        return None
    if iban_ok(t):
        return ("IBAN", t.replace(" ", "").upper())
    if " " in t:
        return None
    for nev, rx in _TIPUSOK:
        if rx.match(t):
            if nev == "Solana / base58" and not (re.search(r"\d", t) and re.search(r"[a-z]", t)
                                                 and re.search(r"[A-Z]", t)):
                return None   # sima szo / azonosito, nem cim
            return (nev, t)
    return None


def rovid(c):
    return c if len(c) <= 14 else "%s…%s" % (c[:6], c[-6:])


def vagolap_cfg():
    cfg = {"FIGYELES": "BE", "VISSZAALLIT": "BE", "AKCIO": "FELFUGGESZT", "KIVETEL": set()}
    try:
        if not os.path.exists(VAGOLAP_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(VAGOLAP_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - vagolap-vedelem (v2.14.0)\n"
                        "# Kriptotarca-cim / IBAN kicserelese a vagolapon (clipper kartevo)\n"
                        "FIGYELES BE\n"
                        "# VISSZAALLIT BE = az eredeti cimet azonnal visszarakja a vagolapra\n"
                        "VISSZAALLIT BE\n"
                        "# A cserelo programmal: FELFUGGESZT (megallitja, te dontesz) / LEALLIT / RIASZT\n"
                        "AKCIO FELFUGGESZT\n"
                        "# KIVETEL <program.exe> = ez a program atirhatja (pl. sajat vagolap-kezelo)\n")
        with open(VAGOLAP_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip() if len(r) > 1 else "")
                if k == "KIVETEL" and v:
                    cfg["KIVETEL"].add(os.path.basename(v).lower())
                elif k == "AKCIO" and v.upper() in ("FELFUGGESZT", "LEALLIT", "RIASZT"):
                    cfg["AKCIO"] = v.upper()
                elif k in ("FIGYELES", "VISSZAALLIT") and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg[k] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


class _Vagolap(object):
    """Win32 vagolap-hivasok (64 bites handle-ok helyes tipusokkal)."""

    def __init__(self):
        from ctypes import wintypes as W
        u = ctypes.WinDLL("user32", use_last_error=True)
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        u.GetClipboardSequenceNumber.restype = W.DWORD
        u.OpenClipboard.argtypes = [W.HWND]
        u.OpenClipboard.restype = W.BOOL
        u.CloseClipboard.restype = W.BOOL
        u.EmptyClipboard.restype = W.BOOL
        u.GetClipboardData.argtypes = [W.UINT]
        u.GetClipboardData.restype = W.HANDLE
        u.SetClipboardData.argtypes = [W.UINT, W.HANDLE]
        u.SetClipboardData.restype = W.HANDLE
        u.IsClipboardFormatAvailable.argtypes = [W.UINT]
        u.IsClipboardFormatAvailable.restype = W.BOOL
        u.GetClipboardOwner.restype = W.HWND
        u.GetForegroundWindow.restype = W.HWND
        u.GetWindowThreadProcessId.argtypes = [W.HWND, ctypes.POINTER(W.DWORD)]
        u.GetWindowThreadProcessId.restype = W.DWORD
        k.GlobalLock.argtypes = [W.HGLOBAL]
        k.GlobalLock.restype = ctypes.c_void_p
        k.GlobalUnlock.argtypes = [W.HGLOBAL]
        k.GlobalUnlock.restype = W.BOOL
        k.GlobalAlloc.argtypes = [W.UINT, ctypes.c_size_t]
        k.GlobalAlloc.restype = W.HGLOBAL
        k.GlobalFree.argtypes = [W.HGLOBAL]
        k.GlobalFree.restype = W.HGLOBAL
        self.u, self.k, self.W = u, k, W

    def seq(self):
        return int(self.u.GetClipboardSequenceNumber())

    def _pid(self, hwnd):
        if not hwnd:
            return 0
        p = self.W.DWORD(0)
        self.u.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
        return int(p.value)

    def owner_pid(self):
        return self._pid(self.u.GetClipboardOwner())

    def fg_pid(self):
        return self._pid(self.u.GetForegroundWindow())

    def _open(self):
        for _ in range(10):
            if self.u.OpenClipboard(None):
                return True
            time.sleep(0.02)
        return False

    def text(self):
        """A vagolap szovege (None, ha nem szoveg / nem nyithato meg)."""
        if not self.u.IsClipboardFormatAvailable(CF_UNICODETEXT):
            return None
        if not self._open():
            return None
        try:
            h = self.u.GetClipboardData(CF_UNICODETEXT)
            if not h:
                return None
            p = self.k.GlobalLock(h)
            if not p:
                return None
            try:
                return ctypes.wstring_at(p)[:4096]
            finally:
                self.k.GlobalUnlock(h)
        finally:
            self.u.CloseClipboard()

    def set_text(self, s):
        data = ctypes.create_unicode_buffer(s)
        n = ctypes.sizeof(data)
        h = self.k.GlobalAlloc(GMEM_MOVEABLE, n)
        if not h:
            return False
        p = self.k.GlobalLock(h)
        if not p:
            self.k.GlobalFree(h)
            return False
        ctypes.memmove(p, data, n)
        self.k.GlobalUnlock(h)
        if not self._open():
            self.k.GlobalFree(h)
            return False
        try:
            self.u.EmptyClipboard()
            if not self.u.SetClipboardData(CF_UNICODETEXT, h):
                self.k.GlobalFree(h)
                return False
            return True        # siker utan a memoria a rendszere, nem szabaditjuk fel
        finally:
            self.u.CloseClipboard()


def _pnev(pid):
    if not pid:
        return "", ""
    try:
        import psutil
        p = psutil.Process(pid)
        nev = p.name()
        try:
            exe = p.exe()
        except Exception:
            exe = ""
        return nev, exe
    except Exception:
        return "", ""


class VagolapMixin(object):
    """Vagolap-vedelem. A GuardCore resze (mixin)."""

    def _vg_dontes(self, elozo, uj, owner, fg):
        """Visszaad: szint (0 = rendben, 2 = gyanus (ismeretlen cserelo), 3 = kritikus)."""
        if owner and owner == elozo["owner"]:
            return 0           # ugyanaz az ablak/program masolt ujra (pl. listabol egymas utan)
        onev, _oexe = _pnev(owner)
        if onev.lower() in _KIVETEL or onev.lower() in self._vg_cfg["KIVETEL"]:
            return 0
        if owner and owner in getattr(self, "_fy_own", {os.getpid()}):
            return 0
        if owner and owner == fg:
            return 0           # az eloterben levo ablakbol masoltal (ember)
        fnev = _pnev(fg)[0].lower()
        if fnev in ("applicationframehost.exe",):
            return 0           # UWP-alkalmazas: az ablak es a masolo folyamat kulon PID
        if owner:
            return 3           # egy HATTERBEN futo program irta at
        return 2               # nem azonosithato, ki irta at (ablak nelkuli iras)

    def _vg_eset(self, elozo, uj, owner, fg, szint):
        cfg = self._vg_cfg
        most = time.time()
        onev, oexe = _pnev(owner)
        fnev, _fexe = _pnev(fg)
        vissza = ""
        if cfg["VISSZAALLIT"] == "BE":
            if most - self._vg_vissza_ts > 30:
                self._vg_vissza_ts, self._vg_vissza_db = most, 0
            if self._vg_vissza_db < 3:
                self._vg_vissza_db += 1
                if self._vg_cb.set_text(elozo["szoveg"]):
                    self._vg_sajat_seq = self._vg_cb.seq()
                    vissza = "Az EREDETI cimet visszaallitottam a vagolapra."
                else:
                    vissza = "A visszaallitas NEM sikerult - NE illeszd be, masold ujra!"
            else:
                vissza = "Tobbszor is kicserelte - NE illeszd be, amig a program fut!"
        akcio = ""
        d = None
        if szint >= 3 and owner:
            try:
                import psutil
                d = {"pid": owner, "name": onev or "?", "exe": oexe, "ctime": psutil.Process(owner).create_time(),
                     "cmd": ""}
            except Exception:
                d = None
            if d and cfg["AKCIO"] == "FELFUGGESZT" and hasattr(self, "_fy_suspend"):
                _ok, akcio = self._fy_suspend(d)
            elif d and cfg["AKCIO"] == "LEALLIT" and hasattr(self, "folyamat_kill"):
                ok, sz = self.folyamat_kill(owner, d["ctime"], ki="vagolap-vedelem")
                akcio = "LEALLITVA" if ok else "LEALLITAS NEM SIKERULT: " + sz
            elif cfg["AKCIO"] == "RIASZT":
                akcio = "(vagolap.txt: AKCIO RIASZT - nem allitottam meg)"
        with self._vg_lock:
            self.vagolap_hits += 1
            self._vg_recent = ([{"ts": most, "szint": szint, "tipus": elozo["tipus"], "regi": rovid(elozo["cim"]),
                                 "uj": rovid(uj["cim"]), "prog": onev or "?", "pid": owner, "akcio": akcio}]
                               + self._vg_recent)[:20]
        fej = "CIMCSERELO KARTEVO (CLIPPER)" if szint >= 3 else "GYANUS VAGOLAP-CSERE"
        msg = ("[VAGOLAP] %s: a masolt %s cimet (%s) %.1f mp mulva kicserelte erre: %s | Cserelo: %s | "
               "Eloterben: %s" % (fej, elozo["tipus"], rovid(elozo["cim"]), uj["ts"] - elozo["ts"], rovid(uj["cim"]),
                                  ("%s (PID %s)" % (onev, owner)) if owner else "nem azonosithato (ablak nelkul irt)",
                                  fnev or "?"))
        if oexe:
            msg += " | Ut: %s" % oexe[:200]
        msg += " | " + vissza
        if akcio:
            msg += " | " + akcio
        msg += " | Utalas elott MINDIG ellenorizd a beillesztett cim elejet ES veget!"
        if szint < 3:
            msg += " Ha te masoltad az ujat (pl. Win+V elozmenybol), masold ujra."
        gombok = []
        try:
            from .telegram import tg_action
            from .folyamat import windows_fajl
            if d:
                ct = int(d["ctime"] or 0)
                if "FELFUGGESZTVE" in akcio:
                    gombok.append([("⛔ Leállítás + teljes vizsgálat", "pk:%s:%d:full" % (owner, ct)),
                                   ("▶ Folytatás (én voltam)", "pr:%s:%d" % (owner, ct))])
                elif "LEALLITVA" not in akcio:
                    gombok.append([("⛔ Leállítás", "pk:%s:%d" % (owner, ct))])
                if oexe and not windows_fajl(oexe):
                    gombok.append([("🗄 Karanténba (fájl)", tg_action("pq", {"pid": owner, "ctime": ct, "fajl": oexe}))])
            gombok.append([("🛡 Teljes vizsgálat", "sf")])
            gombok.append([("✅ Rendben / én voltam", "ok")])
        except Exception:
            gombok = None
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)
        if "FELFUGGESZTVE" in akcio:
            try:
                self.out.put(("ransom", {"tipus": "folyamat", "pid": owner, "ctime": d["ctime"], "name": onev,
                                         "exe": oexe, "cmd": "", "szulo": "",
                                         "where": "Kicserélte a vágólapon a(z) %s címet (%s → %s)" % (
                                             elozo["tipus"], rovid(elozo["cim"]), rovid(uj["cim"])),
                                         "ts": most}))
            except Exception:
                pass
        if szint >= 3 and oexe and os.path.isfile(oexe):
            try:
                self.defender_scan("custom", oexe, elozmeny=[("Vágólap-csere: %s" % onev, most)],
                                   cimke="Clipper: %s" % (onev or "?")[:40])
            except Exception:
                pass
            if hasattr(self, "vt_kerd"):
                try:
                    self.vt_kerd(oexe, "Clipper: %s" % onev[:40])
                except Exception:
                    pass

    def _vg_loop(self):
        try:
            self._vg_cb = _Vagolap()
        except Exception as e:
            self.vagolap_status = "nem elérhető"
            log_line("[VAGOLAP] nem indul: %s" % e)
            return
        cb = self._vg_cb
        utolso_seq = cb.seq()
        elozo = None          # utolso masolt CIM: {"szoveg","tipus","cim","owner","ts"}
        utolso_cfg = 0.0
        self.vagolap_status = "aktív"
        while not self._vg_stop_ev.wait(POLL):
            try:
                most = time.time()
                if most - utolso_cfg >= 30:
                    utolso_cfg = most
                    self._vg_cfg = vagolap_cfg()
                if self._vg_cfg["FIGYELES"] != "BE":
                    self.vagolap_status = "kikapcsolva (vagolap.txt)"
                    utolso_seq = cb.seq()
                    continue
                if not self.is_on() or self.is_paused():
                    utolso_seq = cb.seq()
                    continue
                self.vagolap_status = "aktív"
                s = cb.seq()
                if s == utolso_seq:
                    continue
                utolso_seq = s
                if s == self._vg_sajat_seq:
                    continue            # a sajat visszaallitasunk
                owner = cb.owner_pid()
                fg = cb.fg_pid()
                szoveg = cb.text()
                ct = cim_tipus(szoveg)
                if not ct:
                    elozo = None
                    continue
                self.vagolap_cimek += 1
                uj = {"szoveg": szoveg, "tipus": ct[0], "cim": ct[1], "owner": owner, "ts": most}
                if elozo and uj["cim"] != elozo["cim"] and (most - elozo["ts"]) <= ABLAK:
                    szint = self._vg_dontes(elozo, uj, owner, fg)
                    if szint:
                        self._vg_eset(elozo, uj, owner, fg, szint)
                        continue        # az elozo (eredeti) marad az osszehasonlitas alapja
                    log_line("[VAGOLAP] cim-csere 3 mp-en belul, de rendben (%s, ugyanabbol / az eloterbol)" %
                             _pnev(owner)[0])
                elozo = uj
            except Exception as e:
                log_line("[VAGOLAP] figyelo hiba: %s" % e)
                self._vg_stop_ev.wait(5.0)

    def _vagolap_start(self):
        if getattr(self, "_vg_thread", None) and self._vg_thread.is_alive():
            return
        self._vg_cfg = vagolap_cfg()
        self._vg_lock = threading.Lock()
        self._vg_recent = getattr(self, "_vg_recent", [])
        self._vg_sajat_seq = -1
        self._vg_vissza_ts, self._vg_vissza_db = 0.0, 0
        self.vagolap_hits = getattr(self, "vagolap_hits", 0)
        self.vagolap_cimek = 0
        self.vagolap_status = "indulás…"
        self._vg_stop_ev = threading.Event()
        self._vg_thread = threading.Thread(target=self._vg_loop, name="vagolap", daemon=True)
        self._vg_thread.start()
        log_line("[VAGOLAP] vagolap-vedelem aktiv (visszaallitas: %s, akcio: %s)" % (
            self._vg_cfg["VISSZAALLIT"], self._vg_cfg["AKCIO"]))

    def _vagolap_stop(self):
        ev = getattr(self, "_vg_stop_ev", None)
        if ev is not None:
            ev.set()

    def vagolap_summary(self):
        reszek = [getattr(self, "vagolap_status", "?") if getattr(self, "vagolap_status", "") != "aktív"
                  else "Másolt cím (futam): %d" % getattr(self, "vagolap_cimek", 0),
                  "Csere-riasztás: %d" % getattr(self, "vagolap_hits", 0)]
        rec = getattr(self, "_vg_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s ⚠" % (rec[0]["prog"][:18],
                                               time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"]))))
        return " | ".join(reszek)

    def vagolap_text(self):
        sorok = ["VAGOLAP-VEDELEM: %s" % self.vagolap_summary().replace(" | ", ", ")]
        rec = getattr(self, "_vg_recent", [])
        if rec:
            for r in rec[:10]:
                sorok.append("  %s %s: %s -> %s | %s (PID %s)%s" % (
                    time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), r["tipus"], r["regi"], r["uj"],
                    r["prog"], r["pid"] or "-", (" | " + r["akcio"][:50]) if r["akcio"] else ""))
        else:
            sorok.append("Meg nem volt cim-csere.")
        return "\n".join(sorok)
