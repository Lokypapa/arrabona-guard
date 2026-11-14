# -*- coding: utf-8 -*-
"""Arrabona Guard - USB-figyeles (GuardCore mixin).

Minden soha nem latott USB-eszkozre riaszt. Kulon kiemeli:
  - BILLENTYUZET: a "BadUSB" (pl. Rubber Ducky) billentyuzetnek adja ki magat,
    es masodpercek alatt parancsokat gepel be,
  - HALOZATI ADAPTER: egy bedugott USB-s halozati kartya atiranyithatja a forgalmat,
  - TAROLO (pendrive, kulso lemez): betujel, nev, meret + automatikus
    Defender-vizsgalat (usb.txt: AUTOSCAN UJ / MIND / KI).
Az eszkozlistat a Windows sajat cfgmgr32 fuggvenyei adjak (PowerShell nelkul,
ezredmasodpercek alatt), igy 3 mp-enkent is gyakorlatilag nulla a terheles.
Elso inditaskor a mar csatlakoztatott eszkozoket ismertnek veszi (alapallapot).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import json as _json
import os
import re
import threading
import time
from .common import (APPDATA_DIR, log_line)
from .defender import scan_allapot

USB_KNOWN_FILE = os.path.join(APPDATA_DIR, "usb_ismert.json")
USB_CFG_FILE = os.path.join(APPDATA_DIR, "usb.txt")
# [v2.1.2] a legutobbi futas meghajtoi: a Guard leallasa alatt bedugott uj
# pendrive is "uj meghajtonak" latszik a kovetkezo inditaskor (-> vizsgalat)
USB_DRIVES_FILE = os.path.join(APPDATA_DIR, "usb_meghajtok.json")
USB_POLL = 3.0
USB_ENUMS = ("USB\\", "USBSTOR\\", "HID\\")

# cfgmgr32 konstansok
_CM_GETIDLIST_FILTER_PRESENT = 0x00000100
_CR_SUCCESS = 0
_CR_BUFFER_SMALL = 0x1A
_CM_DRP_DEVICEDESC = 0x00000001
_CM_DRP_CLASS = 0x00000008
_CM_DRP_MFG = 0x0000000C
_CM_DRP_FRIENDLYNAME = 0x0000000D

# osztaly -> (megjelenitett nev, veszelyszint)  2 = kulon figyelmeztetes
_OSZTALYOK = {
    "keyboard": ("BILLENTYŰZET", 2),
    "net": ("HÁLÓZATI ADAPTER", 2),
    "diskdrive": ("TÁROLÓ", 1),
    # [v2.1.1] a gyors (UAS) pendrive-ok / SSD-k "SCSIAdapter" osztalyban jelennek meg
    "scsiadapter": ("TÁROLÓ (UAS)", 1),
    "wpd": ("TELEFON / HORDOZHATÓ ESZKÖZ", 1),
    "ports": ("SOROS PORT", 1),
    "mouse": ("egér", 0),
    "hidclass": ("HID-eszköz", 0),
    "media": ("hangeszköz", 0),
    "audioendpoint": ("hangeszköz", 0),
    "camera": ("kamera", 0),
    "image": ("kamera / képeszköz", 0),
    "bluetooth": ("Bluetooth", 0),
    "usb": ("USB-vezérlő / hub", 0),
}
_VIDPID = re.compile(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", re.I)


# ---------------------------------------------------------------- Windows API
def _cm():
    c = ctypes.WinDLL("cfgmgr32")
    u = ctypes.c_ulong
    c.CM_Get_Device_ID_List_SizeW.argtypes = [ctypes.POINTER(u), ctypes.c_wchar_p, u]
    c.CM_Get_Device_ID_ListW.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, u, u]
    c.CM_Locate_DevNodeW.argtypes = [ctypes.POINTER(u), ctypes.c_wchar_p, u]
    c.CM_Get_DevNode_Registry_PropertyW.argtypes = [u, u, ctypes.POINTER(u), ctypes.c_wchar_p,
                                                    ctypes.POINTER(u), u]
    return c


def usb_present_ids():
    """A jelenleg csatlakoztatott USB/HID/USBSTOR eszkozpeldanyok azonositoi.
    None, ha a lekerdezes nem sikerult (pl. nem Windows)."""
    try:
        cm = _cm()
    except Exception:
        return None
    for _ in range(3):
        meret = ctypes.c_ulong(0)
        if cm.CM_Get_Device_ID_List_SizeW(ctypes.byref(meret), None, _CM_GETIDLIST_FILTER_PRESENT) != _CR_SUCCESS:
            return None
        buf = ctypes.create_unicode_buffer(meret.value + 64)
        r = cm.CM_Get_Device_ID_ListW(None, buf, meret.value + 64, _CM_GETIDLIST_FILTER_PRESENT)
        if r == _CR_BUFFER_SMALL:
            continue   # kozben valtozott az eszkozlista: ujra
        if r != _CR_SUCCESS:
            return None
        return [x for x in buf[:meret.value + 64].split("\x00")
                if x and x.upper().startswith(USB_ENUMS)]
    return None


def usb_device_props(dev_id):
    """(osztaly, leiras, gyarto) egy eszkozpeldanyhoz."""
    try:
        cm = _cm()
        dn = ctypes.c_ulong(0)
        if cm.CM_Locate_DevNodeW(ctypes.byref(dn), dev_id, 0) != _CR_SUCCESS:
            return ("", "", "")
        out = []
        for prop in (_CM_DRP_CLASS, _CM_DRP_FRIENDLYNAME, _CM_DRP_DEVICEDESC, _CM_DRP_MFG):
            buf = ctypes.create_unicode_buffer(512)
            hossz = ctypes.c_ulong(ctypes.sizeof(buf))
            typ = ctypes.c_ulong(0)
            r = cm.CM_Get_DevNode_Registry_PropertyW(dn.value, prop, ctypes.byref(typ), buf,
                                                     ctypes.byref(hossz), 0)
            out.append(buf.value.strip() if r == _CR_SUCCESS else "")
        osztaly, barat, leiras, gyarto = out
        return (osztaly, barat or leiras, gyarto)
    except Exception:
        return ("", "", "")


def removable_drives():
    """{"E:": {"type": 2, "label": "...", "size_gb": 14.9}, ...} - cserelheto (2)
    es kulso/fix (3) meghajtok; a C: kihagyva."""
    out = {}
    try:
        k32 = ctypes.WinDLL("kernel32")
        # ures kartyaolvaso / kiadott lemez eseten NE ugorjon fel a Windows
        # "Nincs lemez a meghajtoban" ablaka (SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX)
        if not getattr(removable_drives, "_errmode", False):
            k32.SetErrorMode(0x0001 | 0x8000)
            removable_drives._errmode = True
        mask = k32.GetLogicalDrives()
    except Exception:
        return out
    for i in range(26):
        if not (mask >> i) & 1:
            continue
        betu = "%s:" % chr(65 + i)
        if betu == "C:":
            continue
        try:
            t = k32.GetDriveTypeW(betu + "\\")
        except Exception:
            continue
        if t not in (2, 3):
            continue
        nev = ctypes.create_unicode_buffer(261)
        try:
            k32.GetVolumeInformationW(betu + "\\", nev, 261, None, None, None, None, 0)
        except Exception:
            pass
        ossz = ctypes.c_ulonglong(0)
        szabad = ctypes.c_ulonglong(0)
        try:
            k32.GetDiskFreeSpaceExW(betu + "\\", None, ctypes.byref(ossz), ctypes.byref(szabad))
        except Exception:
            pass
        out[betu] = {"type": t, "label": nev.value, "size_gb": round(ossz.value / 1e9, 1),
                     "used_gb": round(max(0, ossz.value - szabad.value) / 1e9, 1)}
    return out


# ---------------------------------------------------------------- segedek
def usb_key(dev_id, osztaly=""):
    """Eszkoz-kulcs: VID:PID + osztaly (igy masik portba dugva sem 'uj').
    Sorozatszam nelkuli eszkoznel a Windows portonkent mas azonositot ad,
    ezert az azonosito utolso reszet nem hasznaljuk."""
    up = dev_id.upper()
    enum = up.split("\\", 1)[0]
    m = _VIDPID.search(up)
    if m:
        alap = "%s:%s" % (m.group(1), m.group(2))
    else:
        reszek = up.split("\\")
        alap = reszek[1] if len(reszek) > 1 else up
        alap = re.sub(r"&REV_[^&\\]*", "", alap)
    return "%s|%s|%s" % (enum, alap, (osztaly or "").lower())


def usb_cfg():
    """usb.txt: AUTOSCAN UJ (alap) / MIND / KI. Letrehozza, ha hianyzik."""
    mod = "UJ"
    try:
        if not os.path.exists(USB_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(USB_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - USB-figyeles\n"
                        "# AUTOSCAN UJ   = Defender-vizsgalat a SOHA NEM LATOTT pendrive-okra (ajanlott)\n"
                        "# AUTOSCAN MIND = minden bedugott pendrive / kulso lemez vizsgalata\n"
                        "# AUTOSCAN KI   = nincs automatikus vizsgalat (riasztas tovabbra is van)\n"
                        "AUTOSCAN UJ\n")
        with open(USB_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip().upper()
                if ln.startswith("AUTOSCAN"):
                    v = ln.split(None, 1)[1].strip() if len(ln.split(None, 1)) > 1 else "UJ"
                    if v in ("UJ", "ÚJ", "MIND", "KI"):
                        mod = "UJ" if v == "ÚJ" else v
    except Exception:
        pass
    return mod


# ---------------------------------------------------------------- mixin
class UsbMixin(object):
    """USB-figyeles. A GuardCore resze (mixin)."""

    def _usb_load_known(self):
        try:
            with open(USB_KNOWN_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _usb_save_known(self, d):
        try:
            tmp = USB_KNOWN_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(d, f, ensure_ascii=False, indent=1)
            os.replace(tmp, USB_KNOWN_FILE)
        except OSError as e:
            log_line("[USB] ismert-lista mentesi hiba: %s" % e)

    def _usb_load_drives(self):
        try:
            with open(USB_DRIVES_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _usb_save_drives(self, d):
        try:
            tmp = USB_DRIVES_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(d, f, ensure_ascii=False)
            os.replace(tmp, USB_DRIVES_FILE)
        except OSError:
            pass

    def _usb_check(self):
        """Egy kor: uj eszkozok + uj meghajtok. Visszaad: uj eszkozcsoportok szama."""
        ids = usb_present_ids()
        if ids is None:
            self.usb_status = "nem elérhető"
            return 0
        known = self._usb_known
        most = time.time()
        if known is None:
            # elso inditas: alapallapot - ami most bent van, az ismert
            known = {}
            for i in ids:
                osz, nev, gy = usb_device_props(i)
                known[usb_key(i, osz)] = {"first": most, "name": nev, "class": osz}
            self._usb_known = known
            self._usb_save_known(known)
            self._usb_drives = removable_drives()
            self._usb_save_drives(self._usb_drives)
            log_line("[USB] alapallapot: %d jelenlegi eszkoz ismertnek jelolve" % len(known))
            self.usb_status = "aktív"
            return 0
        uj_peldany = [i for i in ids if i not in self._usb_seen_ids]
        self._usb_seen_ids = set(ids)
        csoportok = {}   # VID:PID (vagy kulcs) -> [(osztaly, nev, gyarto, kulcs)]
        for i in uj_peldany:
            osz, nev, gy = usb_device_props(i)
            k = usb_key(i, osz)
            if k in known:
                continue
            known[k] = {"first": most, "name": nev, "class": osz}
            csop = k.split("|")[1]
            csoportok.setdefault(csop, []).append((osz, nev, gy, k))
        if csoportok:
            self._usb_save_known(known)
            # [v2.1.2] egy pendrive ket reszkent jelenik meg: USBSTOR (a lemez,
            # VID/PID nelkul) + USB\VID_..&PID_.. (a "USB hattertar" szulo).
            # Ha ugyanabban a korben tarolo is jott, a csak "USB-vezerlo" osztalyu
            # csoportokat beolvasztjuk - igy egy pendrive = egy riasztas.
            def _csak_vezerlo(es):
                return all((e[0] or "").lower() == "usb" for e in es)
            van_tarolo = any(e[3].startswith("USBSTOR") or (e[0] or "").lower() in ("diskdrive", "scsiadapter")
                             for es in csoportok.values() for e in es)
            if van_tarolo and len(csoportok) > 1:
                for kulcs in [k for k, es in csoportok.items() if _csak_vezerlo(es)]:
                    del csoportok[kulcs]
        for csop, elemek in csoportok.items():
            self._usb_alert(csop, elemek)
        # meghajtok
        drives = removable_drives()
        uj_betuk = [b for b in drives if b not in self._usb_drives]
        if set(drives) != set(self._usb_drives):
            self._usb_save_drives(drives)
        self._usb_drives = drives
        if csoportok and any(e[0].lower() in ("diskdrive", "scsiadapter") or e[3].startswith("USBSTOR")
                             for es in csoportok.values() for e in es):
            self._usb_new_storage_until = most + 30   # 30 mp-en belul megjeleno betu = uj tarolo
        uj_tarolo = most < getattr(self, "_usb_new_storage_until", 0)
        for b in uj_betuk:
            self._usb_drive_arrived(b, drives[b], uj_tarolo)
        if uj_betuk and uj_tarolo:
            # az uj tarolo meghajtoja megerkezett: a jelzes elhasznalodik (kulonben
            # 30 mp-ig egy masik, ismert pendrive is "ujnak" latszana)
            self._usb_new_storage_until = 0
        # [v2.4.0] kulso meghajtok: minden cserelheto (pendrive) + ami a Guard futasa
        # alatt jelent meg (kulso USB-lemez); a gep sajat belso lemezei NEM
        self._usb_kulso = ({b for b in getattr(self, "_usb_kulso", set()) if b in drives}
                           | set(uj_betuk) | {b for b, v in drives.items() if v.get("type") == 2})
        try:
            self._usb_proc_check()
        except Exception as e:
            log_line("[USB] folyamat-ellenorzesi hiba: %s" % e)
        self.usb_status = "aktív"
        return len(csoportok)

    def _usb_alert(self, csop, elemek):
        szint = 0
        tipusok = []
        nev = ""
        gyarto = ""
        for osz, n, gy, k in elemek:
            leiras, sz = _OSZTALYOK.get((osz or "").lower(), (osz or "ismeretlen", 0))
            if k.startswith("USBSTOR"):
                leiras, sz = "TÁROLÓ", max(sz, 1)
            szint = max(szint, sz)
            if leiras not in tipusok:
                tipusok.append(leiras)
            if n and (not nev or osz.lower() in ("keyboard", "diskdrive", "scsiadapter", "net")):
                nev = n
            gyarto = gyarto or (gy if gy and not gy.startswith("(") else "")
        tarolo = any(t.startswith("TÁROLÓ") for t in tipusok)
        self.usb_new = getattr(self, "usb_new", 0) + 1
        if tarolo:
            # [v2.1.3] a folyamatpanel elso lepese, ha utana meghajto + vizsgalat jon
            self._usb_last_storage = ("Új USB-tároló észlelve: %s" % (nev or csop)[:60], time.time())
        rec = {"ts": time.time(), "name": nev or csop, "types": tipusok, "id": csop, "level": szint}
        self._usb_recent = ([rec] + list(getattr(self, "_usb_recent", [])))[:20]
        fej = "UJ USB-ESZKOZ"
        if any(t == "BILLENTYŰZET" for t in tipusok):
            fej = "UJ USB-BILLENTYUZET! Ha nem te dugtad be, BadUSB lehet (gepelo tamadoeszkoz)"
        elif any(t == "HÁLÓZATI ADAPTER" for t in tipusok):
            fej = "UJ USB-HALOZATI ADAPTER! Ha nem te dugtad be, a forgalmat elterelheti"
        elif tarolo:
            fej = "UJ USB-TAROLO (pendrive / kulso lemez)"
        msg = "[USB] %s: %s%s - %s (%s)" % (
            fej, nev or "ismeretlen eszkoz", (" / %s" % gyarto) if gyarto else "",
            ", ".join(tipusok), csop)
        self.alert("127.0.0.1", msg, always=True)

    def _usb_proc_check(self):
        """[v2.4.0] Pendrive-rol / kulso lemezrol indult program -> riasztas + alairas,
        alairatlan / ervenytelen fajlnal Defender-vizsgalat."""
        betuk = getattr(self, "_usb_kulso", set())
        if not betuk:
            self._usb_proc_seen = None
            return
        try:
            import psutil
        except ImportError:
            return
        futo = {}
        for p in psutil.process_iter(["pid", "exe", "name"]):
            exe = p.info.get("exe") or ""
            if len(exe) > 2 and exe[:2].upper() in betuk:
                futo[p.info["pid"]] = (exe, p.info.get("name") or os.path.basename(exe))
        seen = getattr(self, "_usb_proc_seen", None)
        if seen is None:
            # elso kor (pl. a Guard indulasakor mar futott): alapallapot
            self._usb_proc_seen = set(futo)
            return
        uj = [pid for pid in futo if pid not in seen]
        self._usb_proc_seen = set(futo)
        utolso = getattr(self, "_usb_proc_last", None)
        if utolso is None:
            utolso = self._usb_proc_last = {}
        most = time.time()
        for pid in uj:
            exe, nev = futo[pid]
            k = exe.lower()
            if most - utolso.get(k, 0) < 600:
                continue     # ugyanaz a program 10 percen belul egyszer
            utolso[k] = most
            from .alairas import sig_one, sig_szoveg, sig_veszely
            sig = sig_one(exe)
            v = sig_veszely(sig)
            fej = ("NAGYON GYANUS - MODOSITOTT (ervenytelen alairasu) PROGRAM INDULT PENDRIVE-ROL" if v == 2 else
                   "ALAIRATLAN PROGRAM INDULT PENDRIVE-ROL" if v == 1 else "PROGRAM INDULT PENDRIVE-ROL")
            msg = "[USB] %s: %s (%s) | Alairas: %s | PID %s" % (fej, nev, exe, sig_szoveg(sig, ekezet=False), pid)
            if v >= 1 and hasattr(self, "vt_kerd"):
                self.vt_kerd(exe, "Pendrive-program: %s" % nev[:40])   # [v2.11.0]
            if v >= 1 and usb_cfg() != "KI":
                lepesek = [("Pendrive-ról indult program: %s" % nev[:50], most),
                           ("Aláírás: %s" % sig_szoveg(sig), most)]
                try:
                    ok = self.defender_scan("custom", exe, elozmeny=lepesek, cimke="USB-program: %s" % nev[:40])
                except Exception as e:
                    ok = False
                    log_line("[USB] vizsgalat inditasi hiba: %s" % e)
                msg += " | Defender-vizsgalat %s" % (scan_allapot(ok))
            self.alert("127.0.0.1", msg, always=True)
        if len(utolso) > 500:
            utolso.clear()

    def _usb_drive_arrived(self, betu, info, uj_tarolo):
        nev = info.get("label") or "nevtelen"
        meret = info.get("size_gb") or 0
        tipus = "pendrive" if info.get("type") == 2 else "kulso lemez"
        mod = usb_cfg()
        vizsgal = (mod == "MIND") or (mod == "UJ" and uj_tarolo)
        szoveg = "[USB] Uj meghajto: %s (%s, '%s', %.1f GB)" % (betu, tipus, nev, meret)
        if vizsgal:
            ok = False
            lepesek = []
            ls = getattr(self, "_usb_last_storage", None)
            if uj_tarolo and ls and time.time() - ls[1] < 120:
                lepesek.append(ls)
            adat = info.get("used_gb")
            lepesek.append(("Meghajtó csatlakoztatva: %s '%s' — %.1f GB%s" % (
                betu, nev, meret, (", ebből %.1f GB adat" % adat) if adat is not None else ""), time.time()))
            try:
                ok = self.defender_scan("custom", betu + "\\", elozmeny=lepesek)
            except Exception as e:
                log_line("[USB] vizsgalat inditasi hiba: %s" % e)
            szoveg += " - Defender-vizsgalat %s" % (scan_allapot(ok))
        if uj_tarolo or vizsgal:
            self.alert("127.0.0.1", szoveg, always=True)
        else:
            log_line(szoveg + " (ismert eszkoz)")

    def _usb_loop(self):
        while not self._usb_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    self._usb_check()
            except Exception as e:
                log_line("[USB] figyelo hiba: %s" % e)
            self._usb_stop_ev.wait(USB_POLL)

    def _usb_start(self):
        if getattr(self, "_usb_thread", None) and self._usb_thread.is_alive():
            return
        self._usb_known = self._usb_load_known()
        ids = usb_present_ids()
        # az indulaskor bent levo peldanyok nem "ujonnan csatlakozottak"
        self._usb_seen_ids = set(ids or [])
        most_drives = removable_drives()
        elozo = self._usb_load_drives() if self._usb_known is not None else None
        # a legutobbi futasbol ismert meghajtok; ami azota jelent meg, az "uj" lesz
        # (ugyanazon a betun MASIK lemez - mas nev vagy meret - is ujnak szamit)
        def _ugyanaz(b, v):
            e = (elozo or {}).get(b)
            return bool(e) and e.get("label") == v.get("label") and \
                abs(float(e.get("size_gb") or 0) - float(v.get("size_gb") or 0)) < 0.5
        self._usb_drives = ({b: v for b, v in most_drives.items() if _ugyanaz(b, v)}
                            if elozo is not None else most_drives)
        if self._usb_known is not None and ids:
            # ami a Guard leallasa alatt kerult be ES meg nem ismert: az is jelezzen
            self._usb_seen_ids = {i for i in ids if usb_key(i, usb_device_props(i)[0]) in self._usb_known}
        self._usb_recent = getattr(self, "_usb_recent", [])
        self._usb_started = time.time()
        usb_cfg()
        self._usb_stop_ev = threading.Event()
        self._usb_thread = threading.Thread(target=self._usb_loop, name="usb", daemon=True)
        self._usb_thread.start()
        log_line("[USB] figyeles aktiv: uj eszkozok (BadUSB / halozati adapter / tarolo), autoscan: %s" % usb_cfg())

    def _usb_stop(self):
        ev = getattr(self, "_usb_stop_ev", None)
        if ev is not None:
            ev.set()

    def usb_summary(self):
        known = getattr(self, "_usb_known", None)
        reszek = ["Ismert: %d" % (len(known) if known else 0),
                  "Új (futam): %d" % getattr(self, "usb_new", 0)]
        rec = getattr(self, "_usb_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s" % (rec[0]["name"][:28], time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"]))))
        reszek.append("Autoscan: %s" % {"UJ": "új pendrive-okra", "MIND": "minden pendrive-ra", "KI": "ki"}.get(usb_cfg(), "?"))
        return " | ".join(reszek)

    def usb_recent_text(self):
        rec = getattr(self, "_usb_recent", [])
        known = getattr(self, "_usb_known", None) or {}
        if not rec:
            return "USB: %d ismert eszkoz, a Guard inditasa ota nem jott uj." % len(known)
        sorok = ["USB: %d ismert eszkoz. Legutobbi uj eszkozok:" % len(known)]
        for r in rec[:10]:
            sorok.append("%s  %s (%s)%s" % (time.strftime("%m-%d %H:%M", time.localtime(r["ts"])),
                                           r["name"][:40], ", ".join(r["types"]),
                                           "  <-- FIGYELEM" if r.get("level", 0) >= 2 else ""))
        return "\n".join(sorok)
