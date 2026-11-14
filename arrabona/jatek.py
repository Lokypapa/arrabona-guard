# -*- coding: utf-8 -*-
"""Arrabona Guard - JATEK MOD (GuardCore mixin). [v2.9.0]

Jatek (vagy teljes kepernyos film) kozben a Guard nem zavar:
  - nincs riasztasi hang es felugro ablak (a Telegram-riasztasok ugyanugy mennek),
  - az AUTOMATIKUS Defender-vizsgalatok (USB, inditopult, uj szolgaltatas...) a
    jatek vegeig varnak, a teljes LAN-kereses szunetel (FPS),
  - a jatek vege utan: osszegzes, az elhalasztott vizsgalatok sorban elindulnak, es
    ha kozben zsarolovirus-gyanu volt, akkor jon a donteskero ablak (a gyanus folyamat
    addig is meg van allitva).
Felismeres (MOD AUTO): a Windows "teljes kepernyos / D3D alkalmazas" jelzese,
VAGY az eloteri ablak a teljes monitort lefedi (keret nelkuli jatekok),
VAGY fut egy, a jatek.txt-ben felsorolt program. Ki/bekapcsolas kesleltetve
(10 / 15 mp), igy az Alt-Tab nem kapcsolgatja.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import os
import threading
import time
from ctypes import wintypes
from .common import (APPDATA_DIR, log_line)

JATEK_CFG_FILE = os.path.join(APPDATA_DIR, "jatek.txt")
JATEK_POLL = 5.0
_BE_KELL = 2      # ennyi egymast koveto eszleles (x 5 mp) utan kapcsol be
_KI_KELL = 3      # ennyi egymast koveto nem-eszleles utan kapcsol ki
_HATTER_OSZTALY = ("Progman", "WorkerW", "Shell_TrayWnd", "Shell_SecondaryTrayWnd")


def jatek_cfg():
    """{"MOD": "AUTO"/"BE"/"KI", "JATEKOK": set(kisbetus exe-nevek)}"""
    cfg = {"MOD": "AUTO", "JATEKOK": set()}
    try:
        if not os.path.exists(JATEK_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(JATEK_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - jatek mod\n"
                        "# MOD AUTO = automatikus (teljes kepernyos alkalmazas / listas jatek) - ajanlott\n"
                        "# MOD BE   = mindig jatek mod (amig vissza nem allitod)\n"
                        "# MOD KI   = soha\n"
                        "MOD AUTO\n"
                        "# Ezek futasa MINDIG jatek modot jelent (ablakos modban is). Egy sor = egy program:\n"
                        "# JATEK GTA5.exe\n"
                        "# JATEK Wow.exe\n")
        with open(JATEK_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                r = ln.strip().split(None, 1)
                if len(r) < 2 or r[0].startswith("#"):
                    continue
                if r[0].upper() == "MOD" and r[1].strip().upper() in ("AUTO", "BE", "KI"):
                    cfg["MOD"] = r[1].strip().upper()
                elif r[0].upper() == "JATEK":
                    cfg["JATEKOK"].add(r[1].strip().lower())
    except Exception:
        pass
    return cfg


def jatek_mod_beallit(mod):
    """A MOD sor atirasa a jatek.txt-ben (a jateklista megmarad)."""
    jatek_cfg()
    try:
        with open(JATEK_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            sorok = f.read().splitlines()
        uj, volt = [], False
        for ln in sorok:
            if ln.strip().upper().startswith("MOD ") and not volt:
                uj.append("MOD %s" % mod)
                volt = True
            elif not ln.strip().upper().startswith("MOD "):
                uj.append(ln)
        if not volt:
            uj.append("MOD %s" % mod)
        with open(JATEK_CFG_FILE, "w", encoding="utf-8") as f:
            f.write("\n".join(uj) + "\n")
        return True
    except OSError:
        return False


class _RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long), ("top", ctypes.c_long), ("right", ctypes.c_long), ("bottom", ctypes.c_long)]


class _MONINFO(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", _RECT), ("rcWork", _RECT), ("dwFlags", wintypes.DWORD)]


def teljes_kepernyo():
    """(igaz?, ok-szoveg, eloteri PID)"""
    pid = None
    try:
        allapot = ctypes.c_int(0)
        if ctypes.windll.shell32.SHQueryUserNotificationState(ctypes.byref(allapot)) == 0:
            # 2 = QUNS_BUSY (teljes kepernyo), 3 = D3D teljes kepernyo, 4 = prezentacios mod
            if allapot.value in (2, 3, 4):
                hwnd = ctypes.windll.user32.GetForegroundWindow()
                p = wintypes.DWORD(0)
                ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
                return True, {2: "teljes képernyő", 3: "Direct3D teljes képernyő",
                              4: "prezentációs mód"}[allapot.value], p.value or None
    except Exception:
        pass
    try:
        u32 = ctypes.windll.user32
        hwnd = u32.GetForegroundWindow()
        if not hwnd:
            return False, "", None
        osztaly = ctypes.create_unicode_buffer(256)
        u32.GetClassNameW(hwnd, osztaly, 256)
        if osztaly.value in _HATTER_OSZTALY:
            return False, "", None
        r = _RECT()
        if not u32.GetWindowRect(hwnd, ctypes.byref(r)):
            return False, "", None
        mon = u32.MonitorFromWindow(hwnd, 2)     # MONITOR_DEFAULTTONEAREST
        mi = _MONINFO()
        mi.cbSize = ctypes.sizeof(_MONINFO)
        if not u32.GetMonitorInfoW(mon, ctypes.byref(mi)):
            return False, "", None
        m = mi.rcMonitor
        if r.left <= m.left and r.top <= m.top and r.right >= m.right and r.bottom >= m.bottom:
            p = wintypes.DWORD(0)
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(p))
            pid = p.value or None
            if pid == os.getpid():
                return False, "", None
            return True, "keret nélküli teljes képernyő", pid
    except Exception:
        pass
    return False, "", pid


def _proc_nev(pid):
    if not pid:
        return ""
    try:
        import psutil
        return psutil.Process(pid).name()
    except Exception:
        return ""


def listas_jatek(nevek):
    if not nevek:
        return ""
    try:
        import psutil
        for p in psutil.process_iter(["name"]):
            n = (p.info.get("name") or "").lower()
            if n in nevek:
                return p.info.get("name")
    except Exception:
        pass
    return ""


class GameModeMixin(object):
    """Jatek mod. A GuardCore resze (mixin)."""

    def game_active(self):
        return bool(getattr(self, "_jatek_on", False))

    def game_info(self):
        """(aktiv, szoveg) a feluletnek."""
        cfg = jatek_cfg()
        if self.game_active():
            return True, "🎮 BE — %s (%s)%s" % (
                getattr(self, "_jatek_ok", "?"), time.strftime("%H:%M", time.localtime(getattr(self, "_jatek_kezdet", 0))),
                (" | csendes riasztás: %d" % self._jatek_alert_n) if getattr(self, "_jatek_alert_n", 0) else "")
        return False, {"AUTO": "automatikus (most nem aktív)", "BE": "BE", "KI": "kikapcsolva"}[cfg["MOD"]]

    def game_note_alert(self):
        if self.game_active():
            self._jatek_alert_n = getattr(self, "_jatek_alert_n", 0) + 1

    def game_defer_scan(self, args, kwargs):
        """Automatikus vizsgalat elhalasztasa a jatek vegeig. (A defender_scan hivja.)"""
        lst = getattr(self, "_jatek_scans", None)
        if lst is None:
            lst = self._jatek_scans = []
        # ugyanazt az utat ne tegyuk be ketszer
        if not any(a[:2] == args[:2] for a, _k in lst):
            lst.append((args, kwargs))
        log_line("[JATEK] automatikus vizsgalat elhalasztva a jatek vegeig: %s" % (args[1] if len(args) > 1 else args))

    def _jatek_eszlel(self, cfg):
        if cfg["MOD"] == "BE":
            return True, "kézzel bekapcsolva"
        if cfg["MOD"] == "KI":
            return False, ""
        nev = listas_jatek(cfg["JATEKOK"])
        if nev:
            return True, nev
        ok, mi, pid = teljes_kepernyo()
        if ok:
            pn = _proc_nev(pid)
            return True, ("%s: %s" % (mi, pn)) if pn else mi
        return False, ""

    def _jatek_loop(self):
        igen = nem = 0
        while not self._jatek_stop_ev.is_set():
            try:
                cfg = jatek_cfg()
                van, ok = self._jatek_eszlel(cfg)
                if van:
                    igen, nem = igen + 1, 0
                else:
                    igen, nem = 0, nem + 1
                kezi = cfg["MOD"] in ("BE", "KI")
                if not self.game_active() and van and (igen >= _BE_KELL or kezi):
                    self._jatek_be(ok)
                elif self.game_active() and not van and (nem >= _KI_KELL or kezi):
                    self._jatek_ki()
                elif self.game_active() and van:
                    self._jatek_ok = ok
                if not self.game_active():
                    self._jatek_halasztott_inditas()
            except Exception as e:
                log_line("[JATEK] hiba: %s" % e)
            self._jatek_stop_ev.wait(JATEK_POLL)

    def _jatek_be(self, ok):
        self._jatek_on = True
        self._jatek_ok = ok
        self._jatek_kezdet = time.time()
        self._jatek_alert_n = 0
        log_line("[JATEK] jatek mod BE (%s)" % ok)
        self.out.put(("status", "🎮 Játék mód BE (%s) — nincs hang és felugró ablak, a vizsgálatok várnak." % ok))

    def _jatek_ki(self):
        self._jatek_on = False
        perc = int((time.time() - getattr(self, "_jatek_kezdet", time.time())) / 60)
        n = getattr(self, "_jatek_alert_n", 0)
        halasztott = len(getattr(self, "_jatek_scans", []) or [])
        log_line("[JATEK] jatek mod KI (%d perc, %d riasztas kozben, %d halasztott vizsgalat)" % (perc, n, halasztott))
        self.out.put(("game_end", {"perc": perc, "alerts": n, "scans": halasztott}))

    def _jatek_halasztott_inditas(self):
        lst = getattr(self, "_jatek_scans", None)
        if not lst or getattr(self, "def_scan_running", None):
            return
        args, kwargs = lst.pop(0)
        kwargs = dict(kwargs)
        lepesek = list(kwargs.get("elozmeny") or [])
        lepesek.append(("Elhalasztva a játék végéig — most indul", time.time()))
        kwargs["elozmeny"] = lepesek
        kwargs["auto"] = False
        try:
            self.defender_scan(*args, **kwargs)
        except Exception as e:
            log_line("[JATEK] halasztott vizsgalat hiba: %s" % e)

    def _jatek_start(self):
        if getattr(self, "_jatek_thread", None) and self._jatek_thread.is_alive():
            return
        self._jatek_on = False
        self._jatek_scans = getattr(self, "_jatek_scans", [])
        jatek_cfg()
        self._jatek_stop_ev = threading.Event()
        self._jatek_thread = threading.Thread(target=self._jatek_loop, name="jatek", daemon=True)
        self._jatek_thread.start()
        log_line("[JATEK] jatek mod figyelese aktiv (mod: %s)" % jatek_cfg()["MOD"])

    def _jatek_stop(self):
        ev = getattr(self, "_jatek_stop_ev", None)
        if ev is not None:
            ev.set()

    def game_set_mode(self, mod):
        mod = (mod or "").upper()
        if mod not in ("AUTO", "BE", "KI"):
            return False, "Hasznalat: /jatek be | ki | auto"
        jatek_mod_beallit(mod)
        return True, "Jatek mod: %s" % {"AUTO": "automatikus", "BE": "BEKAPCSOLVA (amig vissza nem allitod)",
                                          "KI": "kikapcsolva"}[mod]
