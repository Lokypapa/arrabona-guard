# -*- coding: utf-8 -*-
"""Arrabona Guard - ARRABONA PASS ERTESITESEK (GuardCore mixin). [v2.21.0]

Az Arrabona Pass (jelszokezelo, v1.11.0-tol) a sajat mappajaba esemenynaplot ir
(%APPDATA%\\ArrabonaPass\\esemenyek.jsonl): sikertelen feloldasi probalkozasok, feloldas,
mesterjelszo-csere, visszaallitas, tomeges torles. A naploban NINCS titok (jelszo,
bejegyzesnev), csak hogy mi tortent, mikor, melyik gepen.

A Guard 3 mp-enkent megnezi, es az uj esemenyeket a szokasos riasztaskent (Telegram is)
kuldi, "🔒 Pass zarolasa" gombbal. A gomb (vagy a /passzar parancs) a
Local\\ArrabonaPass_Lock Windows-esemenyt jelzi: a futo Pass erre azonnal zarol, es
nyugtazza. Igy legfeljebb zarolni lehet tavolrol, feloldani nem.

Ha a Guard nem futott, a kozben keletkezett esemenyeket indulaskor egy osszesitoben kuldi.
A Pass Telegram-kulcsot nem kap: a bot kulcsa csak a Guardnal van.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import sys
import threading
import time
from .common import APPDATA_DIR, log_line

ROAMING = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
PASS_MAPPA = os.path.join(ROAMING, "ArrabonaPass")
ESEMENY_FILE = os.path.join(PASS_MAPPA, "esemenyek.jsonl")
ALLAPOT_FILE = os.path.join(APPDATA_DIR, "pass_esemenyek.json")
LOCK_EVENT = "Local\\ArrabonaPass_Lock"
POLL = 3.0
OSSZESITO = 4            # ennel tobb fuggo esemeny -> egyetlen osszesito uzenet
ELSO_INDULAS_VISSZA = 86400.0   # elso inditaskor legfeljebb 1 napra visszamenoleg
UTOLAGOS = 600.0         # 10 percnel regebbi esemeny: "utolag" (a Guard nem futott)

_IKON = {"unlock_fail": "⚠", "unlock": "🔓", "master_changed": "🔑", "restored": "↩",
         "mass_delete": "🗑"}
_GOMB = [[("🔒 Pass zárolása", "pl")]]


# ---------------------------------------------------------------- Windows-esemeny
def _k32():
    import ctypes
    from ctypes import c_bool, c_uint32, c_void_p, c_wchar_p
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.OpenEventW.restype = c_void_p
    k.OpenEventW.argtypes = [c_uint32, c_bool, c_wchar_p]
    k.SetEvent.restype = c_bool
    k.SetEvent.argtypes = [c_void_p]
    k.CloseHandle.argtypes = [c_void_p]
    return k


def pass_fut():
    """Fut-e az Arrabona Pass (a zarolasi esemenyt a futo Pass hozza letre)."""
    if sys.platform != "win32":
        return False
    try:
        k = _k32()
        h = k.OpenEventW(0x00100000, False, LOCK_EVENT)      # SYNCHRONIZE
        if not h:
            return False
        k.CloseHandle(h)
        return True
    except Exception:
        return False


def _jelez():
    if sys.platform != "win32":
        return False
    try:
        k = _k32()
        h = k.OpenEventW(0x0002, False, LOCK_EVENT)          # EVENT_MODIFY_STATE
        if not h:
            return False
        try:
            return bool(k.SetEvent(h))
        finally:
            k.CloseHandle(h)
    except Exception:
        return False


# ---------------------------------------------------------------- naplo
def esemenyek(utan=0.0):
    """A Pass esemenyei ts szerint, csak az 'utan' idopont utaniak."""
    out = []
    try:
        with open(ESEMENY_FILE, "r", encoding="utf-8", errors="replace") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    e = _json.loads(ln)
                    ts = float(e.get("ts", 0))
                except (ValueError, TypeError, AttributeError):
                    continue
                if ts >= utan and isinstance(e.get("event"), str):
                    e["ts"] = ts
                    out.append(e)
    except OSError:
        pass
    out.sort(key=lambda e: e["ts"])
    return out


def _szoveg(e, rovid=False):
    ikon = _IKON.get(e.get("event"), "•")
    txt = str(e.get("text") or e.get("event"))[:300]
    if rovid:
        return "%s %s  (%s)" % (ikon, txt, str(e.get("time", ""))[5:16])
    return "%s %s | Gép: %s | %s" % (ikon, txt, str(e.get("computer", "?"))[:40], e.get("time", ""))


class PassErtesitesMixin(object):
    """GuardCore resze: az Arrabona Pass esemenyeinek tovabbitasa + tavoli zarolas."""

    # ------------------------------------------------------------ allapot
    def _pe_load(self):
        try:
            with open(ALLAPOT_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
            return float(d.get("ts", 0)), set(d.get("ids", []))
        except Exception:
            return time.time() - ELSO_INDULAS_VISSZA, set()

    def _pe_save(self):
        try:
            with open(ALLAPOT_FILE, "w", encoding="utf-8") as f:
                _json.dump({"ts": self._pe_ts, "ids": sorted(self._pe_ids)}, f)
        except OSError:
            pass

    # ------------------------------------------------------------ feldolgozas
    def _pe_uj(self):
        """Az uj (meg nem kuldott) esemenyek; az allapotot is lepteti."""
        uj = [e for e in esemenyek(self._pe_ts) if e.get("id") not in self._pe_ids]
        if not uj:
            return []
        utolso = max(e["ts"] for e in uj)
        self._pe_ids = {e.get("id") for e in uj if e["ts"] == utolso} | \
            ({i for i in self._pe_ids} if utolso == self._pe_ts else set())
        self._pe_ts = utolso
        self._pe_save()
        return uj

    def _pe_kuld(self, uj):
        uj = [e for e in uj if e.get("event") != "remote_lock"]   # nyugta: a gomb valaszaba megy
        if not uj:
            return
        with self._pe_lock:
            self.pass_esemenyek = ([e for e in reversed(uj)] + self.pass_esemenyek)[:20]
            self.pass_riasztas += len(uj)
        most = time.time()
        utolag = any(most - e["ts"] > UTOLAGOS for e in uj)
        if len(uj) > OSSZESITO or (utolag and len(uj) > 1):
            sorok = [_szoveg(e, rovid=True) for e in uj[-15:]]
            fej = "[ARRABONA PASS] %d esemény%s:" % (
                len(uj), " (amíg a Guard nem futott)" if utolag else "")
            if len(uj) > 15:
                fej += " (az utolsó 15)"
            msg = fej + "\n" + "\n".join(sorok) + "\nHa nem te voltál: zárold a Passt, és cserélj mesterjelszót!"
            self.alert("127.0.0.1", msg, always=True, gombok=_GOMB)
            return
        for e in uj:
            msg = "[ARRABONA PASS] " + _szoveg(e)
            if utolag:
                msg += " (utólag: a Guard akkor nem futott)"
            if e.get("event") in ("unlock_fail", "unlock", "master_changed", "restored", "mass_delete"):
                msg += " | Ha nem te voltál: zárold a Passt a gombbal, és cserélj mesterjelszót!"
            self.alert("127.0.0.1", msg, always=True, gombok=_GOMB)

    def _pe_loop(self):
        utolso_meret = None
        while not self._pe_stop_ev.is_set():
            try:
                try:
                    st = os.stat(ESEMENY_FILE)
                    meret = (st.st_size, st.st_mtime)
                except OSError:
                    meret = None
                if meret is not None and meret != utolso_meret:
                    utolso_meret = meret
                    uj = self._pe_uj()
                    if uj:
                        log_line("[ARRABONA PASS] %d uj esemeny" % len(uj))
                        self._pe_kuld(uj)
                self.pass_status = "aktív (a Pass %s)" % ("fut" if pass_fut() else "nem fut")
            except Exception as ex:
                log_line("[ARRABONA PASS] figyelo hiba: %s" % ex)
                self._pe_stop_ev.wait(10.0)
            self._pe_stop_ev.wait(POLL)

    def _passert_start(self):
        if getattr(self, "_pe_thread", None) and self._pe_thread.is_alive():
            return
        self._pe_lock = threading.Lock()
        self._pe_ts, self._pe_ids = self._pe_load()
        self.pass_esemenyek = getattr(self, "pass_esemenyek", [])
        self.pass_riasztas = getattr(self, "pass_riasztas", 0)
        self.pass_status = "indulás…"
        self._pe_stop_ev = threading.Event()
        self._pe_thread = threading.Thread(target=self._pe_loop, name="pass-ertesites", daemon=True)
        self._pe_thread.start()
        log_line("[ARRABONA PASS] esemenyfigyeles indul (%s)" % ESEMENY_FILE)

    def _passert_stop(self):
        ev = getattr(self, "_pe_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ tavoli zarolas
    def pass_zarol(self, ki="felulet"):
        """A futo Pass zarolasa. Visszaad: (ok, szoveg). Legfeljebb ~5 mp-ig var a nyugtara."""
        t0 = time.time() - 1.0
        if not _jelez():
            return False, "Az Arrabona Pass nem fut ezen a gépen – nincs mit zárolni."
        log_line("[ARRABONA PASS] tavoli zarolas kerese (%s)" % ki)
        for _ in range(25):
            time.sleep(0.2)
            for e in reversed(esemenyek(t0)):
                if e.get("event") == "remote_lock":
                    return True, str(e.get("text") or "Arrabona Pass zárolva.")
        return True, "Zárolási kérés elküldve (a Pass nem nyugtázta – lehet, hogy régebbi verzió)."

    # ------------------------------------------------------------ allapot szovegek
    def pass_summary(self):
        st = getattr(self, "pass_status", "indulás…")
        n = getattr(self, "pass_riasztas", 0)
        return "%s | Értesítés: %d" % (st, n)

    def pass_text(self):
        sorok = ["ARRABONA PASS: %s" % self.pass_summary().replace(" | ", ", ")]
        lst = getattr(self, "pass_esemenyek", [])
        if not lst:
            lst = list(reversed([e for e in esemenyek(time.time() - 7 * 86400)
                                 if e.get("event") != "remote_lock"]))[:10]
        if lst:
            sorok.append("Legutóbbi események:")
            sorok += [_szoveg(e, rovid=True) for e in lst[:10]]
        else:
            sorok.append("Nincs esemény az elmúlt 7 napban.")
        sorok.append("Zárolás távolról: /passzar")
        return "\n".join(sorok)
