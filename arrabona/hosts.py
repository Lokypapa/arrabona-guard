# -*- coding: utf-8 -*-
"""Arrabona Guard - HOSTS-fajl figyeles (GuardCore mixin). [v2.2.0]

A hosts fajl (C:\\Windows\\System32\\drivers\\etc\\hosts) a DNS ELOTT dont:
ami ide bekerul, az a gepen "igaz". A kartevok ezzel szoktak:
  - atiranyitani egy bank / Microsoft / Google cimet egy hamis szerverre,
  - 0.0.0.0-ra / 127.0.0.1-re kotni a virusirto-frissiteseket, a Windows
    Update-et vagy a Guard sajat forrasait (Spamhaus, FireHOL, Telegram),
  - a hosts fajl HELYET atallitani a registryben (DataBasePath).
A Guard 10 mp-enkent osszeveti a fajlt a legutobb elfogadott allapottal
(hosts_alap.json); minden valtozasrol riaszt (a Guard leallasa alatt
tortentrol is, a kovetkezo inditaskor), a gyanus bejegyzeseket kiemeli.
A valtozas elotti valtozat masolata: %APPDATA%\\ArrabonaGuard\\hosts_elozo.txt
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import threading
import time
import winreg
from .common import (APPDATA_DIR, WINDIR, log_line)

HOSTS_STATE_FILE = os.path.join(APPDATA_DIR, "hosts_alap.json")
HOSTS_BACKUP_FILE = os.path.join(APPDATA_DIR, "hosts_elozo.txt")
HOSTS_COPY_FILE = os.path.join(APPDATA_DIR, "hosts_alap.txt")   # az elfogadott allapot masolata
HOSTS_POLL = 10.0
_TCPIP_KEY = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
_DEFAULT_DB = os.path.join(WINDIR, "System32", "drivers", "etc")

# Ezek atiranyitasa / letiltasa gyanus: bankok, fiokok, frissitesek, a Guard forrasai
_ERZEKENY = (
    # Microsoft / Windows Update / Defender / SmartScreen
    "microsoft.com", "windowsupdate.com", "windows.com", "live.com", "msn.com",
    "office.com", "office365.com", "microsoftonline.com", "windows.net", "azureedge.net",
    "msftconnecttest.com", "smartscreen", "wdcp", "defender", "msedge.net",
    # Google / fiokok / kozossegi
    "google.com", "gmail.com", "googleapis.com", "gstatic.com", "youtube.com",
    "apple.com", "icloud.com", "facebook.com", "instagram.com", "messenger.com",
    "whatsapp", "discord.com", "discordapp.com", "steampowered.com", "steamcommunity.com",
    "epicgames.com", "battle.net", "blizzard.com", "github.com", "githubusercontent.com",
    # fizetes / bankok (HU)
    "paypal.", "revolut.", "wise.com", "otpbank", "otpdirekt", "kh.hu", "erstebank",
    "raiffeisen", "granitbank", "mbhbank", "cib.hu", "unicredit", "magnetbank",
    "simplepay", "barion", "ugyfelkapu", "gov.hu", "nav.gov.hu", "magyarorszag.hu",
    # virusirtok
    "kaspersky", "eset.com", "avast", "avg.com", "bitdefender", "malwarebytes",
    "norton", "mcafee", "gdata", "sophos", "virustotal",
    # a Guard sajat forrasai (FEED / GEO / Telegram / publikus IP)
    "spamhaus.org", "telegram.org", "ipify.org", "ip-api.com",
)


def hosts_dir():
    """A hosts fajl mappaja a registry szerint (DataBasePath)."""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_KEY, 0,
                            winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as k:
            v, _t = winreg.QueryValueEx(k, "DataBasePath")
            v = os.path.expandvars(str(v)).strip()
            if v:
                return v
    except OSError:
        pass
    return _DEFAULT_DB


def _norm(p):
    return os.path.normcase(os.path.normpath(p or ""))


def hosts_parse(data):
    """bajtok -> {hostnev: ip}. Megjegyzesek (#) es ures sorok kihagyva."""
    try:
        txt = data.decode("utf-8")
    except UnicodeDecodeError:
        txt = data.decode("cp1250", errors="ignore")
    out = {}
    for ln in txt.splitlines():
        ln = ln.split("#", 1)[0].strip().lstrip("\ufeff")
        if not ln:
            continue
        reszek = ln.split()
        if len(reszek) < 2:
            continue
        ip = reszek[0]
        for h in reszek[1:]:
            out[h.lower().rstrip(".")] = ip
    return out


def hosts_erzekeny(host):
    h = host.lower()
    return any(e in h for e in _ERZEKENY)


def _blokkolo_ip(ip):
    return ip in ("0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0")


class HostsMixin(object):
    """HOSTS-fajl figyeles. A GuardCore resze (mixin)."""

    def _hosts_load_state(self):
        try:
            with open(HOSTS_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) and "entries" in d else None
        except (OSError, ValueError):
            return None

    def _hosts_save_state(self, st):
        try:
            tmp = HOSTS_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(st, f, ensure_ascii=False)
            os.replace(tmp, HOSTS_STATE_FILE)
        except OSError as e:
            log_line("[HOSTS] allapot mentesi hiba: %s" % e)

    def _hosts_read(self, mappa):
        ut = os.path.join(mappa, "hosts")
        try:
            with open(ut, "rb") as f:
                data = f.read(8 * 1024 * 1024)
            return ut, data
        except FileNotFoundError:
            return ut, None
        except OSError:
            return ut, False   # zarolva / nincs jog: kovetkezo korben ujra

    def _hosts_check(self, indulas=False):
        mappa = hosts_dir()
        st = self._hosts_state
        # --- 1) a hosts fajl HELYE (DataBasePath) ---
        if _norm(mappa) != _norm(_DEFAULT_DB):
            if getattr(self, "_hosts_dir_alerted", None) != _norm(mappa):
                self._hosts_dir_alerted = _norm(mappa)
                self.hosts_changes = getattr(self, "hosts_changes", 0) + 1
                self.alert("127.0.0.1", "[HOSTS] GYANUS: a hosts fajl HELYE at van allitva a registryben "
                           "(DataBasePath = %s, alapertelmezett: %s). Kartevo ezzel rejtheti el a "
                           "hamis cimeit!" % (mappa, _DEFAULT_DB), always=True)
        else:
            self._hosts_dir_alerted = None
        # --- 2) a fajl tartalma ---
        ut, data = self._hosts_read(mappa)
        if data is False:
            return
        if data is None:
            if st is not None and st.get("exists", True):
                self.hosts_changes = getattr(self, "hosts_changes", 0) + 1
                self.alert("127.0.0.1", "[HOSTS] A hosts fajl ELTUNT: %s" % ut, always=True)
                st = {"hash": "", "entries": {}, "exists": False, "path": ut, "ts": time.time()}
                self._hosts_state = st
                self._hosts_save_state(st)
            self.hosts_status = "aktív (nincs hosts fájl)"
            return
        h = hashlib.sha256(data).hexdigest()
        if st is not None and st.get("hash") == h and _norm(st.get("path")) == _norm(ut):
            self.hosts_status = "aktív"
            return
        uj = hosts_parse(data)
        if st is None:
            # elso inditas: a mostani allapot az alap
            st = {"hash": h, "entries": uj, "exists": True, "path": ut, "ts": time.time()}
            self._hosts_state = st
            self._hosts_save_state(st)
            self._hosts_copy(data, elozot_ment=False)
            log_line("[HOSTS] alapallapot: %d bejegyzes (%s)" % (len(uj), ut))
            gyanus = [x for x in uj if hosts_erzekeny(x)]
            if gyanus:
                self.alert("127.0.0.1", "[HOSTS] Mar most is van erzekeny bejegyzes a hosts fajlban: %s" %
                           self._hosts_lista(gyanus, uj), always=True)
            self.hosts_status = "aktív"
            return
        regi = st.get("entries") or {}
        hozzaadott = [x for x in uj if x not in regi]
        torolt = [x for x in regi if x not in uj]
        modosult = [x for x in uj if x in regi and regi[x] != uj[x]]
        # a valtozas elotti allapot -> hosts_elozo.txt, az uj -> hosts_alap.txt
        self._hosts_copy(data, elozot_ment=True)
        st = {"hash": h, "entries": uj, "exists": True, "path": ut, "ts": time.time()}
        self._hosts_state = st
        self._hosts_save_state(st)
        if not (hozzaadott or torolt or modosult):
            # csak megjegyzes / formazas valtozott
            log_line("[HOSTS] a hosts fajl megvaltozott, de a bejegyzesek nem (csak megjegyzes/formazas)")
            self.hosts_status = "aktív"
            return
        gyanus = [x for x in hozzaadott + modosult if hosts_erzekeny(x)]
        self.hosts_changes = getattr(self, "hosts_changes", 0) + 1
        self._hosts_recent = ([{"ts": time.time(), "add": len(hozzaadott), "del": len(torolt),
                                "mod": len(modosult), "gyanus": gyanus[:10]}]
                              + list(getattr(self, "_hosts_recent", [])))[:10]
        if gyanus:
            fej = ("[HOSTS] GYANUS VALTOZAS! Erzekeny cim atiranyitva / letiltva: %s"
                   % self._hosts_lista(gyanus, uj))
        else:
            fej = "[HOSTS] A hosts fajl megvaltozott"
        reszek = []
        if hozzaadott:
            reszek.append("+%d uj: %s" % (len(hozzaadott), self._hosts_lista(hozzaadott, uj)))
        if modosult:
            reszek.append("%d modosult: %s" % (len(modosult), ", ".join(
                "%s %s->%s" % (x, regi[x], uj[x]) for x in modosult[:4])
                + (" (+%d)" % (len(modosult) - 4) if len(modosult) > 4 else "")))
        if torolt:
            reszek.append("-%d torolve: %s" % (len(torolt), ", ".join(torolt[:4])
                                               + (" (+%d)" % (len(torolt) - 4) if len(torolt) > 4 else "")))
        msg = "%s%s - %s. Ha nem te voltal: elozo valtozat: %s" % (
            fej, " (a Guard leallasa alatt)" if indulas else "", " | ".join(reszek), HOSTS_BACKUP_FILE)
        self.alert("127.0.0.1", msg, always=True)
        self.hosts_status = "aktív"

    @staticmethod
    def _hosts_lista(hostok, terkep, n=5):
        darab = ["%s -> %s%s" % (x, terkep.get(x, "?"), " (TILTVA)" if _blokkolo_ip(terkep.get(x, "")) else "")
                 for x in hostok[:n]]
        if len(hostok) > n:
            darab.append("+%d tovabbi" % (len(hostok) - n))
        return ", ".join(darab)

    def _hosts_copy(self, data, elozot_ment=True):
        try:
            if elozot_ment and os.path.exists(HOSTS_COPY_FILE):
                os.replace(HOSTS_COPY_FILE, HOSTS_BACKUP_FILE)
            tmp = HOSTS_COPY_FILE + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, HOSTS_COPY_FILE)
        except OSError as e:
            log_line("[HOSTS] masolat mentesi hiba: %s" % e)

    def _hosts_loop(self):
        elso = True
        while not self._hosts_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    lk = self._fix_lock() if hasattr(self, "_fix_lock") else None
                    if lk:
                        with lk:
                            self._hosts_check(indulas=elso)
                    else:
                        self._hosts_check(indulas=elso)
                    elso = False
            except Exception as e:
                log_line("[HOSTS] figyelo hiba: %s" % e)
            self._hosts_stop_ev.wait(HOSTS_POLL)

    def _hosts_start(self):
        if getattr(self, "_hosts_thread", None) and self._hosts_thread.is_alive():
            return
        self._hosts_state = self._hosts_load_state()
        self.hosts_changes = getattr(self, "hosts_changes", 0)
        self.hosts_status = "indulás…"
        self._hosts_recent = getattr(self, "_hosts_recent", [])
        self._hosts_started = time.time()
        self._hosts_stop_ev = threading.Event()
        self._hosts_thread = threading.Thread(target=self._hosts_loop, name="hosts", daemon=True)
        self._hosts_thread.start()
        log_line("[HOSTS] figyeles aktiv: %s (10 mp-enkent)" % os.path.join(hosts_dir(), "hosts"))

    def _hosts_stop(self):
        ev = getattr(self, "_hosts_stop_ev", None)
        if ev is not None:
            ev.set()

    def hosts_summary(self):
        st = getattr(self, "_hosts_state", None) or {}
        reszek = ["Bejegyzés: %d" % len(st.get("entries") or {}),
                  "Változás (futam): %d" % getattr(self, "hosts_changes", 0)]
        rec = getattr(self, "_hosts_recent", [])
        if rec:
            reszek.append("Utolsó: %s%s" % (time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"])),
                                            " ⚠ GYANÚS" if rec[0]["gyanus"] else ""))
        return " | ".join(reszek)

    def hosts_text(self):
        st = getattr(self, "_hosts_state", None) or {}
        e = st.get("entries") or {}
        sorok = ["HOSTS (%s): %d bejegyzes" % (st.get("path") or os.path.join(hosts_dir(), "hosts"), len(e))]
        gy = [x for x in e if hosts_erzekeny(x)]
        if gy:
            sorok.append("Erzekeny bejegyzesek: " + self._hosts_lista(gy, e, 10))
        for x in list(e)[:15]:
            sorok.append("  %s  %s" % (e[x], x))
        if len(e) > 15:
            sorok.append("  ... +%d tovabbi" % (len(e) - 15))
        rec = getattr(self, "_hosts_recent", [])
        if rec:
            r = rec[0]
            sorok.append("Utolso valtozas: %s (+%d / -%d / ~%d)%s" % (
                time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), r["add"], r["del"], r["mod"],
                "  <-- GYANUS" if r["gyanus"] else ""))
        return "\n".join(sorok)
