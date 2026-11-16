# -*- coding: utf-8 -*-
"""Arrabona Guard - Kozos resz: alapimportok, konstansok, tema, IP-segedfuggvenyek, naplo, auto-inditas, tuzfalnaplo."""

import os
import sys
import time
import queue
import threading
import subprocess

_orig_run = subprocess.run
def _quiet_run(*args, **kwargs):
    # Minden subprocess-hivas konzolablak nelkul indul -> nincs kepernyo-villanas frissites kozben.
    kwargs.setdefault("creationflags", 0x08000000)  # CREATE_NO_WINDOW
    return _orig_run(*args, **kwargs)
subprocess.run = _quiet_run
import socket
import datetime
import ctypes
import winreg
import json as _json

import tkinter as tk
from tkinter import ttk
from tkinter import scrolledtext

try:
    import winsound
except ImportError:
    winsound = None

try:
    from PIL import Image, ImageDraw, ImageTk
    import pystray
except ImportError:
    print("HIANYZO MODUL! Futtasd:  pip install pystray Pillow")
    sys.exit(1)

# ----------------------- Konstansok -----------------------

APP_NAME = "Arrabona Guard"
VERSION = "2.19.0"

# --- [v2.18.0] Nyilvanos kiadas: GitHub Release-ekbol frissul (arrabona/updater.py) ---
GITHUB_REPO = "Lokypapa/arrabona-guard"

# --- 3. feladat: frissites-figyeles (dist -> telepitett exe) ---
# Fejlesztoi gep: ha ez a fajl letezik, a helyi build is felajanlhato (regi mukodes).
DIST_EXE    = r"F:\wowserver\ArrabonaGuard\dist\arrabona_guard.exe"
# [v2.18.0] A telepitett exe helye mar nem fix: barki, barhova telepitheti.
if getattr(sys, "frozen", False):
    INSTALL_EXE = os.path.normpath(sys.executable)
else:
    INSTALL_EXE = r"E:\Program Files\Games\Arrabona Guard\Arrabona Guard.exe"
UPDATE_CHECK_MS = 10 * 60 * 1000  # 10 percenkenti ellenorzes

APPDATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ArrabonaGuard")
BLACKLIST_FILE = os.path.join(APPDATA_DIR, "feketelista.txt")
WHITELIST_FILE = os.path.join(APPDATA_DIR, "whitelist.txt")
LOG_FILE = os.path.join(APPDATA_DIR, "guard_naplo.txt")
HONEYPOT_FILE = os.path.join(APPDATA_DIR, "honeypot.txt")
# [v1.9.4] Kimeno vedelem kapcsoloja: "KI" sor -> a FEED csak bejovot tilt
KIMENO_FILE = os.path.join(APPDATA_DIR, "kimeno.txt")
# [v1.9.5] Orkutya (watchdog)
WATCHDOG_TASK = "ArrabonaGuard Watchdog"
# [v1.9.6] Windows Defender
DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"
DEFENDER_EVENTS = ("1116", "1117", "1118", "1119", "5001", "5007", "5010", "5012")
DEF_SIG_MAX_AGE = 3        # ennyi napnal regebbi definicio = riasztas
# [v2.18.2] A telepito a program melle teszi (tools\\watchdog.vbs) es O hozza letre a feladatot is;
# a regi, APPDATA-ba irt valtozat csak a telepito nelkuli futtatashoz maradt meg.
_TELEPITETT_VBS = os.path.join(os.path.dirname(os.path.abspath(sys.executable)), "tools", "watchdog.vbs")
if getattr(sys, "frozen", False) and os.path.isfile(_TELEPITETT_VBS):
    WATCHDOG_VBS = _TELEPITETT_VBS
else:
    WATCHDOG_VBS = os.path.join(APPDATA_DIR, "watchdog.vbs")
QUIT_FLAG = os.path.join(APPDATA_DIR, "kilepes.flag")        # szandekos kilepes jelzese
HEARTBEAT_FILE = os.path.join(APPDATA_DIR, "heartbeat.txt")  # utolso eletjel

WINDIR = os.environ.get("WINDIR", r"C:\Windows")
FW_LOG = os.path.join(WINDIR, r"system32\LogFiles\Firewall\pfirewall.log")

CHECK_INTERVAL = 2.0
# --- KOZOSSEGI BLOCKLIST FEED (Spamhaus DROP v4+v6 + FireHOL Level-1) ---
# Indulaskor betolt (cache-bol is), majd forrasonkenti ciklusban frissul.
# Megjegyzes: az eDROP 2024-tol mar a DROP resze, kulon URL mar nincs.
# Megjegyzes: a Spamhaus a DROP listat MAX napi 1x engedi letolteni!
FEED_URLS = [
    # (nev,                          url,                                                                    formatum, orankenti frissites)
    ("spamhaus_drop_v4", "https://www.spamhaus.org/drop/drop_v4.json",                                    "json", 24),
    ("spamhaus_drop_v6", "https://www.spamhaus.org/drop/drop_v6.json",                                    "json", 24),
    ("firehol_level1",   "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset", "text", 4),
]
FEED_HOURS_DEFAULT = 4              # ha egy forrasnal nincs sajat ciklus megadva
FEED_TIMEOUT = 30                   # letoltesi idokorlat masodpercben
FEED_MAX_PER_RULE = 100             # CIDR darab tuzfal-szabalyonkent (netsh hosszlimit!)
FEED_RULE_PREFIX = "ArrabonaFeed_"
# --- GEO-BLOKK (feketelista mod: csak a geoblock.txt-ben levo orszagok) ---
GEO_URLS = {
    4: ["https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4-cidr.csv",
        "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv4.csv"],
    6: ["https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv6-cidr.csv",
        "https://github.com/sapics/ip-location-db/releases/download/latest/user-country-ipv6.csv"],
}
GEO_CFG  = "geoblock.txt"        # orszagkod-lista az APPDATA Guard-mappaban
GEO_STATE = "geo_state.json"     # letrehozott tuzfal-szabalyok nevei
GEO_CACHE = "geo_cache.txt"     # offline indulashoz: "kod,cidr" sorok
GEO_RULE_PREFIX = "ArrabonaGeo_"
GEO_HOURS = 24                   # teljes frissitesi ciklus

# --- 4625: sikertelen bejelentkezes-figyeles (brute-force detektalas) ---
LOGON_POLL = 60.0               # Security naplo olvasasa ennyisenkent (mp)
LOGON_WINDOW = 600.0             # ennyi mp alatt gyujtjuk a hibas probakat
LOGON_THRESHOLD = 5             # ennyi hibas bejelentkezes = riasztas
LOGON_TYPES = (3, 10)           # csak halozati eredetu probak (3=SMB, 10=RDP)                   # teljes frissitesi ciklus
GEO_POLL = 300                   # konfig-valtozas figyelse 5 percenkent
GEO_MAX_PER_RULE = 100           # CIDR darab tuzfal-szabalyonkent
  # tuzfal mester-szabalyok elotagja
  # tuzfalnaplo gyorsciklus (valos ideju)
NETSTAT_INTERVAL = 30.0  # netstat es listaujratoltes ritkabb ciklusa
POPUP_MS = 5000
ALERT_COOLDOWN = 60.0
FW_THRESHOLD = 10
FW_WINDOW = 60.0
MAX_BLOCKS = 50  # mar nincs hasznalatban: mester-szabalyos blokkolas (1h/24h/Perm)
BLOCK_PREFIX = "ArrabonaBlock_"  # tuzfalszabaly nev eleje

# --- Sulyozott pontrendszer: kritikus portok tobbet szamitanak ---
PORT_WEIGHTS = {
    22: 5, 3389: 5, 5900: 5,     # SSH, RDP, VNC - tavoli belepes
    3306: 4, 1433: 4,            # MySQL, MSSQL - adatbazisok
    445: 4, 139: 4,              # SMB - fajlmegosztas
}
PORT_SCORE_THRESHOLD = 10.0       # ennyi pont / 60 mp = riasztas + blokk
BLOCK_FILE = os.path.join(APPDATA_DIR, "blokkok.json")  # eszkalacios elozmenyek

LOG_TRIM_LIMIT = 10 * 1024 * 1024   # 10 MB felett takarít
LOG_KEEP_TAIL   = 2 * 1024 * 1024   # ennyi utolsó bájtot tart meg

# --- Színpaletta: ZÖLD márka + G DATA-stílusú világos panelek ---
COLORS = {
    'brand':        '#27ae60',
    'brand_dark':   '#1e8a4c',
    'white':        '#ffffff',
    'bg':           '#f0f0f4',
    'panel':        '#ffffff',
    'panel_head':   '#f5f5f7',
    'divider':      '#e0e0e6',
    'text':         '#333333',
    'text_soft':    '#666666',
    'ok':           '#27ae60',
    'warn':         '#e67e22',
    'bad':          '#c0392b',
    'link':         '#27ae60',
}

# hue-eltolás a logó zöldre festéséhez
_HUE_SHIFT_GREEN = (85 - 177) % 256

# ---------- SOTET MOD (dark mode) ----------
DARK_COLORS = {
    'brand':        '#27ae60',
    'brand_dark':   '#1e8a4c',
    'white':        '#ffffff',
    'bg':           '#16161c',
    'panel':        '#1e1e26',
    'panel_head':   '#26262f',
    'divider':      '#3a3a44',
    'text':         '#e8e8ec',
    'text_soft':    '#9a9aa5',
    'ok':           '#2ecc71',
    'warn':         '#e67e22',
    'bad':          '#e05548',
    'link':         '#2ecc71',
}

def _theme_file():
    base = os.path.join(os.environ.get('APPDATA', ''), 'ArrabonaGuard')
    os.makedirs(base, exist_ok=True)
    return os.path.join(base, 'tema.txt')

def _is_dark():
    try:
        with open(_theme_file(), 'r', encoding='utf-8') as f:
            return f.read().strip().lower() == 'dark'
    except Exception:
        return False

# indulasnal visszatoltjuk a mentett temat (meg nincs fel epitve egy widget sem)
if _is_dark():
    COLORS.update(DARK_COLORS)


ENTRY_SCRIPT = os.path.abspath(sys.argv[0]) if (sys.argv and sys.argv[0]) else os.path.abspath(__file__)


def app_dir():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(ENTRY_SCRIPT)


def now_str():
    return datetime.datetime.now().strftime("%H:%M:%S")


def date_str():
    return datetime.datetime.now().strftime("%Y. %m. %d. %H:%M")


# ----------------------- IP besorolás -----------------------

def is_private_ip(ip):
    """Belső/privát/LAN cím-e? Ezek NEM adnak riasztást."""
    if not ip or ip in ("127.0.0.1", "0.0.0.0", "::", "::1"):
        return True
    if ip.startswith(("127.", "10.", "192.168.", "169.254.",
                      "192.0.0.", "fe80:", "fc", "fd")):
        return True
    if ip.startswith("100."):
        # [v1.9.3] 100.64.0.0/10 = 100.64.x.x - 100.127.x.x (Tailscale / CGNAT).
        # Korabban csak a 100.64.x.x-et ismerte fel, a Tailscale cimek nagy resze
        # (pl. 100.101.x.x) kulso IP-nek latszott.
        try:
            return 64 <= int(ip.split(".")[1]) <= 127
        except Exception:
            return False
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except Exception:
            return False
    # multicast / broadcast
    if ip.startswith(("224.", "239.", "255.")):
        return True
    return False


# [v1.9.1] Privat / fenntartott ("bogon") tartomanyok, amiket a Guard
# SOHA nem blokkolhat tuzfal-szaballyal (LAN, Tailscale/CGNAT, loopback,
# link-local, multicast). A FireHOL Level-1 ezeket is tartalmazza!
import ipaddress as _ipaddress
_BOGON_NETS = [_ipaddress.ip_network(_x) for _x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.168.0.0/16",
    "224.0.0.0/3",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)]


def kimeno_blokk_on():
    """[v1.9.4] Kell-e a FEED tartomanyait KIFELE is tiltani? Alapbol IGEN.
    Kikapcsolas: a kimeno.txt-be egy "KI" sor (a Guard ujrainditasa utan el)."""
    try:
        if not os.path.exists(KIMENO_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(KIMENO_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - kimeno vedelem\n"
                        "# BE = a FEED rossz IP-tartomanyai FELE a gep sem kapcsolodhat\n"
                        "#      (kartevo 'hazatelefonalasa' blokkolva). Ajanlott.\n"
                        "# KI = csak bejovo tiltas, kimeno csak riasztas.\n"
                        "# Valtoztatas utan a Guardot ujra kell inditani.\n"
                        "BE\n")
            return True
        with open(KIMENO_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip().upper()
                if not ln or ln.startswith("#"):
                    continue
                return ln not in ("KI", "OFF", "0", "NEM")
    except Exception:
        pass
    return True


class _IpRangeIndex(object):
    """[v1.9.4] Gyors 'benne van-e az IP a FEED tartomanyokban' kereses
    (tobb ezer CIDR, binaris keresessel; IPv4 es IPv6 kulon)."""

    def __init__(self, nets):
        import bisect as _bs
        self._bs = _bs
        self.idx = {4: ([], []), 6: ([], [])}
        tmp = {4: [], 6: []}
        for n in nets or ():
            try:
                tmp[n.version].append((int(n.network_address), int(n.broadcast_address)))
            except Exception:
                pass
        for v in (4, 6):
            rs = sorted(tmp[v])
            merged = []
            for a, b in rs:
                if merged and a <= merged[-1][1] + 1:
                    if b > merged[-1][1]:
                        merged[-1][1] = b
                else:
                    merged.append([a, b])
            self.idx[v] = ([m[0] for m in merged], [m[1] for m in merged])
        self.size = sum(len(self.idx[v][0]) for v in (4, 6))

    def __contains__(self, ip):
        try:
            a = _ipaddress.ip_address(ip)
        except ValueError:
            return False
        if a.version == 6 and a.ipv4_mapped:
            a = a.ipv4_mapped
        starts, ends = self.idx[a.version]
        x = int(a)
        i = self._bs.bisect_right(starts, x) - 1
        return i >= 0 and x <= ends[i]


def _uniq_stamp(pecsat, regi_nevek):
    """[v1.9.1] Idobelyeg a szabalynevekhez, ami garantaltan nem egyezik
    egyik regi szabaly nevevel sem (ha ugyanabban a masodpercben ket
    frissites futna, a regi szabalyok kulonben nem torlodnenek)."""
    alap, n = pecsat, 0
    while any(("_%s_" % pecsat) in r for r in (regi_nevek or [])) and n < 26:
        n += 1
        pecsat = alap + chr(96 + n)
    return pecsat


def is_bogon_net(net):
    """True, ha a tartomany barmely privat/fenntartott tartomannyal atfedesben van."""
    try:
        for b in _BOGON_NETS:
            if b.version == net.version and net.overlaps(b):
                return True
    except Exception:
        return False
    return False


# ----------------------- Feketelista / whitelist -----------------------

def ensure_appdata():
    os.makedirs(APPDATA_DIR, exist_ok=True)
    if not os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            f.write("# Arrabona Guard IP feketelista\n")
            f.write("# Egy IP-t egy sorba irj. A # koddal kezdodo sorok kommentek.\n")
            f.write("# Feketelistas IP mindennemu probalkozasa AZONNAL riasztast ad.\n")
            f.write("# Peldaul:\n")
            f.write("# 203.0.113.66\n")
    if not os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, "w", encoding="utf-8") as f:
            f.write("# Arrabona Guard IP whitelist (figyelmen kivul hagyott IP-k)\n")
            f.write("# Ide irt IP-ket a Guard sosem jelez. Egy IP soronkent.\n")
            f.write("# A belso (LAN) cimeket amugy is automatikusan kihagyja:\n")
            f.write("# 192.168.*, 10.*, 172.16-31.*, 169.254.* stb.\n")
            f.write("# Peldaul:\n")
            f.write("# 8.8.8.8\n")


def _load_ip_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return {ln.strip() for ln in f
                    if ln.strip() and not ln.strip().startswith("#")}
    except OSError:
        return set()


def load_blacklist():
    return _load_ip_file(BLACKLIST_FILE)


def load_whitelist():
    return _load_ip_file(WHITELIST_FILE)


# ----------------------- Segédek -----------------------

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def dec_ki(b):
    """[v2.12.1] Parancs kimenetenek dekodolasa (wevtutil /uni:true -> UTF-16; kulonben
    UTF-8, vegul a magyar Windows kodlapjai: cp852 / cp1250 - amelyikben tobb ekezetes betu van)."""
    if not b:
        return ""
    if isinstance(b, str):
        return b
    if b[:2] in (b"\xff\xfe", b"\xfe\xff") or (len(b) > 3 and b.count(b"\x00") > len(b) // 4):
        try:
            return b.decode("utf-16", errors="replace").lstrip("\ufeff")
        except Exception:
            pass
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        pass
    hu = set("áéíóöőúüűÁÉÍÓÖŐÚÜŰ")
    jelolt = []
    for cp in ("cp852", "cp1250"):
        try:
            t = b.decode(cp, errors="replace")
            jelolt.append((sum(1 for ch in t if ch in hu), t))
        except Exception:
            pass
    return max(jelolt, key=lambda x: x[0])[1] if jelolt else b.decode("utf-8", errors="replace")


def log_line(line):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write("[%s] %s\r\n" % (ts, line))
    except OSError:
        pass


def trim_log():
    """Naplótakarítás: 10 MB felett a régi rész törlése, az utolsó ~2 MB marad."""
    try:
        if not os.path.exists(LOG_FILE):
            return
        if os.path.getsize(LOG_FILE) < LOG_TRIM_LIMIT:
            return
        with open(LOG_FILE, "rb") as f:
            f.seek(0, 2)
            end = f.tell()
            f.seek(max(0, end - LOG_KEEP_TAIL))
            data = f.read()
        nl = data.find(b"\n")
        if nl >= 0:
            data = data[nl + 1:]
        tmp = LOG_FILE + ".tmp"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, LOG_FILE)
    except Exception:
        pass


def play_alert_sound():
    if winsound:
        try:
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except Exception:
            pass


# ----------------------- [v2.18.1] Hibanapló -----------------------
# Kezeletlen kivetelek (felulet, hatterszalak) teljes hibauzenete ide kerul, hogy egy
# felhasznalo hibajelzesehez legyen mibol dolgozni. Csak a gepen marad, sehova nem kuldjuk.
HIBA_LOG = os.path.join(APPDATA_DIR, "hiba_naplo.txt")
_HIBA_MAX = 512 * 1024
_hiba_utolso = {}


def hiba_naplozas(forras, exc_type, exc, tb):
    import traceback
    try:
        szoveg = "".join(traceback.format_exception(exc_type, exc, tb))
        kulcs = (forras, szoveg[-300:])
        most = time.time()
        if most - _hiba_utolso.get(kulcs, 0) < 60:     # ugyanaz a hiba percenkent max. 1x
            return
        _hiba_utolso[kulcs] = most
        os.makedirs(APPDATA_DIR, exist_ok=True)
        if os.path.exists(HIBA_LOG) and os.path.getsize(HIBA_LOG) > _HIBA_MAX:
            with open(HIBA_LOG, "rb") as f:
                f.seek(-_HIBA_MAX // 2, 2)
                maradek = f.read()
            with open(HIBA_LOG, "wb") as f:
                f.write(maradek)
        with open(HIBA_LOG, "a", encoding="utf-8") as f:
            f.write("===== %s | v%s | %s =====\n%s\n" % (
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), VERSION, forras, szoveg))
    except Exception:
        pass


def hiba_hookok_be():
    """sys.excepthook + threading.excepthook: semmi ne vesszen el csendben."""
    def _fo(t, e, tb):
        hiba_naplozas("fo szal", t, e, tb)
        try:
            sys.__excepthook__(t, e, tb)
        except Exception:
            pass
    sys.excepthook = _fo

    def _szal(args):
        if args.exc_type is SystemExit:
            return
        nev = getattr(args.thread, "name", "?") if args.thread else "?"
        hiba_naplozas("szal: %s" % nev, args.exc_type, args.exc_value, args.exc_traceback)
    threading.excepthook = _szal


# ----------------------- Auto-indítás -----------------------

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_NAME = "ArrabonaGuard"


def autostart_cmd():
    if getattr(sys, "frozen", False):
        return '"' + sys.executable + '"'
    return '"%s" "%s"' % (sys.executable, ENTRY_SCRIPT)


# [v2.18.2] Az automatikus inditas utemezett feladatat CSAK a telepito hozza letre
# ("ArrabonaGuard AutoStart": rendszergazdai jog UAC nelkul, akkurol is, idokorlat nelkul).
# A Guard maga csak ki-/bekapcsolja. Ha a Guard sajat maga hozza letre, a Defender
# viselkedes-figyeloje "megkapaszkodasnak" (Behavior:Win32/Persistence) nezi es torli.
AUTOSTART_TASK = "ArrabonaGuard AutoStart"


def _run_key_enabled():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            winreg.QueryValueEx(k, REG_NAME)
            return True
    except OSError:
        return False


def _run_key_torles():
    """A regi verziok Run-kulcsa: a --uac-admin exe-t a Windows onnan nem inditja el."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, REG_NAME)
        return True
    except OSError:
        return False


_AUTOSTART_CACHE = [0.0, None]   # (ido, None = nincs feladat / True / False)


def autostart_task_state(friss=False):
    """None = nincs ilyen feladat, True = bekapcsolva, False = kikapcsolva. 60 mp-ig gyorsitotarazva."""
    if not friss and time.time() - _AUTOSTART_CACHE[0] < 60:
        return _AUTOSTART_CACHE[1]
    allapot = None
    try:
        r = subprocess.run(["schtasks", "/query", "/tn", AUTOSTART_TASK, "/xml"],
                           capture_output=True, timeout=15)
        if r.returncode == 0:
            xml = dec_ki(r.stdout or b"")
            import re as _re
            m = _re.search(r"<Settings>.*?</Settings>", xml, _re.S)
            beall = m.group(0) if m else ""
            # a <Settings> kozvetlen <Enabled> eleme (a triggereke kulon van)
            m2 = _re.search(r"<Enabled>\s*(true|false)\s*</Enabled>", _re.sub(r"<IdleSettings>.*?</IdleSettings>", "", beall, flags=_re.S))
            allapot = not (m2 and m2.group(1) == "false")
    except Exception:
        allapot = None
    _AUTOSTART_CACHE[0], _AUTOSTART_CACHE[1] = time.time(), allapot
    return allapot


def autostart_task_exists(friss=False):
    return autostart_task_state(friss) is not None


def autostart_enabled():
    st = autostart_task_state()
    if st is None:
        return _run_key_enabled()
    return st


def autostart_set(enable):
    """A telepito altal letrehozott feladat ki-/bekapcsolasa. False, ha nincs feladat
    (ilyenkor a telepito ujrafuttatasa allitja helyre)."""
    if autostart_task_state(friss=True) is None:
        if not enable:
            _run_key_torles()
            return True
        return False
    try:
        r = subprocess.run(["schtasks", "/change", "/tn", AUTOSTART_TASK,
                            "/ENABLE" if enable else "/DISABLE"], capture_output=True, timeout=15)
        ok = r.returncode == 0
    except Exception:
        ok = False
    if ok:
        _run_key_torles()
    autostart_task_state(friss=True)
    return ok


# ----------------------- Tűzfal napló -----------------------

def enable_fw_logging():
    if not is_admin():
        return False
    cmds = [
        ["netsh", "advfirewall", "set", "allprofiles",
         "logging", "droppedconnections", "enable"],
        ["netsh", "advfirewall", "set", "allprofiles",
         "logging", "maxfilesize", "16384"],
        ["netsh", "advfirewall", "set", "allprofiles",
         "logging", "filename", FW_LOG],
    ]
    for c in cmds:
        try:
            subprocess.run(c, capture_output=True, timeout=10)
        except Exception:
            return False
    return True
