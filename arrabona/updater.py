# -*- coding: utf-8 -*-
"""Arrabona Guard - ONFRISSITES GitHub Release-bol. [v2.18.0]

Mukodes:
  1. Indulas utan 1 perccel, majd 6 orankent lekerdezi:
       https://api.github.com/repos/<GITHUB_REPO>/releases/latest
  2. Ha a kiadas verzioja (tag, pl. "v2.18.0") ujabb a futonal: savot mutat az ablakban,
     egyszer szol Telegramon (gombbal), a talca-menuben is telepitheto.
  3. Telepiteskor letolti a kiadas telepitojet (ArrabonaGuard_Setup_<ver>.exe) es a
     SHA256SUMS.txt-t, ELLENORZI az ellenorzoosszeget (ha nem egyezik: NEM telepit),
     majd csendes modban elinditja a telepitot es kilep. A telepito a vegen ujrainditja a Guardot.

Beallitas: guard_frissites.txt (APPDATA\\ArrabonaGuard)
  KERESES BE|KI        - keressen-e uj verziot (alap: BE)
  TELEGRAM BE|KI       - szoljon-e Telegramon az uj verziorol (alap: BE)
Soha nem telepit magatol - csak ha te kered (gomb / talca / Telegram).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import re
import sys
import threading
import time
import urllib.request
from .common import (APP_NAME, APPDATA_DIR, GITHUB_REPO, VERSION, log_line)

UPD_CFG_FILE = os.path.join(APPDATA_DIR, "guard_frissites.txt")
UPD_STATE_FILE = os.path.join(APPDATA_DIR, "guard_frissites_allapot.json")
UPD_DIR = os.path.join(os.environ.get("TEMP", APPDATA_DIR), "ArrabonaGuard_frissites")
ELSO_KERESES_MS = 60 * 1000
KERESES_MS = 6 * 3600 * 1000
API_TIMEOUT = 20
LETOLTES_TIMEOUT = 120
MAX_TELEPITO_MB = 300
_UA = "ArrabonaGuard-Updater/%s" % VERSION
_SETUP_MINTA = re.compile(r"setup.*\.exe$", re.I)
_SUMS_MINTA = re.compile(r"^sha256sums(\.txt)?$", re.I)

_lock = threading.Lock()
# Utolso eredmeny: {"ver": "2.18.0", "tag": "v2.18.0", "url": html, "setup": (nev, url, meret),
#                   "sums": url, "notes": str, "ido": ts} vagy None
UJ_VERZIO = None
UTOLSO_KERESES = 0.0
UTOLSO_HIBA = ""
_TELEPITES_FOLYAMATBAN = False
# A felulet allitja be: kilepes a telepito inditasa utan (Telegramrol is hivhato)
KILEPES_HOOK = None


# ----------------------- beallitas / allapot -----------------------

def upd_cfg():
    cfg = {"KERESES": "BE", "TELEGRAM": "BE"}
    try:
        if not os.path.exists(UPD_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(UPD_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - sajat frissites (GitHub: %s) (v2.18.0)\n"
                        "# KERESES BE|KI  = keressen-e uj verziot (6 orankent)\n"
                        "KERESES BE\n"
                        "# TELEGRAM BE|KI = szoljon-e Telegramon az uj verziorol\n"
                        "TELEGRAM BE\n" % GITHUB_REPO)
        with open(UPD_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip().upper() if len(r) > 1 else "")
                if k in cfg and v in ("BE", "KI", "ON", "OFF"):
                    cfg[k] = "KI" if v in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def _state_load():
    try:
        with open(UPD_STATE_FILE, "r", encoding="utf-8") as f:
            return _json.load(f)
    except Exception:
        return {}


def _state_save(d):
    try:
        with open(UPD_STATE_FILE, "w", encoding="utf-8") as f:
            _json.dump(d, f, ensure_ascii=False)
    except Exception:
        pass


# ----------------------- verzio -----------------------

def ver_tuple(v):
    """'v2.18.0' / '2.18' / '2.18.0-beta' -> (2, 18, 0). Hibas -> ()."""
    m = re.match(r"^\s*v?(\d+(?:\.\d+){0,3})", str(v or ""))
    if not m:
        return ()
    t = [int(x) for x in m.group(1).split(".")]
    while len(t) < 3:
        t.append(0)
    return tuple(t)


def ujabb(masik, sajat=VERSION):
    a, b = ver_tuple(masik), ver_tuple(sajat)
    return bool(a) and bool(b) and a > b


# ----------------------- GitHub -----------------------

def _get(url, timeout=API_TIMEOUT, accept="application/vnd.github+json"):
    req = urllib.request.Request(url, headers={"User-Agent": _UA, "Accept": accept})
    return urllib.request.urlopen(req, timeout=timeout)


def keres(kezi=False):
    """Lekerdezi a legujabb kiadast. Visszateres: (van_uj, szoveg).
    Az eredmeny az UJ_VERZIO-ba kerul (None, ha nincs ujabb)."""
    global UJ_VERZIO, UTOLSO_KERESES, UTOLSO_HIBA
    if not kezi and upd_cfg()["KERESES"] != "BE":
        return (False, "A frissites-kereses ki van kapcsolva (guard_frissites.txt).")
    url = "https://api.github.com/repos/%s/releases/latest" % GITHUB_REPO
    try:
        with _get(url) as r:
            d = _json.loads(r.read().decode("utf-8", "replace"))
    except Exception as e:
        hiba = str(e)
        if "404" in hiba:
            hiba = "meg nincs kiadott verzio a GitHubon"
        with _lock:
            UTOLSO_KERESES = time.time()
            UTOLSO_HIBA = hiba
        log_line("[FRISSITES] kereses hiba: %s" % hiba)
        return (False, "Nem sikerült lekérdezni: %s" % hiba)
    tag = str(d.get("tag_name") or "")
    if d.get("draft") or d.get("prerelease"):
        return (False, "A legújabb kiadás még teszt (pre-release).")
    setup, sums = None, None
    for a in d.get("assets") or []:
        nev = str(a.get("name") or "")
        dl = a.get("browser_download_url") or ""
        if _SETUP_MINTA.search(nev) and dl.startswith("https://"):
            setup = (nev, dl, int(a.get("size") or 0))
        elif _SUMS_MINTA.match(nev) and dl.startswith("https://"):
            sums = dl
    with _lock:
        UTOLSO_KERESES = time.time()
        UTOLSO_HIBA = ""
        if ujabb(tag) and setup and sums:
            UJ_VERZIO = {"ver": ".".join(str(x) for x in ver_tuple(tag)), "tag": tag,
                         "url": d.get("html_url") or "", "setup": setup, "sums": sums,
                         "notes": str(d.get("body") or "")[:1500], "ido": time.time()}
        else:
            UJ_VERZIO = None
        uj = UJ_VERZIO
    if uj:
        log_line("[FRISSITES] uj verzio elerheto: %s (fut: v%s)" % (uj["tag"], VERSION))
        return (True, "Új verzió érhető el: v%s (most: v%s)" % (uj["ver"], VERSION))
    if ujabb(tag) and not (setup and sums):
        return (False, "A %s kiadásból hiányzik a telepítő vagy a SHA256SUMS.txt." % tag)
    return (False, "A legfrissebb verzió fut: v%s" % VERSION)


def telegram_ertesites_kell():
    """Uj verziorol csak egyszer szolunk Telegramon (verzionkent)."""
    with _lock:
        uj = UJ_VERZIO
    if not uj or upd_cfg()["TELEGRAM"] != "BE":
        return None
    st = _state_load()
    if st.get("tg_jelezve") == uj["ver"]:
        return None
    st["tg_jelezve"] = uj["ver"]
    _state_save(st)
    jegyzet = uj["notes"].strip()
    if len(jegyzet) > 600:
        jegyzet = jegyzet[:600] + "…"
    return ("⬆ Arrabona Guard: új verzió érhető el: v%s (most: v%s)\n%s%s"
            % (uj["ver"], VERSION, ("\n" + jegyzet + "\n") if jegyzet else "", uj["url"]))


def allapot_szoveg():
    with _lock:
        uj, t, hiba = UJ_VERZIO, UTOLSO_KERESES, UTOLSO_HIBA
    sorok = ["Arrabona Guard verzió: v%s" % VERSION, "Forrás: github.com/%s" % GITHUB_REPO]
    if t:
        sorok.append("Utolsó keresés: %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(t)))
    if hiba:
        sorok.append("Hiba: %s" % hiba)
    if uj:
        sorok.append("ÚJ VERZIÓ: v%s  ->  /guardfrissit" % uj["ver"])
    elif t and not hiba:
        sorok.append("Ez a legfrissebb verzió.")
    return "\n".join(sorok)


# ----------------------- letoltes + ellenorzes -----------------------

def _letolt(url, cel, max_bajt, halad=None):
    h = hashlib.sha256()
    n = 0
    with _get(url, timeout=LETOLTES_TIMEOUT, accept="application/octet-stream") as r, open(cel, "wb") as f:
        osszes = int(r.headers.get("Content-Length") or 0)
        while True:
            darab = r.read(256 * 1024)
            if not darab:
                break
            n += len(darab)
            if n > max_bajt:
                raise IOError("túl nagy fájl (> %d MB)" % (max_bajt // (1024 * 1024)))
            f.write(darab)
            h.update(darab)
            if halad and osszes:
                halad(n * 100 // osszes)
    return h.hexdigest().lower(), n


def letolt_es_ellenoriz(halad=None):
    """Letolti a telepitot + SHA256SUMS-t es ellenoriz. Visszateres: (ok, utvonal_vagy_hiba)."""
    with _lock:
        uj = UJ_VERZIO
    if not uj:
        return (False, "Nincs elérhető új verzió.")
    nev, url, meret = uj["setup"]
    nev = os.path.basename(nev)
    try:
        os.makedirs(UPD_DIR, exist_ok=True)
        for regi in os.listdir(UPD_DIR):
            try:
                os.remove(os.path.join(UPD_DIR, regi))
            except OSError:
                pass
        with _get(uj["sums"], accept="application/octet-stream") as r:
            sums = r.read(64 * 1024).decode("utf-8", "replace")
        vart = None
        for ln in sums.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]{64})\s+\*?(.+?)\s*$", ln)
            if m and os.path.basename(m.group(2)).lower() == nev.lower():
                vart = m.group(1).lower()
                break
        if not vart:
            return (False, "A SHA256SUMS.txt-ben nincs bejegyzés ehhez: %s" % nev)
        cel = os.path.join(UPD_DIR, nev)
        kapott, n = _letolt(url, cel, MAX_TELEPITO_MB * 1024 * 1024, halad)
        if meret and n != meret:
            os.remove(cel)
            return (False, "Hiányos letöltés (%d / %d bájt)." % (n, meret))
        if kapott != vart:
            try:
                os.remove(cel)
            except OSError:
                pass
            log_line("[FRISSITES] ELLENORZOOSSZEG HIBA! vart=%s kapott=%s - NEM telepit" % (vart, kapott))
            return (False, "Az ellenőrzőösszeg NEM egyezik - a fájl sérült vagy módosított, nem telepítem.")
        log_line("[FRISSITES] letoltve es ellenorizve: %s (SHA-256 OK)" % nev)
        return (True, cel)
    except Exception as e:
        log_line("[FRISSITES] letoltesi hiba: %s" % e)
        return (False, "Letöltési hiba: %s" % e)


def telepito_inditasa(utvonal):
    """Csendes telepites inditasa. A hivo ezutan azonnal lepjen ki (a telepito var ra)."""
    import ctypes
    # PyInstaller-kornyezet ne oroklodjon (v2.12.3 hiba): a telepito inditja ujra a Guardot
    for k in list(os.environ):
        if k.upper().startswith("_MEI") or k.upper().startswith("_PYI"):
            os.environ.pop(k, None)
    os.environ["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    params = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG="%s"' % os.path.join(
        UPD_DIR, "telepites_naplo.txt")
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = False
    # Rendszergazdakent kozvetlenul (UAC-ablak nelkul), egyebkent UAC-kerdessel
    se = ctypes.windll.shell32.ShellExecuteW
    se.restype = ctypes.c_void_p
    r = se(None, "open" if admin else "runas", utvonal, params, os.path.dirname(utvonal), 0) or 0
    if r <= 32:
        raise OSError("a telepítő nem indult el (kód %s - UAC elutasítva?)" % r)
    log_line("[FRISSITES] telepito elinditva: %s" % os.path.basename(utvonal))


def frissites_folyamatban():
    return _TELEPITES_FOLYAMATBAN


def telepites(kilepes_fv, halad=None):
    """Teljes folyamat: letoltes -> ellenorzes -> telepito -> kilepes_fv().
    Visszateres: (ok, szoveg). Hatterszalbol hivando."""
    global _TELEPITES_FOLYAMATBAN
    with _lock:
        if _TELEPITES_FOLYAMATBAN:
            return (False, "A frissítés már folyamatban van.")
        _TELEPITES_FOLYAMATBAN = True
    try:
        ok, eredm = letolt_es_ellenoriz(halad)
        if not ok:
            return (False, eredm)
        jelol_telepites_inditva()
        telepito_inditasa(eredm)
        kilepes_fv()
        return (True, "Telepítés elindítva - a Guard pár másodperc múlva újraindul.")
    except Exception as e:
        log_line("[FRISSITES] telepitesi hiba: %s" % e)
        st = _state_load()
        st.pop("telepites_inditva", None)
        _state_save(st)
        return (False, "Nem sikerült: %s" % e)
    finally:
        with _lock:
            _TELEPITES_FOLYAMATBAN = False


def ujraindult_frissites_utan():
    """Indulaskor: ha az elozo futas frissitest inditott, takaritas + visszajelzes szovege."""
    st = _state_load()
    elozo = st.get("telepites_inditva")
    if not elozo:
        return None
    st.pop("telepites_inditva", None)
    _state_save(st)
    try:
        for f in os.listdir(UPD_DIR):
            if f.lower().endswith(".exe"):
                os.remove(os.path.join(UPD_DIR, f))
    except OSError:
        pass
    if ver_tuple(VERSION) >= ver_tuple(elozo):
        return "✅ Arrabona Guard frissítve: v%s" % VERSION
    return "⚠ A frissítés v%s-re nem sikerült, továbbra is v%s fut." % (elozo, VERSION)


def jelol_telepites_inditva():
    with _lock:
        uj = UJ_VERZIO
    if uj:
        st = _state_load()
        st["telepites_inditva"] = uj["ver"]
        _state_save(st)
