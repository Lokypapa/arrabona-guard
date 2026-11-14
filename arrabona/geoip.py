# -*- coding: utf-8 -*-
"""Arrabona Guard - GeoIP: orszagkod a riasztasokhoz (helyi DB-IP mmdb + ip-api tartalek, havi frissites)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import threading
from .common import (is_private_ip)

# ----------------------- GeoIP -----------------------

_geo_cache = {}
_geo_neg = {}       # hibas lekeresek: 5 percig nem probaljuk ujra
_geo_pending = set()  # epp letoltes alatt allo IP-k (szalflood ellen)
_geo_lock = threading.Lock()
_GUARD_DIR = os.path.abspath(os.path.join(os.environ.get("APPDATA") or ".", "ArrabonaGuard"))
_MMDB_PATH = os.path.join(_GUARD_DIR, "dbip-country-lite.mmdb")
_GEO_API = "http://ip-api.com/json/%s?fields=status,countryCode"  # tartalek ut
_geo_reader = None
_geo_reader_lock = threading.Lock()


def _geo_logline(msg):
    """Onallo naplosor a GEOIP frissitesek kovethetosegehez."""
    try:
        import time as _t
        sor = "[%s] GEOIP: %s\n" % (_t.strftime("%Y-%m-%d %H:%M:%S"), msg)
        with open(os.path.join(_GUARD_DIR, "guard_naplo.txt"), "a", encoding="utf-8", errors="replace") as f:
            f.write(sor)
    except Exception:
        pass


def _geo_mmdb():
    """Lokalis MaxMind olvaso (elso hasznalatkor nyilik). None, ha nincs jo DB."""
    global _geo_reader
    if not os.path.isfile(_MMDB_PATH):
        return None
    with _geo_reader_lock:
        if _geo_reader is None:
            try:
                import maxminddb
                _geo_reader = maxminddb.open_database(_MMDB_PATH)
            except Exception:
                _geo_reader = False
        return _geo_reader or None


def geoip_refresh(force=False):
    """DB-IP Country-Lite frissites: honap-URL, kicsomagolas-teszt, atomikus csere."""
    global _geo_reader
    if not os.path.isdir(_GUARD_DIR):
        try:
            os.makedirs(_GUARD_DIR, exist_ok=True)
        except Exception:
            return False
    import time as _t, urllib.request, gzip, shutil
    gz_tmp = os.path.join(_GUARD_DIR, "dbip_lite.gz.tmp")
    mmdb_tmp = _MMDB_PATH + ".tmp"
    honap = "?"
    try:
        if not force and os.path.isfile(_MMDB_PATH):
            kor = (_t.time() - os.path.getmtime(_MMDB_PATH)) / 86400.0
            if kor < 25:
                return True  # meg friss, nem kell letolteni
        url_ok = False
        for honap in (_t.strftime("%Y-%m"),
                      _t.strftime("%Y-%m", _t.localtime(_t.time() - 2678400))):
            url = "https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz" % honap
            try:
                with urllib.request.urlopen(url, timeout=90) as r, open(gz_tmp, "wb") as f:
                    while True:
                        darab = r.read(65536)
                        if not darab:
                            break
                        f.write(darab)
                url_ok = True
                break
            except Exception:
                continue
        if not url_ok:
            _geo_logline("DB-IP letoltes nem sikerult (egyik honap URL sem elo)")
            return False
        with gzip.open(gz_tmp, "rb") as fin, open(mmdb_tmp, "wb") as fout:
            shutil.copyfileobj(fin, fout)
        import maxminddb
        proba = maxminddb.open_database(mmdb_tmp)
        proba.close()
        os.replace(mmdb_tmp, _MMDB_PATH)
        with _geo_reader_lock:
            _geo_reader = None  # uj fajl: ujranyitas
        _geo_logline("DB-IP Country-Lite frissitve (%s)" % honap)
        return True
    except Exception as e:
        _geo_logline("DB-IP frissites hiba: %s" % e)
        return False
    finally:
        for szem in (gz_tmp, mmdb_tmp):
            try:
                if os.path.isfile(szem):
                    os.remove(szem)
            except Exception:
                pass


def _geoip_refresher():
    geoip_refresh()
    import time as _t
    while True:
        _t.sleep(21600)  # 6 orankent eletkor-ellenorzes
        geoip_refresh()


_geoip_started = False


def geoip_refresher_start():
    global _geoip_started
    if _geoip_started:
        return
    _geoip_started = True
    threading.Thread(target=_geoip_refresher, daemon=True).start()



def _fetch_geo(ip):
    try:
        geo_country(ip)
    except Exception:
        pass
    finally:
        with _geo_lock:
            _geo_pending.discard(ip)


def _geo_local(ip):
    """[v1.9.2] Orszagkod a helyi DB-IP mmdb-bol (halozat nelkul, mikroszekundumok)."""
    r = _geo_mmdb()
    if r is None:
        return ""
    try:
        rec = r.get(ip)
        if rec and isinstance(rec, dict):
            ctry = rec.get("country") or {}
            return (ctry.get("iso_code") or "").strip().upper()
    except Exception:
        pass
    return ""


def geo_country_bg(ip):
    """Azonnal cache-bol valasz; ha nincs benne, a helyi mmdb-bol AZONNAL
    (v1.9.2), es csak ha az sem tudja, hatterszal kerdezi az ip-api-t."""
    import time as _gt
    if ip in ("127.0.0.1", "::1"):
        return ""      # helyi esemeny (teszt, perzisztencia): nincs orszagkod
    if is_private_ip(ip):
        return "LAN"
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
        if ip in _geo_pending:
            return ""
        if _gt.time() < _geo_neg.get(ip, 0):
            return ""
    # [v1.9.2] helyi adatbazis szinkronban: igy mar az ELSO riasztasban is
    # ott az orszagkod (korabban az elso riasztas mindig kod nelkul ment ki)
    cc = _geo_local(ip)
    if cc:
        with _geo_lock:
            _geo_cache[ip] = cc
        return cc
    with _geo_lock:
        if ip in _geo_pending:
            return ""
        _geo_pending.add(ip)
    try:
        threading.Thread(target=_fetch_geo, args=(ip,), daemon=True).start()
    except Exception:
        with _geo_lock:
            _geo_pending.discard(ip)
    return ""


def geo_country(ip):
    """
    Orszagkod az IP-hez (pl. "RU"). LAN cimeknel "LAN".
    Eloszor lokalis DB-IP mmdb (halo hivas nelkul),
    tartalek: ip-api.com, ha nincs/rossz a lokalis DB.
    Eredmeny gyorsitotarazva; hibanal 5 perc negativ cache a regi.
    """
    if is_private_ip(ip):
        return "LAN"
    import time as _gt
    with _geo_lock:
        if ip in _geo_cache:
            return _geo_cache[ip]
        if _gt.time() < _geo_neg.get(ip, 0):
            return ""
    cc = _geo_local(ip)
    if not cc:
        try:
            import urllib.request
            with urllib.request.urlopen(_GEO_API % ip, timeout=3) as resp:
                data = _json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("status") == "success":
                cc = (data.get("countryCode") or "").strip().upper()
        except Exception:
            cc = ""
    with _geo_lock:
        if cc:
            _geo_cache[ip] = cc
        else:
            _geo_neg[ip] = _gt.time() + 300
    return cc


geoip_refresher_start()  # indulaskor elindul a havi frissito szal
