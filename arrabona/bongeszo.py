# -*- coding: utf-8 -*-
"""Arrabona Guard - BONGESZO-BOVITMENYEK figyelese (GuardCore mixin). [v2.6.0]

Chromium-alapu bongeszok (Chrome, Edge, Brave, Vivaldi, Opera - minden profil) es
Firefox. Forras:
  - Extensions mappa (boltbol telepitett bovitmenyek), manifest.json (nev, verzio, jogok),
  - Preferences / Secure Preferences: a FEJLESZTOI MODBAN betoltott ("unpacked")
    bovitmenyek is - ezek nincsenek az Extensions mappaban, a kartevok szeretik,
  - Firefox: extensions.json,
  - HAZIREND: ExtensionInstallForcelist (HKLM/HKCU) - a "bongeszodet a szervezeted
    kezeli" trukk: ezt a felhasznalo nem tudja eltavolitani,
  - registry-bol telepitett ("oldalrol betoltott") bovitmenyek.
Uj bovitmeny, uj kenyszeritett bovitmeny, vagy egy meglevo bovitmeny jogosultsagainak
BOVULESE (eladott bovitmeny -> kartevo frissites) -> riasztas, a jogok magyarazataval.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import glob
import json as _json
import os
import threading
import time
import winreg
from .common import (APPDATA_DIR, log_line)

BONG_STATE_FILE = os.path.join(APPDATA_DIR, "bovitmenyek_ismert.json")
BONG_POLL = 60.0

_LOCAL = os.environ.get("LOCALAPPDATA", "")
_ROAM = os.environ.get("APPDATA", "")
_CHROMIUM = (
    ("Chrome", os.path.join(_LOCAL, r"Google\Chrome\User Data")),
    ("Edge", os.path.join(_LOCAL, r"Microsoft\Edge\User Data")),
    ("Brave", os.path.join(_LOCAL, r"BraveSoftware\Brave-Browser\User Data")),
    ("Vivaldi", os.path.join(_LOCAL, r"Vivaldi\User Data")),
    ("Opera", os.path.join(_ROAM, r"Opera Software\Opera Stable")),
    ("Opera GX", os.path.join(_ROAM, r"Opera Software\Opera GX Stable")),
)
_FIREFOX = os.path.join(_ROAM, r"Mozilla\Firefox\Profiles")
_POLICY = (
    ("Chrome", r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"),
    ("Edge", r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"),
    ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallForcelist"),
)
_EXTERNAL = (
    ("Chrome", r"SOFTWARE\Google\Chrome\Extensions"),
    ("Chrome", r"SOFTWARE\WOW6432Node\Google\Chrome\Extensions"),
    ("Edge", r"SOFTWARE\Microsoft\Edge\Extensions"),
    ("Edge", r"SOFTWARE\WOW6432Node\Microsoft\Edge\Extensions"),
)
_W64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
# a hivatalos bovitmeny-boltok frissitesi cimei
_BOLT_URL = ("https://clients2.google.com/service/update2/crx", "http://clients2.google.com/service/update2/crx",
             "https://edge.microsoft.com/extensionwebstorebase/v1/crx")


def _bolt_url(url):
    return (url or "").strip().rstrip("/").lower() in _BOLT_URL

# Chromium "location" kodok
# (Chromium Manifest::Location: 1 INTERNAL, 2 EXTERNAL_PREF, 3 EXTERNAL_REGISTRY, 4 UNPACKED, 5 COMPONENT,
#  6 EXTERNAL_PREF_DOWNLOAD, 7 EXTERNAL_POLICY_DOWNLOAD, 8 COMMAND_LINE, 9 EXTERNAL_POLICY, 10 EXTERNAL_COMPONENT)
_LOC = {1: "bolt", 2: "kulso fajl (program tette fel)", 3: "registry (program tette fel)",
        4: "FEJLESZTOI MOD (unpacked)", 5: "beepitett", 6: "kulso letoltes (program tette fel)",
        7: "HAZIREND (kenyszeritett)", 8: "PARANCSSOR (--load-extension)", 9: "HAZIREND (kenyszeritett)",
        10: "beepitett"}

_SZELES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "*://*/", "<all_urls>/*")
_JOGOK = {   # jogosultsag -> (magyar magyarazat, sulyos?)
    "cookies": ("sütik (bejelentkezések ellopása)", True),
    "webRequest": ("forgalom figyelése", True),
    "webRequestBlocking": ("forgalom módosítása", True),
    "debugger": ("hibakereső (bármit láthat)", True),
    "proxy": ("proxy átállítása (forgalom elterelése)", True),
    "nativeMessaging": ("program futtatása a gépen", True),
    "scripting": ("kód beszúrása oldalakba", True),
    "management": ("más bővítmények kezelése", True),
    "clipboardRead": ("vágólap olvasása", True),
    "history": ("előzmények", False),
    "downloads": ("letöltések", False),
    "privacy": ("adatvédelmi beállítások", False),
    "declarativeNetRequest": ("kérések átírása", False),
    "tabs": ("lapok címei", False),
    "webNavigation": ("böngészés követése", False),
    "contentSettings": ("oldalengedélyek", False),
    "desktopCapture": ("képernyő rögzítése", True),
    "geolocation": ("helymeghatározás", False),
}


# ---------------------------------------------------------------- olvasok
def _json_file(p):
    try:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            return _json.load(f)
    except (OSError, ValueError):
        return None


def _lokalizalt(nev, ext_dir, manifest):
    """__MSG_appName__ -> a _locales/<alap>/messages.json-beli szoveg."""
    if not isinstance(nev, str) or not nev.startswith("__MSG_"):
        return nev
    kulcs = nev[6:].rstrip("_").lower()
    for loc in [manifest.get("default_locale") or "en", "hu", "en", "en_US"]:
        msgs = _json_file(os.path.join(ext_dir, "_locales", loc, "messages.json"))
        if isinstance(msgs, dict):
            for k, v in msgs.items():
                if k.lower() == kulcs and isinstance(v, dict) and v.get("message"):
                    return v["message"]
    return nev


def _manifest_info(ext_dir):
    m = _json_file(os.path.join(ext_dir, "manifest.json"))
    if not isinstance(m, dict):
        return None
    jogok = set()
    for k in ("permissions", "optional_permissions", "host_permissions"):
        for x in m.get(k) or []:
            if isinstance(x, str):
                jogok.add(x)
    for cs in m.get("content_scripts") or []:
        for x in (cs or {}).get("matches") or []:
            if isinstance(x, str):
                jogok.add(x)
    return {"name": str(_lokalizalt(m.get("name") or "?", ext_dir, m))[:80],
            "version": str(m.get("version") or "?"), "perms": sorted(jogok)}


def _chromium_profilok(gyoker):
    if not os.path.isdir(gyoker):
        return []
    if os.path.isdir(os.path.join(gyoker, "Extensions")) and not os.path.isdir(os.path.join(gyoker, "Default")):
        return [("", gyoker)]   # Opera: nincs profil-alkonyvtar
    out = []
    for n in os.listdir(gyoker):
        if n == "Default" or n.startswith("Profile "):
            p = os.path.join(gyoker, n)
            if os.path.isdir(p):
                out.append((n, p))
    return out


def _chromium_settings(profil):
    """extensions.settings a Preferences + Secure Preferences fajlbol (osszefesulve)."""
    s = {}
    for fn in ("Preferences", "Secure Preferences"):
        d = _json_file(os.path.join(profil, fn))
        try:
            st = d["extensions"]["settings"]
            if isinstance(st, dict):
                for k, v in st.items():
                    if isinstance(v, dict):
                        s.setdefault(k, {}).update(v)
        except (KeyError, TypeError):
            pass
    return s


def chromium_extensions(bong, gyoker):
    out = {}
    for pnev, profil in _chromium_profilok(gyoker):
        hely = bong + ((" / " + pnev) if pnev else "")
        settings = _chromium_settings(profil)
        exts = os.path.join(profil, "Extensions")
        idk = set()
        try:
            idk = {i for i in os.listdir(exts) if len(i) == 32 and i.isalpha()}
        except OSError:
            pass
        for eid in idk | set(settings):
            st = settings.get(eid) or {}
            loc = st.get("location")
            if loc in (5, 10) or st.get("was_installed_by_default") or st.get("was_installed_by_oem"):
                continue   # beepitett / gyari
            info = None
            if eid in idk:
                verziok = sorted(glob.glob(os.path.join(exts, eid, "*", "manifest.json")))
                if verziok:
                    info = _manifest_info(os.path.dirname(verziok[-1]))
            if info is None:
                ut = st.get("path")
                if isinstance(ut, str) and os.path.isabs(ut) and os.path.isfile(os.path.join(ut, "manifest.json")):
                    info = _manifest_info(ut)
                    if info is not None:
                        info["path"] = ut
            if info is None:
                continue   # pl. eltavolitott, de a beallitasban bennmaradt
            info["loc"] = _LOC.get(loc, "telepitett" if loc is None else str(loc))
            info["store"] = bool(st.get("from_webstore")) or loc == 1
            info["enabled"] = st.get("state", 1) != 0 and not st.get("disable_reasons")
            info["hely"] = hely
            if loc in (7, 9):
                info["policy"] = True
                info["url"] = st.get("update_url") or ""
            elif loc in (2, 3, 6):
                info["external"] = True
                info["store"] = bool(st.get("from_webstore")) or _bolt_url(st.get("update_url"))
            out["%s|%s" % (hely, eid)] = info
    return out


def firefox_extensions():
    out = {}
    for prof in glob.glob(os.path.join(_FIREFOX, "*")):
        d = _json_file(os.path.join(prof, "extensions.json"))
        if not isinstance(d, dict):
            continue
        hely = "Firefox / " + os.path.basename(prof).split(".", 1)[-1]
        for a in d.get("addons") or []:
            if not isinstance(a, dict) or a.get("type") != "extension":
                continue
            if (a.get("location") or "").startswith(("app-builtin", "app-system")):
                continue
            up = a.get("userPermissions") or {}
            out["%s|%s" % (hely, a.get("id"))] = {
                "name": str(((a.get("defaultLocale") or {}).get("name")) or a.get("id"))[:80],
                "version": str(a.get("version") or "?"),
                "perms": sorted(set((up.get("permissions") or []) + (up.get("origins") or []))),
                "loc": "bolt" if (a.get("sourceURI") or "").startswith("https://addons.mozilla.org") else
                       (a.get("location") or "?"),
                "store": (a.get("sourceURI") or "").startswith("https://addons.mozilla.org"),
                "enabled": bool(a.get("active")) and not a.get("userDisabled"),
                "hely": hely}
    return out


def _reg_list(gy, ut, kulcsok=False):
    try:
        k = winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | _W64)
    except OSError:
        return {}
    out = {}
    try:
        i = 0
        while True:
            try:
                if kulcsok:
                    n = winreg.EnumKey(k, i)
                    out[n] = ""
                else:
                    n, v, _t = winreg.EnumValue(k, i)
                    out[n] = str(v)
            except OSError:
                break
            i += 1
    finally:
        winreg.CloseKey(k)
    return out


def policy_extensions():
    """Kenyszeritett (hazirend) + registry-bol telepitett bovitmenyek."""
    out = {}
    for gy, gnev in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
        for bong, ut in _POLICY:
            for _n, v in _reg_list(gy, ut).items():
                eid, _, url = v.partition(";")
                eid = eid.strip()
                if eid:
                    out["Hazirend %s %s|%s" % (bong, gnev, eid)] = {
                        "name": eid, "version": "-", "perms": [], "loc": "HAZIREND (kenyszeritett)",
                        "store": (not url.strip()) or _bolt_url(url),
                        "url": url.strip(), "enabled": True, "hely": "%s házirend (%s)" % (bong, gnev),
                        "policy": True, "regkulcs": "%s\\%s" % (gnev, ut)}
    for bong, ut in _EXTERNAL:
        for eid in _reg_list(winreg.HKEY_LOCAL_MACHINE, ut, kulcsok=True):
            ertekek = _reg_list(winreg.HKEY_LOCAL_MACHINE, ut + "\\" + eid)
            url = ertekek.get("update_url", "")
            helyi = ertekek.get("path", "")
            bolt = _bolt_url(url) and not helyi
            out["Registry %s|%s" % (bong, eid)] = {
                "name": eid, "version": "-", "perms": [],
                "loc": "program telepitette a boltbol" if bolt else
                       "registry: %s" % (helyi or url or "ismeretlen forras"),
                "store": bolt, "url": url, "enabled": True, "hely": "%s registry" % bong, "external": True,
                "regkulcs_ext": "HKLM\\%s\\%s" % (ut, eid)}
    return out


def extensions_snapshot():
    snap = {}
    for bong, gy in _CHROMIUM:
        try:
            snap.update(chromium_extensions(bong, gy))
        except Exception as e:
            log_line("[BONGESZO] %s olvasasi hiba: %s" % (bong, e))
    try:
        snap.update(firefox_extensions())
    except Exception as e:
        log_line("[BONGESZO] Firefox olvasasi hiba: %s" % e)
    try:
        pol = policy_extensions()
    except Exception as e:
        log_line("[BONGESZO] hazirend olvasasi hiba: %s" % e)
        pol = {}
    # a registry-bol (oldalrol) telepitett bovitmeny a profilban is megjelenik: egyszer szamoljuk.
    # A registry adja meg, honnan jon (hivatalos bolt vagy idegen cim / helyi fajl).
    profil_idk = {}
    for k, e in snap.items():
        profil_idk.setdefault(k.split("|", 1)[1], []).append(e)
    for k, e in pol.items():
        eid = k.split("|", 1)[1]
        if e.get("external") and eid in profil_idk:
            for pe in profil_idk[eid]:
                pe["external"] = True
                pe["store"] = bool(e.get("store"))
                pe["loc"] = e["loc"]
                if not e.get("store"):
                    pe["regkulcs_ext"] = e.get("regkulcs_ext")
            continue
        snap[k] = e
    return snap


def kockazat(info, csak=None):
    """(szint 0-2, [magyar okok]). csak: ha megadott, csak ezeket a jogokat nezi (bovules)."""
    jogok = set(info.get("perms") or []) if csak is None else set(csak)
    okok = []
    szeles = any(j in _SZELES or j.startswith(("*://*", "http://*/", "https://*/")) for j in jogok)
    if szeles:
        okok.append("MINDEN weboldalt lát és módosíthat")
    sulyos = False
    for j in sorted(jogok):
        if j in _JOGOK:
            okok.append(_JOGOK[j][0])
            sulyos = sulyos or _JOGOK[j][1]
    szint = 2 if (szeles and sulyos) else (1 if (szeles or sulyos) else 0)
    if csak is None:
        if info.get("policy"):
            szint = 2
            okok.insert(0, "HÁZIRENDDEL KÉNYSZERÍTVE (nem távolítható el)" +
                        ("" if info.get("store") else ", NEM a hivatalos boltból: %s" % (info.get("url") or "?")))
        if info.get("external"):
            if info.get("store"):
                okok.insert(0, "egy program telepítette a hivatalos boltból (pl. vírusirtó, Adobe) - rendben")
            else:
                szint = max(szint, 1)
                okok.insert(0, "egy program telepítette, NEM a hivatalos boltból (%s)" % (info.get("loc") or "?"))
        if "unpacked" in (info.get("loc") or ""):
            szint = 2
            okok.insert(0, "FEJLESZTŐI MÓDBAN betöltve (nem boltból): %s" % info.get("path", "?"))
        if "PARANCSSOR" in (info.get("loc") or ""):
            szint = 2
            okok.insert(0, "PARANCSSORBÓL betöltve (--load-extension) - kártevő trükk")
    return szint, okok


def gyanus_forras(info):
    """Nem a felhasznalo telepitette a boltbol: hazirend / fejlesztoi mod / parancssor / program tette fel."""
    loc = info.get("loc") or ""
    if info.get("policy"):
        return True   # kenyszeritett: mindig jelezzuk (otthoni gepen ennek nincs helye)
    if info.get("external"):
        return not info.get("store")
    return "unpacked" in loc or "PARANCSSOR" in loc


# ---------------------------------------------------------------- mixin
class BrowserMixin(object):
    """Bongeszo-bovitmenyek figyelese. A GuardCore resze (mixin)."""

    def _bong_load(self):
        d = _json_file(BONG_STATE_FILE)
        return d if isinstance(d, dict) else None

    def _bong_save(self, d):
        try:
            tmp = BONG_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(d, f, ensure_ascii=False)
            os.replace(tmp, BONG_STATE_FILE)
        except OSError as e:
            log_line("[BONGESZO] mentesi hiba: %s" % e)

    def _bong_check(self, indulas=False):
        most = extensions_snapshot()
        regi = self._bong_known
        if regi is None:
            self._bong_known = most
            self._bong_save(most)
            log_line("[BONGESZO] alapallapot: %d bovitmeny ismertnek jelolve" % len(most))
            for k, e in most.items():
                szint, okok = kockazat(e)
                if gyanus_forras(e):
                    self.alert("127.0.0.1", "[BONGESZO] Mar most is GYANUS bovitmeny: %s - %s (%s) | %s" % (
                        e["hely"], e["name"], k.split("|", 1)[1], "; ".join(okok)), always=True)
            self.bong_status = "aktív"
            return
        if most == regi:
            self.bong_status = "aktív"
            return
        for k, e in most.items():
            r = regi.get(k)
            if r is None:
                self._bong_alert("UJ", k, e, None, indulas)
            else:
                uj_jogok = sorted(set(e.get("perms") or []) - set(r.get("perms") or []))
                if uj_jogok:
                    self._bong_alert("JOG", k, e, uj_jogok, indulas)
                elif e.get("version") != r.get("version"):
                    log_line("[BONGESZO] frissult: %s - %s %s -> %s" % (e["hely"], e["name"],
                                                                        r.get("version"), e.get("version")))
        for k in regi:
            if k not in most:
                log_line("[BONGESZO] eltavolitva: %s - %s" % (regi[k].get("hely"), regi[k].get("name")))
        self._bong_known = most
        self._bong_save(most)
        self.bong_status = "aktív"

    def _bong_alert(self, mi, kulcs, e, uj_jogok, indulas):
        eid = kulcs.split("|", 1)[1]
        if mi == "JOG":
            szint, okok = kockazat(e, csak=uj_jogok)
            fej = "BOVITMENY UJ JOGOSULTSAGOT KAPOTT (frissites)"
            reszlet = "uj jogok: %s" % ", ".join(uj_jogok[:8])
        else:
            szint, okok = kockazat(e)
            fej = "UJ BONGESZO-BOVITMENY"
            reszlet = "forras: %s%s" % (e.get("loc") or "?", "" if e.get("enabled", True) else ", letiltva")
        if mi == "UJ" and gyanus_forras(e):
            fej = "GYANUS " + fej          # nem boltbol / nem te telepitetted
        elif mi == "JOG" and szint >= 1:
            fej = "FIGYELEM: " + fej       # eladott bovitmeny -> kartevo frissites gyanuja
        elif szint >= 2:
            fej = fej + " (SOK JOGOT KER)"
        self.bong_changes = getattr(self, "bong_changes", 0) + 1
        self._bong_recent = ([{"ts": time.time(), "mi": mi, "hely": e["hely"], "name": e["name"],
                               "id": eid, "szint": szint}] + list(getattr(self, "_bong_recent", [])))[:20]
        msg = "[BONGESZO] %s%s: %s - %s v%s (%s) | %s" % (
            fej, " (a Guard leallasa alatt)" if indulas else "", e["hely"], e["name"], e.get("version", "?"),
            eid, reszlet)
        if okok:
            msg += " | Jogok: %s" % "; ".join(okok)
        if e.get("regkulcs_ext") and not e.get("store"):
            msg += (" | Eltavolitas: a bongeszobol torolve a program ujra felteszi - elobb a registry-kulcsot "
                    "torold (regedit, rendszergazda): %s" % e["regkulcs_ext"])
        elif e.get("regkulcs"):
            msg += (" | Eltavolitas: a bongeszobol NEM lehet - torold a registry-erteket (regedit, rendszergazda): %s"
                    % e["regkulcs"])
        elif szint >= 1 or gyanus_forras(e):
            msg += " | Ha nem te telepitetted: tavolitsd el (chrome://extensions / edge://extensions / about:addons)"
        self.alert("127.0.0.1", msg, always=True)

    def _bong_loop(self):
        elso = True
        while not self._bong_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    self._bong_check(indulas=elso)
                    elso = False
            except Exception as ex:
                log_line("[BONGESZO] figyelo hiba: %s" % ex)
            self._bong_stop_ev.wait(BONG_POLL)

    def _bong_start(self):
        if getattr(self, "_bong_thread", None) and self._bong_thread.is_alive():
            return
        self._bong_known = self._bong_load()
        self.bong_changes = getattr(self, "bong_changes", 0)
        self.bong_status = "indulás…"
        self._bong_recent = getattr(self, "_bong_recent", [])
        self._bong_started = time.time()
        self._bong_stop_ev = threading.Event()
        self._bong_thread = threading.Thread(target=self._bong_loop, name="bongeszo", daemon=True)
        self._bong_thread.start()
        log_line("[BONGESZO] figyeles aktiv: Chrome/Edge/Brave/Vivaldi/Opera/Firefox + hazirend")

    def _bong_stop(self):
        ev = getattr(self, "_bong_stop_ev", None)
        if ev is not None:
            ev.set()

    def browser_summary(self):
        known = getattr(self, "_bong_known", None) or {}
        veszelyes = sum(1 for e in known.values() if kockazat(e)[0] >= 2)
        reszek = ["Bővítmény: %d" % len(known), "Sok joggal: %d" % veszelyes,
                  "Új (futam): %d" % getattr(self, "bong_changes", 0)]
        rec = getattr(self, "_bong_recent", [])
        if rec:
            reszek.append("Utolsó: %s%s" % (rec[0]["name"][:24], " ⚠" if rec[0]["szint"] >= 2 else ""))
        return " | ".join(reszek)

    def browser_text(self):
        known = getattr(self, "_bong_known", None) or {}
        sorok = ["Bongeszo-bovitmenyek: %d" % len(known)]
        hely = None
        for k in sorted(known, key=lambda x: (known[x]["hely"], known[x]["name"].lower())):
            e = known[k]
            if e["hely"] != hely:
                hely = e["hely"]
                sorok.append("[%s]" % hely)
            szint, _o = kockazat(e)
            sorok.append("  %s v%s%s%s" % (e["name"][:40], e.get("version", "?"),
                                           "" if e.get("enabled", True) else " (letiltva)",
                                           "  <-- SOK JOG" if szint >= 2 else ""))
        return "\n".join(sorok)
