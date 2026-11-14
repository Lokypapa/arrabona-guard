# -*- coding: utf-8 -*-
"""Arrabona Guard - LETOLTESEK AUTOMATIKUS VIZSGALATA (GuardCore mixin). [v2.15.0]

A Letoltesek mappaba (es a letoltes.txt-ben megadott tovabbi mappakba) erkezo
minden futtathato / veszelyes fajlt MEG AZ ELINDITAS ELOTT megnez:
  - honnan jott (a Windows "Zone.Identifier" jelolesebol: letoltesi oldal),
  - digitalis alairas (exe, msi, dll, msix...),
  - trukkok: dupla kiterjesztes (szamla.pdf.exe), RTLO-karakter, .scr / .hta /
    .js / .vbs / .lnk letoltes, makros Office-fajl, lemezkep (ISO/IMG/VHD),
  - ZIP: futtathato fajl van-e benne, JELSZAVAS-e (a kartevok kedvelt modszere,
    mert a vírusirto nem latja bele), dupla kiterjesztes a ZIP-en belul,
  - aláiratlan / gyanus esetben: Defender-vizsgalat + VirusTotal (ha van kulcs).
A rendben levo (ervenyes alairasu) programokrol csak naplo-sor keszul.
A bongeszo ideiglenes fajljait (.crdownload, .part, .tmp) megvarja, amig a
letoltes befejezodik.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import os
import re
import threading
import time
import zipfile
from .common import (APPDATA_DIR, log_line)

LETOLTES_CFG_FILE = os.path.join(APPDATA_DIR, "letoltes.txt")
POLL = 2.0
_IDEIGLENES = (".crdownload", ".part", ".partial", ".download", ".tmp", ".opdownload", ".!ut")
_FUTTATHATO = {".exe", ".msi", ".scr", ".com", ".pif", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
               ".wsh", ".hta", ".ps1", ".lnk", ".dll", ".cpl", ".jar", ".msix", ".msixbundle", ".appx",
               ".appxbundle", ".reg", ".chm", ".application", ".msc", ".scf", ".url", ".appref-ms"}
_SZKRIPT = {".scr", ".hta", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".lnk", ".chm", ".cpl", ".scf",
            ".application", ".appref-ms"}
_ALAIRHATO = {".exe", ".msi", ".dll", ".msix", ".msixbundle", ".appx", ".appxbundle", ".cpl", ".scr", ".ps1"}
_TOMORITETT = {".zip", ".rar", ".7z", ".cab", ".gz", ".tar", ".tgz", ".xz", ".bz2", ".arj", ".ace", ".r00"}
_LEMEZKEP = {".iso", ".img", ".vhd", ".vhdx"}
_MAKROS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam", ".sldm", ".one", ".xll"}
_DUPLA = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|rtf|mp[34]|avi|mkv|mov|wav|zip|rar|7z|html?)"
                    r"\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|hta|lnk|msi|wsf)$", re.I)
_SZINT_NEV = {3: "VESZELYES", 2: "NAGYON GYANUS", 1: "GYANUS"}


def letoltes_cfg():
    cfg = {"FIGYELES": "BE", "VT": "BE", "DEFENDER": "BE", "MAPPA": []}
    try:
        if not os.path.exists(LETOLTES_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(LETOLTES_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - letoltesek automatikus vizsgalata (v2.15.0)\n"
                        "FIGYELES BE\n"
                        "# DEFENDER BE = alairatlan / gyanus letoltes azonnali Defender-vizsgalata\n"
                        "DEFENDER BE\n"
                        "# VT BE = VirusTotal-lekerdezes (csak ha a virustotal.txt-ben van KULCS)\n"
                        "VT BE\n"
                        "# MAPPA <ut> = tovabbi figyelt mappa (a Letoltesek mindig figyelve van), pl.:\n"
                        "# MAPPA D:\\Letoltesek\n")
        with open(LETOLTES_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip().strip('"') if len(r) > 1 else "")
                if k == "MAPPA" and v:
                    cfg["MAPPA"].append(os.path.expandvars(v))
                elif k in ("FIGYELES", "VT", "DEFENDER") and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg[k] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def bongeszo_letoltesi_mappak():
    """[v2.15.1] A bongeszokben BEALLITOTT letoltesi mappak (ha nem az alapertelmezett Letoltesek)."""
    import json as _j
    out = []
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    gyokerek = [os.path.join(local, *r) for r in (("Google", "Chrome", "User Data"), ("Microsoft", "Edge", "User Data"),
                                                 ("BraveSoftware", "Brave-Browser", "User Data"), ("Vivaldi", "User Data"))]
    prefs = []
    for gy in gyokerek:
        try:
            for d in os.listdir(gy):
                if d == "Default" or d.startswith("Profile "):
                    prefs.append(os.path.join(gy, d, "Preferences"))
        except OSError:
            pass
    for o in ("Opera Stable", "Opera GX Stable"):
        prefs.append(os.path.join(roaming, "Opera Software", o, "Preferences"))
    for p in prefs:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                d = (_j.load(f).get("download") or {}).get("default_directory")
            if d:
                out.append(d)
        except Exception:
            pass
    ff = os.path.join(roaming, "Mozilla", "Firefox", "Profiles")
    try:
        for d in os.listdir(ff):
            try:
                with open(os.path.join(ff, d, "prefs.js"), "r", encoding="utf-8", errors="ignore") as f:
                    m = re.search(r'user_pref\("browser\.download\.dir",\s*"((?:[^"\\]|\\.)*)"\)', f.read())
                if m:
                    out.append(m.group(1).replace("\\\\", "\\"))
            except OSError:
                pass
    except OSError:
        pass
    return out


def letoltes_mappak(cfg):
    out = []
    try:
        from .csali import _shell_folder
        d = _shell_folder("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads")
    except Exception:
        d = os.path.join(os.path.expanduser("~"), "Downloads")
    try:
        bong = bongeszo_letoltesi_mappak()
    except Exception:
        bong = []
    for p in [d] + bong + list(cfg.get("MAPPA") or []):
        if p and os.path.isdir(p) and os.path.normcase(p) not in [os.path.normcase(x) for x in out]:
            out.append(p)
    return out


def zona_info(p):
    """A Windows letoltes-jelolese (Zone.Identifier ADS): {"zona", "url", "referrer"} vagy {}."""
    try:
        with open(p + ":Zone.Identifier", "r", encoding="utf-8", errors="ignore") as f:
            t = f.read()
    except OSError:
        return {}
    d = {}
    for ln in t.splitlines():
        k, _, v = ln.partition("=")
        k = k.strip().lower()
        if k == "zoneid":
            d["zona"] = v.strip()
        elif k == "hosturl":
            d["url"] = v.strip()
        elif k == "referrerurl":
            d["referrer"] = v.strip()
    return d


def domain(url):
    m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", url or "", re.I)
    return m.group(1).lower() if m else ""


def zip_vizsgal(p):
    """[(szint, ok)] egy ZIP tartalmarol (kicsomagolas nelkul)."""
    okok = []
    try:
        with zipfile.ZipFile(p) as z:
            nevek = z.infolist()
            futt = [i for i in nevek if os.path.splitext(i.filename)[1].lower() in _FUTTATHATO - {".url"}]
            # [v2.15.2] forraskod-csomag (pl. GitHub "Download ZIP"): a .js / .bat a projekt resze
            forraskod = any(os.path.basename(i.filename).lower() in ("package.json", "readme.md", "makefile",
                                                                      "cmakelists.txt", ".gitignore", "setup.py")
                            for i in nevek) and sum(1 for i in nevek if os.path.splitext(i.filename)[1].lower() in
                                                    (".js", ".ts", ".py", ".c", ".cpp", ".h", ".cs", ".lua", ".json",
                                                     ".md", ".html", ".css", ".sql")) >= 5
            jelszavas = any(i.flag_bits & 0x1 for i in nevek)
            dupla = [i.filename for i in nevek if _DUPLA.search(os.path.basename(i.filename))]
            belso = [i.filename for i in nevek if os.path.splitext(i.filename)[1].lower() in _TOMORITETT | _LEMEZKEP]
            if dupla:
                okok.append((3, "a ZIP-ben dupla kiterjesztésű fájl van (%s)" % os.path.basename(dupla[0])[:60]))
            if jelszavas and futt:
                okok.append((3, "JELSZAVAS ZIP futtatható fájllal (%s) - a vírusirtó nem lát bele, "
                                "tipikus kártevő-terjesztés" % os.path.basename(futt[0].filename)[:60]))
            elif jelszavas:
                okok.append((1, "jelszavas ZIP (a vírusirtó nem lát bele)"))
            szkr = [i for i in futt if os.path.splitext(i.filename)[1].lower() in _SZKRIPT]
            if forraskod and not jelszavas and not dupla:
                return []      # forraskod: nem riasztunk (a futtathato fajlok forrasbol epulnek)
            if szkr:
                okok.append((2, "a ZIP-ben szkript / parancsikon van (%s)" % os.path.basename(szkr[0].filename)[:60]))
            elif futt and not jelszavas:
                okok.append((1, "a ZIP-ben futtatható fájl van (%d db, pl. %s)" % (
                    len(futt), os.path.basename(futt[0].filename)[:60])))
            if belso and (jelszavas or futt):
                okok.append((1, "a ZIP-ben további tömörített fájl / lemezkép van (%s)" % os.path.basename(belso[0])[:60]))
            # aranytalanul nagy kibontott meret (pl. 700 MB-ra "felfujt" exe a vírusirto kijatszasara)
            for i in futt:
                if i.file_size > 300 * 1024 * 1024 and i.compress_size < i.file_size / 50:
                    okok.append((2, "a ZIP-ben irreálisan nagyra felfújt futtatható fájl (%s, %d MB) - "
                                    "vírusirtó-kijátszás" % (os.path.basename(i.filename)[:40], i.file_size // 1048576)))
                    break
    except zipfile.BadZipFile:
        okok.append((1, "sérült / nem szabványos ZIP"))
    except Exception:
        pass
    return okok


def fajl_okok(p):
    """[(szint, ok)] alairas NELKUL (az kulon jon)."""
    nev = os.path.basename(p)
    ext = os.path.splitext(nev)[1].lower()
    okok = []
    if u"\u202e" in nev:
        okok.append((3, "fordított írásirányú (RTLO) karakter a névben - kiterjesztés-hamisítás"))
    if _DUPLA.search(nev):
        okok.append((3, "dupla kiterjesztés (%s) - dokumentumnak álcázott program" % nev[-30:]))
    if ext in _SZKRIPT:
        okok.append((2, "%s fájl - ilyet szinte csak kártevők terjesztenek letöltésként" % ext))
    elif ext in (".bat", ".cmd", ".ps1", ".vbs"):
        okok.append((2, "parancsfájl (%s) - csak akkor futtasd, ha tudod, mit csinál" % ext))
    if ext in _MAKROS:
        okok.append((2, "makrós Office / OneNote fájl - ne engedélyezd a makrókat / tartalmat"))
    if ext in _LEMEZKEP:
        okok.append((1, "lemezkép (%s) - a benne levő .exe / .lnk fájlokat ne futtasd, ha nem ismered" % ext))
    if ext == ".zip":
        okok.extend(zip_vizsgal(p))
    try:
        if ext in (".exe", ".msi", ".scr") and os.path.getsize(p) < 12 * 1024:
            okok.append((1, "gyanúsan kicsi telepítő (letöltő-program lehet)"))
    except OSError:
        pass
    return okok


def erdekes(p):
    ext = os.path.splitext(p)[1].lower()
    return ext in _FUTTATHATO or ext in _TOMORITETT or ext in _LEMEZKEP or ext in _MAKROS or \
        u"\u202e" in os.path.basename(p)


class LetoltesMixin(object):
    """Letoltesek automatikus vizsgalata. A GuardCore resze (mixin)."""

    def _dl_pillanat(self, mappak):
        """{ut: (meret, mtime)} a figyelt mappak 1. szintjen (+ 1 almappa szint)."""
        out = {}
        for m in mappak:
            try:
                with os.scandir(m) as it:
                    for e in it:
                        try:
                            if e.is_file():
                                st = e.stat()
                                out[e.path] = (st.st_size, st.st_mtime)
                            elif e.is_dir() and time.time() - e.stat().st_mtime < 3600:
                                # frissen letrehozott almappa (pl. kicsomagolt ZIP)
                                with os.scandir(e.path) as it2:
                                    for e2 in it2:
                                        # kicsomagolt mappaban a DLL-ek nem erdekesek (jatekoknal szazval)
                                        if e2.is_file() and not e2.name.lower().endswith(".dll"):
                                            st = e2.stat()
                                            out[e2.path] = (st.st_size, st.st_mtime)
                        except OSError:
                            pass
            except OSError:
                pass
        return out

    def _dl_vizsgal(self, p):
        from .alairas import sig_one, sig_szoveg, sig_veszely
        cfg = self._dl_cfg
        nev = os.path.basename(p)
        ext = os.path.splitext(nev)[1].lower()
        okok = fajl_okok(p)
        z = zona_info(p)
        forras = domain(z.get("url")) or domain(z.get("referrer"))
        sig = None
        if ext in _ALAIRHATO:
            sig = sig_one(p)
            v = sig_veszely(sig)
            if v == 2:
                okok.append((3, "ÉRVÉNYTELEN aláírás - a fájlt aláírás után módosították"))
            elif v == 1 and ext in (".exe", ".msi", ".scr", ".msix", ".appx"):
                okok.append((1, "aláíratlan program" if (sig or {}).get("allapot") == "nincs"
                             else "nem megbízható tanúsítvánnyal aláírt program"))
        self.dl_db += 1
        szint = max([o[0] for o in okok] or [0])
        rec = {"ts": time.time(), "nev": nev, "ut": p, "szint": szint, "forras": forras,
               "okok": "; ".join(o[1] for o in okok), "sig": sig_szoveg(sig, ekezet=False) if sig else ""}
        with self._dl_lock:
            self._dl_recent = ([rec] + self._dl_recent)[:40]
        if szint == 0:
            log_line("[LETOLTES] rendben: %s%s%s" % (nev, (" | " + rec["sig"]) if sig else "",
                                                      (" | forras: " + forras) if forras else ""))
            return
        self.dl_gyanus += 1
        # Defender + VirusTotal
        vizsg = ""
        if cfg["DEFENDER"] == "BE":
            try:
                from .defender import scan_allapot
                ok = self.defender_scan("custom", p, elozmeny=[("Új letöltés: %s" % nev[:50], time.time()),
                                                               ("Ok: %s" % okok[0][1][:70], time.time())],
                                        cimke="Letöltés: %s" % nev[:40])
                vizsg = " | Defender-vizsgalat %s" % scan_allapot(ok)
            except Exception as e:
                log_line("[LETOLTES] vizsgalati hiba: %s" % e)
        if cfg["VT"] == "BE" and hasattr(self, "vt_kerd"):
            try:
                if self.vt_kerd(p, "Letöltés: %s" % nev[:40]):
                    vizsg += " | VirusTotal: sorban"
            except Exception:
                pass
        msg = "[LETOLTES] %s LETOLTES: %s%s | Gyanus: %s%s%s" % (
            _SZINT_NEV.get(szint, "GYANUS"), nev, (" | Forras: %s" % forras) if forras else " | Forras: ismeretlen",
            rec["okok"], (" | Alairas: " + rec["sig"]) if sig else "", vizsg)
        msg += (" | NE INDITSD EL! Ha nem tudod, mi ez: karantenba vele." if szint >= 2 else
                " | Csak akkor inditsd, ha megbizhato helyrol, tudatosan toltotted le.")
        gombok = []
        try:
            from .telegram import tg_action
            gombok.append([("🗄 Karanténba", tg_action("pq", {"pid": None, "ctime": 0, "fajl": p}))])
            gombok.append([("✅ Rendben / én töltöttem le", "ok")])
        except Exception:
            gombok = None
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)

    def _dl_loop(self):
        ismert = None
        varo = {}         # ut -> (meret, mtime, hanyszor_volt_ugyanaz)
        utolso_cfg = 0.0
        mappak = []
        while not self._dl_stop_ev.wait(POLL):
            try:
                most = time.time()
                if most - utolso_cfg >= 30:
                    utolso_cfg = most
                    self._dl_cfg = letoltes_cfg()
                    mappak = letoltes_mappak(self._dl_cfg)
                    if mappak != self._dl_mappak:
                        log_line("[LETOLTES] figyelt mappak: %s" % (", ".join(mappak) or "NINCS (nem talalom a Letoltesek mappat)"))
                        # [v2.15.2] menet kozben hozzaadott mappa: a mar benne levo fajlok ismertek
                        # (korabban az egesz mappat "uj letoltesnek" vette -> riasztas-aradat)
                        ujak = [m for m in mappak if m not in self._dl_mappak]
                        if ismert is not None and ujak:
                            ismert.update(self._dl_pillanat(ujak))
                    self._dl_mappak = mappak
                if self._dl_cfg["FIGYELES"] != "BE":
                    self.letoltes_status = "kikapcsolva (letoltes.txt)"
                    ismert = None
                    continue
                if not mappak:
                    self.letoltes_status = "nincs Letöltések mappa"
                    continue
                pill = self._dl_pillanat(mappak)
                if ismert is None:
                    ismert = pill          # induláskor a meglevo fajlok ismertek
                    self.letoltes_status = "aktív"
                    continue
                self.letoltes_status = "aktív"
                keszek = []
                for p, adat in pill.items():
                    if ismert.get(p) == adat:
                        continue
                    if os.path.splitext(p)[1].lower() in _IDEIGLENES or not erdekes(p):
                        ismert[p] = adat
                        continue
                    if adat[0] == 0 or any(os.path.exists(p + x) for x in (".part", ".crdownload", ".download")):
                        continue        # Firefox: a vegleges nevu ures fajl + .part letoltes kozben
                    v = varo.get(p)
                    if v and v[0] == adat:
                        # 2 egymas utani korben valtozatlan: kesz a letoltes
                        if v[1] >= 1:
                            varo.pop(p, None)
                            ismert[p] = adat
                            if self.is_on() and not self.is_paused():
                                keszek.append(p)
                        else:
                            varo[p] = (adat, v[1] + 1)
                    else:
                        varo[p] = (adat, 0)
                if keszek:
                    # alairas kotegelve (1 PowerShell-hivas), utana a vizsgalat a gyorsitotarbol
                    try:
                        from .alairas import sig_check
                        sig_check([k for k in keszek if os.path.splitext(k)[1].lower() in _ALAIRHATO][:60])
                    except Exception:
                        pass
                    for p in keszek[:60]:
                        try:
                            self._dl_vizsgal(p)
                        except Exception as e:
                            log_line("[LETOLTES] hiba (%s): %s" % (p, e))
                for p in [x for x in ismert if x not in pill]:
                    ismert.pop(p, None)
                    varo.pop(p, None)
            except Exception as e:
                log_line("[LETOLTES] figyelo hiba: %s" % e)
                self._dl_stop_ev.wait(10.0)

    def _letoltes_start(self):
        if getattr(self, "_dl_thread", None) and self._dl_thread.is_alive():
            return
        self._dl_cfg = letoltes_cfg()
        self._dl_lock = threading.Lock()
        self._dl_recent = getattr(self, "_dl_recent", [])
        self._dl_mappak = []
        self.dl_db = 0
        self.dl_gyanus = getattr(self, "dl_gyanus", 0)
        self.letoltes_status = "indulás…"
        self._dl_stop_ev = threading.Event()
        self._dl_thread = threading.Thread(target=self._dl_loop, name="letoltes", daemon=True)
        self._dl_thread.start()
        log_line("[LETOLTES] letoltes-figyeles indul (Defender: %s, VirusTotal: %s)" % (
            self._dl_cfg["DEFENDER"], self._dl_cfg["VT"]))

    def _letoltes_stop(self):
        ev = getattr(self, "_dl_stop_ev", None)
        if ev is not None:
            ev.set()

    def letoltes_summary(self):
        if getattr(self, "letoltes_status", "") != "aktív":
            return getattr(self, "letoltes_status", "?")
        reszek = ["Vizsgálva (futam): %d" % getattr(self, "dl_db", 0),
                  "Gyanús: %d" % getattr(self, "dl_gyanus", 0)]
        rec = [r for r in getattr(self, "_dl_recent", []) if r["szint"]]
        if rec:
            reszek.append("Utolsó: %s ⚠" % rec[0]["nev"][:24])
        return " | ".join(reszek)

    def letoltes_text(self):
        sorok = ["LETOLTESEK: %s" % self.letoltes_summary().replace(" | ", ", "),
                 "Figyelt mappak: %s" % (", ".join(getattr(self, "_dl_mappak", [])) or "-")]
        rec = getattr(self, "_dl_recent", [])
        if rec:
            sorok.append("Legutobbi letoltesek:")
            for r in rec[:12]:
                sorok.append("  %s %s %s%s%s" % (
                    time.strftime("%m-%d %H:%M", time.localtime(r["ts"])),
                    ("[%s]" % _SZINT_NEV[r["szint"]]) if r["szint"] else "[rendben]", r["nev"][:50],
                    (" (%s)" % r["forras"]) if r["forras"] else "", (" - " + r["okok"][:100]) if r["okok"] else ""))
        else:
            sorok.append("Meg nem volt uj letoltes.")
        return "\n".join(sorok)
