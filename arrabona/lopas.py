# -*- coding: utf-8 -*-
"""Arrabona Guard - INFOSTEALER-CSAPDA (GuardCore mixin). [v2.13.0]

A mai leggyakoribb kartevok (RedLine, Lumma, Vidar, Raccoon...) a bongeszokben
tarolt jelszavakat, sutiket (= belepett munkamenetek) es a kriptotarcakat lopjak.
Ehhez el kell olvasniuk bizonyos fajlokat. A Guard ezeket a fajlokat "megjeloli"
(Windows-naplozas: SACL, csak az OLVASAST naplozza), es 2 mp-enkent megnezi, ki
olvasta oket (4663-as esemeny a Biztonsagi naplobol: PONTOSAN melyik program).

  1) VALODI fajlok: Chrome / Edge / Brave / Opera / Vivaldi / Yandex: Local State
     (a jelszavak titkositasi kulcsa), Login Data, Cookies, Web Data (bankkartya);
     Firefox: logins.json, key4.db, cookies.sqlite.
     A bongeszo sajat folyamatai (alairt, telepitett) nem szamitanak.
  2) CSALIK: csak olyan program helyere, ami NINCS telepitve (Yandex bongeszo,
     Opera GX, Exodus es Electrum tarca, FileZilla). Ezekhez ember es normal
     program nem nyul - aki megis olvassa, az szinte biztosan adatlopo.

  3) [v2.20.0] ARRABONA PASS: a jelszotrezor (vault.apv, .bak, hello.json) es a
     biztonsagi mentesek. Csak maga az Arrabona Pass olvashatja oket - ha mas
     program nyul hozzajuk, ugyanugy riaszt (es felfuggeszti), mint a bongeszoknel.
     A mappakra oroklodo naplozas kerul, igy a Pass mentesei utan is ervenyes marad.

Teendo (infolopas.txt): AKCIO FELFUGGESZT (alap) / LEALLIT / RIASZT,
CSALIK BE/KI, VALODI BE/KI, KIVETEL <reszlet>.
Rendszergazdai jog kell hozza (naplozasi hazirend + SACL).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import base64
import json as _json
import os
import random
import subprocess
import threading
import time
from .common import (APPDATA_DIR, WINDIR, dec_ki, log_line)

LOPAS_CFG_FILE = os.path.join(APPDATA_DIR, "infolopas.txt")
LOPAS_STATE_FILE = os.path.join(APPDATA_DIR, "infolopas_csalik.json")
POLL = 2.0
SACL_FRISSIT = 600.0           # a bongeszo neha ujrairja a fajlt (pl. Local State) -> jeloles ujra
_AUDIT_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"   # File System (4663)
LOCAL = os.environ.get("LOCALAPPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Local"))
ROAMING = os.environ.get("APPDATA", os.path.join(os.path.expanduser("~"), "AppData", "Roaming"))
PF = [os.environ.get(k) for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432") if os.environ.get(k)]

# (nev, gyoker, a profilok a gyokerben vannak-e (Opera))
_CHROMIUM = (
    ("Chrome", os.path.join(LOCAL, "Google", "Chrome", "User Data"), False),
    ("Edge", os.path.join(LOCAL, "Microsoft", "Edge", "User Data"), False),
    ("Brave", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser", "User Data"), False),
    ("Vivaldi", os.path.join(LOCAL, "Vivaldi", "User Data"), False),
    ("Yandex", os.path.join(LOCAL, "Yandex", "YandexBrowser", "User Data"), False),
    ("Chromium", os.path.join(LOCAL, "Chromium", "User Data"), False),
    ("Opera", os.path.join(ROAMING, "Opera Software", "Opera Stable"), True),
    ("Opera GX", os.path.join(ROAMING, "Opera Software", "Opera GX Stable"), True),
)
_CHROMIUM_FAJLOK = (("Login Data", "mentett jelszavak"), ("Login Data For Account", "mentett jelszavak"),
                    (os.path.join("Network", "Cookies"), "sütik (belépett munkamenetek)"),
                    ("Cookies", "sütik (belépett munkamenetek)"), ("Web Data", "bankkártyák / űrlapadatok"))
_FIREFOX = os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles")
_FIREFOX_FAJLOK = (("logins.json", "mentett jelszavak"), ("key4.db", "a jelszavak kulcsa"),
                   ("cookies.sqlite", "sütik (belépett munkamenetek)"))
_BONGESZO_KIADO = ("google", "microsoft", "brave", "opera", "vivaldi", "mozilla", "yandex", "chromium")
_BONGESZO_EXE = {"chrome.exe", "msedge.exe", "brave.exe", "opera.exe", "vivaldi.exe", "browser.exe",
                 "firefox.exe", "launcher.exe", "opera_gx_splash.exe"}
# ezek soha nem szamitanak (Defender, rendszer, kereses-indexelo)
_MINDIG_OK = {"msmpeng.exe", "mpdefendercoreservice.exe", "nissrv.exe", "mpcmdrun.exe", "system",
              "searchprotocolhost.exe", "searchindexer.exe", "searchfilterhost.exe", "explorer.exe"}

# csali-csomagok: (nev, a program "otthona" - ha letezik, nem rakunk csalit, [(relativ ut, tipus)])
# + a program telepitesi helyei es exe-nevei: ha kesobb feltelepited, a csali azonnal eltunik
_TELEPITVE = {
    "Yandex bongeszo": ([os.path.join(LOCAL, "Yandex", "YandexBrowser", "Application")], {"browser.exe"}),
    "Opera GX": ([os.path.join(LOCAL, "Programs", "Opera GX")], {"opera.exe", "opera_gx_splash.exe"}),
    "Exodus tarca": ([os.path.join(LOCAL, "exodus")], {"exodus.exe"}),
    "Electrum tarca": ([os.path.join(p, "Electrum") for p in PF], {"electrum.exe"}),
    "FileZilla": ([os.path.join(p, "FileZilla FTP Client") for p in PF], {"filezilla.exe"}),
}
_CSALIK = (
    ("Yandex bongeszo", os.path.join(LOCAL, "Yandex"),
     [(os.path.join("YandexBrowser", "User Data", "Local State"), "localstate"),
      (os.path.join("YandexBrowser", "User Data", "Default", "Ya Passman Data"), "logindata"),
      (os.path.join("YandexBrowser", "User Data", "Default", "Login Data"), "logindata")]),
    ("Opera GX", os.path.join(ROAMING, "Opera Software", "Opera GX Stable"),
     [("Local State", "localstate"), ("Login Data", "logindata")]),
    ("Exodus tarca", os.path.join(ROAMING, "Exodus"),
     [(os.path.join("exodus.wallet", "seed.seco"), "seco"), (os.path.join("exodus.wallet", "passphrase.json"), "json")]),
    ("Electrum tarca", os.path.join(ROAMING, "Electrum"),
     [(os.path.join("wallets", "default_wallet"), "electrum")]),
    ("FileZilla", os.path.join(ROAMING, "FileZilla"),
     [("recentservers.xml", "filezilla"), ("sitemanager.xml", "filezilla")]),
)

_PS_SACL = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "$l=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json;"
            "$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0');$o=@();"
            "foreach($p in @($l)){try{$a=Get-Acl -LiteralPath $p -Audit;$van=$false;"
            "foreach($r in $a.GetAuditRules($true,$false,[System.Security.Principal.SecurityIdentifier])){"
            "if($r.IdentityReference.Value -eq 'S-1-1-0' -and (([int]$r.FileSystemRights) -band 1)){$van=$true}};"
            "if(-not $van){$r=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,"
            "[System.Security.AccessControl.FileSystemRights]::ReadData,[System.Security.AccessControl.AuditFlags]::Success);"
            "$a.AddAuditRule($r);[System.IO.File]::SetAccessControl($p,$a);$o+=('uj|'+$p)}else{$o+=('van|'+$p)}}"
            "catch{$o+=('hiba|'+$p+'|'+$_.Exception.Message)}};$o -join [Environment]::NewLine")


# [v2.20.0] mappara: oroklodo olvasas-naplozas (csak a benne levo fajlokra, a mappara nem)
_PS_SACL_MAPPA = ("$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
            "$l=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json;"
            "$sid=New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0');$o=@();"
            "$inh=[System.Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit';"
            "$prop=[System.Security.AccessControl.PropagationFlags]::InheritOnly;"
            "foreach($p in @($l)){try{$a=Get-Acl -LiteralPath $p -Audit;$van=$false;"
            "foreach($r in $a.GetAuditRules($true,$false,[System.Security.Principal.SecurityIdentifier])){"
            "if($r.IdentityReference.Value -eq 'S-1-1-0' -and (([int]$r.FileSystemRights) -band 1) -and "
            "(([int]$r.InheritanceFlags) -band 2)){$van=$true}};"
            "if(-not $van){$r=New-Object System.Security.AccessControl.FileSystemAuditRule($sid,"
            "[System.Security.AccessControl.FileSystemRights]::ReadData,$inh,$prop,"
            "[System.Security.AccessControl.AuditFlags]::Success);"
            "$a.AddAuditRule($r);[System.IO.Directory]::SetAccessControl($p,$a);$o+=('uj|'+$p)}else{$o+=('van|'+$p)}}"
            "catch{$o+=('hiba|'+$p+'|'+$_.Exception.Message)}};$o -join [Environment]::NewLine")

PASS_MAPPA = os.path.join(ROAMING, "ArrabonaPass")
_PASS_FAJLOK = (("vault.apv", "a jelszótrezor"), ("vault.apv.bak", "a trezor előző állapota"),
                ("hello.json", "a Windows Hello-kulcs (titkosítva)"))
_PYTHON_EXE = {"python.exe", "pythonw.exe", "py.exe", "pyw.exe"}


def _norm(p):
    return os.path.normcase(os.path.normpath(p or ""))


def pass_mentes_mappa():
    """Az Arrabona Pass biztonsagi menteseinek mappaja (a Pass beallitasaibol)."""
    mappa = ""
    try:
        with open(os.path.join(PASS_MAPPA, "beallitasok.json"), "r", encoding="utf-8") as f:
            d = _json.load(f)
        if d.get("backup_enabled", True) is False:
            return ""
        mappa = d.get("backup_folder") or ""
    except Exception:
        pass
    if not mappa:
        docs = os.path.join(os.path.expanduser("~"), "Documents")
        mappa = os.path.join(docs if os.path.isdir(docs) else os.path.expanduser("~"),
                             "Arrabona Pass mentesek")
    return mappa if os.path.isdir(mappa) else ""


def pass_mappak():
    return [m for m in (PASS_MAPPA if os.path.isdir(PASS_MAPPA) else "", pass_mentes_mappa()) if m]


def pass_celpontok():
    """{normalt_ut: (ut, leiras)} az Arrabona Pass fajljai."""
    out = {}
    for fn, leiras in _PASS_FAJLOK:
        p = os.path.join(PASS_MAPPA, fn)
        if os.path.isfile(p):
            out[_norm(p)] = (p, "Arrabona Pass: %s (%s)" % (fn, leiras))
    m = pass_mentes_mappa()
    if m:
        try:
            for fn in os.listdir(m):
                if fn.lower().startswith("arrabona_pass_") and fn.lower().endswith(".apv"):
                    p = os.path.join(m, fn)
                    out[_norm(p)] = (p, "Arrabona Pass: biztonsági mentés (%s)" % fn)
        except OSError:
            pass
    return out


def _arrabona_pass_folyamat(pid, exe):
    """Maga az Arrabona Pass olvassa-e (telepitett exe, vagy forrasbol: python arrabona_pass.py)."""
    nev = os.path.basename(exe or "").lower()
    if nev == "arrabona pass.exe":
        try:
            from . import pass_inditas
            ismert = pass_inditas.keres() or ""
        except Exception:
            ismert = ""
        return _megbizhato_hely(exe) or (ismert and _norm(ismert) == _norm(exe))
    if nev in _PYTHON_EXE:
        try:
            import psutil
            return any("arrabona_pass" in (a or "").lower() for a in psutil.Process(pid).cmdline())
        except Exception:
            return False
    return False


def lopas_cfg():
    cfg = {"CSALIK": "BE", "VALODI": "BE", "AKCIO": "FELFUGGESZT", "KIVETEL": []}
    try:
        if not os.path.exists(LOPAS_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(LOPAS_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - infostealer-csapda (v2.13.0)\n"
                        "# CSALIK BE = csali bongeszoprofil / kriptotarca / FileZilla a nem telepitett programok helyere\n"
                        "CSALIK BE\n"
                        "# VALODI BE = a bongeszok valodi jelszo- es suti-fajljainak figyelese\n"
                        "VALODI BE\n"
                        "# Ha ismeretlen program olvassa oket: FELFUGGESZT (megallitja, te dontesz) / LEALLIT / RIASZT\n"
                        "AKCIO FELFUGGESZT\n"
                        "# KIVETEL <reszlet> = ha az olvaso program utja tartalmazza, nem riaszt (pl. jelszokezelo, mentoprogram)\n"
                        "# pl.: KIVETEL \\bitwarden\\\n")
        with open(LOPAS_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip() if len(r) > 1 else "")
                if k == "KIVETEL" and v:
                    cfg["KIVETEL"].append(v.lower())
                elif k == "AKCIO" and v.upper() in ("FELFUGGESZT", "LEALLIT", "RIASZT"):
                    cfg["AKCIO"] = v.upper()
                elif k in ("CSALIK", "VALODI") and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg[k] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def valodi_celpontok():
    """{normalt_ut: (ut, leiras)} a gepen talalhato bongeszo-adatfajlok."""
    out = {}

    def add(p, leiras):
        if os.path.isfile(p):
            out[_norm(p)] = (p, leiras)
    for nev, gy, gyokerben in _CHROMIUM:
        if not os.path.isdir(gy):
            continue
        add(os.path.join(gy, "Local State"), "%s: Local State (a jelszavak titkosító kulcsa)" % nev)
        profilok = [gy] if gyokerben else []
        if not gyokerben:
            try:
                for d in os.listdir(gy):
                    if d == "Default" or d.startswith("Profile "):
                        profilok.append(os.path.join(gy, d))
            except OSError:
                pass
        for pr in profilok:
            for rel, leiras in _CHROMIUM_FAJLOK:
                add(os.path.join(pr, rel), "%s%s: %s (%s)" % (
                    nev, "" if gyokerben else " / " + os.path.basename(pr), os.path.basename(rel), leiras))
    try:
        for d in os.listdir(_FIREFOX):
            for fn, leiras in _FIREFOX_FAJLOK:
                add(os.path.join(_FIREFOX, d, fn), "Firefox / %s: %s (%s)" % (d.split(".")[-1], fn, leiras))
    except OSError:
        pass
    out.update(pass_celpontok())   # [v2.20.0]
    return out


def _rnd(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def csali_tartalom(tipus):
    if tipus == "localstate":
        kulcs = base64.b64encode(b"DPAPI" + _rnd(226)).decode("ascii")
        return _json.dumps({"os_crypt": {"encrypted_key": kulcs},
                            "profile": {"info_cache": {"Default": {"name": "Felhasznalo"}}}}).encode("utf-8")
    if tipus == "seco":
        return b"SECO" + b"\x00\x00\x00\x01" + _rnd(4088)
    if tipus == "json":
        return _json.dumps({"passphrase": base64.b64encode(_rnd(48)).decode("ascii")}).encode("utf-8")
    if tipus == "electrum":
        return base64.b64encode(b"BIE1" + _rnd(1500))
    if tipus == "filezilla":
        u = random.choice(("admin", "ftpuser", "webmaster", "laszlo"))
        pw = base64.b64encode(_rnd(12)).decode("ascii")
        return ('<?xml version="1.0" encoding="UTF-8"?>\n<FileZilla3 version="3.66.4" platform="windows">\n'
                '\t<RecentServers>\n\t\t<Server>\n\t\t\t<Host>ftp.%s.hu</Host>\n\t\t\t<Port>21</Port>\n'
                '\t\t\t<Protocol>0</Protocol>\n\t\t\t<Type>0</Type>\n\t\t\t<User>%s</User>\n'
                '\t\t\t<Pass encoding="base64">%s</Pass>\n\t\t</Server>\n\t</RecentServers>\n</FileZilla3>\n'
                % (random.choice(("tarhely", "webshop", "sajatoldal")), u, pw)).encode("utf-8")
    # logindata: valodi SQLite adatbazis "logins" tablaval (a lopok sqlite-tal nyitjak meg)
    try:
        import sqlite3
        import tempfile
        fd, tmp = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        con = sqlite3.connect(tmp)
        con.execute("CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_value VARCHAR,"
                    " password_value BLOB, date_created INTEGER NOT NULL, times_used INTEGER)")
        for site in ("https://accounts.google.com/", "https://www.facebook.com/", "https://www.otpbank.hu/",
                     "https://www.paypal.com/signin", "https://discord.com/login"):
            con.execute("INSERT INTO logins VALUES (?,?,?,?,?,?)",
                        (site, site, "user%d@gmail.com" % random.randint(10, 99),
                         b"v10" + _rnd(28), 13300000000000000 + random.randint(0, 10 ** 12), random.randint(1, 40)))
        con.commit()
        con.close()
        with open(tmp, "rb") as f:
            adat = f.read()
        os.remove(tmp)
        return adat
    except Exception:
        return b"SQLite format 3\x00" + _rnd(4080)


def _megbizhato_hely(exe):
    n = _norm(exe)
    helyek = [_norm(p) + "\\" for p in PF] + [_norm(WINDIR) + "\\",
                                              _norm(os.path.join(LOCAL, "Programs")) + "\\",
                                              _norm(os.path.join(LOCAL, "Microsoft", "WindowsApps")) + "\\"]
    for nev, gy, _g in _CHROMIUM:
        # felhasznaloi telepitesu bongeszo (pl. LocalAppData\Google\Chrome\Application)
        alap = os.path.dirname(gy) if not _g else gy
        helyek.append(_norm(os.path.join(alap, "Application")) + "\\")
    if n.startswith(_norm(os.path.join(WINDIR, "Temp")) + "\\"):
        return False
    return any(n.startswith(h) for h in helyek)


class LopasMixin(object):
    """Infostealer-csapda. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ csalik
    def _lp_state_load(self):
        try:
            with open(LOPAS_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _lp_state_save(self):
        try:
            tmp = LOPAS_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._lp_state, f, ensure_ascii=False, indent=1)
            os.replace(tmp, LOPAS_STATE_FILE)
        except OSError as e:
            log_line("[INFOLOPAS] mentesi hiba: %s" % e)

    def _lp_csalik_telepit(self):
        """A hianyzo programok helyere csali fajlok. {normalt_ut: (ut, leiras)}"""
        st = self._lp_state.setdefault("csalik", {})      # {ut: {"csomag":..., "otthon":..., "uj_otthon":bool}}
        out = {}
        for nev, otthon, fajlok in _CSALIK:
            sajat = any(v.get("otthon") == otthon for v in st.values())
            if any(os.path.isdir(d) for d in _TELEPITVE.get(nev, ([], set()))[0]):
                if sajat:
                    self._lp_csomag_torol(nev, "a program telepitve lett")
                continue
            if os.path.exists(otthon) and not sajat:
                continue        # a program telepitve van (vagy volt): oda nem nyulunk
            uj_otthon = not os.path.exists(otthon) or any(v.get("uj_otthon") for v in st.values()
                                                          if v.get("otthon") == otthon)
            for rel, tipus in fajlok:
                p = os.path.join(otthon, rel)
                try:
                    if not os.path.isfile(p):
                        os.makedirs(os.path.dirname(p), exist_ok=True)
                        with open(p, "wb") as f:
                            f.write(csali_tartalom(tipus))
                        # hihetobb datum: nehany honappal korabbi
                        t = time.time() - random.randint(40, 400) * 86400
                        os.utime(p, (t, t))
                        log_line("[INFOLOPAS] csali letrehozva: %s" % p)
                    st[p] = {"csomag": nev, "otthon": otthon, "uj_otthon": uj_otthon}
                    out[_norm(p)] = (p, "CSALI - %s: %s" % (nev, os.path.basename(p)))
                except OSError as e:
                    log_line("[INFOLOPAS] csali hiba (%s): %s" % (p, e))
        self._lp_state_save()
        return out

    def _lp_csomag_torol(self, csomag, ok=""):
        """Egy csali-csomag eltavolitasa (pl. mert a valodi program felkerult a gepre)."""
        st = self._lp_state.get("csalik", {})
        for p, v in list(st.items()):
            if v.get("csomag") != csomag:
                continue
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass
            st.pop(p, None)
            with self._lp_lock:
                self._lp_cel.pop(_norm(p), None)
        self._lp_state_save()
        log_line("[INFOLOPAS] csali eltavolitva: %s (%s)" % (csomag, ok))

    def lopas_csalik_torol(self):
        import shutil
        st = self._lp_state.get("csalik", {})
        otthonok = set()
        for p, v in list(st.items()):
            try:
                if os.path.isfile(p):
                    os.remove(p)
            except OSError:
                pass
            if v.get("uj_otthon"):
                otthonok.add(v.get("otthon"))
        for o in otthonok:
            # csak akkor toroljuk a mappat, ha mi hoztuk letre es nincs benne mas
            try:
                maradt = [os.path.join(r, f) for r, _d, fs in os.walk(o) for f in fs]
                if not maradt:
                    shutil.rmtree(o, ignore_errors=True)
            except Exception:
                pass
        self._lp_state["csalik"] = {}
        self._lp_state_save()
        log_line("[INFOLOPAS] csalik eltavolitva")

    # ------------------------------------------------------------ jeloles (SACL) + naplozas
    def _lp_audit_be(self):
        try:
            r = subprocess.run(["auditpol", "/set", "/subcategory:" + _AUDIT_GUID, "/success:enable"],
                               capture_output=True, timeout=20)
            ok = r.returncode == 0
        except Exception as e:
            log_line("[INFOLOPAS] auditpol hiba: %s" % e)
            ok = False
        log_line("[INFOLOPAS] fajlrendszer-naplozas (4663): %s" % ("bekapcsolva" if ok else "SIKERTELEN"))
        return ok

    def _lp_sacl(self, utak):
        """Olvasas-naplozas (SACL) a fajlokra. Visszaad: (uj, mar_volt, hibas) db."""
        uj = van = hiba = 0
        for i in range(0, len(utak), 40):
            resz = utak[i:i + 40]
            b64 = base64.b64encode(_json.dumps(resz).encode("utf-8")).decode("ascii")
            try:
                r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SACL % b64],
                                   capture_output=True, timeout=60 + 2 * len(resz))
                for ln in dec_ki(r.stdout).splitlines():
                    if ln.startswith("uj|"):
                        uj += 1
                    elif ln.startswith("van|"):
                        van += 1
                    elif ln.startswith("hiba|"):
                        hiba += 1
                        if hiba <= 3:
                            log_line("[INFOLOPAS] jeloles sikertelen: %s" % ln[5:300])
            except Exception as e:
                hiba += len(resz)
                log_line("[INFOLOPAS] jelolesi hiba: %s" % e)
        return uj, van, hiba

    def _lp_sacl_mappa(self, mappak):
        """[v2.20.0] Oroklodo olvasas-naplozas mappakra (az ujonnan letrejovo fajlokra is)."""
        if not mappak:
            return
        b64 = base64.b64encode(_json.dumps(mappak).encode("utf-8")).decode("ascii")
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SACL_MAPPA % b64],
                               capture_output=True, timeout=60)
            for ln in dec_ki(r.stdout).splitlines():
                if ln.startswith("uj|"):
                    log_line("[INFOLOPAS] Arrabona Pass mappa megjelolve: %s" % ln[3:300])
                elif ln.startswith("hiba|"):
                    log_line("[INFOLOPAS] Arrabona Pass mappa jelolese sikertelen: %s" % ln[5:300])
        except Exception as e:
            log_line("[INFOLOPAS] Arrabona Pass mappa jelolesi hiba: %s" % e)

    def _lp_celpontok_frissit(self):
        cfg = self._lp_cfg
        cel = {}
        if cfg["VALODI"] == "BE":
            cel.update({k: (p, l, False) for k, (p, l) in valodi_celpontok().items()})
        if cfg["CSALIK"] == "BE":
            cel.update({k: (p, l, True) for k, (p, l) in self._lp_csalik_telepit().items()})
        elif self._lp_state.get("csalik"):
            self.lopas_csalik_torol()
        uj, van, hiba = self._lp_sacl([p for p, _l, _c in cel.values()])
        if cfg["VALODI"] == "BE":
            self._lp_sacl_mappa(pass_mappak())   # [v2.20.0] Arrabona Pass mappai (oroklodo)
        if uj:
            log_line("[INFOLOPAS] %d fajl megjelolve olvasas-naplozasra (%d mar jelolt, %d hiba)" % (uj, van, hiba))
        with self._lp_lock:
            self._lp_cel = cel
            self._lp_jelolt = uj + van
            self._lp_hiba = hiba

    # ------------------------------------------------------------ 4663 olvasas
    def _lp_utolso_rekord(self):
        r = subprocess.run(["wevtutil", "qe", "Security", "/c:1", "/rd:true", "/f:XML", "/uni:true"],
                           capture_output=True, timeout=30)
        t = dec_ki(r.stdout)
        i = t.find("<EventRecordID>")
        if i < 0:
            return 0
        try:
            return int(t[i + 15:t.find("</EventRecordID>", i)])
        except ValueError:
            return 0

    def _lp_4663(self):
        import xml.etree.ElementTree as ET
        q = "*[System[(EventID=4663) and (EventRecordID > %d)]]" % self._lp_rekord
        r = subprocess.run(["wevtutil", "qe", "Security", "/q:" + q, "/f:XML", "/c:300", "/uni:true"],
                           capture_output=True, timeout=45)
        out = dec_ki(r.stdout)
        if not out.strip():
            return
        doc = ET.fromstring("<events>" + out + "</events>")
        for ev in doc:
            adat, rid = {}, 0
            for el in ev.iter():
                tag = el.tag.split("}")[-1]
                if tag == "EventRecordID":
                    try:
                        rid = int(el.text or 0)
                    except ValueError:
                        pass
                elif tag == "Data" and el.get("Name"):
                    adat[el.get("Name")] = el.text or ""
            if rid > self._lp_rekord:
                self._lp_rekord = rid
            obj = _norm(adat.get("ObjectName"))
            with self._lp_lock:
                c = self._lp_cel.get(obj)
            if not c:
                continue
            try:
                pid = int(adat.get("ProcessId", "0"), 16)
            except ValueError:
                pid = 0
            self._lp_esemeny(pid, adat.get("ProcessName") or "", c, adat.get("SubjectUserName") or "")

    def _lp_esemeny(self, pid, exe, cel, user):
        from .alairas import sig_one, sig_szoveg
        ut, leiras, csali = cel
        nev = os.path.basename(exe).lower()
        if pid in (0, 4) or nev in _MINDIG_OK or pid == os.getpid():
            return
        own = getattr(self, "_fy_own", None) or {os.getpid()}
        if pid in own:
            return
        try:
            import sys
            if getattr(sys, "frozen", False) and _norm(exe) == _norm(sys.executable):
                return
        except Exception:
            pass
        if any(k in exe.lower() for k in self._lp_cfg["KIVETEL"]):
            return
        if leiras.startswith("Arrabona Pass") and _arrabona_pass_folyamat(pid, exe):
            return      # [v2.20.0] maga az Arrabona Pass
        sig = sig_one(exe) if exe and os.path.isfile(exe) else None
        alairt = bool(sig) and sig.get("allapot") == "ok"
        kiado = ((sig or {}).get("kiado") or "").lower()
        bizt_hely = _megbizhato_hely(exe)
        pass_mentes = leiras.startswith("Arrabona Pass: biztonsági mentés")
        if pass_mentes and alairt and "microsoft" in kiado:
            return      # [v2.20.0] OneDrive / Windows-mentes szinkronizalja a mentes-mappat
        if (not csali and alairt and bizt_hely and
                (nev in _BONGESZO_EXE or any(k in kiado for k in _BONGESZO_KIADO))):
            return      # a bongeszo (vagy a gyartoja) sajat programja
        if csali and alairt and bizt_hely:
            # a VALODI program (frissen telepitve) nyitotta meg a csalit: a csali tunjon el, ne zavarja
            csomag = leiras.split(":")[0].replace("CSALI - ", "")
            if nev in _TELEPITVE.get(csomag, ([], set()))[1]:
                self._lp_csomag_torol(csomag, "a valodi program (%s) hasznalni kezdte" % nev)
                return
        szint = 2 if (alairt and (bizt_hely or pass_mentes)) else 3
        kulcs = (pid, _norm(exe), csali)
        most = time.time()
        if most - self._lp_last.get(kulcs, 0.0) < 600:
            self._lp_targyak.setdefault(kulcs, set()).add(leiras)
            return
        self._lp_last[kulcs] = most
        self._lp_targyak[kulcs] = {leiras}
        d = {"pid": pid, "name": os.path.basename(exe) or "?", "exe": exe, "ctime": None, "cmd": ""}
        try:
            import psutil
            p = psutil.Process(pid)
            d["ctime"] = p.create_time()
            d["name"] = p.name()
            try:
                d["cmd"] = " ".join(p.cmdline())
            except Exception:
                pass
            el = True
        except Exception:
            el = False
        akcio = ""
        if szint >= 3:
            if not el:
                akcio = "a folyamat mar kilepett"
            elif self._lp_cfg["AKCIO"] == "FELFUGGESZT" and hasattr(self, "_fy_suspend"):
                _ok, akcio = self._fy_suspend(d)
            elif self._lp_cfg["AKCIO"] == "LEALLIT" and hasattr(self, "folyamat_kill"):
                ok, sz = self.folyamat_kill(pid, d["ctime"], ki="infostealer-csapda")
                akcio = "LEALLITVA" if ok else "LEALLITAS NEM SIKERULT: " + sz
            else:
                akcio = "(infolopas.txt: AKCIO RIASZT - nem allitottam meg)"
        with self._lp_lock:
            self.lopas_hits += 1
            self._lp_recent = ([{"ts": most, "szint": szint, "pid": pid, "name": d["name"], "exe": exe,
                                 "mit": leiras, "csali": csali, "akcio": akcio}] + self._lp_recent)[:30]
        fej = ("ADATLOPO KARTEVO (CSALIT OLVASOTT)" if csali else "JELSZOLOPAS GYANU") if szint >= 3 else \
              ("CSALIT OLVASOTT EGY ALAIRT PROGRAM" if csali else "ALAIRT PROGRAM OLVASTA A BONGESZO ADATAIT")
        msg = "[INFOLOPAS] %s: %s (PID %s) olvasta: %s | Ut: %s" % (fej, d["name"], pid, leiras, exe[:200])
        if d["cmd"]:
            msg += " | Parancs: %s" % d["cmd"][:200]
        if sig:
            msg += " | Alairas: %s" % sig_szoveg(sig, ekezet=False)
        if akcio:
            msg += " | " + akcio
        if szint >= 3:
            msg += (" | HA NEM TE VOLTAL: allitsd le, futtass teljes vizsgalatot, es egy MASIK eszkozrol "
                    "valts jelszot (e-mail, bank, Discord, Steam), jelentkezz ki minden munkamenetbol!")
        else:
            from .folyamat import windows_fajl as _wf
            msg += (" | Windows-program: ha te voltal (pl. teszt), Rendben. Ha nem, nezd meg, mi inditotta!"
                    if _wf(exe) else
                    " | Ha ez a jelszokezelod / mentoprogramod: infolopas.txt KIVETEL vagy 'Megbizhato' gomb.")
        gombok = []
        try:
            from .telegram import tg_action
            ct = int(d["ctime"] or 0)
            if el:
                if "FELFUGGESZTVE" in akcio:
                    gombok.append([("⛔ Leállítás + teljes vizsgálat", "pk:%s:%d:full" % (pid, ct)),
                                   ("▶ Folytatás (én voltam)", "pr:%s:%d" % (pid, ct))])
                elif "LEALLITVA" not in akcio:
                    gombok.append([("⛔ Leállítás", "pk:%s:%d" % (pid, ct))])
            from .folyamat import windows_fajl
            if exe and os.path.isfile(exe) and not windows_fajl(exe):
                gombok.append([("🗄 Karanténba (fájl)", tg_action("pq", {"pid": pid if el else None,
                                                                         "ctime": ct, "fajl": exe}))])
            gombok.append([("🛡 Teljes vizsgálat", "sf")])
            if exe and not windows_fajl(exe):
                gombok.append([("✅ Megbízható (ez a program)", tg_action("lk", {"exe": exe}))])
            else:
                gombok.append([("✅ Rendben / én voltam", "ok")])
        except Exception:
            gombok = None
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)
        if "FELFUGGESZTVE" in akcio:
            try:
                self.out.put(("ransom", {"tipus": "folyamat", "pid": pid, "ctime": d["ctime"], "name": d["name"],
                                         "exe": exe, "cmd": d["cmd"][:300], "szulo": "",
                                         "where": "Adatlopás gyanú - olvasta: %s" % leiras, "ts": most}))
            except Exception:
                pass
        if szint >= 3 and exe and os.path.isfile(exe):
            try:
                self.defender_scan("custom", exe, elozmeny=[("Adatlopás gyanú: %s" % d["name"], most),
                                                            ("Olvasta: %s" % leiras[:70], most)],
                                   cimke="Infostealer: %s" % d["name"][:40])
            except Exception:
                pass
            if hasattr(self, "vt_kerd"):
                try:
                    self.vt_kerd(exe, "Infostealer: %s" % d["name"][:40])
                except Exception:
                    pass

    def lopas_kivetel(self, exe, ki="felulet"):
        """A program felvetele a KIVETEL-ek koze (infolopas.txt)."""
        if not exe:
            return False, "Nincs program-utvonal."
        from .folyamat import windows_fajl
        if windows_fajl(exe):
            # [v2.14.0] PowerShell / cmd / rundll32... kivetele az OSSZES ezt hasznalo kartevot atengedne
            return False, ("Windows-programot (%s) nem veszek fel kivetelnek: a kartevok is ezeket hasznaljak. "
                           "Ha te voltal, csak nyomd meg a Rendben gombot." % os.path.basename(exe))
        try:
            with open(LOPAS_CFG_FILE, "a", encoding="utf-8") as f:
                f.write("KIVETEL %s\n" % exe)
            self._lp_cfg = lopas_cfg()
        except OSError as e:
            return False, "Nem sikerult: %s" % e
        log_line("[INFOLOPAS] kivetel hozzaadva (%s): %s" % (ki, exe))
        return True, "Kivétel hozzáadva, erre többet nem szólok: %s" % exe

    # ------------------------------------------------------------ ciklus
    def _lp_loop(self):
        if not getattr(self, "admin", False):
            self.lopas_status = "nincs rendszergazdai jog"
            log_line("[INFOLOPAS] nincs rendszergazdai jog - a csapda nem indul")
            return
        self._lp_audit_ok = self._lp_audit_be()
        try:
            self._lp_rekord = self._lp_utolso_rekord()
        except Exception:
            self._lp_rekord = 0
        utolso_jel = 0.0
        utolso_rek = time.time()
        while not self._lp_stop_ev.is_set():
            try:
                most = time.time()
                if most - utolso_jel >= SACL_FRISSIT:
                    utolso_jel = most
                    self._lp_cfg = lopas_cfg()
                    self._lp_celpontok_frissit()
                    self.lopas_status = "aktív" if (self._lp_audit_ok and self._lp_jelolt) else \
                        ("naplózás sikertelen" if not self._lp_audit_ok else "nincs megjelölt fájl")
                if most - utolso_rek >= 60:
                    # naplotorles / forgatas utan az azonositok elolrol indulnak
                    utolso_rek = most
                    u = self._lp_utolso_rekord()
                    if u and u < self._lp_rekord:
                        self._lp_rekord = u
                if self.is_on() and not self.is_paused() and self._lp_cel:
                    self._lp_4663()
            except Exception as e:
                log_line("[INFOLOPAS] figyelo hiba: %s" % e)
                self._lp_stop_ev.wait(10.0)
            self._lp_stop_ev.wait(POLL)

    def _lopas_start(self):
        if getattr(self, "_lp_thread", None) and self._lp_thread.is_alive():
            return
        self._lp_cfg = lopas_cfg()
        self._lp_state = self._lp_state_load()
        self._lp_lock = threading.Lock()
        self._lp_cel, self._lp_last, self._lp_targyak = {}, {}, {}
        self._lp_recent = getattr(self, "_lp_recent", [])
        self._lp_jelolt = self._lp_hiba = 0
        self._lp_audit_ok = False
        self._lp_rekord = 0
        self.lopas_hits = getattr(self, "lopas_hits", 0)
        self.lopas_status = "indulás…"
        self._lp_started = time.time()
        self._lp_stop_ev = threading.Event()
        self._lp_thread = threading.Thread(target=self._lp_loop, name="infolopas", daemon=True)
        self._lp_thread.start()
        log_line("[INFOLOPAS] csapda indul (csalik: %s, valodi: %s, akcio: %s)" % (
            self._lp_cfg["CSALIK"], self._lp_cfg["VALODI"], self._lp_cfg["AKCIO"]))

    def _lopas_stop(self):
        ev = getattr(self, "_lp_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ allapot
    def lopas_summary(self):
        cel = getattr(self, "_lp_cel", None) or {}
        if not cel:
            return getattr(self, "lopas_status", "indulás…")
        cs = sum(1 for _p, _l, c in cel.values() if c)
        reszek = ["Figyelt: %d fájl (%d csali)" % (len(cel), cs),
                  "Riasztás: %d" % getattr(self, "lopas_hits", 0)]
        if getattr(self, "_lp_hiba", 0):
            reszek.append("jelölési hiba: %d" % self._lp_hiba)
        rec = getattr(self, "_lp_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s ⚠" % (rec[0]["name"][:20],
                                               time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"]))))
        return " | ".join(reszek)

    def lopas_text(self):
        cel = getattr(self, "_lp_cel", None) or {}
        sorok = ["INFOSTEALER-CSAPDA: %s (%s)" % (getattr(self, "lopas_status", "?"),
                                                  self.lopas_summary().replace(" | ", ", "))]
        csalik = sorted({l.split(":")[0] for _p, l, c in cel.values() if c})
        if csalik:
            sorok.append("Csalik: %s" % ", ".join(x.replace("CSALI - ", "") for x in csalik))
        valodi = sorted({l.split(":")[0].split(" / ")[0] for _p, l, c in cel.values() if not c})
        if valodi:
            sorok.append("Figyelt bongeszok: %s" % ", ".join(valodi))
        rec = getattr(self, "_lp_recent", [])
        if rec:
            sorok.append("Legutobbi esetek:")
            for r in rec[:10]:
                sorok.append("  %s %s (PID %s) - %s%s" % (
                    time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), r["name"], r["pid"], r["mit"][:80],
                    (" | " + r["akcio"][:50]) if r["akcio"] else ""))
        else:
            sorok.append("Meg senki nem nyult a figyelt fajlokhoz.")
        return "\n".join(sorok)
