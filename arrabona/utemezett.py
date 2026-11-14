# -*- coding: utf-8 -*-
"""Arrabona Guard - UTEMEZETT FELADATOK TELJES ATNEZESE (GuardCore mixin). [v2.17.0]

Az utemezett feladat a kartevok kedvenc rejtekhelye: a gep minden inditasakor / bejelentkezeskor
/ percenkent ujraindítja oket, es a Feladatutemezo melyen senki nem nez. A 4698-as esemeny csak az
UJ feladatot jelzi - ez a modul a MEGLEVOKET is atnezi (30 percenkent + 4698 utan azonnal):

  - minden feladat XML-je (C:\\Windows\\System32\\Tasks): Exec + COM-kezelo muveletek, futtato fiok,
    inditok (bejelentkezes / rendszerinditas / percenkenti ismetles), rejtett jelzo
  - gyanus parancsok: kodolt / rejtett / letolto PowerShell, mshta / rundll32 / regsvr32 / certutil
    trukkok, internetes cim a parancsban, szkript Temp / AppData / Public / Letoltesek mappabol
  - a futtatott program digitalis alairasa (aláíratlan / ervenytelen) + futasi helye
  - Microsoft-feladatnak ALCAZOTT feladat (\\Microsoft\\... alatt, de nem Windows-program)
  - COM-ELTERITES: a COM-kezelos feladat osztalyat a felhasznaloi agban (HKCU) atiranyitottak
  - REJTETT FELADAT (Tarrask-technika): a TaskCache-bol torolt biztonsagi leiro (SD) -> a
    Feladatutemezo es a schtasks sem mutatja, de fut
  - uj / MODOSULT feladat -> riasztas (ha gyanus), kulonben csak naplo
Muveletek: letiltas / engedelyezes (schtasks /Change), a program karantenba, megbizhato.
utemezett.txt: FIGYELES BE/KI, KIVETEL <feladatut- vagy parancsreszlet>.
Telegram: /feladatok, /feladattiltas <szam>, /feladatengedely <szam>
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import re
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from .common import (APPDATA_DIR, INSTALL_EXE, WATCHDOG_TASK, WATCHDOG_VBS, WINDIR, log_line)

UT_CFG_FILE = os.path.join(APPDATA_DIR, "utemezett.txt")
UT_STATE_FILE = os.path.join(APPDATA_DIR, "utemezett_allapot.json")
TASKS_DIR = os.path.join(WINDIR, "System32", "Tasks")
TASKCACHE = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
SCAN_POLL = 1800
_SZINT_NEV = {3: "KRITIKUS", 2: "NAGYON GYANUS", 1: "GYANUS", 0: "rendben"}
_I = re.I

_ERTELMEZOK = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
               "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msiexec.exe", "conhost.exe",
               "forfiles.exe", "wmic.exe", "curl.exe", "python.exe", "pythonw.exe", "node.exe", "java.exe",
               "javaw.exe", "explorer.exe", "schtasks.exe", "reg.exe", "bash.exe", "wsl.exe"}
# (szint, regex a teljes parancssorra, magyar indoklas)
_MINTAK = (
    (3, re.compile(r"\s-e(nc|ncodedcommand|c)?\s+[A-Za-z0-9+/=]{24,}", _I), "KÓDOLT PowerShell-parancs"),
    (3, re.compile(r"downloadstring|downloadfile|downloaddata|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|"
                   r"net\.webclient|start-bitstransfer|webrequest", _I), "az internetről tölt le és futtat"),
    (3, re.compile(r"mshta(\.exe)?\W+[\"']?(https?|javascript|vbscript):", _I), "mshta internetes / szkript-címmel"),
    (3, re.compile(r"rundll32(\.exe)?.*javascript:", _I), "rundll32 JavaScript-trükk"),
    (3, re.compile(r"regsvr32(\.exe)?.*/i:\s*https?", _I), "regsvr32 internetes szkript (Squiblydoo)"),
    (3, re.compile(r"certutil(\.exe)?.*(-urlcache|-decode|-decodehex)", _I), "certutil letöltés / dekódolás"),
    (2, re.compile(r"bitsadmin(\.exe)?.*/(transfer|addfile)", _I), "bitsadmin letöltés"),
    (2, re.compile(r"\biex\b|invoke-expression", _I), "szöveget futtat programkódként (IEX)"),
    (2, re.compile(r"frombase64string", _I), "base64-ben elrejtett tartalom"),
    (2, re.compile(r"conhost(\.exe)?\s+--headless", _I), "rejtett konzol (conhost --headless)"),
    (2, re.compile(r"https?://", _I), "internetes cím a parancsban"),
    (1, re.compile(r"-w(indowstyle)?\s+(h|hidden)\b", _I), "rejtett ablakban fut"),
    (1, re.compile(r"-(ep|exec|executionpolicy)\s+(bypass|unrestricted)", _I), "kikapcsolt PowerShell-végrehajtási házirend"),
    (1, re.compile(r"\\(appdata|temp|users\\public|programdata)\\[^\"]*\.(vbs|vbe|js|jse|ps1|bat|cmd|hta|wsf)\b", _I),
     "szkriptet futtat felhasználói / Temp mappából"),
)
_FAJL = re.compile(r"[A-Za-z]:\\[^\"<>|*?\r\n,]*?\.(exe|dll|scr|bat|cmd|vbs|vbe|js|jse|ps1|hta|wsf|com|pif|cpl|jar|py)\b", _I)
_ERTELMEZO_ARG = re.compile(r"powershell|pwsh|mshta|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|"
                            r"conhost|curl(\.exe)?\s", _I)
# rundll32 url.dll,FileProtocolHandler https://... = csak megnyit egy weboldalt a bongeszoben (pl. RoboForm)
_URL_NYITAS = re.compile(r"url\.dll\s*,\s*(fileprotocolhandler|openurl)\s+[\"']?https?://", _I)
_TRIGGER_NEV = {"LogonTrigger": "bejelentkezéskor", "BootTrigger": "rendszerinduláskor", "TimeTrigger": "időpontban",
                "CalendarTrigger": "naptár szerint", "IdleTrigger": "tétlenségkor", "EventTrigger": "eseményre",
                "RegistrationTrigger": "létrehozáskor", "SessionStateChangeTrigger": "munkamenet-váltáskor",
                "WnfStateChangeTrigger": "rendszerállapotra"}


def ut_cfg():
    cfg = {"FIGYELES": "BE", "KIVETEL": []}
    try:
        if not os.path.exists(UT_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(UT_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - utemezett feladatok atnezese (v2.17.0)\n"
                        "FIGYELES BE\n"
                        "# KIVETEL <feladat utjanak vagy parancsanak reszlete> = nem jelzi gyanusnak (tobb sor is lehet), pl.:\n"
                        "# KIVETEL \\MyBackupTask\n")
        with open(UT_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip() if len(r) > 1 else "")
                if k == "KIVETEL" and v:
                    cfg["KIVETEL"].append(v.lower())
                elif k == "FIGYELES" and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg["FIGYELES"] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


# ------------------------------------------------------------------ XML
def _lok(tag):
    return tag.rsplit("}", 1)[-1]


def _xml_szoveg(b):
    if b[:2] in (b"\xff\xfe", b"\xfe\xff"):
        t = b.decode("utf-16")
    else:
        try:
            t = b.decode("utf-8-sig")
        except UnicodeDecodeError:
            t = b.decode("utf-16", errors="ignore")
    # a deklaracio (encoding="UTF-16") a mar dekodolt szovegnel zavarna
    return re.sub(r"^\s*<\?xml[^>]*\?>", "", t)


def _gyerek(el, nev):
    for c in el:
        if _lok(c.tag) == nev:
            return c
    return None


def _szoveg(el, *ut):
    for n in ut:
        if el is None:
            return ""
        el = _gyerek(el, n)
    return ((el.text or "").strip()) if el is not None else ""


def feladat_parse(adat, ut):
    """Egy feladat-XML -> szotar. ut: "\\Mappa\\Nev"."""
    g = ET.fromstring(_xml_szoveg(adat))
    d = {"ut": ut, "nev": ut.rsplit("\\", 1)[-1], "author": _szoveg(g, "RegistrationInfo", "Author"),
         "leiras": _szoveg(g, "RegistrationInfo", "Description")[:200],
         "enabled": _szoveg(g, "Settings", "Enabled").lower() != "false",
         "hidden": _szoveg(g, "Settings", "Hidden").lower() == "true",
         "user": "", "runlevel": "", "triggers": [], "ismetles": "", "exec": [], "com": []}
    pr = _gyerek(g, "Principals")
    if pr is not None:
        p = _gyerek(pr, "Principal")
        if p is not None:
            d["user"] = _szoveg(p, "UserId") or _szoveg(p, "GroupId")
            d["runlevel"] = _szoveg(p, "RunLevel")
    tr = _gyerek(g, "Triggers")
    if tr is not None:
        for t in tr:
            n = _lok(t.tag)
            if _szoveg(t, "Enabled").lower() == "false":
                continue
            d["triggers"].append(n)
            iv = _szoveg(t, "Repetition", "Interval")
            if iv and not d["ismetles"]:
                d["ismetles"] = iv
    ac = _gyerek(g, "Actions")
    if ac is not None:
        for a in ac:
            n = _lok(a.tag)
            if n == "Exec":
                d["exec"].append({"cmd": _szoveg(a, "Command"), "args": _szoveg(a, "Arguments"),
                                  "wd": _szoveg(a, "WorkingDirectory")})
            elif n == "ComHandler":
                d["com"].append({"clsid": _szoveg(a, "ClassId"), "data": _szoveg(a, "Data")[:200]})
    return d


def feladatok_olvas(gyoker=TASKS_DIR):
    """[feladat-szotar, ...] a Tasks mappabol (rendszergazda kell hozza)."""
    out = []
    for mappa, _dirs, fajlok in os.walk(gyoker):
        for f in fajlok:
            p = os.path.join(mappa, f)
            ut = "\\" + os.path.relpath(p, gyoker).replace("/", "\\")
            try:
                with open(p, "rb") as fh:
                    adat = fh.read(2 * 1024 * 1024)
                out.append(feladat_parse(adat, ut))
            except (OSError, ET.ParseError, ValueError):
                continue
    return out


def ismetles_perc(iv):
    """PT5M / PT1H / P1D -> percek (None, ha nincs)."""
    m = re.fullmatch(r"P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?", iv or "")
    if not m or not iv:
        return None
    d, h, mi, s = (int(x or 0) for x in m.groups())
    return d * 1440 + h * 60 + mi + (1 if s else 0)


def _feloldas(cmd):
    """A muvelet programjanak teljes utja (env-valtozok, idezojelek, System32-kereses)."""
    c = os.path.expandvars((cmd or "").strip().strip('"'))
    if not c:
        return ""
    if not os.path.dirname(c):
        nev = c if c.lower().endswith((".exe", ".com", ".bat", ".cmd")) else c + ".exe"
        for d in (os.path.join(WINDIR, "System32"), WINDIR, os.path.join(WINDIR, "System32", "WindowsPowerShell", "v1.0")):
            if os.path.isfile(os.path.join(d, nev)):
                return os.path.join(d, nev)
        return nev
    return c


def _norm(p):
    return os.path.normcase(os.path.normpath(p or ""))


def _windows_fajl(p):
    try:
        from .folyamat import windows_fajl
        return windows_fajl(p)
    except Exception:
        return _norm(p).startswith(_norm(WINDIR) + "\\")


def _program_files(p):
    n = _norm(p)
    for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        v = os.environ.get(k)
        if v and n.startswith(_norm(v).rstrip("\\/") + "\\"):
            return True
    return False


def hivatkozott_fajlok(d):
    """A feladat futtatott programja(i) + a parancssorban szereplo fajlok (pl. szkript)."""
    out = []
    for e in d["exec"]:
        p = _feloldas(e["cmd"])
        if p and os.path.dirname(p):     # csak a megtalalt (teljes utu) program; a puszta nevet nem itelhetjuk meg
            out.append(p)
        for m in _FAJL.finditer(os.path.expandvars(e["args"] or "")):
            out.append(m.group(0).strip())
    seen, uniq = set(), []
    for p in out:
        if _norm(p) not in seen:
            seen.add(_norm(p))
            uniq.append(p)
    return uniq


def ujjlenyomat(d):
    """Valtozas-ellenorzeshez: muveletek + futtato + inditok + allapot."""
    s = _json.dumps([d["exec"], d["com"], d["user"], d["runlevel"], sorted(d["triggers"]), d["enabled"], d["hidden"]],
                    sort_keys=True, ensure_ascii=False)
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:16]


def taskcache_rejtett():
    """[(feladat_ut, ok)] - a TaskCache\\Tree-ben levo, de rejtett feladatok:
    SD (biztonsagi leiro) nelkul = Tarrask-technika.
    [v2.17.1] Az XML nelkuli Tree-bejegyzes NEM szamit: a Windows-frissitesek utan sok regi beepitett
    feladat (Clip, WS, SettingSync...) "arvan" bennmarad - ezek artalmatlanok (hamis riasztas volt)."""
    try:
        import winreg
    except ImportError:
        return []
    out = []

    def _bejar(kulcs_ut, rel):
        try:
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, kulcs_ut, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0))
        except OSError:
            return
        try:
            ertekek = {}
            i = 0
            while True:
                try:
                    n, v, _t = winreg.EnumValue(k, i)
                    ertekek[n.lower()] = v
                    i += 1
                except OSError:
                    break
            if "id" in ertekek and rel:
                if "sd" not in ertekek:
                    out.append((rel, "SD-nélküli (Tarrask-technika: a Feladatütemező nem mutatja)"))
            j = 0
            while True:
                try:
                    al = winreg.EnumKey(k, j)
                    j += 1
                except OSError:
                    break
                _bejar(kulcs_ut + "\\" + al, rel + "\\" + al)
        finally:
            winreg.CloseKey(k)
    _bejar(TASKCACHE, "")
    return out


def com_kezelo(clsid):
    """(dll_ut, hkcu_elteritve?) a COM-osztalyhoz."""
    try:
        import winreg
    except ImportError:
        return "", False
    clsid = (clsid or "").strip()
    if not clsid:
        return "", False
    hkcu = False
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID\%s\InprocServer32" % clsid)
        winreg.CloseKey(k)
        hkcu = True
    except OSError:
        pass
    for gy, ut in ((winreg.HKEY_CURRENT_USER, r"Software\Classes\CLSID\%s\InprocServer32" % clsid),
                   (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Classes\CLSID\%s\InprocServer32" % clsid)):
        try:
            k = winreg.OpenKey(gy, ut)
            try:
                v, _t = winreg.QueryValueEx(k, "")
            finally:
                winreg.CloseKey(k)
            return os.path.expandvars(str(v or "").strip('"')), hkcu
        except OSError:
            continue
    return "", hkcu


def ertekel(d, sigs, com_info=None):
    """(szint 0-3, [indoklas]) egy feladatra. sigs: {ut: alairas-info}."""
    okok = []
    szint = 0

    def add(sz, o):
        nonlocal szint
        szint = max(szint, sz)
        if o not in okok:
            okok.append(o)
    ms = d["ut"].lower().startswith("\\microsoft\\")
    for e in d["exec"]:
        prog = _feloldas(e["cmd"])
        nev = os.path.basename(prog).lower()
        teljes = "%s %s" % (e["cmd"], e["args"])
        # a parancs-mintak csak ertelmezore (PowerShell, cmd, mshta...) vonatkoznak - egy sima program
        # argumentumaban levo URL (pl. frissito) nem gyanus
        if nev in _ERTELMEZOK or _ERTELMEZO_ARG.search(e["args"] or ""):
            url_nyitas = bool(_URL_NYITAS.search(e["args"] or ""))
            for sz, rx, o in _MINTAK:
                if url_nyitas and o == "internetes cím a parancsban":
                    continue
                if rx.search(" " + teljes):
                    add(sz, o)
    for p in hivatkozott_fajlok(d):
        if _windows_fajl(p):
            continue
        si = sigs.get(p) or {}
        a = si.get("allapot")
        try:
            from .folyamat import hely_okok
            hely = hely_okok(p)
        except Exception:
            hely = []
        if a == "hianyzik":
            add(1, "a feladat programja nem létezik: %s (maradvány - vagy törölte magát)" % os.path.basename(p))
            continue
        if a == "rossz":
            add(3, "ÉRVÉNYTELEN aláírás (módosított fájl): %s" % os.path.basename(p))
        rossz_al = a in ("nincs", "megbizhatatlan")
        for _s, o in hely:
            add(2 if rossz_al else 1, "%s %s" % (os.path.basename(p), o.replace(" fut", " indul")))
        if rossz_al and not hely and not _program_files(p):
            add(1, "aláíratlan program (nem a Program Files-ban): %s" % os.path.basename(p))
        ms_alairt = a == "ok" and "microsoft" in (si.get("kiado") or "").lower()
        if ms and not _program_files(p) and not ms_alairt:
            add(2, "Microsoft-feladatnak ÁLCÁZOTT (\\Microsoft\\ alatt, de nem Windows-program): %s"
                % os.path.basename(p))
    for c in (com_info or []):
        dll, hkcu = c
        if hkcu:
            add(3, "COM-ELTÉRÍTÉS: a feladat COM-osztályát a felhasználói ágban (HKCU) átirányították: %s"
                % (dll or "?"))
        elif dll and not _windows_fajl(dll):
            si = sigs.get(dll) or {}
            if si.get("allapot") in ("nincs", "megbizhatatlan", "rossz"):
                add(2, "aláíratlan COM-kezelő DLL: %s" % dll)
    # \Microsoft\ feladat, ami csak Windows-programot futtat: az enyhe (1-es) jelek nem szamitanak
    if ms and szint == 1 and all(_windows_fajl(p) for p in hivatkozott_fajlok(d)):
        return 0, []
    if szint:
        if d["hidden"]:
            add(min(3, szint + 1), "rejtett feladat")
        perc = ismetles_perc(d["ismetles"])
        if perc is not None and perc <= 10:
            okok.append("%d percenként újraindul" % max(1, perc))
        if (d["user"] in ("S-1-5-18", "SYSTEM", "NT AUTHORITY\\SYSTEM") or d["runlevel"] == "HighestAvailable") \
                and szint >= 2:
            add(3, "rendszergazdai / SYSTEM joggal fut")
    return szint, okok


def schtasks(muvelet, ut):
    """('/ENABLE' | '/DISABLE', '\\Mappa\\Nev') -> (ok, szoveg)."""
    try:
        r = subprocess.run(["schtasks", "/Change", "/TN", ut, muvelet], capture_output=True, timeout=30)
    except Exception as e:
        return False, str(e)
    kimenet = (r.stdout or b"") + (r.stderr or b"")
    for enc in ("utf-8", "cp852", "mbcs"):
        try:
            sz = kimenet.decode(enc).strip()
            break
        except (UnicodeDecodeError, LookupError):
            sz = kimenet.decode("utf-8", errors="replace").strip()
    return r.returncode == 0, sz[:200]


class UtemezettMixin(object):
    """Utemezett feladatok atnezese. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ allapot
    def _ut_load(self):
        try:
            with open(UT_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                if isinstance(d, dict):
                    d.setdefault("known", {})
                    d.setdefault("rejtett", [])
                    return d
        except (OSError, ValueError):
            pass
        return {"known": {}, "rejtett": [], "first_done": False}

    def _ut_save(self):
        try:
            tmp = UT_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._ut_state, f, ensure_ascii=False, indent=1)
            os.replace(tmp, UT_STATE_FILE)
        except OSError as e:
            log_line("[UTEMEZETT] mentesi hiba: %s" % e)

    def _ut_kivetel(self, d):
        # a Guard sajat orkutya-feladata
        if d["nev"].lower() == WATCHDOG_TASK.lower() or any(
                _norm(p) in (_norm(WATCHDOG_VBS), _norm(INSTALL_EXE)) for p in hivatkozott_fajlok(d)):
            return True
        s = ("%s %s" % (d["ut"], " ".join("%s %s" % (e["cmd"], e["args"]) for e in d["exec"]))).lower()
        return any(k in s for k in self._ut_cfg["KIVETEL"])

    # ------------------------------------------------------------ atnezes
    def ut_scan(self, ki="automatikus"):
        """Teljes atnezes. Visszaad: (ok, szoveg)."""
        if not self._ut_scan_lock.acquire(blocking=False):
            return False, "Már fut egy átnézés."
        try:
            return self._ut_scan(ki)
        finally:
            self._ut_scan_lock.release()

    def _ut_scan(self, ki):
        if not os.path.isdir(TASKS_DIR):
            self.ut_status = "nem elérhető (nincs Tasks mappa)"
            return False, self.ut_status
        lista = feladatok_olvas()
        if not lista:
            self.ut_status = "nem elérhető (rendszergazda kell)"
            return False, self.ut_status
        # COM-kezelok + alairasok (kotegelve, gyorsitotarral)
        com = {}
        fajlok = []
        for d in lista:
            for p in hivatkozott_fajlok(d):
                if not _windows_fajl(p):
                    fajlok.append(p)
            cl = []
            for c in d["com"]:
                dll, hkcu = com_kezelo(c["clsid"])
                cl.append((dll, hkcu))
                if dll and not _windows_fajl(dll):
                    fajlok.append(dll)
            com[d["ut"]] = cl
        sigs = {}
        try:
            from .alairas import sig_check
            fajlok = list(dict.fromkeys(fajlok))
            for i in range(0, len(fajlok), 120):
                sigs.update(sig_check(fajlok[i:i + 120]))
        except Exception as e:
            log_line("[UTEMEZETT] alairas-ellenorzesi hiba: %s" % e)
        eredm = []
        for d in lista:
            sz, okok = ertekel(d, sigs, com.get(d["ut"]))
            d["szint"], d["okok"] = sz, okok
            d["kivetel"] = bool(sz) and self._ut_kivetel(d)
            d["hash"] = ujjlenyomat(d)
            prog = hivatkozott_fajlok(d)
            d["fajl"] = next((p for p in prog if not _windows_fajl(p)), prog[0] if prog else "")
            d["sig"] = sigs.get(d["fajl"]) if d["fajl"] else None
            eredm.append(d)
        try:
            rejtett = taskcache_rejtett()
        except Exception as e:
            rejtett = []
            log_line("[UTEMEZETT] TaskCache-olvasasi hiba: %s" % e)
        # sorrend: gyanus elol (szint szerint), aztan nem-Microsoft, aztan ut
        eredm.sort(key=lambda d: (-(d["szint"] if not d["kivetel"] else 0), d["ut"].lower().startswith("\\microsoft\\"),
                                  d["ut"].lower()))
        with self._ut_lock:
            self._ut_lista = eredm
            self._ut_rejtett = rejtett
            self._ut_last = time.time()
        self.ut_status = "aktív"
        self._ut_valtozasok(eredm, rejtett, ki)
        gy = [d for d in eredm if d["szint"] and not d["kivetel"]]
        log_line("[UTEMEZETT] atnezes (%s): %d feladat, %d gyanus, %d rejtett" % (ki, len(eredm), len(gy), len(rejtett)))
        return True, self.ut_text()

    def _ut_valtozasok(self, eredm, rejtett, ki):
        kn = self._ut_state.setdefault("known", {})
        most = time.time()
        elso = not self._ut_state.get("first_done")
        regi_rejt = set(self._ut_state.get("rejtett") or [])
        if elso:
            for d in eredm:
                kn[d["ut"]] = d["hash"]
            self._ut_state["first_done"] = True
            self._ut_state["rejtett"] = [r[0] for r in rejtett]
            self._ut_save()
            self._ut_elso_osszegzes(eredm, rejtett)
            return
        figyel = self.is_on() and not self.is_paused()
        for d in eredm:
            regi = kn.get(d["ut"])
            if regi == d["hash"]:
                continue
            kn[d["ut"]] = d["hash"]
            mi = "UJ" if regi is None else "MODOSULT"
            if d["szint"] and not d["kivetel"] and figyel:
                self._ut_riaszt(d, mi)
            else:
                log_line("[UTEMEZETT] %s feladat: %s -> %s%s" % (
                    mi.lower().replace("modosult", "modosult"), d["ut"], self._ut_parancs(d)[:160],
                    " (kivetel)" if d["kivetel"] else ""))
        for ut in [u for u in kn if u not in {d["ut"] for d in eredm}]:
            kn.pop(ut, None)
            log_line("[UTEMEZETT] feladat torolve: %s" % ut)
        for r_ut, ok in rejtett:
            if r_ut not in regi_rejt and figyel:
                self._ut_riaszt_rejtett(r_ut, ok)
        self._ut_state["rejtett"] = [r[0] for r in rejtett]
        self._ut_save()

    def _ut_parancs(self, d):
        r = ["%s %s" % (e["cmd"], e["args"]) for e in d["exec"]] + ["COM %s" % c["clsid"] for c in d["com"]]
        return " | ".join(x.strip() for x in r) or "-"

    def _ut_gombok(self, d):
        try:
            from .telegram import tg_action
            g = [[("⏸ Feladat letiltása", tg_action("ud", {"ut": d["ut"]}))]]
            if d.get("fajl") and not _windows_fajl(d["fajl"]):
                g.append([("🗄 Letiltás + program karanténba", tg_action("uq", {"ut": d["ut"], "fajl": d["fajl"]}))])
            g.append([("✅ Megbízható (ismerem)", tg_action("uk", {"ut": d["ut"]}))])
            return g
        except Exception:
            return None

    def _ut_riaszt(self, d, mi):
        from .alairas import sig_szoveg
        self.ut_alerts += 1
        msg = ("[UTEMEZETT] %s %s UTEMEZETT FELADAT: %s | Parancs: %s | Fut: %s%s | Indul: %s%s | Program: %s | "
               "Alairas: %s | Gyanus: %s | A kartevok igy indulnak ujra minden bejelentkezeskor. Ha nem ismered: "
               "tiltsd le." % (
                   _SZINT_NEV.get(d["szint"], "GYANUS"), mi, d["ut"], self._ut_parancs(d)[:300], d["user"] or "?",
                   " (rendszergazda)" if d["runlevel"] == "HighestAvailable" else "",
                   ", ".join(_TRIGGER_NEV.get(t, t) for t in d["triggers"]) or "kézi",
                   "" if d["enabled"] else " (LETILTVA)", d.get("fajl") or "-",
                   sig_szoveg(d.get("sig"), ekezet=False) if d.get("sig") else "-", "; ".join(d["okok"])))
        with self._ut_lock:
            self._ut_recent = ([{"ts": time.time(), "ut": d["ut"], "szint": d["szint"], "mi": mi,
                                 "okok": "; ".join(d["okok"])[:160]}] + self._ut_recent)[:30]
        self.alert("127.0.0.1", msg, always=True, gombok=self._ut_gombok(d))

    def _ut_riaszt_rejtett(self, ut, ok):
        self.ut_alerts += 1
        msg = ("[UTEMEZETT] KRITIKUS REJTETT UTEMEZETT FELADAT: %s | %s | A Feladatutemezo es a schtasks sem mutatja, "
               "de a gep futtatja - ezt szinte csak kartevo csinalja. Javasolt: Defender TELJES vizsgalat, es a "
               "registryben (TaskCache\\Tree) a kulcs atnezese." % (ut, ok))
        with self._ut_lock:
            self._ut_recent = ([{"ts": time.time(), "ut": ut, "szint": 3, "mi": "REJTETT", "okok": ok}]
                               + self._ut_recent)[:30]
        self.alert("127.0.0.1", msg, always=True, gombok=[[("🛡 Teljes vizsgálat", "sf")]])

    def _ut_elso_osszegzes(self, eredm, rejtett):
        from .telegram import tg_send
        gy = [d for d in eredm if d["szint"] and not d["kivetel"]]
        if not gy and not rejtett:
            tg_send("✅ [UTEMEZETT] Ütemezett feladatok átnézve: %d feladat, egyik sem gyanús. Mostantól szólok, "
                    "ha új vagy módosult gyanús feladat jelenik meg." % len(eredm))
            log_line("[UTEMEZETT] elso atnezes: %d feladat, nincs gyanus" % len(eredm))
            return
        sorok = ["⚠ [UTEMEZETT] Ütemezett feladatok átnézve: %d feladat, ebből %d GYANÚS%s:" % (
            len(eredm), len(gy), (", %d REJTETT" % len(rejtett)) if rejtett else "")]
        for i, d in enumerate(gy[:15], 1):
            sorok.append("%d. [%s] %s%s - %s" % (i, _SZINT_NEV[d["szint"]], d["ut"][:60],
                                                 "" if d["enabled"] else " (letiltva)", "; ".join(d["okok"])[:140]))
        for r_ut, ok in rejtett[:5]:
            sorok.append("REJTETT: %s - %s" % (r_ut[:60], ok))
        sorok.append("Letiltás: /feladattiltas <szám> | Részletek: /feladatok | Javítás ablak > Ütemezett feladatok")
        log_line("[UTEMEZETT] elso atnezes: %d gyanus: %s" % (len(gy), "; ".join(d["ut"] for d in gy[:20])))
        if any(d["szint"] >= 2 and d["enabled"] for d in gy) or rejtett:
            self.alert("127.0.0.1", "[UTEMEZETT] NAGYON GYANUS / REJTETT UTEMEZETT FELADAT van a gepen (%d) - lista: "
                       "/feladatok" % (sum(1 for d in gy if d["szint"] >= 2) + len(rejtett)), always=True)
        tg_send("\n".join(sorok))

    # ------------------------------------------------------------ ciklus
    def _ut_loop(self):
        if self._ut_stop_ev.wait(120):
            return
        while True:
            self._ut_cfg = ut_cfg()
            try:
                if self._ut_cfg["FIGYELES"] != "BE":
                    self.ut_status = "kikapcsolva (utemezett.txt)"
                else:
                    self.ut_scan()
            except Exception as e:
                log_line("[UTEMEZETT] hiba: %s" % e)
            # 30 percenkent, vagy azonnal, ha 4698 (uj feladat) jott
            hatar = time.time() + SCAN_POLL
            while time.time() < hatar:
                if self._ut_stop_ev.wait(5):
                    return
                if self._ut_soon.is_set():
                    self._ut_soon.clear()
                    self._ut_stop_ev.wait(3)      # a feladat-XML kiirasa befejezodjon
                    break

    def utem_soon(self):
        """4698 (uj feladat) utan azonnali atnezes."""
        ev = getattr(self, "_ut_soon", None)
        if ev is not None:
            ev.set()

    def _utemezett_start(self):
        if getattr(self, "_ut_thread", None) and self._ut_thread.is_alive():
            return
        self._ut_cfg = ut_cfg()
        self._ut_state = self._ut_load()
        self._ut_lock = threading.Lock()
        self._ut_scan_lock = threading.Lock()
        self._ut_lista, self._ut_rejtett, self._ut_recent, self._ut_last = [], [], [], 0.0
        self.ut_alerts = getattr(self, "ut_alerts", 0)
        self.ut_status = "indulás…"
        self._ut_t0 = time.time()
        self._ut_soon = threading.Event()
        self._ut_stop_ev = threading.Event()
        self._ut_thread = threading.Thread(target=self._ut_loop, name="utemezett", daemon=True)
        self._ut_thread.start()

    def _utemezett_stop(self):
        ev = getattr(self, "_ut_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ muveletek
    def _ut_keres(self, mi):
        """Feladat sorszamrol (a gyanus lista szerint) vagy utrol."""
        mi = str(mi or "").strip()
        lst = self.ut_gyanusak()
        if mi.isdigit():
            n = int(mi)
            return lst[n - 1] if 1 <= n <= len(lst) else None
        for d in getattr(self, "_ut_lista", []) or []:
            if d["ut"].lower() == mi.lower():
                return d
        return {"ut": mi, "exec": [], "com": [], "fajl": ""} if mi.startswith("\\") else None

    def ut_tilt(self, mi, ki="felulet"):
        d = self._ut_keres(mi)
        if not d:
            return False, "Nincs ilyen feladat (lista: /feladatok)."
        ok, sz = schtasks("/DISABLE", d["ut"])
        if ok:
            d["enabled"] = False
            log_line("[UTEMEZETT] LETILTVA (%s): %s" % (ki, d["ut"]))
            return True, "Letiltva: %s. Visszakapcsolás: /feladatengedely vagy Javítás ablak." % d["ut"]
        return False, "Nem sikerült letiltani (%s): %s" % (d["ut"], sz)

    def ut_enged(self, mi, ki="felulet"):
        d = self._ut_keres(mi)
        if not d:
            return False, "Nincs ilyen feladat (lista: /feladatok)."
        ok, sz = schtasks("/ENABLE", d["ut"])
        if ok:
            d["enabled"] = True
            log_line("[UTEMEZETT] ENGEDELYEZVE (%s): %s" % (ki, d["ut"]))
            return True, "Engedélyezve: %s" % d["ut"]
        return False, "Nem sikerült engedélyezni (%s): %s" % (d["ut"], sz)

    def ut_karanten(self, ut, fajl, ki="felulet"):
        ok1, sz1 = self.ut_tilt(ut, ki=ki)
        if not fajl or _windows_fajl(fajl):
            return ok1, sz1
        try:
            ok2, sz2 = self.folyamat_quarantine(fajl, None, None, ki=ki)
        except Exception as e:
            ok2, sz2 = False, "Karantén nem sikerült: %s" % e
        return (ok1 and ok2), "%s | %s" % (sz1, sz2)

    def ut_megbizhato(self, ut, ki="felulet"):
        ut = (ut or "").strip()
        if not ut:
            return False, "Nincs mit kivételnek jelölni."
        try:
            ut_cfg()
            with open(UT_CFG_FILE, "a", encoding="utf-8") as f:
                f.write("KIVETEL %s\n" % ut.replace("\n", " ")[:260])
            self._ut_cfg = ut_cfg()
        except OSError as e:
            return False, "Nem sikerült menteni: %s" % e
        with self._ut_lock:
            for d in self._ut_lista:
                if d["ut"].lower() == ut.lower():
                    d["kivetel"] = True
        log_line("[UTEMEZETT] kivetel (%s): %s" % (ki, ut))
        return True, "Megbízható - erre a feladatra többet nem szólok: %s" % ut[:120]

    # ------------------------------------------------------------ megjelenites
    def ut_gyanusak(self):
        return [d for d in (getattr(self, "_ut_lista", []) or []) if d.get("szint") and not d.get("kivetel")]

    def ut_ok(self):
        """None = nincs adat; True = nincs bekapcsolt, nagyon gyanus vagy rejtett feladat."""
        if not getattr(self, "_ut_last", 0):
            return None
        return not getattr(self, "_ut_rejtett", None) and \
            not any(d["szint"] >= 2 and d["enabled"] for d in self.ut_gyanusak())

    def ut_summary(self):
        s = getattr(self, "ut_status", "?")
        if s != "aktív":
            if s.startswith("indulás"):
                t0 = getattr(self, "_ut_t0", 0)
                return "Első átnézés: %s" % time.strftime("%H:%M", time.localtime(t0 + 120)) if t0 else s
            return s
        lst = getattr(self, "_ut_lista", []) or []
        gy = self.ut_gyanusak()
        rejt = getattr(self, "_ut_rejtett", []) or []
        reszek = ["Feladat: %d" % len(lst)]
        if gy:
            reszek.append("Gyanús: %d ⚠" % len(gy))
        if rejt:
            reszek.append("REJTETT: %d ⛔" % len(rejt))
        if not gy and not rejt:
            reszek.append("Mind rendben ✔")
        reszek.append("Átnézve: %s" % time.strftime("%H:%M", time.localtime(self._ut_last)))
        return " | ".join(reszek)

    def ut_text(self):
        sorok = ["UTEMEZETT FELADATOK: %s" % self.ut_summary().replace(" | ", ", ")]
        gy = self.ut_gyanusak()
        for i, d in enumerate(gy[:25], 1):
            sorok.append("%d. [%s] %s%s\n   %s\n   -> %s" % (
                i, _SZINT_NEV.get(d["szint"], "?"), d["ut"][:80], "" if d["enabled"] else " (LETILTVA)",
                "; ".join(d["okok"])[:200], self._ut_parancs(d)[:160]))
        for r_ut, ok in (getattr(self, "_ut_rejtett", []) or [])[:10]:
            sorok.append("REJTETT: %s - %s" % (r_ut[:80], ok))
        if gy:
            sorok.append("Letiltas: /feladattiltas <szam> | Vissza: /feladatengedely <szam>")
        elif getattr(self, "_ut_last", 0):
            sorok.append("Nincs gyanus feladat.")
        return "\n".join(sorok)
