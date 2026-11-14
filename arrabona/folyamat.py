# -*- coding: utf-8 -*-
"""Arrabona Guard - FOLYAMATFIGYELES (GuardCore mixin). [v2.12.0]

Minden UJ folyamatot megnez, abban a pillanatban, amikor elindul:
  - psutil: 0,5 mp-enkent az uj PID-ek (nev, ut, parancssor, szulo, nagyszulo),
  - 4688-as esemeny (Biztonsagi naplo): a fel masodpercnel rovidebb eletu
    folyamatokat is latja (pl. egy "powershell -enc ..." ami azonnal kilep).
    Ehhez a Guard bekapcsolja a "Folyamat letrehozasa" naplozast + a parancssor
    naplozasat (folyamat.txt: NAPLO BE / KI).

Mit keres (szintek: 3 = KRITIKUS, 2 = NAGYON GYANUS, 1 = GYANUS):
  3  arnyekmasolat / biztonsagi mentes torlese (zsarolovirus elokeszulet),
     Defender kikapcsolasa / kivetel hozzaadasa, tuzfal kikapcsolasa,
     Office / PDF-olvaso altal inditott parancssor / PowerShell / script (makrovirus),
     alcazott rendszerfolyamat (pl. svchost.exe NEM a Windows mappabol, scvhost.exe),
     forditott iranyu (RTLO) karakter a fajlnevben
  2  kodolt / rejtett PowerShell, "letolt es futtat" parancs, certutil/bitsadmin
     letoltes, mshta/rundll32/regsvr32 trukkok, script futtatasa Temp/Letoltesek
     mappabol, fiok hozzaadasa / admin csoportba tetel, naplotorles,
     bongeszo altal inditott shell, dupla kiterjesztes (szamla.pdf.exe),
     ervenytelen alairasu program, alairatlan program Lomtarbol / Public mappabol
  1  alairatlan program Temp / Letoltesek / AppData\\Roaming / ProgramData gyokerebol

Teendo (folyamat.txt):
  AKCIO FELFUGGESZT (alap) - a KRITIKUS folyamatot megallitja (szunetelteti,
                             nem oli meg): te dontesz (Leallitas / Folytatas)
  AKCIO LEALLIT            - a KRITIKUS folyamatot azonnal leallitja
  AKCIO RIASZT             - csak riaszt
  SZINT 1|2|3              - ettol a szinttol riaszt (alacsonyabb: csak naplo)
A "Megbizhato" gomb (Telegram / ablak) utan ugyanarra tobbet nem szol.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from .common import (APPDATA_DIR, WATCHDOG_VBS, WINDIR, dec_ki, log_line)

FOLYAMAT_CFG_FILE = os.path.join(APPDATA_DIR, "folyamat.txt")
FOLYAMAT_TRUST_FILE = os.path.join(APPDATA_DIR, "folyamat_ismert.json")
POLL = 0.5
EVT_POLL = 15.0
ISMETLES = 600.0          # ugyanarra (kulcs) max 10 percenkent 1 riasztas
_AUDIT_GUID = "{0CCE922B-69AE-11D9-BED3-505054503030}"   # Process Creation (4688)
_CMDLINE_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"

# ------------------------------------------------------------------ nevek
_SHELLEK = {"cmd.exe", "powershell.exe", "pwsh.exe", "powershell_ise.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe",
            "curl.exe", "wmic.exe", "forfiles.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
            "regsvcs.exe", "cmstp.exe", "hh.exe"}
_SCRIPTHOST = {"wscript.exe", "cscript.exe", "mshta.exe"}
_OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe", "msaccess.exe",
           "mspub.exe", "visio.exe", "eqnedt32.exe", "wordview.exe"}
_PDF = {"acrord32.exe", "acrobat.exe", "foxitpdfreader.exe", "foxitreader.exe", "foxitphantompdf.exe",
        "sumatrapdf.exe", "pdfxedit.exe"}
_BONGESZO = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
             "iexplore.exe", "yandex.exe"}
# ezek csak a Windows mappabol futhatnak legitim modon
_RENDSZER = {"svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe",
             "wininit.exe", "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe",
             "sihost.exe", "ctfmon.exe", "dwm.exe", "lsaiso.exe", "explorer.exe", "searchindexer.exe",
             "runtimebroker.exe", "fontdrvhost.exe", "audiodg.exe", "taskmgr.exe", "regsvr32.exe",
             "cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe", "userinit.exe",
             "wuauclt.exe", "msiexec.exe", "certutil.exe"}  # (notepad: Win11-en WindowsApps-bol fut)
# ismert alcazo nevek (betucsere)
_ALNEV = {"scvhost.exe", "svch0st.exe", "svchosts.exe", "svhost.exe", "svchost32.exe", "svchest.exe",
          "lsas.exe", "lsasss.exe", "isass.exe", "lssas.exe", "csrs.exe", "crss.exe", "csrsss.exe",
          "winlogin.exe", "winlogon32.exe", "expl0rer.exe", "explore.exe", "explorer32.exe",
          "servicess.exe", "service.exe", "smss32.exe", "rundl32.exe", "rundll.exe", "dllhst.exe",
          "dIlhost.exe".lower(), "conhost32.exe", "taskhost32.exe", "spoolsvc.exe", "wininit32.exe"}
_VEDETT = {"system", "registry", "idle", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
           "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "dwm.exe", "msmpeng.exe",
           "mpdefendercoreservice.exe", "nissrv.exe", "fontdrvhost.exe", "sihost.exe", "taskhostw.exe",
           "audiodg.exe", "memory compression", "securityhealthservice.exe"}

# ------------------------------------------------------------------ parancssor-szabalyok
# (azonosito, szint, csak ezekre a programokra (None = barmi), regex, magyar indoklas)
_I = re.I
_SZABALYOK = (
    # --- 3: KRITIKUS
    ("arnyekmasolat", 3, None,
     re.compile(r"vssadmin(\.exe)?\W.*\b(delete\s+shadows|resize\s+shadowstorage)|shadowcopy\s+delete|"
                r"win32_shadowcopy.*(delete|remove)|wbadmin(\.exe)?\W.*delete\s+(catalog|systemstatebackup|backup)|"
                r"bcdedit(\.exe)?\W.*(recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)", _I),
     "árnyékmásolatok / biztonsági mentések törlése (zsarolóvírus jellemző lépése)"),
    ("defender_ki", 3, None,
     re.compile(r"set-mppreference\W.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|"
                r"scriptscanning|intrusionpreventionsystem|blockatfirstseen)\s+(\$?true|1)\b|"
                r"add-mppreference\W.*-exclusion(path|process|extension|ipaddress)|"
                r"\bsc(\.exe)?\s+(stop|config|delete)\s+(windefend|wdnissvc|sense)\b|"
                r"windows defender.*disable(antispyware|antivirus|realtimemonitoring)", _I),
     "a Windows Defender kikapcsolása / kivétel hozzáadása"),
    ("tuzfal_ki", 3, None,
     re.compile(r"netsh(\.exe)?\W.*advfirewall\s+set\s+\w+\s+state\s+off|netsh(\.exe)?\W.*firewall\s+set\s+opmode\s+"
                r"(mode=)?disable|set-netfirewallprofile\W.*-enabled\s+(\$?false|0)\b", _I),
     "a Windows tűzfal kikapcsolása"),
    # --- 2: NAGYON GYANUS
    ("ps_kodolt", 2, {"powershell.exe", "pwsh.exe"},
     re.compile(r"\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedcommand)?\s+[a-z0-9+/=]{20,}", _I),
     "kódolt (base64) PowerShell-parancs"),
    ("ps_letolt_futtat", 2, None,
     re.compile(r"(downloadstring|downloaddata|net\.webclient|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b|"
                r"start-bitstransfer|\bwget\b|\bcurl\b)[^\n]*(\biex\b|invoke-expression|\|\s*&|start-process|"
                r"\.invoke\(|frombase64string)|(\biex\b|invoke-expression)[^\n]*(downloadstring|net\.webclient|"
                r"invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)", _I),
     "internetről letölt és azonnal futtat (\"download & execute\")"),
    ("ps_memoria", 2, {"powershell.exe", "pwsh.exe"},
     re.compile(r"frombase64string[^\n]*(\biex\b|invoke-expression|reflection\.assembly|::load\()|"
                r"reflection\.assembly\]::load|virtualalloc|amsiutils|amsiinitfailed", _I),
     "memóriába tölt / AMSI-kikerülés (fájl nélküli kártevő jele)"),
    ("ps_rejtett", 1, {"powershell.exe", "pwsh.exe"},
     re.compile(r"\s[-/]w(i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+(h|hi|hid|hidd|hidde|"
                r"hidden|1)\b", _I),
     "rejtett ablakos PowerShell"),
    ("certutil", 2, {"certutil.exe"},
     re.compile(r"[-/](urlcache|verifyctl|decode|decodehex)\b|https?://", _I),
     "certutil letöltésre / dekódolásra használva"),
    ("bitsadmin", 2, {"bitsadmin.exe"},
     re.compile(r"/(transfer|addfile|setnotifycmdline)\b", _I),
     "bitsadmin háttérletöltés"),
    ("mshta", 2, {"mshta.exe"},
     re.compile(r"https?://|javascript:|vbscript:|\\(temp|downloads|letöltések|appdata|public)\\", _I),
     "mshta internetes / ideiglenes HTA-val vagy szkripttel"),
    ("rundll32", 2, {"rundll32.exe"},
     re.compile(r"javascript:|https?://|\\(temp|tmp|downloads|letöltések|users\\public|programdata)\\[^,]*\.\w+\s*,|"
                r"\\appdata\\(roaming|local\\temp)\\[^,]*,", _I),
     "rundll32 gyanús helyről tölt DLL-t / szkriptet"),
    ("regsvr32", 2, {"regsvr32.exe"},
     re.compile(r"/i:\s*https?://|scrobj\.dll|\\(temp|downloads|letöltések|users\\public)\\", _I),
     "regsvr32 trükk (\"Squiblydoo\") / DLL gyanús helyről"),
    ("script_tempbol", 2, _SCRIPTHOST,
     re.compile(r"\\(temp|tmp|downloads|letöltések|users\\public)\\[^\"]*\.(js|jse|vbs|vbe|wsf|hta)\b|"
                r"\\appdata\\(roaming|local\\temp)\\[^\"]*\.(js|jse|vbs|vbe|wsf|hta)\b", _I),
     "szkript futtatása Temp / Letöltések / AppData mappából"),
    ("fiok", 2, None,
     re.compile(r"\bnet1?(\.exe)?\s+user\s+\S+\s+\S*\s*/add\b|\bnet1?(\.exe)?\s+localgroup\s+"
                r"(administrators|rendszergazdák|rendszergazdak|\"remote desktop users\"|"
                r"\"távoli asztal felhasználói\")\s+\S+\s*/add\b|add-localgroupmember\W.*administrators", _I),
     "új felhasználói fiók / felvétel a rendszergazdák közé"),
    ("naplotorles", 2, None,
     re.compile(r"\bwevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog|remove-eventlog|"
                r"\bfsutil(\.exe)?\s+usn\s+deletejournal", _I),
     "eseménynapló törlése (nyomok eltüntetése)"),
    ("curl_futtat", 1, {"curl.exe", "cmd.exe"},
     re.compile(r"curl(\.exe)?\s[^\n]*https?://[^\n]*\s-o\s*\S*\\(temp|appdata|users\\public|programdata)\\", _I),
     "curl letöltés Temp / AppData / Public mappába"),
)

_HELYEK = (
    # (regex az utvonalra, szint ha alairatlan, magyar)
    (re.compile(r"\\\$recycle\.bin\\", _I), 2, "a Lomtárból fut"),
    (re.compile(r"\\users\\public\\", _I), 2, "a Public (közös) mappából fut"),
    (re.compile(r"^[a-z]:\\windows\\temp\\", _I), 2, "a Windows\\Temp mappából fut"),
    (re.compile(r"\\appdata\\local\\temp\\|\\temp\\|\\tmp\\", _I), 1, "a Temp mappából fut"),
    (re.compile(r"\\downloads\\|\\letöltések\\", _I), 1, "a Letöltések mappából fut"),
    (re.compile(r"\\appdata\\roaming\\(?:[^\\]+\\)?[^\\]+\.(exe|scr|com|pif)$", _I), 1,
     "közvetlenül az AppData\\Roaming-ból fut"),
    (re.compile(r"^[a-z]:\\programdata\\(?:[^\\]+\\)?[^\\]+\.(exe|scr|com|pif)$", _I), 1,
     "közvetlenül a ProgramData-ból fut"),
)
_DUPLA = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|bmp|txt|rtf|mp[34]|avi|mkv|zip|rar|7z)"
                    r"\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|hta)$", _I)
_RTLO = u"\u202e"
_SZINT_NEV = {3: "KRITIKUS", 2: "NAGYON GYANUS", 1: "GYANUS"}


def _norm(p):
    return os.path.normcase(os.path.normpath(p or ""))


_WIN = _norm(WINDIR).rstrip("\\/") + "\\"


def windows_fajl(p):
    """A Windows mappaban van (a Windows\\Temp NEM szamit annak: oda barki irhat)."""
    n = _norm(p)
    return bool(p) and n.startswith(_WIN) and not n.startswith(_WIN + "temp\\")


def folyamat_cfg():
    """{"FIGYELES": BE/KI, "AKCIO": FELFUGGESZT/LEALLIT/RIASZT, "SZINT": 1-3, "NAPLO": BE/KI,
        "AUTOSCAN": BE/KI, "KIVETEL": [reszletek kisbetuvel]}"""
    cfg = {"FIGYELES": "BE", "AKCIO": "FELFUGGESZT", "SZINT": 1, "NAPLO": "BE", "AUTOSCAN": "BE", "KIVETEL": []}
    try:
        if not os.path.exists(FOLYAMAT_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(FOLYAMAT_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - folyamatfigyeles (v2.12.0)\n"
                        "# FIGYELES BE / KI\n"
                        "FIGYELES BE\n"
                        "# KRITIKUS esetben (arnyekmasolat-torles, Defender kikapcsolasa, Office -> PowerShell,\n"
                        "# alcazott rendszerfolyamat): FELFUGGESZT (megallitja, te dontesz) / LEALLIT / RIASZT\n"
                        "AKCIO FELFUGGESZT\n"
                        "# Ettol a szinttol riaszt: 1 = minden gyanus (alap), 2 = csak a nagyon gyanus, 3 = csak a kritikus\n"
                        "# (az alacsonyabbak csak a naploba kerulnek)\n"
                        "SZINT 1\n"
                        "# NAPLO BE = a 4688-as esemennyel a nagyon rovid eletu folyamatokat is latja\n"
                        "# (bekapcsolja a Windows 'folyamat letrehozasa' + parancssor naplozasat)\n"
                        "NAPLO BE\n"
                        "# AUTOSCAN BE = a gyanus helyrol futo program fajljat a Defender azonnal atvizsgalja\n"
                        "AUTOSCAN BE\n"
                        "# KIVETEL <reszlet> = ha a program utja vagy parancssora tartalmazza, kihagyja (tobb sor is lehet)\n"
                        "# pl.: KIVETEL \\steamapps\\common\\\n")
        with open(FOLYAMAT_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k = r[0].upper()
                v = r[1].strip() if len(r) > 1 else ""
                if k == "KIVETEL":
                    if v:
                        cfg["KIVETEL"].append(v.lower())
                elif k == "SZINT":
                    if v in ("1", "2", "3"):
                        cfg["SZINT"] = int(v)
                elif k == "AKCIO":
                    if v.upper() in ("FELFUGGESZT", "LEALLIT", "RIASZT"):
                        cfg["AKCIO"] = v.upper()
                elif k in ("FIGYELES", "NAPLO", "AUTOSCAN"):
                    vv = v.upper()
                    if vv in ("BE", "KI", "ON", "OFF"):
                        cfg[k] = "KI" if vv in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def _sha256(p, limit=200 * 1024 * 1024):
    try:
        if os.path.getsize(p) > limit:
            return ""
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for blk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(blk)
        return h.hexdigest()
    except OSError:
        return ""


_FAJL = re.compile(r"[A-Za-z]:\\[^\"<>|*?\r\n,]*?\.(exe|dll|scr|bat|cmd|vbs|vbe|js|jse|ps1|hta|wsf|com|pif)\b", _I)


def fajl_a_parancsban(cmd):
    """Az elso NEM Windows-mappabeli, letezo fajl a parancssorban (pl. a futtatott szkript)."""
    for m in _FAJL.finditer(os.path.expandvars(cmd or "")):
        j = m.group(0).strip()
        if not windows_fajl(j) and os.path.isfile(j):
            return j
    return None


_ENYHE = {"ps_rejtett", "curl_futtat"}


def _program_files(p):
    n = _norm(p)
    for k in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        v = os.environ.get(k)
        if v and n.startswith(_norm(v).rstrip("\\/") + "\\"):
            return True
    return False


def ertekel(info, felmenok):
    """Szabalyok egy folyamatra (alairas nelkul). Visszaad: [(szint, azonosito, indoklas)].
    info: {"name","exe","cmd"}; felmenok: [{"name","exe","cmd"}, ...] (szulo, nagyszulo)."""
    nev = (info.get("name") or "").lower()
    exe = info.get("exe") or ""
    cmd = info.get("cmd") or ""
    hits = []
    # alcazott rendszerfolyamat
    if exe and nev in _RENDSZER and not windows_fajl(exe):
        hits.append((3, "alcazott", "rendszerfolyamat nevét viseli (%s), de NEM a Windows mappából fut" % nev))
    if nev in _ALNEV:
        hits.append((3, "alnev", "rendszerfolyamatnak álcázott név (%s)" % nev))
    if _RTLO in (exe + nev):
        hits.append((3, "rtlo", "fordított írásirányú (RTLO) karakter a fájlnévben - kiterjesztés-hamisítás"))
    if _DUPLA.search(nev):
        hits.append((2, "dupla", "dupla kiterjesztés (%s) - dokumentumnak álcázott program" % nev))
    # parancssor
    for azon, szint, csak, rx, ok in _SZABALYOK:
        if csak is not None and nev not in csak:
            continue
        if rx.search(cmd):
            hits.append((szint, azon, ok))
    # szulo / nagyszulo
    if nev in _SHELLEK:
        for i, f in enumerate(felmenok[:2]):
            fn = (f.get("name") or "").lower()
            mi = "szülő" if i == 0 else "nagyszülő"
            if fn in _OFFICE:
                hits.append((3, "office", "Office-program (%s, %s) indította - makróvírus jele" % (fn, mi)))
                break
            if fn in _PDF:
                hits.append((3, "pdf", "PDF-olvasó (%s, %s) indította" % (fn, mi)))
                break
            if i == 0 and fn in _BONGESZO and nev in ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe",
                                                       "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe"):
                lc = cmd.lower()
                if ("chrome-extension://" in lc or "moz-extension://" in lc or "nativemessaging" in lc
                        or "native-messaging" in lc or (fn == "firefox.exe" and ".json" in lc)):
                    break   # bovitmeny "native messaging" segedprogramja: normalis
                hits.append((2, "bongeszo", "a böngésző (%s) közvetlenül parancssort / szkriptet indított" % fn))
                break
    # csak a legsulyosabb azonos azonositoju
    lat, ki = set(), []
    for h in sorted(hits, key=lambda x: -x[0]):
        if h[1] not in lat:
            lat.add(h[1])
            ki.append(h)
    return ki


def hely_okok(exe):
    """[(alap_szint, indoklas)] a futasi helyrol (alairas nelkul meg nem dontheto el)."""
    out = []
    if not exe or windows_fajl(exe):
        return out
    for rx, szint, ok in _HELYEK:
        if rx.search(exe):
            out.append((szint, ok))
            break
    return out


class FolyamatMixin(object):
    """Folyamatfigyeles. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ megbizhato lista
    def _fy_trust_load(self):
        try:
            with open(FOLYAMAT_TRUST_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _fy_trust_save(self):
        try:
            tmp = FOLYAMAT_TRUST_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._fy_trust, f, ensure_ascii=False, indent=1)
            os.replace(tmp, FOLYAMAT_TRUST_FILE)
        except OSError as e:
            log_line("[FOLYAMAT] mentesi hiba: %s" % e)

    def folyamat_trust(self, kulcs, leiras="", ki="felulet"):
        self._fy_trust[kulcs] = {"ts": time.time(), "leiras": leiras[:200], "ki": ki}
        self._fy_trust_save()
        log_line("[FOLYAMAT] megbizhatonak jelolve (%s): %s" % (ki, leiras[:200] or kulcs))
        return True, "Megbízhatónak jelölve - erre többet nem szólok: %s" % (leiras[:120] or kulcs)

    def folyamat_untrust_all(self):
        n = len(self._fy_trust)
        self._fy_trust = {}
        self._fy_trust_save()
        return n

    # ------------------------------------------------------------ sajat folyamatok
    def _fy_sajat_init(self):
        own = {os.getpid()}
        self._fy_own_exe = _norm(sys.executable) if getattr(sys, "frozen", False) else ""
        try:
            import psutil
            me = psutil.Process()
            p = me.parent()
            # PyInstaller onefile: a bootloader a szulo (ugyanaz az exe)
            if p and _norm(p.exe()) == _norm(me.exe()):
                own.add(p.pid)
        except Exception:
            pass
        self._fy_own = own

    def _fy_sajat(self, info, felmenok):
        if info.get("pid") in self._fy_own:
            return True
        exe = _norm(info.get("exe"))
        if self._fy_own_exe and exe == self._fy_own_exe:
            return True
        for f in felmenok:
            if f.get("pid") in self._fy_own:
                return True
            if self._fy_own_exe and _norm(f.get("exe")) == self._fy_own_exe:
                return True
        lc = (info.get("cmd") or "").lower()
        if WATCHDOG_VBS and WATCHDOG_VBS.lower() in lc:
            return True
        return False

    # ------------------------------------------------------------ adatgyujtes
    def _fy_info(self, pid):
        import psutil
        try:
            p = psutil.Process(pid)
            with p.oneshot():
                d = {"pid": pid, "ppid": p.ppid(), "ctime": p.create_time(), "name": p.name()}
                try:
                    d["exe"] = p.exe()
                except Exception:
                    d["exe"] = ""
                try:
                    d["cmd"] = " ".join(p.cmdline())
                except Exception:
                    d["cmd"] = ""
                try:
                    d["user"] = p.username()
                except Exception:
                    d["user"] = ""
            return d
        except Exception:
            return None

    def _fy_felmenok(self, d, melyseg=3):
        out, ppid, ctime = [], d.get("ppid"), d.get("ctime") or 0
        for _ in range(melyseg):
            if not ppid or ppid in (0, 4):
                break
            f = self._fy_cache.get(ppid)
            # PID-ujrahasznositas: a szulo nem lehet fiatalabb a gyereknel
            if f and ctime and f.get("ctime") and f["ctime"] > ctime + 1:
                f = None
            if f is None:
                f = self._fy_info(ppid)
                if f and ctime and f.get("ctime") and f["ctime"] > ctime + 1:
                    f = None
                if f:
                    self._fy_cache[ppid] = f
            if not f:
                break
            out.append(f)
            ppid, ctime = f.get("ppid"), f.get("ctime") or ctime
        return out

    # ------------------------------------------------------------ kiertekeles
    def _fy_vizsgal(self, d, forras="psutil", indulas=False):
        """Szabalyok + (szukseg eseten) alairas-sor. forras: psutil / 4688 / indulas."""
        felmenok = d.get("_felmenok")
        if felmenok is None:
            felmenok = self._fy_felmenok(d)
        if self._fy_sajat(d, felmenok):
            return
        cfg = self._fy_cfg
        lc = ((d.get("exe") or "") + " " + (d.get("cmd") or "")).lower()
        if any(k in lc for k in cfg["KIVETEL"]):
            return
        hits = ertekel(d, felmenok)
        helyek = hely_okok(d.get("exe"))
        # [v2.13.1] enyhe (1-es szintu) parancssori jel + a szulo egy TELEPITETT program
        # (Program Files): ha a szulo alairt, ez a program sajat mukodese (pl. KerishDoctor,
        # ASUS, NVIDIA rejtett PowerShellje) - csak naplo, nincs riasztas
        szulo_exe = (felmenok[0].get("exe") or "") if felmenok else ""
        if (hits and not helyek and all(h[0] == 1 and h[1] in _ENYHE for h in hits)
                and szulo_exe and _program_files(szulo_exe)):
            d["_szulo_ell"] = szulo_exe
        if helyek or d.get("_szulo_ell") or (d.get("exe") and not windows_fajl(d.get("exe")) and hits):
            # alairas kell: a hatter-szal nezi meg (PowerShell, ~1 mp)
            with self._fy_q_lock:
                if len(self._fy_q) < 300:
                    self._fy_q.append((d, felmenok, hits, helyek, forras, indulas))
            self._fy_q_ev.set()
            return
        if hits:
            self._fy_dont(d, felmenok, hits, None, forras, indulas)

    def _fy_sig_worker(self):
        from .alairas import sig_check, sig_veszely
        while not self._fy_stop_ev.is_set():
            self._fy_q_ev.wait(2.0)
            self._fy_q_ev.clear()
            with self._fy_q_lock:
                tetelek, self._fy_q = self._fy_q, []
            if not tetelek:
                continue
            try:
                sigs = sig_check([t[0].get("exe") for t in tetelek if t[0].get("exe")] +
                                 [t[0]["_szulo_ell"] for t in tetelek if t[0].get("_szulo_ell")])
            except Exception as e:
                log_line("[FOLYAMAT] alairas-hiba: %s" % e)
                sigs = {}
            for d, felmenok, hits, helyek, forras, indulas in tetelek:
                try:
                    if d.get("_szulo_ell"):
                        ssig = sigs.get(d["_szulo_ell"])
                        if (ssig or {}).get("allapot") == "ok":
                            log_line("[FOLYAMAT] (alairt telepitett szulo: %s, %s - nincs riasztas) %s PID %s: %s" % (
                                os.path.basename(d["_szulo_ell"]), ssig.get("kiado") or "?", d.get("name"),
                                d.get("pid"), (d.get("cmd") or "")[:200]))
                            continue
                    sig = sigs.get(d.get("exe"))
                    v = sig_veszely(sig)
                    hits = list(hits)
                    if v == 2:
                        hits.append((2, "rossz_alairas", "ÉRVÉNYTELEN aláírás - a fájlt aláírás után módosították"))
                    elif v == 1 and helyek:
                        szint, ok = helyek[0]
                        fn = ((felmenok[0].get("name") if felmenok else "") or "").lower()
                        if szint == 1 and (fn in _SHELLEK or fn in _OFFICE or fn in _PDF):
                            szint = 2
                            ok += " (%s indította)" % fn
                        hits.append((szint, "hely", "aláíratlan program, " + ok))
                    if hits:
                        self._fy_dont(d, felmenok, sorted(hits, key=lambda x: -x[0]), sig, forras, indulas)
                except Exception as e:
                    log_line("[FOLYAMAT] kiertekelesi hiba: %s" % e)

    def _fy_kulcs(self, d, felmenok, hit, sha):
        azon = hit[1]
        if azon in ("hely", "rossz_alairas", "dupla", "alcazott", "alnev", "rtlo"):
            return "f|%s|%s" % (azon, sha or _norm(d.get("exe")))
        szulo = _norm(felmenok[0].get("exe")) if felmenok else "?"
        return "c|%s|%s|%s" % (azon, (d.get("name") or "").lower(), szulo)

    def _fy_dont(self, d, felmenok, hits, sig, forras, indulas):
        from .alairas import sig_szoveg
        cfg = self._fy_cfg
        szint = hits[0][0]
        exe = d.get("exe") or ""
        sha = _sha256(exe) if exe and not windows_fajl(exe) and os.path.isfile(exe) else ""
        kulcs = self._fy_kulcs(d, felmenok, hits[0], sha)
        if kulcs in self._fy_trust:
            log_line("[FOLYAMAT] megbizhato, kihagyva: %s (PID %s)" % (d.get("name"), d.get("pid")))
            return
        most = time.time()
        okok = "; ".join(h[2] for h in hits)
        szulo = felmenok[0] if felmenok else {}
        nagy = felmenok[1] if len(felmenok) > 1 else {}
        rec = {"ts": most, "szint": szint, "pid": d.get("pid"), "ctime": d.get("ctime"), "name": d.get("name"),
               "exe": exe, "cmd": (d.get("cmd") or "")[:400], "szulo": szulo.get("name") or "",
               "okok": okok, "kulcs": kulcs, "forras": forras, "akcio": ""}
        if szint < cfg["SZINT"] or (indulas and szint < 2):
            log_line("[FOLYAMAT] (szint %d, nincs riasztas) %s PID %s: %s | %s" % (
                szint, d.get("name"), d.get("pid"), okok, rec["cmd"][:200]))
            return
        if most - self._fy_last.get(kulcs, 0.0) < ISMETLES:
            log_line("[FOLYAMAT] ismetles (10 percen belul): %s PID %s" % (d.get("name"), d.get("pid")))
            return
        self._fy_last[kulcs] = most
        # --- automatikus teendo (KRITIKUS)
        akcio = ""
        el = forras != "4688"
        if szint >= 3 and el:
            if cfg["AKCIO"] == "FELFUGGESZT":
                ok, sz = self._fy_suspend(d)
                akcio = sz
            elif cfg["AKCIO"] == "LEALLIT":
                ok, sz = self.folyamat_kill(d["pid"], d.get("ctime"), ki="automatikus")
                akcio = ("LEALLITVA" if ok else "LEALLITAS NEM SIKERULT: " + sz)
            else:
                akcio = "(folyamat.txt: AKCIO RIASZT - nem allitottam meg)"
        elif forras == "4688":
            akcio = "(rovid eletu folyamat - mar lefutott)"
        rec["akcio"] = akcio
        with self._fy_lock:
            self.proc_alerts += 1
            self._fy_recent = ([rec] + self._fy_recent)[:30]
        fej = _SZINT_NEV.get(szint, "GYANUS")
        msg = "[FOLYAMAT] %s FOLYAMAT%s: %s (PID %s)" % (
            fej, " (mar futott a Guard indulasakor)" if indulas else "", d.get("name"), d.get("pid"))
        if exe:
            msg += " | Ut: %s" % exe[:200]
        if d.get("cmd"):
            msg += " | Parancs: %s" % d["cmd"][:300]
        if szulo:
            msg += " | Szulo: %s (PID %s)" % (szulo.get("name"), szulo.get("pid"))
            if nagy:
                msg += " <- %s" % nagy.get("name")
        if sig:
            msg += " | Alairas: %s" % sig_szoveg(sig, ekezet=False)
        msg += " | Gyanus: %s" % okok
        if akcio:
            msg += " | " + akcio
        if any(h[1] == "hely" for h in hits) and szint == 1:
            msg += " | Ha epp most telepitesz / inditasz valamit, ez normalis lehet."
        # Defender + VirusTotal a program fajljara (vagy a futtatott szkriptre)
        cel = exe if exe and not windows_fajl(exe) and os.path.isfile(exe) else fajl_a_parancsban(d.get("cmd"))
        if cel and cfg["AUTOSCAN"] == "BE":
            try:
                from .defender import scan_allapot
                lep = [("Gyanús folyamat: %s (PID %s)" % (d.get("name"), d.get("pid")), most),
                       ("Fájl: %s" % cel[-70:], most), ("Ok: %s" % hits[0][2][:80], most)]
                okv = self.defender_scan("custom", cel, elozmeny=lep, cimke="Folyamat: %s" % os.path.basename(cel)[:40])
                msg += " | Defender-vizsgalat %s" % scan_allapot(okv)
            except Exception as ex:
                log_line("[FOLYAMAT] vizsgalat inditasi hiba: %s" % ex)
        if cel and hasattr(self, "vt_kerd"):
            try:
                self.vt_kerd(cel, "Folyamat: %s" % os.path.basename(cel)[:40])
            except Exception:
                pass
        # gombok
        gombok = []
        try:
            from .telegram import tg_action
            ct = int(d.get("ctime") or 0)
            if el:
                if "FELFUGGESZTVE" in akcio:
                    gombok.append([("⛔ Leállítás + teljes vizsgálat", "pk:%s:%d:full" % (d["pid"], ct)),
                                   ("▶ Folytatás (én voltam)", "pr:%s:%d" % (d["pid"], ct))])
                elif "LEALLITVA" not in akcio:
                    gombok.append([("⛔ Leállítás", "pk:%s:%d" % (d["pid"], ct))])
            if cel and not windows_fajl(cel):
                gombok.append([("🗄 Karanténba (fájl)", tg_action("pq", {"pid": d["pid"], "ctime": ct, "fajl": cel}))])
            # [v2.14.0] parancssori szabalynal, ha a szulo Windows-program (cmd, explorer, svchost...),
            # a "megbizhato" MINDEN kesobbi ilyen esetet elnemitana (a kartevoet is) -> csak Rendben
            szulo_exe = (felmenok[0].get("exe") or "") if felmenok else ""
            fajl_alapu = kulcs.startswith("f|")
            if fajl_alapu or (szulo_exe and not windows_fajl(szulo_exe)):
                gombok.append([("✅ Megbízható, ne szólj többet",
                                tg_action("pt", {"kulcs": kulcs, "leiras": "%s: %s" % (d.get("name"), hits[0][2])}))])
            else:
                gombok.append([("✅ Rendben / én voltam", "ok")])
        except Exception:
            gombok = None
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)
        if "FELFUGGESZTVE" in akcio:
            # dontes-ablak a feluleten (jatek kozben a jatek vegen jon)
            try:
                self.out.put(("ransom", {"tipus": "folyamat", "pid": d["pid"], "ctime": d.get("ctime"),
                                         "name": d.get("name"), "exe": exe, "cmd": rec["cmd"],
                                         "szulo": rec["szulo"], "where": okok, "ts": most}))
            except Exception:
                pass

    # ------------------------------------------------------------ muveletek
    def _fy_get(self, pid, ctime=None):
        import psutil
        p = psutil.Process(int(pid))
        if ctime and abs(int(p.create_time()) - int(ctime)) > 1:
            raise ValueError("a PID %s mar egy MASIK folyamate (az eredeti kozben kilepett)" % pid)
        return p

    def _fy_vedett(self, p):
        try:
            nev = p.name().lower()
            exe = p.exe()
        except Exception:
            return True
        return p.pid in (0, 4) or p.pid in self._fy_own or (nev in _VEDETT and windows_fajl(exe))

    def _fy_suspend(self, d):
        try:
            p = self._fy_get(d["pid"], d.get("ctime"))
            if self._fy_vedett(p):
                return False, "Windows-/vedett folyamat: NEM allitottam meg"
            p.suspend()
        except Exception as e:
            return False, "MEGALLITAS NEM SIKERULT: %s" % e
        with self._fy_lock:
            self._proc_suspended[int(d["pid"])] = {"name": d.get("name"), "exe": d.get("exe"),
                                                    "ctime": d.get("ctime"), "ts": time.time()}
        log_line("[FOLYAMAT] FELFUGGESZTVE: %s (PID %s)" % (d.get("name"), d["pid"]))
        return True, "FOLYAMAT FELFUGGESZTVE (megallitva) - dontes: Leallitas / Folytatas"

    def folyamat_kill(self, pid, ctime=None, ki="felulet"):
        try:
            p = self._fy_get(pid, ctime)
            nev = p.name()
            if self._fy_vedett(p):
                return False, "%s Windows-/vedett folyamat - nem allitom le." % nev
            try:
                p.resume()      # felfuggesztett folyamatot is le lehessen allitani
            except Exception:
                pass
            p.kill()
        except Exception as e:
            return False, "Leallitas nem sikerult (PID %s): %s" % (pid, e)
        with self._fy_lock:
            self._proc_suspended.pop(int(pid), None)
        log_line("[FOLYAMAT] LEALLITVA (%s): %s (PID %s)" % (ki, nev, pid))
        return True, "LEALLITVA: %s (PID %s)." % (nev, pid)

    def folyamat_resume(self, pid, ctime=None, ki="felulet"):
        try:
            p = self._fy_get(pid, ctime)
            nev = p.name()
            p.resume()
        except Exception as e:
            return False, "Folytatas nem sikerult (PID %s): %s" % (pid, e)
        with self._fy_lock:
            self._proc_suspended.pop(int(pid), None)
        log_line("[FOLYAMAT] FOLYTATVA (%s): %s (PID %s)" % (ki, nev, pid))
        return True, "Folytatva: %s (PID %s)." % (nev, pid)

    def folyamat_quarantine(self, fajl, pid=None, ctime=None, ki="felulet"):
        """A program / szkript fajljanak karantenba tetele (elotte a folyamat leallitasa).
        A javitas-karantenba kerul, onnan visszaallithato (/karanten, /visszaallit)."""
        if not fajl or windows_fajl(fajl):
            return False, "Windows-mappabeli fajlt nem teszek karantenba."
        leallitva = ""
        if pid:
            ok, sz = self.folyamat_kill(pid, ctime, ki=ki)
            leallitva = " " + sz if ok else ""
        try:
            from .javitas import KARANTEN_DIR, stop_processes
            stop_processes(fajl)
            lk = self._fix_lock() if hasattr(self, "_fix_lock") else threading.Lock()
            with lk:
                lst = self.quarantine_list()
                alap = time.strftime("%m%d%H%M")
                letezo = {r.get("id") for r in lst}
                n = 1
                while "%s-%d" % (alap, n) in letezo:
                    n += 1
                qid = "%s-%d" % (alap, n)
                os.makedirs(KARANTEN_DIR, exist_ok=True)
                cel = os.path.join(KARANTEN_DIR, "%s_%s.karanten" % (qid, os.path.basename(fajl)))
                shutil.move(fajl, cel)
                lst.insert(0, {"id": qid, "ts": time.time(), "hely": "Folyamatfigyelés",
                               "nev": os.path.basename(fajl), "cmd": fajl, "ki": ki,
                               "tipus": "fajl", "eredeti": fajl, "karanten": cel})
                self._quarantine_save(lst)
        except PermissionError:
            return False, "Nincs jogosultsag / a fajl meg hasznalatban van: %s%s" % (fajl, leallitva)
        except Exception as e:
            return False, "Karanten nem sikerult: %s%s" % (e, leallitva)
        sz = "%s karantenba teve (azonosito: %s).%s Visszaallitas: /visszaallit %s" % (fajl, qid, leallitva, qid)
        log_line("[FOLYAMAT] KARANTEN (%s): %s" % (ki, sz))
        return True, sz

    # ------------------------------------------------------------ 4688 (rovid eletu folyamatok)
    def _fy_naplo_beallit(self):
        if not getattr(self, "admin", False):
            log_line("[FOLYAMAT] 4688-naplozas: nincs rendszergazdai jog, kihagyva")
            return False
        ok = True
        try:
            r = subprocess.run(["auditpol", "/set", "/subcategory:" + _AUDIT_GUID, "/success:enable"],
                               capture_output=True, timeout=20)
            ok = r.returncode == 0
        except Exception as e:
            log_line("[FOLYAMAT] auditpol hiba: %s" % e)
            ok = False
        try:
            import winreg
            with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, _CMDLINE_KEY, 0,
                                    winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)) as k:
                winreg.SetValueEx(k, "ProcessCreationIncludeCmdLine_Enabled", 0, winreg.REG_DWORD, 1)
        except Exception as e:
            log_line("[FOLYAMAT] parancssor-naplozas beallitasa sikertelen: %s" % e)
        log_line("[FOLYAMAT] 4688 folyamat-naplozas: %s" % ("bekapcsolva" if ok else "SIKERTELEN"))
        return ok

    def _fy_4688(self):
        import xml.etree.ElementTree as ET
        vissza = int(EVT_POLL * 2000) + 15000
        q = "*[System[(EventID=4688) and TimeCreated[timediff(@SystemTime) <= %d]]]" % vissza
        r = subprocess.run(["wevtutil", "qe", "Security", "/q:" + q, "/f:XML", "/rd:true", "/c:400", "/uni:true"],
                           capture_output=True, timeout=45)
        out = dec_ki(r.stdout)
        if not out.strip():
            return
        doc = ET.fromstring("<events>" + out + "</events>")
        most = time.time()
        for ev in doc:
            adat = {}
            for el in ev.iter():
                if el.tag.endswith("Data") and el.get("Name"):
                    adat[el.get("Name")] = el.text or ""
            try:
                pid = int(adat.get("NewProcessId", "0"), 16)
                ppid = int(adat.get("ProcessId", "0"), 16)
            except ValueError:
                continue
            exe = adat.get("NewProcessName") or ""
            nev = os.path.basename(exe)
            k = (pid, nev.lower())
            if k in self._fy_evt_seen:
                continue
            self._fy_evt_seen[k] = most
            latott = self._fy_seen.get(pid)
            if latott and latott[0] == nev.lower():
                continue          # a psutil mar latta es kiertekelte
            d = {"pid": pid, "ppid": ppid, "ctime": 0, "name": nev, "exe": exe,
                 "cmd": adat.get("CommandLine") or "", "user": adat.get("SubjectUserName") or ""}
            # a szulo meg futhat: psutil; ha nem, a 4688 ParentProcessName-je
            fel = self._fy_felmenok(dict(d, ctime=0))
            if not fel and adat.get("ParentProcessName"):
                fel = [{"pid": ppid, "name": os.path.basename(adat["ParentProcessName"]),
                        "exe": adat["ParentProcessName"], "cmd": ""}]
            d["_felmenok"] = fel
            self._fy_vizsgal(d, forras="4688")
        # takaritas
        for kk, t in list(self._fy_evt_seen.items()):
            if most - t > 600:
                self._fy_evt_seen.pop(kk, None)

    def _fy_evt_loop(self):
        bekapcsolva = False
        if self._fy_cfg["NAPLO"] == "BE":
            bekapcsolva = True
            self.proc_naplo_ok = self._fy_naplo_beallit()
        while not self._fy_stop_ev.wait(EVT_POLL):
            try:
                if self._fy_cfg["NAPLO"] != "BE" or not self.is_on() or self.is_paused():
                    continue
                if not bekapcsolva:
                    bekapcsolva = True
                    self.proc_naplo_ok = self._fy_naplo_beallit()
                if self.proc_naplo_ok:
                    self._fy_4688()
            except Exception as e:
                log_line("[FOLYAMAT] 4688 hiba: %s" % e)

    # ------------------------------------------------------------ fo ciklus
    def _fy_loop(self):
        import psutil
        try:
            elozo = set(psutil.pids())
        except Exception:
            elozo = set()
        # a mar futo folyamatok: egyszer atnezzuk (a kritikus / nagyon gyanus szol)
        try:
            for pid in elozo:
                d = self._fy_info(pid)
                if d:
                    self._fy_cache[pid] = d
                    self._fy_seen[pid] = ((d.get("name") or "").lower(), time.time())
            for pid in list(elozo):
                d = self._fy_cache.get(pid)
                if not d:
                    continue
                felmenok = self._fy_felmenok(d)
                hits = ertekel(d, felmenok)
                if hits and hits[0][0] >= 2:
                    d["_felmenok"] = felmenok
                    self._fy_vizsgal(d, forras="indulas", indulas=True)
                elif hely_okok(d.get("exe")):
                    d["_felmenok"] = felmenok
                    # csak naplo / riasztas a szint szerint (alairatlan + gyanus hely)
                    self._fy_vizsgal(d, forras="indulas", indulas=True)
        except Exception as e:
            log_line("[FOLYAMAT] kezdeti atnezes hiba: %s" % e)
        self.proc_status = "aktív"
        utolso_cfg = time.time()
        while not self._fy_stop_ev.wait(POLL):
            try:
                most = time.time()
                if most - utolso_cfg >= 30:
                    utolso_cfg = most
                    self._fy_cfg = folyamat_cfg()
                if self._fy_cfg["FIGYELES"] != "BE":
                    self.proc_status = "kikapcsolva (folyamat.txt)"
                    elozo = set(psutil.pids())
                    continue
                if not self.is_on() or self.is_paused():
                    elozo = set(psutil.pids())
                    continue
                self.proc_status = "aktív"
                most_pids = set(psutil.pids())
                ujak = most_pids - elozo
                for pid in list(elozo - most_pids):
                    self._fy_cache.pop(pid, None)
                    with self._fy_lock:
                        self._proc_suspended.pop(pid, None)
                elozo = most_pids
                for pid in sorted(ujak):
                    d = self._fy_info(pid)
                    if not d:
                        continue
                    self._fy_cache[pid] = d
                    if d.get("cmd") or d.get("exe"):
                        # ha a folyamat mar kilepoben volt (nincs parancssor), a 4688 nezi meg
                        self._fy_seen[pid] = ((d.get("name") or "").lower(), most)
                    self.proc_new += 1
                    try:
                        self._fy_vizsgal(d)
                    except Exception as e:
                        log_line("[FOLYAMAT] vizsgalati hiba (PID %s): %s" % (pid, e))
                if most - self._fy_gc >= 300:
                    self._fy_gc = most
                    for p, (_n, t) in list(self._fy_seen.items()):
                        if most - t > 1800 and p not in most_pids:
                            self._fy_seen.pop(p, None)
                    for k, t in list(self._fy_last.items()):
                        if most - t > 2 * ISMETLES:
                            self._fy_last.pop(k, None)
            except Exception as e:
                log_line("[FOLYAMAT] figyelo hiba: %s" % e)
                self._fy_stop_ev.wait(5.0)

    def _proc_start(self):
        if getattr(self, "_proc_thread", None) and self._proc_thread.is_alive():
            return
        try:
            import psutil  # noqa: F401
        except Exception:
            self.proc_status = "nem elérhető (psutil hiányzik)"
            log_line("[FOLYAMAT] psutil nem erheto el - a folyamatfigyeles nem indul")
            return
        self._fy_cfg = folyamat_cfg()
        self._fy_trust = self._fy_trust_load()
        self._fy_lock = threading.Lock()
        self._fy_q, self._fy_q_lock, self._fy_q_ev = [], threading.Lock(), threading.Event()
        self._fy_cache, self._fy_seen, self._fy_evt_seen = {}, {}, {}
        self._fy_last, self._proc_suspended = {}, {}
        self._fy_recent = getattr(self, "_fy_recent", [])
        self._fy_gc = time.time()
        self.proc_new = 0
        self.proc_alerts = getattr(self, "proc_alerts", 0)
        self.proc_naplo_ok = False
        self.proc_status = "indulás…"
        self._fy_started = time.time()
        self._fy_sajat_init()
        self._fy_stop_ev = threading.Event()
        self._proc_thread = threading.Thread(target=self._fy_loop, name="folyamat", daemon=True)
        self._proc_thread.start()
        threading.Thread(target=self._fy_sig_worker, name="folyamat-alairas", daemon=True).start()
        threading.Thread(target=self._fy_evt_loop, name="folyamat-4688", daemon=True).start()
        log_line("[FOLYAMAT] figyeles aktiv (akcio: %s, szint: %d, 4688: %s)" % (
            self._fy_cfg["AKCIO"], self._fy_cfg["SZINT"], self._fy_cfg["NAPLO"]))

    def _proc_stop(self):
        ev = getattr(self, "_fy_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ allapot
    def proc_summary(self):
        if not getattr(self, "_fy_cfg", None):
            return getattr(self, "proc_status", "nem fut")
        reszek = ["Új folyamat: %d" % getattr(self, "proc_new", 0),
                  "Riasztás: %d" % getattr(self, "proc_alerts", 0)]
        sp = getattr(self, "_proc_suspended", {}) or {}
        if sp:
            reszek.append("⏸ Megállítva: %d" % len(sp))
        reszek.append("4688: %s" % ("be" if getattr(self, "proc_naplo_ok", False)
                                    else ("ki" if self._fy_cfg["NAPLO"] != "BE" else "—")))
        rec = getattr(self, "_fy_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s ⚠" % (rec[0]["name"][:20],
                                               time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"]))))
        return " | ".join(reszek)

    def proc_text(self):
        sorok = ["FOLYAMATFIGYELES: %s" % self.proc_summary().replace(" | ", ", ")]
        sp = getattr(self, "_proc_suspended", {}) or {}
        if sp:
            sorok.append("Megallitott folyamatok (/leallit <PID>, /folytat <PID>):")
            for pid, e in sp.items():
                sorok.append("  PID %s  %s" % (pid, e.get("name")))
        rec = getattr(self, "_fy_recent", [])
        if rec:
            sorok.append("Legutobbi riasztasok:")
            for r in rec[:10]:
                sorok.append("  %s [%s] %s (PID %s, szulo: %s) - %s%s" % (
                    time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), _SZINT_NEV.get(r["szint"], "?"),
                    r["name"], r["pid"], r["szulo"] or "-", r["okok"][:120],
                    (" | " + r["akcio"][:60]) if r["akcio"] else ""))
        else:
            sorok.append("Meg nem volt gyanus folyamat.")
        sorok.append("Megbizhatonak jelolt: %d (torles: /folyamatreset)" % len(getattr(self, "_fy_trust", {}) or {}))
        return "\n".join(sorok)
