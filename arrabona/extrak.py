# -*- coding: utf-8 -*-
"""Arrabona Guard - v2.11.0 extrak (GuardCore mixin):
  1) KISZIVARGOTT JELSZO-ellenorzes (Have I Been Pwned, k-anonimitas: csak a SHA-1
     elso 5 karaktere megy ki - a jelszo SOHA nem hagyja el a gepet, naploba sem kerul),
  2) VIRUSTOTAL: gyanus fajlok ujjlenyomatanak lekerdezese (virustotal.txt: KULCS=...),
     ingyenes kulcs: max 4 / perc - sorban, gyorsitotarral,
  3) WINDOWS UPDATE-figyeles: szolgaltatas tiltva? utolso sikeres frissites?
     hazirenddel kikapcsolva? ujrainditasra var?
  4) BIZTONSAGI PONTSZAM (0-100) a meglevo allapotokbol + tippek.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import hashlib
import json as _json
import os
import subprocess
import threading
import time
import winreg
from .common import (APPDATA_DIR, log_line)

VT_CFG_FILE = os.path.join(APPDATA_DIR, "virustotal.txt")
VT_CACHE_FILE = os.path.join(APPDATA_DIR, "virustotal_cache.json")
VT_SZUNET = 16.0                 # ingyenes kulcs: 4 keres / perc
WU_POLL = 6 * 3600
WU_MAX_NAP = 14


# ======================================================== 1) JELSZO (HIBP)
def pwned_count(jelszo):
    """Hany adatszivargasban szerepel a jelszo? None = nem sikerult lekerdezni.
    Csak a SHA-1 elso 5 hexa karaktere megy ki (k-anonimitas)."""
    if not jelszo:
        return None
    h = hashlib.sha1(jelszo.encode("utf-8")).hexdigest().upper()
    eleje, vege = h[:5], h[5:]
    try:
        import urllib.request
        req = urllib.request.Request("https://api.pwnedpasswords.com/range/" + eleje,
                                     headers={"User-Agent": "ArrabonaGuard", "Add-Padding": "true"})
        with urllib.request.urlopen(req, timeout=15) as r:
            for ln in r.read().decode("utf-8", errors="ignore").splitlines():
                suf, _, db = ln.strip().partition(":")
                if suf == vege:
                    return int(db or 0)
        return 0
    except Exception:
        return None


# ======================================================== 2) VIRUSTOTAL
def vt_kulcs():
    try:
        if not os.path.exists(VT_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(VT_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - VirusTotal\n"
                        "# Ingyenes kulcs: https://www.virustotal.com -> regisztracio -> profil -> API Key\n"
                        "# Csak a fajlok ujjlenyomata (SHA-256) megy ki, maga a fajl NEM.\n"
                        "KULCS=\n")
        with open(VT_CFG_FILE, "r", encoding="utf-8-sig", errors="ignore") as f:
            for ln in f:
                k, _, v = ln.strip().partition("=")
                if k.strip().upper() == "KULCS" and v.strip():
                    return v.strip()
    except Exception:
        pass
    return ""


def _sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def vt_lookup(sha, kulcs):
    """{"talalt": bool, "rossz": n, "gyanus": n, "osszes": n, "nev": "..."} vagy {"hiba": "..."}"""
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request("https://www.virustotal.com/api/v3/files/" + sha,
                                     headers={"x-apikey": kulcs, "User-Agent": "ArrabonaGuard"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                d = _json.loads(r.read().decode("utf-8", errors="ignore"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return {"talalt": False}
            return {"hiba": "HTTP %s%s" % (e.code, " (rossz kulcs?)" if e.code in (401, 403) else
                                            " (tul sok keres)" if e.code == 429 else "")}
        a = (d.get("data") or {}).get("attributes") or {}
        st = a.get("last_analysis_stats") or {}
        nevek = (a.get("popular_threat_classification") or {}).get("suggested_threat_label") or ""
        return {"talalt": True, "rossz": int(st.get("malicious", 0)), "gyanus": int(st.get("suspicious", 0)),
                "osszes": sum(int(v) for v in st.values() if isinstance(v, int)), "nev": nevek}
    except Exception as e:
        return {"hiba": str(e)[:100]}


def vt_szoveg(r):
    if not r:
        return "?"
    if r.get("hiba"):
        return "VirusTotal: hiba (%s)" % r["hiba"]
    if not r.get("talalt"):
        return "VirusTotal: ISMERETLEN fajl (meg senki nem toltotte fel - ritka / egyedi program)"
    return "VirusTotal: %d/%d virusirto jelzi%s%s" % (
        r["rossz"], r["osszes"], (" (+%d gyanus)" % r["gyanus"]) if r.get("gyanus") else "",
        (" - %s" % r["nev"]) if r.get("nev") else "")


# ======================================================== 3) WINDOWS UPDATE
_WU_PS = (
    "$ErrorActionPreference='SilentlyContinue';$o=@{};"
    "$s=Get-Service wuauserv;$o.start=[string]$s.StartType;$o.state=[string]$s.Status;"
    "try{$se=New-Object -ComObject Microsoft.Update.Session;$q=$se.CreateUpdateSearcher();"
    "$n=$q.GetTotalHistoryCount();if($n -gt 0){$h=$q.QueryHistory(0,[Math]::Min($n,100))|"
    "Where-Object{$_.ResultCode -eq 2 -and $_.Operation -eq 1}|Sort-Object Date -Descending|Select-Object -First 1;"
    "if($h){$o.last=$h.Date.ToString('yyyy-MM-dd');$o.title=[string]$h.Title}}}catch{$o.err=$_.Exception.Message};"
    "if(-not $o.last){$hf=Get-HotFix|Where-Object InstalledOn|Sort-Object InstalledOn -Descending|Select-Object -First 1;"
    "if($hf){$o.last=$hf.InstalledOn.ToString('yyyy-MM-dd');$o.title=[string]$hf.HotFixID}};"
    "$o|ConvertTo-Json -Compress")


def _reg(gy, ut, nev):
    try:
        with winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)) as k:
            return winreg.QueryValueEx(k, nev)[0]
    except OSError:
        return None


def _reg_kulcs_van(gy, ut):
    try:
        winreg.CloseKey(winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)))
        return True
    except OSError:
        return False


def wu_query():
    st = {"ts": time.time()}
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _WU_PS],
                           capture_output=True, timeout=180)
        txt = (r.stdout or b"").decode("utf-8", errors="ignore")
        i = txt.find("{")
        if i >= 0:
            st.update(_json.loads(txt[i:]))
    except Exception as e:
        st["err"] = str(e)
    hk = winreg.HKEY_LOCAL_MACHINE
    st["policy_off"] = _reg(hk, r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate") == 1
    st["reboot"] = _reg_kulcs_van(hk, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired")
    pause = _reg(hk, r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings", "PauseUpdatesExpiryTime")
    st["pause"] = str(pause)[:10] if pause else ""
    if st.get("last"):
        try:
            st["days"] = int((time.time() - time.mktime(time.strptime(st["last"], "%Y-%m-%d"))) // 86400)
        except ValueError:
            pass
    return st


# ======================================================== mixin
class ExtrasMixin(object):

    # ---------------------------------------------------- VirusTotal
    def vt_kerd(self, fajl, mi=""):
        """Gyanus fajl sorba allitasa VirusTotal-lekerdezesre (ha van kulcs). Nem blokkol."""
        if not fajl or not vt_kulcs() or not os.path.isfile(fajl):
            return False
        q = getattr(self, "_vt_q", None)
        if q is None:
            q = self._vt_q = []
        if len(q) < 50 and not any(x[0] == fajl for x in q):
            q.append((fajl, mi))
        return True

    def _vt_cache(self):
        c = getattr(self, "_vt_c", None)
        if c is None:
            try:
                with open(VT_CACHE_FILE, "r", encoding="utf-8") as f:
                    c = _json.load(f)
            except (OSError, ValueError):
                c = {}
            self._vt_c = c
        return c

    def vt_check_now(self, fajl):
        """Szinkron lekerdezes (Telegram /vt). (szoveg, eredmeny)"""
        kulcs = vt_kulcs()
        if not kulcs:
            return "Nincs VirusTotal-kulcs: %s (KULCS=...)" % VT_CFG_FILE, None
        if not os.path.isfile(fajl):
            return "Nincs ilyen fajl: %s" % fajl, None
        sha = _sha256(fajl)
        c = self._vt_cache()
        r = c.get(sha)
        if not r or time.time() - r.get("ts", 0) > 7 * 86400 or not r.get("talalt"):
            r = vt_lookup(sha, kulcs)
            if not r.get("hiba"):
                r["ts"] = time.time()
                c[sha] = r
                self._vt_save()
        return "%s\nSHA-256: %s\n%s" % (fajl, sha, vt_szoveg(r)), r

    def _vt_save(self):
        try:
            c = self._vt_cache()
            if len(c) > 2000:
                for k in sorted(c, key=lambda x: c[x].get("ts", 0))[:500]:
                    c.pop(k, None)
            with open(VT_CACHE_FILE, "w", encoding="utf-8") as f:
                _json.dump(c, f)
        except OSError:
            pass

    def _vt_tick(self):
        q = getattr(self, "_vt_q", None)
        if not q or time.time() - getattr(self, "_vt_last", 0) < VT_SZUNET:
            return
        fajl, mi = q.pop(0)
        self._vt_last = time.time()
        try:
            szoveg, r = self.vt_check_now(fajl)
        except Exception as e:
            log_line("[VIRUSTOTAL] hiba: %s" % e)
            return
        if not r:
            return
        self.vt_checked = getattr(self, "vt_checked", 0) + 1
        if r.get("talalt") and r.get("rossz", 0) >= 1:
            self.vt_bad = getattr(self, "vt_bad", 0) + 1
            fej = "KARTEVO!" if r["rossz"] >= 3 else "GYANUS:"
            self.alert("127.0.0.1", "[VIRUSTOTAL] %s %s - %s | %s" % (fej, mi or os.path.basename(fajl), fajl,
                                                                     vt_szoveg(r)), always=True)
        else:
            log_line("[VIRUSTOTAL] %s: %s" % (fajl, vt_szoveg(r)))

    # ---------------------------------------------------- Windows Update
    def _wu_check(self):
        st = wu_query()
        elozo = getattr(self, "wu_status", None) or {}
        self.wu_status = st
        if (st.get("start") or "").lower() == "disabled" and (elozo.get("start") or "").lower() != "disabled":
            self.alert("127.0.0.1", "[WINUPDATE] A WINDOWS UPDATE SZOLGALTATAS TILTVA VAN! Kartevo vagy "
                       "'optimalizalo' program kapcsolhatta ki - biztonsagi frissitesek nem jonnek.", always=True)
        if st.get("policy_off") and not elozo.get("policy_off"):
            self.alert("127.0.0.1", "[WINUPDATE] Az automatikus frissites HAZIRENDDEL KI VAN KAPCSOLVA "
                       "(NoAutoUpdate=1).", always=True)
        d = st.get("days")
        if isinstance(d, int) and d > WU_MAX_NAP:
            ma = time.strftime("%Y-%m-%d")
            if getattr(self, "_wu_alert_day", "") != ma:
                self._wu_alert_day = ma
                self.alert("127.0.0.1", "[WINUPDATE] %d napja nem volt sikeres Windows-frissites (utolso: %s). "
                           "Gephaz > Windows Update > Frissitesek keresese." % (d, st.get("last")), always=True)

    def wu_summary(self):
        st = getattr(self, "wu_status", None)
        if not st:
            return "lekérdezés…"
        r = []
        r.append("Szolgáltatás: %s" % ("TILTVA" if (st.get("start") or "").lower() == "disabled" else "rendben"))
        r.append("Utolsó frissítés: %s" % (("%s (%d napja)" % (st["last"], st["days"])) if "days" in st else "?"))
        if st.get("policy_off"):
            r.append("⚠ házirend: KI")
        if st.get("pause"):
            r.append("szüneteltetve: %s-ig" % st["pause"])
        if st.get("reboot"):
            r.append("⟳ újraindításra vár")
        return " | ".join(r)

    def wu_ok(self):
        st = getattr(self, "wu_status", None) or {}
        return ((st.get("start") or "").lower() != "disabled" and not st.get("policy_off")
                and isinstance(st.get("days"), int) and st["days"] <= WU_MAX_NAP)

    # ---------------------------------------------------- Biztonsagi pontszam
    def security_score(self):
        """(pont 0-100, [(rendben?, sulypont, megnevezes, tipp)])"""
        t = []

        def add(ok, suly, nev, tipp):
            t.append((bool(ok), suly, nev, tipp))
        ds = getattr(self, "def_status", None) or {}
        add(getattr(self, "admin", False), 10, "Guard rendszergazdaként fut",
            "Indítsd a Guardot rendszergazdaként (tűzfal, blokkolás, HKLM-figyelés csak így megy).")
        add(getattr(self, "fw_ok", False), 10, "Tűzfalnapló aktív", "A tűzfalnapló bekapcsolásához admin jog kell.")
        add(ds.get("rt"), 15, "Defender valós idejű védelem", "Kapcsold be: Windows Biztonság > Vírus- és fenyegetésvédelem.")
        add(isinstance(ds.get("sigage"), int) and ds["sigage"] < 3, 5, "Friss vírusdefiníciók",
            "Frissítsd: Telegram /defupdate vagy Windows Biztonság.")
        add(ds.get("tamper"), 5, "Szabotázsvédelem", "Windows Biztonság > Vírusvédelem beállításai > Szabotázsvédelem: BE.")
        add(ds.get("hvci"), 5, "Memóriaintegritás", "Windows Biztonság > Eszközbiztonság > Magelkülönítés > Memóriaintegritás: BE.")
        add(self.wu_ok(), 10, "Windows Update rendben", "Keress frissítést: Gépház > Windows Update (és ne legyen tiltva).")
        add(str(getattr(self, "wd_status", "")).startswith("aktív"),
            5, "Őrkutya aktív", "Az őrkutya a telepített exe-vel működik (nem sima .py futtatással).")
        try:
            from .telegram import _tg_cfg
            tg = all(_tg_cfg())
        except Exception:
            tg = False
        add(tg, 5, "Telegram-riasztás beállítva", "telegram.txt: token= és chat_id= kitöltése.")
        add(getattr(self, "csali_status", "") == "aktív", 5, "Ransomware-csapda aktív", "csali.txt: CSAPDA BE")
        add(getattr(self, "proc_status", "") == "aktív", 5, "Folyamatfigyelés aktív",   # [v2.12.0]
            "folyamat.txt: FIGYELES BE (psutil kell hozzá).")
        add(getattr(self, "lopas_status", "") == "aktív", 5, "Infostealer-csapda aktív",   # [v2.13.0]
            "Rendszergazdaként kell futnia a Guardnak (fájl-naplózás).")
        add(getattr(self, "vagolap_status", "") == "aktív", 5, "Vágólap-védelem aktív",   # [v2.14.0]
            "vagolap.txt: FIGYELES BE")
        add(getattr(self, "letoltes_status", "") == "aktív", 5, "Letöltések vizsgálata aktív",   # [v2.15.0]
            "letoltes.txt: FIGYELES BE")
        add(getattr(self, "kisz_status", "") == "aktív", 5, "Adatkiszivárgás-figyelés aktív",   # [v2.16.0]
            "Rendszergazdaként kell futnia a Guardnak; kiszivargas.txt: FIGYELES BE")
        try:
            _utok = self.ut_ok()
        except Exception:
            _utok = None
        if _utok is not None:
            add(_utok, 5, "Ütemezett feladatok tiszták", "Javítás ablak > Ütemezett feladatok: gyanús / rejtett "
                "feladat van (Telegram: /feladatok).")
        try:
            _fok = self.frissites_ok()
        except Exception:
            _fok = None
        if _fok is not None:
            add(_fok, 5, "Kiemelt programok naprakészek", "Telegram /frissitesek - a régi böngésző / "
                "tömörítő / csevegő a leggyakoribb behatolási pont.")
        try:
            _uok = self.upnp_ok()
        except Exception:
            _uok = None
        if _uok is not None:
            add(_uok, 5, "Router: nincs veszélyes nyitott port", "Telegram /upnp - RDP / SMB / SSH / VNC port "
                "nyitva a routeren: zárd be (/upnpzar), vagy kapcsold ki az UPnP-t a routeren.")
        try:
            rossz_net = any(sz >= 1 for _c, _l, sz in self.net_rows())
        except Exception:
            rossz_net = False
        add(not rossz_net, 5, "DNS és proxy rendben", "Nézd meg: Javítás ablak > Hálózat fül.")
        try:
            from .hosts import hosts_erzekeny
            hb = any(hosts_erzekeny(h) for h in ((getattr(self, "_hosts_state", None) or {}).get("entries") or {}))
        except Exception:
            hb = False
        add(not hb, 5, "Hosts-fájl tiszta", "Javítás ablak > Hosts fül: érzékeny bejegyzés van benne.")
        try:
            gy_ind = any(o for _i, _k, _e, o in self.startup_entries())
        except Exception:
            gy_ind = False
        add(not gy_ind, 5, "Indítópult tiszta", "Javítás ablak > Indítópult: piros (gyanús) bejegyzés van.")
        try:
            from .bongeszo import gyanus_forras
            gyb = any(gyanus_forras(e) for e in (getattr(self, "_bong_known", None) or {}).values())
        except Exception:
            gyb = False
        add(not gyb, 5, "Böngésző-bővítmények rendben", "Telegram /bovitmenyek: gyanús forrású bővítmény van.")
        try:
            from .common import autostart_enabled
            au = autostart_enabled()
        except Exception:
            au = False
        add(au, 5, "Guard indul a Windowszal", "Pipáld be: Automatikus indítás.")
        add(bool(vt_kulcs()), 0, "VirusTotal-kulcs (bónusz)", "virustotal.txt: KULCS=... (ingyenes regisztráció).")
        osszes = sum(s for _o, s, _n, _t in t) or 1
        pont = int(round(100.0 * sum(s for o, s, _n, _t in t if o) / osszes))
        return pont, t

    def score_text(self, ekezet=True):
        pont, t = self.security_score()
        sorok = ["Biztonsági pontszám: %d/100" % pont]
        for ok, suly, nev, tipp in t:
            sorok.append("%s %s%s" % ("✔" if ok else "✘", nev, "" if ok else " — " + tipp))
        return "\n".join(sorok)

    # ---------------------------------------------------- ciklus
    def _extra_loop(self):
        while not self._extra_stop_ev.is_set():
            try:
                if time.time() - getattr(self, "_wu_last", 0) >= WU_POLL:
                    self._wu_last = time.time()
                    self._wu_check()
                self._vt_tick()
            except Exception as e:
                log_line("[EXTRA] hiba: %s" % e)
            self._extra_stop_ev.wait(4.0)

    def _extra_start(self):
        if getattr(self, "_extra_thread", None) and self._extra_thread.is_alive():
            return
        vt_kulcs()
        self._wu_last = time.time() - WU_POLL + 90   # elso Windows Update-lekerdezes 90 mp mulva
        self._extra_stop_ev = threading.Event()
        self._extra_thread = threading.Thread(target=self._extra_loop, name="extra", daemon=True)
        self._extra_thread.start()

    def _extra_stop(self):
        ev = getattr(self, "_extra_stop_ev", None)
        if ev is not None:
            ev.set()
