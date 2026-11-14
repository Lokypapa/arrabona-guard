# -*- coding: utf-8 -*-
"""Arrabona Guard - Belepes- es esemenyfigyeles (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import os
import subprocess
import threading
import time
from .common import (
    DEFENDER_EVENTS,
    DEFENDER_LOG,
    LOGON_POLL,
    LOGON_THRESHOLD,
    LOGON_TYPES,
    LOGON_WINDOW,
    dec_ki,
    is_private_ip,
    log_line,
)

class LogonMixin(object):
    """Belepes- es esemenyfigyeles (4625/4624/4720/4732/1102/104, 4698/7045, auditpol).
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""

    # ========== 4625: SIKERTELEN BEJELENTKEZES FIGYELES ==========

    def _logon_load_lists(self):
        wl = set()
        bl = set()
        for fname, target in (("whitelist.txt", wl), ("feketelista.txt", bl)):
            try:
                p = self._feed_path(fname)
                with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            target.add(line)
            except Exception:
                pass
        return wl, bl

    def _logon_check(self):
        import subprocess
        import xml.etree.ElementTree as ET
        back_ms = int(LOGON_POLL * 2000) + 60000
        query = "*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= %d]]]" % back_ms
        proc = subprocess.run(
            ["wevtutil", "qe", "Security", "/q:" + query, "/f:XML", "/rd:true", "/c:100", "/uni:true"],
            capture_output=True, timeout=45)
        out = proc.stdout
        if not out:
            return
        if isinstance(out, bytes):
            out = dec_ki(out)
        doc = ET.fromstring("<events>" + out + "</events>")
        whitelist, blacklist = self._logon_load_lists()
        import time as _t
        now = _t.time()
        skipped_own = 0
        for ev in doc:
            rid = None
            data = {}
            for el in ev.iter():
                tag = el.tag.split("}")[-1]
                if tag == "EventRecordID":
                    rid = (el.text or "").strip()
                elif tag == "Data" and el.get("Name"):
                    data[el.get("Name")] = (el.text or "").strip()
            if rid is None or rid in self._logon_seen:
                continue
            self._logon_seen.add(rid)
            if len(self._logon_seen) > 5000:
                self._logon_seen = set(list(self._logon_seen)[-1000:])
            try:
                ltype = int(data.get("LogonType", ""))
            except Exception:
                continue
            if ltype not in LOGON_TYPES:
                continue
            ip = data.get("IpAddress") or ""
            if not ip or ip == "-" or ip == "::1":
                continue
            user = data.get("TargetUserName") or "?"
            sub = (data.get("SubStatus") or "").upper()
            if ip in whitelist:
                continue
            # [v1.9.2] A feketelistas IP-t NEM hagyjuk ki (korabban igen): ha
            # bejelentkezessel probalkozik, az kulonosen fontos riasztas.
            feketelistas = ip in blacklist
            # Belso / sajat forras (loopback, LAN, sajat gep, sajat IPv6-prefix):
            # szamoljuk es riasztunk, de SOHA nem blokkoljuk (karvelo jele lehet).
            belso = (ip in ("127.0.0.1", "::1") or is_private_ip(ip)
                     or ip in self.own_ips() or self.is_own_prefix(ip))
            entries = [t for t in self._logon_hits.get(ip, []) if now - t < LOGON_WINDOW]
            entries.append(now)
            self._logon_hits[ip] = entries
            kuszob = 1 if feketelistas else LOGON_THRESHOLD
            if len(entries) >= kuszob:
                self._logon_hits[ip] = []
                eredet = "RDP" if ltype == 10 else "halozati (SMB)"
                info = ""
                if sub.endswith("C0000064"):
                    info = " [NEM LETEZO FIOK!]"
                if feketelistas:
                    self.alert(ip, "4625 FEKETELISTAS IP bejelentkezesi probaja - %s (%s fiok, %s%s)" %
                               (ip, user, eredet, info), always=True)
                else:
                    self.alert(ip, "4625 BRUTE-FORCE: %d sikertelen bejelentkezes %d mp alatt - %s (%s fiok, %s%s)" %
                               (len(entries), int(LOGON_WINDOW), ip, user, eredet, info), always=True)
                if belso:
                    skipped_own += 1
                    log_line("[4625] BELSO/sajat forras: csak riasztva, blokk nelkul: " + ip)
                else:
                    self.block_ip(ip)
        # [v1.9.2] memoria-takaritas: lejart probalkozasok eldobasa
        for _ip, _lst in list(self._logon_hits.items()):
            if not _lst or all(now - t >= LOGON_WINDOW for t in _lst):
                self._logon_hits.pop(_ip, None)
        if skipped_own:
            log_line("[4625] belso/sajat forras: %d riasztas blokk nelkul" % skipped_own)

    def _logon_loop(self):
        while not self._logon_stop_ev.is_set():
            try:
                self._logon_check()
            except Exception as e:
                log_line("[4625] hiba a naplo olvasasaban: %s" % e)
            self._logon_stop_ev.wait(LOGON_POLL)

    # ========== 4698/7045: PERZISZTENCIA-FIGYELES (rootkit-nyomok) ==========
    def _persist_check(self):
        # [v1.9.6] zar: a Defender-vizsgalat szala is meghivhatja
        lk = getattr(self, "_persist_lock", None)
        if lk is None:
            lk = self._persist_lock = threading.Lock()
        with lk:
            return self._persist_check_impl()

    def _persist_check_impl(self):
        import xml.etree.ElementTree as ET
        NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
        back_ms = 10 * 60 * 1000
        ido = "TimeCreated[timediff(@SystemTime) <= %d]" % back_ms
        queries = [
            ("Security", "*[System[(EventID=4698) and %s]]" % ido, 50),
            ("System",   "*[System[(EventID=7045) and %s]]" % ido, 50),
            # [v1.9.3] biztonsagi esemenyek:
            #  4624 sikeres belepes - csak halozati (3) es RDP (10) tipus
            ("Security", "*[System[(EventID=4624) and %s] and EventData["
                         "Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]" % ido, 200),
            #  4720 uj fiok, 4732 tag hozzaadasa helyi csoporthoz, 1102 Security naplo torolve
            ("Security", "*[System[(EventID=4720 or EventID=4732 or EventID=1102) and %s]]" % ido, 50),
            #  104 System (vagy mas) naplo torolve
            ("System",   "*[System[(EventID=104) and %s]]" % ido, 20),
            # [v1.9.6] Windows Defender: eszleles, kezeles, hiba, kikapcsolas, kivetel
            (DEFENDER_LOG, "*[System[(%s) and %s]]" % (
                " or ".join("EventID=%s" % e for e in DEFENDER_EVENTS), ido), 50),
        ]
        for logname, query, darab in queries:
            try:
                out = subprocess.check_output(
                    ["wevtutil", "qe", logname, "/q:" + query, "/f:XML", "/rd:true", "/c:%d" % darab, "/uni:true"],
                    timeout=20, stderr=subprocess.DEVNULL,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            except Exception as e:
                log_line("[4698/7045] hiba a(z) %s naplo olvasasaban: %s" % (logname, e))
                continue
            evs = []
            for chunk in dec_ki(out).split("</Event>"):
                pos = chunk.find("<Event")
                if pos < 0:
                    continue
                try:
                    evs.append(ET.fromstring(chunk[pos:] + "</Event>"))
                except Exception:
                    pass
            for ev in reversed(evs):
                eid = ev.find(NS + "System/" + NS + "EventID")
                if eid is None or not eid.text:
                    continue
                rec = ev.find(NS + "System/" + NS + "EventRecordID")
                key = "%s/%s/%s" % (logname, eid.text, rec.text if rec is not None else "?")
                if key in self._persist_seen:
                    continue
                self._persist_seen.add(key)
                if len(self._persist_seen) > 5000:
                    # [v1.9.3] a 10 perces ablak miatt eleg a frissebb fele;
                    # a rekordazonositok novekvok, igy a legkisebbeket dobjuk
                    def _rid(k):
                        try:
                            return int(k.rsplit("/", 1)[1])
                        except Exception:
                            return 0
                    self._persist_seen = set(sorted(self._persist_seen, key=_rid)[-2500:])
                if logname == DEFENDER_LOG:
                    if eid.text in DEFENDER_EVENTS:
                        try:
                            self._defender_event(eid.text, ev)
                        except Exception as e:
                            log_line("[DEFENDER] feldolgozasi hiba (%s): %s" % (eid.text, e))
                    continue
                if eid.text in ("4624", "4720", "4732", "1102", "104"):
                    try:
                        if self._secevt_handle(eid.text, ev, NS):
                            self.sec_events = getattr(self, "sec_events", 0) + 1
                    except Exception as e:
                        log_line("[BIZTONSAG] feldolgozasi hiba (%s): %s" % (eid.text, e))
                    continue
                who = ""
                for d in ev.iter(NS + "Data"):
                    nm = d.get("Name") or ""
                    if nm in ("SubjectUserName", "TaskName", "ServiceName", "ServiceFileName", "AccountName"):
                        who += " %s='%s'" % (nm, (d.text or "").strip()[:80])
                if eid.text == "4698":
                    msg = "4698 UTEMEZETT FELADAT LETREHOZVA%s" % who
                    try:
                        self.utem_soon()     # [v2.17.0] azonnali teljes atnezes (aláírás, minták)
                    except Exception:
                        pass
                else:
                    msg = "7045 UJ SZOLGALTATAS TELEPITVE%s" % who
                # [v2.4.0] a futtatott program: alairas + gyanus minta + Defender-vizsgalat
                try:
                    msg = self._persist_program_info(eid.text, ev, NS, msg)
                except Exception as e:
                    log_line("[PERZISZTENCIA] program-ellenorzesi hiba: %s" % e)
                log_line("[PERZISZTENCIA] " + msg)
                try:
                    # [v1.9.2] always=True: minden perzisztencia-esemeny kulon
                    # riasztas (korabban a 127.0.0.1-es 60 mp-es cooldown miatt
                    # az egy percen beluli masodik esemeny nem ment el Telegramra)
                    self.alert("127.0.0.1", "[PERZISZTENCIA] " + msg, always=True)
                except Exception:
                    pass

    def _persist_program_info(self, eid, ev, NS, msg):
        """[v2.4.0] 4698: a feladat <Command> + <Arguments> resze, 7045: ServiceFileName.
        Hozzafuzi az alairast es a gyanus mintakat; alairatlan / ervenytelen fajlnal
        Defender-vizsgalatot indit."""
        import re as _re
        from .alairas import sig_one, sig_szoveg, sig_veszely
        from .startup import fajl_a_parancsban, gyanus_okok, startup_cfg
        parancs = ""
        for d in ev.iter(NS + "Data"):
            nm = d.get("Name") or ""
            if eid == "7045" and nm == "ServiceFileName":
                parancs = (d.text or "").strip()
            elif eid == "4698" and nm == "TaskContent":
                x = d.text or ""
                cmds = _re.findall(r"<Command>(.*?)</Command>", x, _re.S)
                args = _re.findall(r"<Arguments>(.*?)</Arguments>", x, _re.S)
                parancs = " ".join((cmds[:1] or [""]) + (args[:1] or [""])).strip()
                parancs = parancs.replace("&quot;", '"').replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if not parancs:
            return msg
        # a "\??\C:\..." es a "\SystemRoot\..." alakot is ertelmezzuk
        tiszta = _re.sub(r"^\\\?\?\\", "", parancs)
        windir = os.environ.get("WINDIR", "C:\\Windows")
        tiszta = _re.sub(r"(?i)^\\?SystemRoot\\", lambda _m: windir + "\\", tiszta)
        if _re.match(r"(?i)^system32\\", tiszta):
            tiszta = os.path.join(windir, tiszta)
        okok = gyanus_okok(tiszta)
        fajl = fajl_a_parancsban(tiszta)
        sig = sig_one(fajl) if fajl else None
        v = sig_veszely(sig)
        msg += " | Program: %s" % parancs[:250]
        if sig:
            msg += " | Alairas: %s" % sig_szoveg(sig, ekezet=False)
        if okok:
            msg += " | Gyanus: %s" % "; ".join(okok)
        if v == 2 or (v == 1 and okok):
            msg = "NAGYON GYANUS! " + msg
        elif okok or v == 1:
            msg = "GYANUS: " + msg
        if fajl and v >= 1 and hasattr(self, "vt_kerd"):
            self.vt_kerd(fajl, "%s: %s" % ("Szolgáltatás" if eid == "7045" else "Ütemezett feladat",
                                            os.path.basename(fajl)[:40]))   # [v2.11.0]
        if fajl and v >= 1 and startup_cfg() == "BE":
            tipus = "Új szolgáltatás" if eid == "7045" else "Új ütemezett feladat"
            lepesek = [("%s: %s" % (tipus, os.path.basename(fajl)[:50]), time.time()),
                       ("Aláírás: %s" % sig_szoveg(sig), time.time())]
            # a vizsgalat szala a vegen _persist_check-et hiv: kulon szalon inditjuk, hogy a zar ne akadjon
            def _scan():
                try:
                    ok = self.defender_scan("custom", fajl, elozmeny=lepesek,
                                            cimke="%s: %s" % (tipus, os.path.basename(fajl)[:40]))
                    log_line("[PERZISZTENCIA] Defender-vizsgalat %s: %s" % (
                        "a jatek vegeig elhalasztva" if ok == "HALASZTVA" else ("elinditva" if ok else "nem indult"), fajl))
                except Exception as e:
                    log_line("[PERZISZTENCIA] vizsgalat inditasi hiba: %s" % e)
            threading.Thread(target=_scan, daemon=True).start()
            msg += " | Defender-vizsgalat indul"
        return msg

    # ========== [v1.9.3] BIZTONSAGI ESEMENYEK: 4624/4720/4732/1102/104 ==========
    _ADMIN_SIDS = {
        "S-1-5-32-544": "Administrators (rendszergazdak)",
        "S-1-5-32-555": "Remote Desktop Users (tavoli asztal)",
    }

    @staticmethod
    def _ev_data(ev):
        """EventData/Data[@Name] es UserData/* mezok egy szotarba."""
        d = {}
        for resz in ev:
            # a System reszt kihagyjuk (pl. a 104-nel ott a Channel mindig
            # "System", a torolt naplo neve a UserData-ban van)
            if resz.tag.split("}")[-1] not in ("EventData", "UserData"):
                continue
            for el in resz.iter():
                tag = el.tag.split("}")[-1]
                nm = el.get("Name")
                if tag == "Data" and nm:
                    d[nm] = (el.text or "").strip()
                elif len(el) == 0 and tag not in d and el.text and el.text.strip():
                    d[tag] = el.text.strip()
        return d

    def _secevt_handle(self, eid, ev, NS=""):
        d = self._ev_data(ev)
        ki = d.get("SubjectUserName") or "?"
        if eid == "4624":
            return self._secevt_4624(d)
        elif eid == "4720":
            msg = "4720 UJ FELHASZNALOI FIOK LETREHOZVA: '%s' (letrehozta: %s)" % (
                d.get("TargetUserName") or "?", ki)
            self.alert("127.0.0.1", "[BIZTONSAG] " + msg, always=True)
            return True
        elif eid == "4732":
            sid = (d.get("TargetSid") or "").upper()
            csoport = self._ADMIN_SIDS.get(sid)
            if not csoport:
                return  # egyeb csoport: csak a rendszergazda / RDP csoport erdekes
            tag = d.get("MemberName") or ""
            if not tag or tag == "-":
                tag = d.get("MemberSid") or "?"
            msg = "4732 UJ TAG A(Z) %s CSOPORTBAN: %s (hozzaadta: %s)" % (csoport, tag, ki)
            self.alert("127.0.0.1", "[BIZTONSAG] " + msg, always=True)
            return True
        elif eid in ("1102", "104"):
            naplo = "Security" if eid == "1102" else (d.get("Channel") or "System")
            msg = "%s ESEMENYNAPLO TOROLVE: %s (torolte: %s) - tipikus tamadoi nyomeltuntetes!" % (
                eid, naplo, ki)
            self.alert("127.0.0.1", "[BIZTONSAG] " + msg, always=True)
            return True
        return False

    def _secevt_4624(self, d):
        """Sikeres halozati/RDP belepes KULSO IP-rol = a legveszelyesebb eset."""
        ip = (d.get("IpAddress") or "").strip()
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if not ip or ip in ("-", "::1", "127.0.0.1"):
            return
        if is_private_ip(ip) or ip in self.own_ips() or self.is_own_prefix(ip):
            return  # LAN, Tailscale, sajat gep: normal mukodes
        wl, bl = self._logon_load_lists()
        if ip in wl:
            return
        user = d.get("TargetUserName") or "?"
        dom = d.get("TargetDomainName") or ""
        if dom and dom not in ("-", "?"):
            user = "%s\\%s" % (dom, user)
        try:
            ltype = int(d.get("LogonType") or 0)
        except ValueError:
            ltype = 0
        eredet = "RDP / tavoli asztal" if ltype == 10 else "halozati (SMB)"
        anonim = (d.get("TargetUserName") or "").upper() == "ANONYMOUS LOGON"
        # ugyanaz az IP + fiok 10 percen belul csak egyszer (egy SMB-munkamenet
        # sok 4624-et general)
        kulcs = "%s|%s" % (ip, user)
        if not hasattr(self, "_succ_last"):
            self._succ_last = {}
        now = time.time()
        if now - self._succ_last.get(kulcs, 0) < 600:
            return
        self._succ_last[kulcs] = now
        if ip in bl:
            msg = ("4624 FEKETELISTAS IP SIKERESEN BELEPETT! %s - fiok: %s (%s) "
                   "-> azonnali vegleges blokk" % (ip, user, eredet))
            self.alert(ip, "[BIZTONSAG] " + msg, always=True)
            self.block_ip_perm(ip, "feketelistas IP sikeres belepese")
            return True
        msg = ("4624 SIKERES BELEPES KULSO IP-ROL! %s - fiok: %s (%s)%s. "
               "Ha nem te voltal: /block %s" % (
                   ip, user, eredet, " [ANONIM / null session]" if anonim else "", ip))
        self.alert(ip, "[BIZTONSAG] " + msg, always=True)
        return True

    # [v1.9.3] Naplozasi alkategoriak GUID-dal (nyelvfuggetlen: magyar
    # Windowson is mukodik, ahol az alkategoriak nevei forditva vannak)
    _AUDIT_SUBCATS = (
        ("{0CCE9215-69AE-11D9-BED3-505054503030}", True,  "Bejelentkezes (4624/4625)"),
        ("{0CCE9235-69AE-11D9-BED3-505054503030}", False, "Felhasznaloi fiokok kezelese (4720)"),
        ("{0CCE9237-69AE-11D9-BED3-505054503030}", False, "Biztonsagi csoportok kezelese (4732)"),
    )

    def _audit_ensure(self):
        """Bekapcsolja a szukseges naplozast, kulonben a Windows nem irja a
        4624/4625/4720/4732 esemenyeket es a figyeles "vak" lenne."""
        if not getattr(self, "admin", False):
            log_line("[BIZTONSAG] naplozasi hazirend: nincs rendszergazdai jog, kihagyva")
            return
        for guid, hibas_is, nev in self._AUDIT_SUBCATS:
            cmd = ["auditpol", "/set", "/subcategory:" + guid, "/success:enable"]
            if hibas_is:
                cmd.append("/failure:enable")
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=20,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if r.returncode == 0:
                    log_line("[BIZTONSAG] naplozas bekapcsolva: " + nev)
                else:
                    log_line("[BIZTONSAG] naplozas beallitasa SIKERTELEN: %s (kod %s)" % (nev, r.returncode))
            except Exception as e:
                log_line("[BIZTONSAG] auditpol hiba (%s): %s" % (nev, e))

    def _persist_loop(self):
        import time as _t
        try:
            self._audit_ensure()
        except Exception as e:
            log_line("[BIZTONSAG] naplozasi hazirend hiba: %s" % e)
        while getattr(self, "_persist_run", False):
            try:
                if _t.time() - getattr(self, "_def_last_status", 0.0) >= 600.0:
                    self._def_last_status = _t.time()
                    self._defender_status_check()
            except Exception as e:
                log_line("[DEFENDER] allapot hiba: %s" % e)
            try:
                if getattr(self, "monitoring_on", True):
                    self._persist_check()
            except Exception as e:
                log_line("[4698/7045] figyelo hiba: %s" % e)
            _t.sleep(60)

    def _persist_start(self):
        import threading
        if getattr(self, "_persist_thread", None) and self._persist_thread.is_alive():
            return
        self._persist_run = True
        self._persist_seen = getattr(self, "_persist_seen", set())
        self._persist_thread = threading.Thread(target=self._persist_loop, daemon=True)
        self._persist_thread.start()
        log_line("[4698/7045] perzisztencia-figyeles aktiv: utemezett feladat + szolgaltatas telepites")
        log_line("[BIZTONSAG] figyeles aktiv: 4624 sikeres kulso belepes, 4720 uj fiok, "
                 "4732 admin/RDP csoport, 1102/104 naplotorles")

    def _persist_stop(self):
        self._persist_run = False

    def _logon_start(self):
        self._logon_hits = {}
        self._logon_seen = set()
        self._logon_stop_ev = threading.Event()
        self._logon_thread = threading.Thread(target=self._logon_loop, daemon=True)
        self._logon_thread.start()

        import time as _tm
        self._logon_started = _tm.time()
        log_line("[4625] bejelentkezes-figyeles aktiv: sikertelen halozati probak (SMB+RDP)")
        try:
            self._persist_start()
        except Exception:
            pass

    def _logon_stop(self):
        ev = getattr(self, "_logon_stop_ev", None)
        if ev:
            ev.set()
