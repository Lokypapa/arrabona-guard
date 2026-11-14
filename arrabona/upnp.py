# -*- coding: utf-8 -*-
"""Arrabona Guard - ROUTER NYITOTT PORTJAI (UPnP) (GuardCore mixin). [v2.16.0]

A programok (es a kartevok is!) UPnP-vel a tudtod nelkul nyithatnak portot a routereden
az internet fele: onnantol barki elerheti a gepet / a halozat egy eszkozet azon a porton.
A Guard 5 percenkent lekerdezi a routertol (Arris is) a nyitott porttovabbitasokat
(SSDP-kereses + WANIPConnection / WANPPPConnection GetGenericPortMappingEntry), es:
  - UJ PORT -> riasztas: kulso port, melyik gep / melyik PROGRAM (ha ez a gep), alairas,
    lejarat; a veszelyes portok (RDP, SMB, SSH, VNC, adatbazisok...) kiemelve
  - gombok: Port bezarasa (DeletePortMapping) / + program leallitasa / Megbizhato
  - csak a sajat alapertelmezett atjarodtol (routertol) fogad el valaszt
Ha a router nem valaszol UPnP-re, az a legjobb eset: az UPnP ki van kapcsolva.
upnp.txt: FIGYELES BE/KI, POLL <mp>, KIVETEL <leirasreszlet vagy kulso port>.
Telegram: /upnp, /upnpzar <szam>
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from .common import (APPDATA_DIR, log_line)

UPNP_CFG_FILE = os.path.join(APPDATA_DIR, "upnp.txt")
UPNP_STATE_FILE = os.path.join(APPDATA_DIR, "upnp_allapot.json")
_SSDP = ("239.255.255.250", 1900)
_ST = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
       "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
       "urn:schemas-upnp-org:service:WANIPConnection:1",
       "urn:schemas-upnp-org:service:WANIPConnection:2",
       "urn:schemas-upnp-org:service:WANPPPConnection:1")
_MAX_VALASZ = 1024 * 1024
_MAX_BEJEGYZES = 512
VESZELYES_PORT = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 135: "Windows RPC", 137: "NetBIOS",
                  138: "NetBIOS", 139: "NetBIOS / SMB", 445: "SMB (fájlmegosztás)", 1433: "MS SQL",
                  1900: "UPnP", 2375: "Docker API", 2376: "Docker API", 3306: "MySQL",
                  3389: "RDP (távoli asztal)", 5432: "PostgreSQL", 5555: "Android ADB", 5800: "VNC",
                  5900: "VNC", 5901: "VNC", 5985: "WinRM (távoli PowerShell)", 5986: "WinRM",
                  6379: "Redis", 8291: "MikroTik Winbox", 9200: "Elasticsearch", 11211: "memcached",
                  27017: "MongoDB", 47001: "WinRM"}
_SZINT_NEV = {3: "VESZELYES", 2: "GYANUS", 1: "UJ"}
# proxy NELKUL (egy kartevo altal beallitott proxy ne lassa / ne hamisithassa a router valaszait)
_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class UpnpHiba(Exception):
    def __init__(self, kod, leiras=""):
        Exception.__init__(self, "%s %s" % (kod, leiras))
        self.kod = kod
        self.leiras = leiras


def upnp_cfg():
    cfg = {"FIGYELES": "BE", "POLL": 300, "KIVETEL": []}
    try:
        if not os.path.exists(UPNP_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(UPNP_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - router nyitott portjai (UPnP) (v2.16.0)\n"
                        "FIGYELES BE\n"
                        "# POLL <mp> = ennyi masodpercenkent kerdezi a routert (alap 300 = 5 perc, min. 60)\n"
                        "POLL 300\n"
                        "# KIVETEL <leiras-reszlet vagy kulso port> = erre nem riaszt (tobb sor is lehet), pl.:\n"
                        "# KIVETEL Steam\n"
                        "# KIVETEL 3724\n")
        with open(UPNP_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip() if len(r) > 1 else "")
                if k == "KIVETEL" and v:
                    cfg["KIVETEL"].append(v.lower())
                elif k == "POLL" and v.isdigit():
                    cfg["POLL"] = max(60, min(3600, int(v)))
                elif k == "FIGYELES" and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg["FIGYELES"] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


# ------------------------------------------------------------------ alacsony szint
def _helyi_ip(cel):
    """Melyik helyi cimunkrol erjuk el a 'cel'-t (a router)? (UDP connect: nem kuld csomagot)"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((cel, 1900))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def ssdp_keres(gw=None, idokorlat=3.0):
    """[LOCATION URL, ...] az UPnP-routerektol. gw megadasa eseten csak attol (a tobbi: idegen)."""
    sajat, idegen = [], []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    except OSError:
        return sajat, idegen
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        hip = _helyi_ip(gw) if gw else None
        if hip:
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(hip))
                s.bind((hip, 0))
            except OSError:
                pass
        s.settimeout(0.4)
        for st in _ST:
            msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
                   "MX: 2\r\nST: %s\r\n\r\n" % st).encode("ascii")
            try:
                s.sendto(msg, _SSDP)
                if gw:
                    s.sendto(msg, (gw, 1900))   # nehany router csak unicastra valaszol
            except OSError:
                pass
        hatar = time.time() + idokorlat
        while time.time() < hatar:
            try:
                adat, (felado, _p) = s.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            m = re.search(rb"(?im)^location:\s*(\S+)", adat)
            if not m:
                continue
            loc = m.group(1).decode("ascii", errors="ignore")
            host = urllib.parse.urlparse(loc).hostname or ""
            if gw and (felado != gw or host != gw):
                if loc not in idegen:
                    idegen.append(loc)
                continue
            if loc not in sajat:
                sajat.append(loc)
    finally:
        s.close()
    return sajat, idegen


def _http(url, adat=None, fejlec=None, idokorlat=6.0):
    req = urllib.request.Request(url, data=adat, headers=fejlec or {})
    with _OPENER.open(req, timeout=idokorlat) as r:
        return r.read(_MAX_VALASZ)


def _lokalis(tag):
    return tag.rsplit("}", 1)[-1]


def igd_leiras(loc):
    """{"control", "stype", "nev"} a router WANIPConnection / WANPPPConnection szolgaltatasahoz, vagy None."""
    try:
        gyoker = ET.fromstring(_http(loc))
    except Exception:
        return None
    alap = loc
    nev = ""
    for el in gyoker.iter():
        t = _lokalis(el.tag)
        if t == "URLBase" and (el.text or "").strip():
            alap = el.text.strip()
        elif t in ("friendlyName", "modelName") and not nev and (el.text or "").strip():
            nev = el.text.strip()
    talalt = []
    for el in gyoker.iter():
        if _lokalis(el.tag) != "service":
            continue
        d = {_lokalis(c.tag): (c.text or "").strip() for c in el}
        st = d.get("serviceType", "")
        if ("WANIPConnection" in st or "WANPPPConnection" in st) and d.get("controlURL"):
            talalt.append({"control": urllib.parse.urljoin(alap, d["controlURL"]), "stype": st, "nev": nev})
    # a WANIPConnection az elsodleges (a PPP gyakran csak "ures" masodik)
    talalt.sort(key=lambda x: "WANPPP" in x["stype"])
    return talalt[0] if talalt else None


def soap(dev, akcio, argok=()):
    """UPnP SOAP-hivas. Visszaad: {mezo: ertek}; UPnP-hibanal UpnpHiba(kod)."""
    test = "".join("<%s>%s</%s>" % (k, _xml_esc(v), k) for k, v in argok)
    boritek = ('<?xml version="1.0"?>'
               '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
               's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
               '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>' % (akcio, dev["stype"], test, akcio))
    fej = {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": '"%s#%s"' % (dev["stype"], akcio)}
    try:
        valasz = _http(dev["control"], boritek.encode("utf-8"), fej)
    except urllib.error.HTTPError as e:
        try:
            szoveg = e.read(_MAX_VALASZ)
            g = ET.fromstring(szoveg)
            kod = desc = ""
            for el in g.iter():
                if _lokalis(el.tag) == "errorCode":
                    kod = (el.text or "").strip()
                elif _lokalis(el.tag) == "errorDescription":
                    desc = (el.text or "").strip()
            raise UpnpHiba(kod or str(e.code), desc)
        except UpnpHiba:
            raise
        except Exception:
            raise UpnpHiba(str(e.code), "HTTP-hiba")
    g = ET.fromstring(valasz)
    out = {}
    for el in g.iter():
        if _lokalis(el.tag).endswith("Response"):
            for c in el:
                out[_lokalis(c.tag)] = (c.text or "").strip()
    return out


def _xml_esc(v):
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def port_lista(dev):
    """A router osszes UPnP-porttovabbitasa: [{"proto","ext","host","int_ip","int_port","desc","lease","enabled"}]."""
    out = []
    for i in range(_MAX_BEJEGYZES):
        try:
            r = soap(dev, "GetGenericPortMappingEntry", (("NewPortMappingIndex", i),))
        except UpnpHiba as e:
            if i == 0 and e.kod not in ("713", "714", "402", "501"):
                raise
            break       # 713 = SpecifiedArrayIndexInvalid: vege a listanak
        if not r:
            break
        try:
            ext = int(r.get("NewExternalPort") or 0)
            ip_ = int(r.get("NewInternalPort") or 0)
        except ValueError:
            continue
        out.append({"proto": (r.get("NewProtocol") or "?").upper(), "ext": ext,
                    "host": r.get("NewRemoteHost") or "", "int_ip": r.get("NewInternalClient") or "",
                    "int_port": ip_, "desc": r.get("NewPortMappingDescription") or "",
                    "lease": int(r.get("NewLeaseDuration") or 0) if (r.get("NewLeaseDuration") or "0").isdigit() else 0,
                    "enabled": (r.get("NewEnabled") or "1") not in ("0", "false")})
    return out


def kulcs(m):
    return "%s|%s|%s" % (m["proto"], m["ext"], m.get("host") or "")


def alairas_kulcs(m):
    """Ugyanaz a port + ugyanaz a gep/port + ugyanaz a leiras = mar latott (pl. jatek ujranyitja)."""
    return "%s|%s|%s|%s" % (kulcs(m), m.get("int_ip"), m.get("int_port"), (m.get("desc") or "").lower()[:40])


def port_veszely(m):
    """(szint, indoklas) a portszam alapjan."""
    for p in (m.get("ext"), m.get("int_port")):
        if p in VESZELYES_PORT:
            return 3, "%s port (%d) nyitva az internet felé!" % (VESZELYES_PORT[p], p)
    return 1, ""


def lejarat_szoveg(sec):
    if not sec:
        return "nincs (végleges)"
    if sec >= 3600:
        return "%d óra" % (sec // 3600)
    return "%d perc" % max(1, sec // 60)


class UpnpMixin(object):
    """Router UPnP-portok figyelese. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ allapot
    def _up_load(self):
        try:
            with open(UPNP_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                if isinstance(d, dict):
                    d.setdefault("known", {})
                    return d
        except (OSError, ValueError):
            pass
        return {"known": {}, "first_done": False}

    def _up_save(self):
        try:
            # 60 napnal regebben latott bejegyzesek ki
            hatar = time.time() - 60 * 86400
            kn = self._up_state.get("known") or {}
            for k in [k for k, v in kn.items() if float(v.get("last", 0)) < hatar]:
                kn.pop(k, None)
            tmp = UPNP_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._up_state, f, ensure_ascii=False, indent=1)
            os.replace(tmp, UPNP_STATE_FILE)
        except OSError as e:
            log_line("[UPNP] mentesi hiba: %s" % e)

    # ------------------------------------------------------------ router keresese
    def _up_router(self):
        """(dev, gw) - dev: igd_leiras() + "location"; None ha nincs UPnP."""
        try:
            from .lan import atjarok
            gws = atjarok()
        except Exception:
            gws = []
        if not gws:
            return None, None
        for gw in gws[:2]:
            sajat, idegen = ssdp_keres(gw)
            if idegen:
                uj = [x for x in idegen if x not in self._up_idegen]
                if uj:
                    self._up_idegen.extend(uj)
                    log_line("[UPNP] mas eszkoz is routernek (IGD) mondja magat a halozaton: %s" % ", ".join(uj[:5]))
            for loc in sajat:
                dev = igd_leiras(loc)
                if dev:
                    dev["location"] = loc
                    dev["gw"] = gw
                    return dev, gw
        return None, gws[0]

    # ------------------------------------------------------------ ki nyitotta?
    def _up_program(self, port, proto):
        """(pid, nev, exe, ctime) a helyi programhoz, ami ezen a porton figyel, vagy None."""
        try:
            import psutil
            kind = "udp" if proto == "UDP" else "tcp"
            for c in psutil.net_connections(kind=kind):
                if not c.laddr or c.laddr.port != port or not c.pid:
                    continue
                if kind == "tcp" and c.status != psutil.CONN_LISTEN:
                    continue
                nev, exe = self._proc_info(c.pid)
                try:
                    ct = int(psutil.Process(c.pid).create_time())
                except Exception:
                    ct = 0
                return c.pid, nev, exe, ct
        except Exception:
            pass
        return None

    def _up_eszkoz_nev(self, ip):
        try:
            for _i, _m, d, oip in self.lan_devices():
                if oip == ip or ip in (d.get("ips") or []):
                    return d.get("label") or d.get("name") or ""
        except Exception:
            pass
        return ""

    def _up_kivetel(self, m, prog=None):
        d = (m.get("desc") or "").lower()
        for k in self._up_cfg["KIVETEL"]:
            if k == str(m.get("ext")) or (k and k in d) or (prog and k in (prog[1] or "").lower()):
                return True
        return False

    def _up_reszletek(self, m):
        """(szint, okok[], kie_szoveg, prog) egy porthoz."""
        szint, ok = port_veszely(m)
        okok = [ok] if ok else []
        prog = None
        sajat = m["int_ip"] in self.own_ips()
        if sajat:
            prog = self._up_program(m["int_port"], m["proto"])
            if prog:
                kie = "EZ A GEP: %s (PID %s) %s" % (prog[1], prog[0], prog[2] or "")
                try:
                    from .alairas import sig_one, sig_szoveg, sig_veszely
                    si = sig_one(prog[2]) if prog[2] else None
                    if si:
                        kie += " | Alairas: %s" % sig_szoveg(si, ekezet=False)
                        if sig_veszely(si):
                            szint = max(szint, 2)
                            okok.append("aláíratlan / nem megbízható program nyitotta")
                except Exception:
                    pass
                try:
                    from .folyamat import hely_okok
                    for _sz, o in hely_okok(prog[2]):
                        szint = max(szint, 2)
                        okok.append("a program %s" % o)
                except Exception:
                    pass
            else:
                kie = "EZ A GEP (most egy program sem figyel a %s/%d porton)" % (m["proto"], m["int_port"])
        else:
            nev = self._up_eszkoz_nev(m["int_ip"])
            kie = "%s%s" % (m["int_ip"] or "?", (" (%s)" % nev) if nev else " (masik eszkoz a halozaton)")
        if not m.get("lease"):
            okok.append("végleges (nem jár le magától)")
        return szint, okok, kie, prog

    def _up_sor(self, m):
        return "%s %d -> %s:%d%s%s" % (m["proto"], m["ext"], m["int_ip"], m["int_port"],
                                        (" '%s'" % m["desc"][:40]) if m.get("desc") else "",
                                        "" if m.get("enabled", True) else " (kikapcsolt)")

    def _up_riaszt(self, m):
        szint, okok, kie, prog = self._up_reszletek(m)
        if self._up_kivetel(m, prog):
            log_line("[UPNP] uj port (kivetel, nem riasztok): %s | %s" % (self._up_sor(m), kie))
            return
        self.upnp_new += 1
        msg = ("[UPNP] %s NYITOTT PORT A ROUTEREN: %s %d (internet) -> %s:%d | Leiras: %s | Kie: %s | "
               "Lejarat: %s%s | Az internetrol BARKI elerheti ezt a portot. Ha nem te / nem egy ismert "
               "program (jatek, torrent, Steam) nyitotta: zard be." % (
                   _SZINT_NEV.get(szint, "UJ"), m["proto"], m["ext"], m["int_ip"], m["int_port"],
                   m.get("desc") or "-", kie, lejarat_szoveg(m.get("lease")),
                   (" | FIGYELEM: " + "; ".join(okok)) if okok else ""))
        gombok = None
        try:
            from .telegram import tg_action
            pl = {"proto": m["proto"], "ext": m["ext"], "host": m.get("host") or ""}
            gombok = [[("⛔ Port bezárása", tg_action("uz", pl))]]
            if prog:
                pl2 = dict(pl, pid=prog[0], ctime=prog[3])
                gombok.append([("⛔ Bezárás + program leállítása", tg_action("uz", pl2))])
            gombok.append([("✅ Megbízható (én / ismert program)", tg_action("ut", {"desc": m.get("desc") or "",
                                                                                  "ext": m["ext"]}))])
        except Exception:
            pass
        with self._up_lock:
            self._up_recent = ([{"ts": time.time(), "sor": self._up_sor(m), "szint": szint, "kie": kie}]
                               + self._up_recent)[:30]
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)

    def _up_elso_osszegzes(self, lista):
        from .telegram import tg_send
        if not lista:
            tg_send("✅ [UPNP] A router UPnP-je be van kapcsolva, de most egy port sincs nyitva rajta. "
                    "Mostantól szólok, ha egy program portot nyit.")
            log_line("[UPNP] elso lekerdezes: nincs nyitott UPnP-port")
            return
        sorok = ["[UPNP] Jelenleg nyitott portok a routereden (UPnP, %d db) - ezeket ismertnek veszem, "
                 "mostantól csak az ÚJ portokra szólok:" % len(lista)]
        vesz = 0
        for i, m in enumerate(lista[:30], 1):
            szint, okok, kie, _p = self._up_reszletek(m)
            if szint >= 3:
                vesz += 1
            sorok.append("%d. %s%s | %s" % (i, "⚠ " if szint >= 2 else "", self._up_sor(m), kie[:110]))
        if vesz:
            sorok.append("⚠ %d VESZÉLYES port (RDP / SMB / SSH / VNC / adatbázis) - zárd be: /upnpzar <szám>" % vesz)
            self.alert("127.0.0.1", "[UPNP] VESZELYES PORT NYITVA a routeren (UPnP): %d db - lista: /upnp" % vesz,
                       always=True)
        log_line("[UPNP] elso lekerdezes: %d nyitott port: %s" % (len(lista), "; ".join(self._up_sor(m) for m in lista[:20])))
        tg_send("\n".join(sorok))

    # ------------------------------------------------------------ egy kor
    def _up_kor(self):
        most = time.time()
        if not self._up_dev or self._up_hibak >= 2 or most - self._up_dev_ts > 6 * 3600:
            dev, gw = self._up_router()
            self._up_dev_ts = most
            self._up_hibak = 0
            elozo = bool(self._up_dev)
            self._up_dev = dev
            self._up_gw = gw
            if not dev:
                self._up_now = []
                self.upnp_elerheto = False
                self.upnp_status = ("aktív" if gw else "nincs router (átjáró)")
                if elozo:
                    log_line("[UPNP] a router mar nem valaszol UPnP-re (kikapcsoltad? ujraindult?)")
                return
            if not elozo:
                log_line("[UPNP] router UPnP: %s (%s) - %s" % (dev.get("nev") or "?", gw, dev["stype"].rsplit(":", 2)[-2]))
                try:
                    self._up_kulso = soap(dev, "GetExternalIPAddress").get("NewExternalIPAddress", "")
                except Exception:
                    self._up_kulso = ""
        try:
            lista = port_lista(self._up_dev)
        except Exception as e:
            self._up_hibak += 1
            log_line("[UPNP] port-lekerdezesi hiba (%s): %s" % (self._up_hibak, e))
            return
        self.upnp_elerheto = True
        self.upnp_status = "aktív"
        self._up_now = lista
        kn = self._up_state.setdefault("known", {})
        if not self._up_state.get("first_done"):
            for m in lista:
                kn[alairas_kulcs(m)] = {"first": most, "last": most, "sor": self._up_sor(m)}
            self._up_state["first_done"] = True
            self._up_save()
            self._up_elso_osszegzes(lista)
            self._up_elozo = {kulcs(m): m for m in lista}
            return
        valtozott = False
        for m in lista:
            ak = alairas_kulcs(m)
            if ak in kn:
                kn[ak]["last"] = most
                continue
            kn[ak] = {"first": most, "last": most, "sor": self._up_sor(m)}
            valtozott = True
            if self.is_on() and not self.is_paused():
                self._up_riaszt(m)
            else:
                log_line("[UPNP] uj port (szunet alatt): %s" % self._up_sor(m))
        most_k = {kulcs(m): m for m in lista}
        for k, m in (self._up_elozo or {}).items():
            if k not in most_k:
                log_line("[UPNP] port bezarult: %s" % self._up_sor(m))
        self._up_elozo = most_k
        if valtozott or most - self._up_mentve > 3600:
            self._up_mentve = most
            self._up_save()

    def _up_loop(self):
        if self._up_stop_ev.wait(45):
            return
        while True:
            self._up_cfg = upnp_cfg()
            try:
                if self._up_cfg["FIGYELES"] != "BE":
                    self.upnp_status = "kikapcsolva (upnp.txt)"
                else:
                    with self._up_kor_lock:
                        self._up_kor()
            except Exception as e:
                log_line("[UPNP] hiba: %s" % e)
            if self._up_stop_ev.wait(self._up_cfg["POLL"]):
                return

    def _upnp_start(self):
        if getattr(self, "_up_thread", None) and self._up_thread.is_alive():
            return
        self._up_cfg = upnp_cfg()
        self._up_state = self._up_load()
        self._up_lock = threading.Lock()
        self._up_kor_lock = threading.Lock()
        self._up_dev, self._up_gw, self._up_dev_ts, self._up_hibak = None, None, 0.0, 0
        self._up_now, self._up_elozo, self._up_idegen, self._up_recent = [], None, [], []
        self._up_kulso, self._up_mentve = "", time.time()
        self.upnp_new = 0
        self.upnp_elerheto = None
        self.upnp_status = "indulás…"
        self._up_stop_ev = threading.Event()
        self._up_thread = threading.Thread(target=self._up_loop, name="upnp", daemon=True)
        self._up_thread.start()

    def _upnp_stop(self):
        ev = getattr(self, "_up_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ muveletek
    def upnp_zar(self, mi, pid=None, ctime=None, ki="felulet"):
        """Port bezarasa. mi: sorszam (/upnp lista) vagy {"proto","ext","host"}."""
        dev = getattr(self, "_up_dev", None)
        if not dev:
            return False, "A router most nem érhető el UPnP-n."
        if isinstance(mi, dict):
            m = mi
        else:
            lst = getattr(self, "_up_now", []) or []
            s = str(mi).strip()
            if not (s.isdigit() and 1 <= int(s) <= len(lst)):
                return False, "Nincs ilyen sorszám (lista: /upnp)."
            m = lst[int(s) - 1]
        leallitva = ""
        if pid:
            try:
                ok, sz = self.folyamat_kill(int(pid), ctime, ki=ki)
                leallitva = " " + sz
            except Exception as e:
                leallitva = " (program leállítása nem sikerült: %s)" % e
        try:
            soap(dev, "DeletePortMapping", (("NewRemoteHost", m.get("host") or ""),
                                            ("NewExternalPort", m["ext"]), ("NewProtocol", m["proto"])))
        except UpnpHiba as e:
            if e.kod in ("606", "714"):
                ok_szoveg = ("A router nem engedte (%s) - csak az a gép törölheti, amelyik nyitotta, vagy már "
                             "nincs meg. Zárd be a router admin felületén (http://%s), vagy kapcsold ki ott az "
                             "UPnP-t, ha nem kell." % (e.leiras or e.kod, dev.get("gw") or "router"))
                return False, ok_szoveg + leallitva
            return False, "Bezárás nem sikerült: UPnP-hiba %s %s%s" % (e.kod, e.leiras, leallitva)
        except Exception as e:
            return False, "Bezárás nem sikerült: %s%s" % (e, leallitva)
        log_line("[UPNP] PORT BEZARVA (%s): %s %s%s" % (ki, m["proto"], m["ext"], leallitva))
        try:
            self._up_now = [x for x in self._up_now if kulcs(x) != kulcs(m)]
        except Exception:
            pass
        return True, ("%s %s port bezárva a routeren.%s Ha újra megnyílik, a program újranyitotta - akkor a "
                      "programot kell leállítani / beállítani (vagy az UPnP-t kikapcsolni a routeren)."
                      % (m["proto"], m["ext"], leallitva))

    def upnp_kivetel(self, desc, ext=None, ki="felulet"):
        """KIVETEL sor az upnp.txt-be (leiras, ha van; kulonben a port)."""
        mit = (desc or "").strip() or (str(ext) if ext else "")
        if not mit:
            return False, "Nincs mit kivételnek jelölni."
        try:
            upnp_cfg()   # letrehozza, ha meg nincs
            with open(UPNP_CFG_FILE, "a", encoding="utf-8") as f:
                f.write("KIVETEL %s\n" % mit.replace("\n", " ")[:80])
            self._up_cfg = upnp_cfg()
        except OSError as e:
            return False, "Nem sikerült menteni: %s" % e
        log_line("[UPNP] kivetel (%s): %s" % (ki, mit))
        return True, "Megbízható: '%s' - erre többet nem szólok (upnp.txt)." % mit[:60]

    # ------------------------------------------------------------ megjelenites
    def upnp_summary(self):
        s = getattr(self, "upnp_status", "?")
        if s != "aktív":
            return s
        if getattr(self, "upnp_elerheto", None) is None:
            return "Első lekérdezés…"
        if not self.upnp_elerheto:
            return "A router UPnP-je ki van kapcsolva ✔ (nem nyitható port)"
        lst = getattr(self, "_up_now", []) or []
        vesz = sum(1 for m in lst if port_veszely(m)[0] >= 3)
        reszek = ["Nyitott port: %d" % len(lst)]
        if vesz:
            reszek.append("VESZÉLYES: %d ⚠" % vesz)
        reszek.append("Új (futam): %d" % getattr(self, "upnp_new", 0))
        dev = getattr(self, "_up_dev", None) or {}
        if dev.get("nev"):
            reszek.append(dev["nev"][:24])
        return " | ".join(reszek)

    def upnp_ok(self):
        """None = nincs adat; True = nincs veszelyes nyitott port."""
        if getattr(self, "upnp_elerheto", None) is None:
            return None
        return not any(port_veszely(m)[0] >= 3 for m in (getattr(self, "_up_now", []) or []))

    def upnp_text(self):
        sorok = ["ROUTER UPnP-PORTOK: %s" % self.upnp_summary().replace(" | ", ", ")]
        dev = getattr(self, "_up_dev", None)
        if dev:
            sorok.append("Router: %s (%s)%s" % (dev.get("nev") or "?", dev.get("gw") or "?",
                                                (", kulso IP: %s" % self._up_kulso) if self._up_kulso else ""))
        lst = getattr(self, "_up_now", []) or []
        for i, m in enumerate(lst[:40], 1):
            szint, okok, kie, _p = self._up_reszletek(m)
            sorok.append("%d. %s%s | %s | lejar: %s%s" % (
                i, "[VESZELYES] " if szint >= 3 else ("[!] " if szint >= 2 else ""), self._up_sor(m), kie[:90],
                lejarat_szoveg(m.get("lease")),
                (" | " + "; ".join(o for o in okok if "végleges" not in o)) if [o for o in okok if "végleges" not in o] else ""))
        if lst:
            sorok.append("Bezaras: /upnpzar <szam>")
        if getattr(self, "_up_idegen", None):
            sorok.append("Mas eszkoz is routernek mondja magat: %s" % ", ".join(self._up_idegen[:3]))
        if dev:
            sorok.append("Tipp: ha nem jatszol / nem torrentezel, az UPnP-t a router admin feluleten "
                         "(http://%s) erdemes kikapcsolni - akkor semmi nem nyithat portot." % (dev.get("gw") or "router"))
        return "\n".join(sorok)
