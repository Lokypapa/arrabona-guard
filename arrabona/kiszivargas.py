# -*- coding: utf-8 -*-
"""Arrabona Guard - ADATKISZIVARGAS-FIGYELES (GuardCore mixin). [v2.16.0]

Riaszt, ha egy program szokatlanul sok adatot TOLT FEL az internetre. Igy viselkednek az
adatlopok (jelszavak, dokumentumok, sutik feltoltese) es a mai zsarolovirusok is: a
titkositas ELOTT kimasoljak az adatokat ("dupla zsarolas").

Hogyan merunk: a Windows TCP-statisztikai (EStats) funkciojaval kapcsolatonkent pontosan
latjuk a kikuldott bajtokat (DataBytesOut), es a kapcsolat tulajdonos programjahoz adjuk
(GetExtendedTcpTable, IPv4 + IPv6). Csak kulso (internetes) celcimek szamitanak; a LAN /
Tailscale forgalom nem. Rendszergazdai jog kell hozza.

Kuszobok (kiszivargas.txt):
  - ISMERETLEN_MB (alap 30): alairatlan / nem megbizhato program ennyit tolt fel 5 perc alatt
  - ALAIRT_MB (alap 1500): ervenyesen alairt program 10 perc alatt ennyit, ES legalabb 3x
    annyit, mint az eddigi sajat rekordja (a Guard tanulja, mennyi a megszokott)
  - ROSSZ IP: feketelistas / FEED-ben szereplo cimre 5 MB feletti feltoltes - barmelyik program
  - AKCIO FELFUGGESZT: a NAGYON GYANUS (alairatlan + Temp / Letoltesek / AppData-gyoker, vagy
    rossz IP) programot megallitja, te dontesz (Leallitas / Folytatas / Karanten / Megbizhato)
  - KIVETEL <utreszlet vagy programnev>: felhoszinkron, torrent, streaming, sajat szerver...
Korlat: csak a TCP-forgalmat latja (a QUIC/UDP-feltoltest nem) - a kartevok szinte mindig
HTTPS-t (TCP) hasznalnak. Telegram: /kiszivargas
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import json as _json
import os
import socket
import struct
import threading
import time
from collections import deque
from .common import (APPDATA_DIR, is_private_ip, log_line)

KISZ_CFG_FILE = os.path.join(APPDATA_DIR, "kiszivargas.txt")
KISZ_STATE_FILE = os.path.join(APPDATA_DIR, "kiszivargas_allapot.json")
POLL = 2.0
ABLAK_RO = 300.0      # 5 perc
ABLAK_HO = 600.0      # 10 perc
MB = 1024.0 * 1024.0
_COOLDOWN = 3600.0
_SIG_MIN = 5 * MB     # ez alatt alairast sem nezunk (felesleges PowerShell)

# Ismert, sokat feltolto (legitim) programok - ezek nem riasztanak.
_ALAP_KIVETEL = ("onedrive.exe", "dropbox.exe", "googledrivefs.exe", "megasync.exe", "pcloud.exe",
                 "nextcloud.exe", "owncloud.exe", "syncthing.exe", "icloud", "bztransmit", "backblaze",
                 "idrive", "acronis", "veeam", "qbittorrent.exe", "utorrent.exe", "bittorrent.exe",
                 "transmission", "deluge", "tixati.exe", "biglybt", "obs64.exe", "obs32.exe",
                 "streamlabs", "xsplit", "tailscaled.exe", "tailscale-ipn.exe", "sunshine.exe",
                 "parsecd.exe", "anydesk.exe", "teamviewer", "rustdesk.exe", "nvcontainer.exe",
                 "steam.exe", "steamwebhelper.exe", "steamservice.exe")
_SZINT_NEV = {3: "KRITIKUS", 2: "NAGYON GYANUS", 1: "GYANUS", 0: "SZOKATLAN"}

# ------------------------------------------------------------------ Win32 strukturak
_U32 = ctypes.c_uint32
_U64 = ctypes.c_uint64
AF_INET, AF_INET6 = 2, 23
TCP_TABLE_OWNER_PID_ALL = 5
MIB_TCP_STATE_ESTAB = 5
TCP_ESTATS_DATA = 1          # TcpConnectionEstatsData
ERROR_INSUFFICIENT_BUFFER = 122


class MIB_TCPROW(ctypes.Structure):
    _fields_ = [("dwState", _U32), ("dwLocalAddr", _U32), ("dwLocalPort", _U32),
                ("dwRemoteAddr", _U32), ("dwRemotePort", _U32)]


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("dwState", _U32), ("dwLocalAddr", _U32), ("dwLocalPort", _U32),
                ("dwRemoteAddr", _U32), ("dwRemotePort", _U32), ("dwOwningPid", _U32)]


class MIB_TCP6ROW(ctypes.Structure):
    _fields_ = [("State", _U32), ("LocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", _U32),
                ("dwLocalPort", _U32), ("RemoteAddr", ctypes.c_ubyte * 16), ("dwRemoteScopeId", _U32),
                ("dwRemotePort", _U32)]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [("ucLocalAddr", ctypes.c_ubyte * 16), ("dwLocalScopeId", _U32), ("dwLocalPort", _U32),
                ("ucRemoteAddr", ctypes.c_ubyte * 16), ("dwRemoteScopeId", _U32), ("dwRemotePort", _U32),
                ("dwState", _U32), ("dwOwningPid", _U32)]


class TCP_ESTATS_DATA_RW_v0(ctypes.Structure):
    _fields_ = [("EnableCollection", ctypes.c_ubyte)]


class TCP_ESTATS_DATA_ROD_v0(ctypes.Structure):
    _fields_ = [("DataBytesOut", _U64), ("DataSegsOut", _U64), ("DataBytesIn", _U64), ("DataSegsIn", _U64),
                ("SegsOut", _U64), ("SegsIn", _U64), ("SoftErrors", _U32), ("SoftErrorReason", _U32),
                ("SndUna", _U32), ("SndNxt", _U32), ("SndMax", _U32), ("ThruBytesAcked", _U64),
                ("RcvNxt", _U32), ("ThruBytesReceived", _U64)]


_API = None


def _api():
    """iphlpapi fuggvenyek (csak Windowson); None, ha nem elerheto."""
    global _API
    if _API is None:
        try:
            ip = ctypes.WinDLL("iphlpapi.dll")
            f = {}
            f["tabla"] = ip.GetExtendedTcpTable
            f["tabla"].argtypes = [ctypes.c_void_p, ctypes.POINTER(_U32), ctypes.c_int, _U32, ctypes.c_int, _U32]
            f["tabla"].restype = _U32
            for nev, row in (("4", MIB_TCPROW), ("6", MIB_TCP6ROW)):
                g = getattr(ip, "GetPerTcp%sConnectionEStats" % ("" if nev == "4" else "6"))
                g.argtypes = [ctypes.POINTER(row), ctypes.c_int, ctypes.c_void_p, _U32, _U32,
                              ctypes.c_void_p, _U32, _U32, ctypes.c_void_p, _U32, _U32]
                g.restype = _U32
                s = getattr(ip, "SetPerTcp%sConnectionEStats" % ("" if nev == "4" else "6"))
                s.argtypes = [ctypes.POINTER(row), ctypes.c_int, ctypes.c_void_p, _U32, _U32, _U32]
                s.restype = _U32
                f["get" + nev], f["set" + nev] = g, s
            _API = f
        except Exception:
            _API = False
    return _API or None


def _port(dw):
    return socket.ntohs(dw & 0xFFFF)


def _tabla(af):
    api = _api()
    meret = _U32(0)
    api["tabla"](None, ctypes.byref(meret), 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
    for _ in range(4):
        buf = (ctypes.c_ubyte * (meret.value + 4096))()
        meret = _U32(len(buf))
        r = api["tabla"](buf, ctypes.byref(meret), 0, af, TCP_TABLE_OWNER_PID_ALL, 0)
        if r == 0:
            n = _U32.from_buffer(buf).value
            row = MIB_TCPROW_OWNER_PID if af == AF_INET else MIB_TCP6ROW_OWNER_PID
            n = min(n, (len(buf) - 4) // ctypes.sizeof(row))
            return (row * n).from_buffer(buf, 4)
        if r != ERROR_INSUFFICIENT_BUFFER:
            return []
    return []


def kapcsolatok():
    """[(kulcs, estats_row, af, pid, tavoli_ip, tavoli_port)] - csak ESTABLISHED, kulso celcimre."""
    out = []
    for r in _tabla(AF_INET):
        if r.dwState != MIB_TCP_STATE_ESTAB:
            continue
        rip = socket.inet_ntoa(struct.pack("<I", r.dwRemoteAddr))
        if is_private_ip(rip):
            continue
        er = MIB_TCPROW(r.dwState, r.dwLocalAddr, r.dwLocalPort, r.dwRemoteAddr, r.dwRemotePort)
        k = (4, r.dwLocalAddr, r.dwLocalPort, r.dwRemoteAddr, r.dwRemotePort)
        out.append((k, er, AF_INET, r.dwOwningPid, rip, _port(r.dwRemotePort)))
    for r in _tabla(AF_INET6):
        if r.dwState != MIB_TCP_STATE_ESTAB:
            continue
        rb = bytes(r.ucRemoteAddr)
        try:
            rip = socket.inet_ntop(socket.AF_INET6, rb)
        except (OSError, ValueError, AttributeError):
            continue
        if rip.startswith("::ffff:"):
            rip = rip[7:]
        if is_private_ip(rip.lower()):
            continue
        er = MIB_TCP6ROW(r.dwState, r.ucLocalAddr, r.dwLocalScopeId, r.dwLocalPort,
                         r.ucRemoteAddr, r.dwRemoteScopeId, r.dwRemotePort)
        k = (6, bytes(r.ucLocalAddr), r.dwLocalPort, rb, r.dwRemotePort)
        out.append((k, er, AF_INET6, r.dwOwningPid, rip, _port(r.dwRemotePort)))
    return out


def estats_be(row, af):
    """Statisztika-gyujtes bekapcsolasa a kapcsolatra. 0 = OK, 5 = nincs admin jog."""
    api = _api()
    rw = TCP_ESTATS_DATA_RW_v0(1)
    return api["set" + ("4" if af == AF_INET else "6")](ctypes.byref(row), TCP_ESTATS_DATA, ctypes.byref(rw),
                                                         0, ctypes.sizeof(rw), 0)


def estats_olvas(row, af):
    """(ki_bajt, be_bajt) a kapcsolat statisztika-bekapcsolasa ota, vagy None."""
    api = _api()
    rod = TCP_ESTATS_DATA_ROD_v0()
    r = api["get" + ("4" if af == AF_INET else "6")](ctypes.byref(row), TCP_ESTATS_DATA, None, 0, 0,
                                                     None, 0, 0, ctypes.byref(rod), 0, ctypes.sizeof(rod))
    if r != 0:
        return None
    return rod.DataBytesOut, rod.DataBytesIn


def kisz_cfg():
    cfg = {"FIGYELES": "BE", "ISMERETLEN_MB": 30, "ALAIRT_MB": 1500, "AKCIO": "FELFUGGESZT", "KIVETEL": []}
    try:
        if not os.path.exists(KISZ_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(KISZ_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - adatkiszivargas-figyeles (v2.16.0)\n"
                        "FIGYELES BE\n"
                        "# ISMERETLEN_MB <n> = alairatlan / nem megbizhato program 5 perc alatt ennyi MB-ot tolt fel -> riasztas\n"
                        "ISMERETLEN_MB 30\n"
                        "# ALAIRT_MB <n> = alairt program 10 perc alatt ennyit (es 3x a sajat rekordjat) -> riasztas\n"
                        "ALAIRT_MB 1500\n"
                        "# AKCIO FELFUGGESZT = a NAGYON GYANUS programot megallitja (te dontesz) / RIASZT = csak szol\n"
                        "AKCIO FELFUGGESZT\n"
                        "# KIVETEL <utreszlet vagy programnev> = nem figyeli (tobb sor is lehet). A felhoszinkron,\n"
                        "# torrent, streaming, Steam, Tailscale, AnyDesk, TeamViewer stb. alapbol kivetel.\n"
                        "# A sajat WoW-szervered a jatekosoknak kuld adatot - ezert kivetel:\n"
                        "KIVETEL \\wowserver\\\n")
        with open(KISZ_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip().strip('"') if len(r) > 1 else "")
                if k == "KIVETEL" and v:
                    cfg["KIVETEL"].append(v.lower())
                elif k in ("ISMERETLEN_MB", "ALAIRT_MB") and v.isdigit() and int(v) >= 1:
                    cfg[k] = int(v)
                elif k == "AKCIO" and v.upper() in ("FELFUGGESZT", "RIASZT"):
                    cfg["AKCIO"] = v.upper()
                elif k == "FIGYELES" and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg["FIGYELES"] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def _mb(b):
    return b / MB


def mb_szoveg(b):
    m = _mb(b)
    return ("%.1f GB" % (m / 1024.0)) if m >= 1024 else ("%.0f MB" % m if m >= 10 else "%.1f MB" % m)


class KiszivargasMixin(object):
    """Adatkiszivargas-figyeles. A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ allapot
    def _kz_load(self):
        try:
            with open(KISZ_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                if isinstance(d, dict):
                    d.setdefault("rekord", {})
                    return d
        except (OSError, ValueError):
            pass
        return {"rekord": {}}

    def _kz_save(self):
        try:
            tmp = KISZ_STATE_FILE + ".tmp"
            with self._kz_lock:
                adat = _json.dumps(self._kz_state, ensure_ascii=False, indent=1)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(adat)
            os.replace(tmp, KISZ_STATE_FILE)
        except OSError as e:
            log_line("[KISZIVARGAS] mentesi hiba: %s" % e)

    # ------------------------------------------------------------ program-adatok
    def _kz_prog(self, pid):
        """{"name","exe","ctime"} a PID-hez (gyorsitotarral)."""
        p = self._kz_pinfo.get(pid)
        if p and time.time() - p["ts"] < 120:
            return p
        nev, exe = self._proc_info(pid)
        ct = 0
        try:
            import psutil
            ct = int(psutil.Process(pid).create_time())
        except Exception:
            pass
        p = {"name": nev, "exe": exe or "", "ctime": ct, "ts": time.time()}
        self._kz_pinfo[pid] = p
        return p

    def _kz_kivetel(self, nev, exe):
        n, e = (nev or "").lower(), (exe or "").lower()
        if self._kz_own_exe and e and os.path.normcase(e) == self._kz_own_exe:
            return True
        for k in _ALAP_KIVETEL:
            if n.startswith(k) or (e and os.path.basename(e).startswith(k)):
                return True
        for k in self._kz_cfg["KIVETEL"]:
            if k and (k in e or k == n):
                return True
        return False

    def _kz_tipus(self, exe):
        """("ismeretlen" | "alairt" | "windows", sig) - fajlonkent gyorsitotarazva."""
        if not exe:
            return "windows", None      # vedett rendszerfolyamat (az utja sem olvashato)
        c = self._kz_tcache.get(exe)
        if c and time.time() - c[2] < 6 * 3600:
            return c[0], c[1]
        try:
            from .folyamat import windows_fajl
            win = windows_fajl(exe)
        except Exception:
            win = exe.lower().startswith(os.environ.get("WINDIR", r"C:\Windows").lower() + "\\")
        sig = None
        try:
            from .alairas import sig_one, sig_veszely
            sig = sig_one(exe)
            # az eltunt fajl (onmagat torolte futas kozben) kulonosen gyanus
            rossz = sig_veszely(sig) >= 1 or (sig or {}).get("allapot") == "hianyzik"
        except Exception:
            rossz = False
        t = "windows" if (win and not rossz) else ("ismeretlen" if rossz else "alairt")
        self._kz_tcache[exe] = (t, sig, time.time())
        return t, sig

    # ------------------------------------------------------------ meres
    def _kz_meres(self):
        most = time.time()
        lst = kapcsolatok()
        lat = set()
        for k, row, af, pid, rip, rport in lst:
            if pid in (0, 4) or pid in self._kz_own:
                continue
            lat.add(k)
            c = self._kz_conns.get(k)
            if c is None or c["pid"] != pid:
                r = estats_be(row, af)
                if r == 5:
                    self.kisz_admin = False
                    return
                v = estats_olvas(row, af)
                # alapertek: ami a bekapcsolaskor mar benne volt, az nem "uj" feltoltes
                self._kz_conns[k] = {"pid": pid, "out": v[0] if v else 0, "in": v[1] if v else 0,
                                     "ip": rip, "port": rport}
                continue
            v = estats_olvas(row, af)
            if not v:
                continue
            d_out, d_in = v[0] - c["out"], v[1] - c["in"]
            if d_out < 0 or d_in < 0:
                d_out, d_in = max(0, v[0]), max(0, v[1])
            c["out"], c["in"] = v
            if not (d_out or d_in):
                continue
            self._kz_ossz_ki += d_out
            p = self._kz_akt.get(pid)
            if p is None:
                p = self._kz_akt[pid] = {"b": deque(), "dest": {}, "t0": most}
            p["b"].append((most, d_out, d_in))
            if d_out:
                dd = p["dest"].setdefault(rip, [0, rport, most])
                dd[0] += d_out
                dd[2] = most
        for k in [k for k in self._kz_conns if k not in lat]:
            self._kz_conns.pop(k, None)
        self.kisz_admin = True
        self.kisz_kapcsolat = len(lat)

    def _kz_osszeg(self, p, most, ablak):
        ki = be = 0
        for t, o, i in p["b"]:
            if most - t <= ablak:
                ki += o
                be += i
        return ki, be

    def _kz_kiertekel(self):
        most = time.time()
        try:
            from .common import load_blacklist
            bl = load_blacklist()
        except Exception:
            bl = set()
        rekord = self._kz_state.setdefault("rekord", {})
        top = []
        for pid, p in list(self._kz_akt.items()):
            b = p["b"]
            while b and most - b[0][0] > ABLAK_HO:
                b.popleft()
            for ip in [ip for ip, d in p["dest"].items() if most - d[2] > ABLAK_HO]:
                p["dest"].pop(ip, None)
            if not b:
                self._kz_akt.pop(pid, None)
                continue
            ki5, _be5 = self._kz_osszeg(p, most, ABLAK_RO)
            ki10, be10 = self._kz_osszeg(p, most, ABLAK_HO)
            info = self._kz_prog(pid)
            top.append((ki10, pid, info["name"], be10))
            if ki5 < 2 * MB and ki10 < _SIG_MIN:
                continue
            if self._kz_kivetel(info["name"], info["exe"]):
                continue
            kulcs = (info["exe"] or info["name"]).lower()
            # rossz celcim (feketelista / FEED)?
            rossz_cel = []
            for ip, d in p["dest"].items():
                if d[0] >= 1 * MB:
                    try:
                        ok = self._rossz_ip(ip, bl)
                    except Exception:
                        ok = None
                    if ok:
                        rossz_cel.append((ip, ok))
            if ki10 < _SIG_MIN and not rossz_cel:
                continue
            tipus, sig = self._kz_tipus(info["exe"])
            elozo_rek = float(rekord.get(kulcs, 0.0))
            cfg = self._kz_cfg
            szint, okok = None, []
            if rossz_cel and ki5 >= 5 * MB:
                szint = 3
                okok.append("ROSSZ HÍRŰ címre tölt fel: %s" % ", ".join("%s (%s)" % x for x in rossz_cel[:3]))
            elif tipus == "ismeretlen" and ki5 >= cfg["ISMERETLEN_MB"] * MB:
                szint = 1
                al = (sig or {}).get("allapot")
                okok.append({"nincs": "aláíratlan program",
                             "megbizhatatlan": "nem megbízható tanúsítvánnyal aláírt program",
                             "rossz": "ÉRVÉNYTELEN aláírás - a programfájlt módosították",
                             "hianyzik": "a program fájlja eltűnt a lemezről (önmagát törölte?)"}.get(
                                 al, "nem ellenőrizhető program"))
                try:
                    from .folyamat import hely_okok
                    for _s, o in hely_okok(info["exe"]):
                        szint = 2
                        okok.append(o)
                except Exception:
                    pass
                if al in ("rossz", "hianyzik"):
                    szint = 2
            elif (tipus == "alairt" and ki10 >= cfg["ALAIRT_MB"] * MB and ki10 >= 3 * elozo_rek) or \
                    (tipus == "windows" and ki10 >= 3 * cfg["ALAIRT_MB"] * MB and ki10 >= 3 * elozo_rek):
                szint = 0
                okok.append("a szokásosnál sokkal több (eddigi rekordja 10 perc alatt: %s)" % mb_szoveg(elozo_rek)
                            if elozo_rek else "aláírt program, de szokatlanul nagy feltöltés")
            if ki10 > elozo_rek:
                rekord[kulcs] = float(ki10)
            if szint is None:
                continue
            if most - self._kz_last.get(kulcs, 0.0) < _COOLDOWN:
                continue
            self._kz_last[kulcs] = most
            self._kz_riaszt(pid, info, tipus, sig, szint, okok, ki5, ki10, be10, p)
            p["b"].clear()       # a kovetkezo riasztashoz uj adatmennyiseg kell
            p["dest"].clear()
        top.sort(reverse=True)
        self._kz_top = top[:15]

    def _kz_riaszt(self, pid, info, tipus, sig, szint, okok, ki5, ki10, be10, p):
        from .alairas import sig_szoveg
        self.kisz_alerts += 1
        celok = sorted(p["dest"].items(), key=lambda x: -x[1][0])[:4]
        try:
            from .geoip import geo_country_bg
        except Exception:
            geo_country_bg = None

        def cc(ip):
            try:
                c = geo_country_bg(ip) if geo_country_bg else ""
            except Exception:
                c = ""
            return (" [%s]" % c) if c else ""
        cel_sz = ", ".join("%s:%s%s %s" % (ip, d[1], cc(ip), mb_szoveg(d[0])) for ip, d in celok) or "?"
        akcio = ""
        felf = False
        if szint >= 2 and tipus == "ismeretlen" and self._kz_cfg["AKCIO"] == "FELFUGGESZT" \
                and getattr(self, "_fy_lock", None) is not None:
            ok, sz = self._fy_suspend({"pid": pid, "ctime": info["ctime"], "name": info["name"], "exe": info["exe"]})
            felf = ok
            akcio = " | " + sz
        elif szint >= 2 and tipus == "ismeretlen":
            akcio = " | (nem allitottam meg - kiszivargas.txt: AKCIO RIASZT)"
        msg = ("[KISZIVARGAS] %s FELTOLTES: %s (PID %s) %s 5 perc alatt (10 perc: %s fel / %s le) | Cel: %s | "
               "Program: %s | Alairas: %s | Gyanus: %s%s | Igy viselkednek az adatlopok es a zsarolovirusok "
               "a titkositas elott. Ha nem te toltesz fel (felhobe mentes, video, jatek): allitsd le!" % (
                   _SZINT_NEV.get(szint, "GYANUS"), info["name"], pid, mb_szoveg(ki5), mb_szoveg(ki10),
                   mb_szoveg(be10), cel_sz, info["exe"] or "?",
                   sig_szoveg(sig, ekezet=False) if sig else ("Windows-folyamat" if tipus == "windows" else "?"),
                   "; ".join(okok) or "-", akcio))
        log_line("[KISZIVARGAS] riasztas: %s %s" % (info["name"], mb_szoveg(ki10)))
        gombok = None
        try:
            from .telegram import tg_action
            ct = info["ctime"] or 0
            if felf:
                gombok = [[("⛔ Leállítás + teljes vizsgálat", "pk:%d:%d:full" % (pid, ct)),
                           ("▶ Folytatás (én voltam)", "pr:%d:%d" % (pid, ct))]]
            else:
                gombok = [[("⛔ Program leállítása", "pk:%d:%d" % (pid, ct))]]
            if info["exe"] and tipus != "windows":
                gombok.append([("🗄 Karanténba", tg_action("pq", {"pid": pid, "ctime": ct, "fajl": info["exe"]}))])
            if celok and not is_private_ip(celok[0][0]):
                gombok.append([("🚫 Cél IP végleges blokk (%s)" % celok[0][0][:24], "b:%s" % celok[0][0])])
            gombok.append([("✅ Megbízható (én töltök fel)", tg_action("kt", {"exe": info["exe"] or info["name"]}))])
        except Exception:
            pass
        with self._kz_lock:
            self._kz_recent = ([{"ts": time.time(), "name": info["name"], "pid": pid, "szint": szint,
                                 "mb": _mb(ki10), "cel": cel_sz[:120], "felf": felf}] + self._kz_recent)[:30]
        self.alert("127.0.0.1", msg, always=True, gombok=gombok)

    # ------------------------------------------------------------ ciklus
    def _kz_loop(self):
        utolso_cfg = utolso_ert = 0.0
        utolso_mentes = time.time()
        while not self._kz_stop_ev.wait(POLL):
            try:
                most = time.time()
                if most - utolso_cfg >= 30:
                    utolso_cfg = most
                    self._kz_cfg = kisz_cfg()
                if self._kz_cfg["FIGYELES"] != "BE":
                    self.kisz_status = "kikapcsolva (kiszivargas.txt)"
                    self._kz_conns.clear()
                    self._kz_akt.clear()
                    continue
                if not self.is_on():
                    continue
                self._kz_meres()
                if self.kisz_admin is False:
                    self.kisz_status = "nem elérhető (rendszergazda kell)"
                    self._kz_stop_ev.wait(300)
                    continue
                self.kisz_status = "aktív"
                if most - utolso_ert >= 10 and not self.is_paused():
                    utolso_ert = most
                    self._kz_kiertekel()
                if most - utolso_mentes >= 600:
                    utolso_mentes = most
                    self._kz_save()
                if len(self._kz_pinfo) > 3000:
                    self._kz_pinfo.clear()
            except Exception as e:
                log_line("[KISZIVARGAS] figyelo hiba: %s" % e)
                self._kz_stop_ev.wait(10.0)

    def _kiszivargas_start(self):
        if getattr(self, "_kz_thread", None) and self._kz_thread.is_alive():
            return
        self._kz_lock = threading.Lock()
        self._kz_recent = getattr(self, "_kz_recent", [])
        self._kz_top = []
        self.kisz_alerts = getattr(self, "kisz_alerts", 0)
        self.kisz_kapcsolat = 0
        self.kisz_admin = None
        if not _api():
            self.kisz_status = "nem elérhető (csak Windowson)"
            return
        self._kz_cfg = kisz_cfg()
        self._kz_state = self._kz_load()
        self._kz_conns, self._kz_akt, self._kz_pinfo, self._kz_tcache, self._kz_last = {}, {}, {}, {}, {}
        self._kz_ossz_ki = 0
        self._kz_own = {os.getpid()}
        try:
            import psutil
            me = psutil.Process()
            par = me.parent()
            if par and par.exe() == me.exe():
                self._kz_own.add(par.pid)
        except Exception:
            pass
        import sys
        self._kz_own_exe = os.path.normcase(sys.executable).lower() if getattr(sys, "frozen", False) else ""
        self.kisz_status = "indulás…"
        self._kz_stop_ev = threading.Event()
        self._kz_thread = threading.Thread(target=self._kz_loop, name="kiszivargas", daemon=True)
        self._kz_thread.start()
        log_line("[KISZIVARGAS] figyeles indul (ismeretlen: %d MB / 5 perc, alairt: %d MB / 10 perc, akcio: %s)" % (
            self._kz_cfg["ISMERETLEN_MB"], self._kz_cfg["ALAIRT_MB"], self._kz_cfg["AKCIO"]))

    def _kiszivargas_stop(self):
        ev = getattr(self, "_kz_stop_ev", None)
        if ev is not None:
            ev.set()
        try:
            if getattr(self, "_kz_state", None) is not None:
                self._kz_save()
        except Exception:
            pass

    # ------------------------------------------------------------ muveletek
    def kisz_kivetel(self, mit, ki="felulet"):
        mit = (mit or "").strip()
        if not mit:
            return False, "Nincs mit kivételnek jelölni."
        try:
            from .folyamat import windows_fajl
            if windows_fajl(mit):
                # Windows-folyamatnal (pl. svchost) az egesz programot nem mentjuk fel - csak a nevet
                mit = os.path.basename(mit).lower()
        except Exception:
            pass
        try:
            kisz_cfg()
            with open(KISZ_CFG_FILE, "a", encoding="utf-8") as f:
                f.write("KIVETEL %s\n" % mit.replace("\n", " ")[:260])
            self._kz_cfg = kisz_cfg()
        except OSError as e:
            return False, "Nem sikerült menteni: %s" % e
        log_line("[KISZIVARGAS] kivetel (%s): %s" % (ki, mit))
        return True, "Megbízható - ennek a feltöltéseire többet nem szólok: %s" % mit[:120]

    # ------------------------------------------------------------ megjelenites
    def kisz_summary(self):
        s = getattr(self, "kisz_status", "?")
        if s != "aktív":
            return s
        reszek = ["Figyelt kapcsolat: %d" % getattr(self, "kisz_kapcsolat", 0)]
        top = getattr(self, "_kz_top", [])
        if top and top[0][0] >= 1 * MB:
            reszek.append("Legtöbb fel (10 p): %s %s" % (top[0][2][:18], mb_szoveg(top[0][0])))
        reszek.append("Riasztás: %d" % getattr(self, "kisz_alerts", 0))
        rec = getattr(self, "_kz_recent", [])
        if rec:
            reszek.append("Utolsó: %s ⚠" % rec[0]["name"][:20])
        return " | ".join(reszek)

    def kisz_text(self):
        sorok = ["ADATKISZIVARGAS-FIGYELES: %s" % self.kisz_summary().replace(" | ", ", ")]
        cfg = getattr(self, "_kz_cfg", None)
        if cfg:
            sorok.append("Kuszob: alairatlan %d MB / 5 perc, alairt %d MB / 10 perc, akcio: %s" % (
                cfg["ISMERETLEN_MB"], cfg["ALAIRT_MB"], cfg["AKCIO"]))
        top = [t for t in getattr(self, "_kz_top", []) if t[0] >= 0.1 * MB]
        if top:
            sorok.append("Legtobbet feltolto programok (utolso 10 perc):")
            for ki10, pid, nev, be10 in top[:10]:
                sorok.append("  %s (PID %s): %s fel / %s le" % (nev[:30], pid, mb_szoveg(ki10), mb_szoveg(be10)))
        else:
            sorok.append("Az utolso 10 percben nem volt szamottevo feltoltes.")
        rec = getattr(self, "_kz_recent", [])
        if rec:
            sorok.append("Legutobbi riasztasok:")
            for r in rec[:8]:
                sorok.append("  %s [%s] %s %.0f MB -> %s%s" % (
                    time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), _SZINT_NEV.get(r["szint"], "?"),
                    r["name"], r["mb"], r["cel"][:80], " (megallitva)" if r["felf"] else ""))
        return "\n".join(sorok)
