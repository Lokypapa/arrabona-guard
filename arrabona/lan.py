# -*- coding: utf-8 -*-
"""Arrabona Guard - HALOZATI (LAN) ESZKOZOK figyelese (GuardCore mixin). [v2.7.0]

  - Passziv: 30 mp-enkent az ARP-tabla (arp -a; nyelvfuggetlen feldolgozas).
  - Aktiv: 10 percenkent a teljes helyi alhalozat vegigkerdezese SendARP-vel
    (iphlpapi; nem ping - a pinget tilto eszkozok is valaszolnak), 64 szalon.
    Csak a valodi otthoni halozat: Tailscale / Hyper-V / WSL / VirtualBox /
    VMware adapterek kihagyva, max. /22 meretu halozat.
  - Uj (soha nem latott) MAC-cim -> riasztas (IP, nev, "veletlen MAC" jelzes).
  - ARP-MERGEZES (MITM): ha a router (alapertelmezett atjaro) MAC-cime megvaltozik,
    vagy egy MASIK eszkoz is a router MAC-jet hasznalja -> azonnali riasztas.
Elso futaskor a mar csatlakoztatott eszkozok ismertnek szamitanak.
Eszkozok elnevezese: Telegram /lannev <sorszam> <nev>
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import ipaddress
import json as _json
import os
import re
import socket
import subprocess
import threading
import time
from .common import (APPDATA_DIR, log_line)

LAN_STATE_FILE = os.path.join(APPDATA_DIR, "lan_eszkozok.json")
LAN_CFG_FILE = os.path.join(APPDATA_DIR, "lan.txt")
LAN_PASSIVE = 30.0
LAN_ACTIVE = 600.0
_KIHAGY_ADAPTER = ("tailscale", "vethernet", "virtualbox", "vmware", "loopback", "wsl", "hyper-v",
                   "zerotier", "wireguard", "openvpn", "tap-", "npcap", "bluetooth")
_MAC_RX = re.compile(r"((?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2})", re.I)
_IP_RX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


def lan_cfg():
    cfg = {"FIGYELES": "BE", "AKTIV": "BE"}
    try:
        if not os.path.exists(LAN_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(LAN_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - LAN-eszkoz figyeles\n"
                        "# FIGYELES BE / KI\n"
                        "FIGYELES BE\n"
                        "# AKTIV BE = 10 percenkent a teljes halozat vegigkerdezese (minden eszkozt megtalal)\n"
                        "# AKTIV KI = csak az ARP-tabla (amivel a gep amugy is beszelt)\n"
                        "AKTIV BE\n")
        with open(LAN_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                r = ln.strip().upper().split()
                if len(r) >= 2 and r[0] in cfg:
                    cfg[r[0]] = "KI" if r[1] in ("KI", "OFF", "0") else "BE"
    except Exception:
        pass
    return cfg


def norm_mac(m):
    return (m or "").lower().replace(":", "-")


def mac_ervenyes(m):
    m = norm_mac(m)
    if len(m) != 17 or m in ("ff-ff-ff-ff-ff-ff", "00-00-00-00-00-00"):
        return False
    return not (int(m[:2], 16) & 1)        # multicast bit (01-00-5e..., 33-33...)


def mac_veletlen(m):
    """Helyileg kiosztott (veletlenszeru / privat) MAC: telefonok, tabletek."""
    try:
        return bool(int(norm_mac(m)[:2], 16) & 2)
    except ValueError:
        return False


def helyi_halozatok():
    """[(halozat, sajat_ip, adapter)] - csak valodi LAN-adapterek, IPv4."""
    out = []
    try:
        import psutil
        stats = psutil.net_if_stats()
        for nev, cimek in psutil.net_if_addrs().items():
            if any(k in nev.lower() for k in _KIHAGY_ADAPTER):
                continue
            if nev in stats and not stats[nev].isup:
                continue
            for c in cimek:
                if c.family != socket.AF_INET or not c.netmask:
                    continue
                try:
                    net = ipaddress.ip_network("%s/%s" % (c.address, c.netmask), strict=False)
                except ValueError:
                    continue
                if not net.is_private or net.prefixlen < 22 or c.address.startswith(("127.", "169.254.")):
                    continue
                if net.subnet_of(ipaddress.ip_network("100.64.0.0/10")):
                    continue   # Tailscale / CGNAT
                out.append((net, c.address, nev))
    except Exception as e:
        log_line("[LAN] adapter-lekerdezesi hiba: %s" % e)
    return out


def sajat_macok():
    out = set()
    try:
        import psutil
        for cimek in psutil.net_if_addrs().values():
            for c in cimek:
                if c.family == getattr(psutil, "AF_LINK", -1):
                    out.add(norm_mac(c.address))
    except Exception:
        pass
    return out


def arp_tabla():
    """{ip: mac} az ARP-tablabol (arp -a; a magyar es angol kimenet is)."""
    out = {}
    try:
        r = subprocess.run(["arp", "-a"], capture_output=True, timeout=15)
        for ln in (r.stdout or b"").decode("cp852", errors="ignore").splitlines():
            ip, mac = _IP_RX.search(ln), _MAC_RX.search(ln)
            if ip and mac and mac_ervenyes(mac.group(1)):
                out[ip.group(1)] = norm_mac(mac.group(1))
    except Exception as e:
        log_line("[LAN] arp hiba: %s" % e)
    return out


def send_arp(ip):
    """MAC-cim egy IP-hez (iphlpapi.SendARP). None, ha nem valaszol."""
    try:
        cel = int.from_bytes(socket.inet_aton(ip), "little")
        buf = (ctypes.c_ulong * 2)()
        hossz = ctypes.c_ulong(6)
        if ctypes.windll.iphlpapi.SendARP(cel, 0, ctypes.byref(buf), ctypes.byref(hossz)) != 0:
            return None
        b = bytes(buf)[:hossz.value]
        mac = "-".join("%02x" % x for x in b)
        return mac if mac_ervenyes(mac) else None
    except Exception:
        return None


def aktiv_kereses(halozatok):
    """{ip: mac} a teljes helyi alhalozat(ok)ra."""
    from concurrent.futures import ThreadPoolExecutor
    cimek = []
    for net, sajat, _a in halozatok:
        cimek += [str(h) for h in net.hosts() if str(h) != sajat]
    out = {}
    if not cimek:
        return out
    with ThreadPoolExecutor(max_workers=64) as ex:
        for ip, mac in zip(cimek, ex.map(send_arp, cimek)):
            if mac:
                out[ip] = mac
    return out


def atjarok():
    """Alapertelmezett atjaro(k) IPv4-cime."""
    try:
        r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction SilentlyContinue | "
                            "Sort-Object RouteMetric | Select-Object -ExpandProperty NextHop"],
                           capture_output=True, timeout=20)
        return [x.strip() for x in (r.stdout or b"").decode("utf-8", errors="ignore").splitlines()
                if _IP_RX.fullmatch(x.strip() or "-") and x.strip() != "0.0.0.0"]
    except Exception:
        return []


def eszkoz_nev(ip):
    """Forditott DNS (a router altalaban tudja a DHCP-nevet). Idokorlattal."""
    eredm = [""]

    def _f():
        try:
            eredm[0] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
    t = threading.Thread(target=_f, daemon=True)
    t.start()
    t.join(3.0)
    n = eredm[0]
    return "" if (not n or n == ip) else n.split(".")[0] if not n.endswith(".arpa") else ""


class LanMixin(object):
    """LAN-eszkoz figyeles. A GuardCore resze (mixin)."""

    def _lan_load(self):
        try:
            with open(LAN_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) and "devices" in d else None
        except (OSError, ValueError):
            return None

    def _lan_save(self):
        try:
            tmp = LAN_STATE_FILE + ".tmp"
            with self._lan_lock:
                adat = _json.dumps(self._lan_state, ensure_ascii=False, indent=1)
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(adat)
            os.replace(tmp, LAN_STATE_FILE)
        except OSError as e:
            log_line("[LAN] mentesi hiba: %s" % e)

    def _lan_scan(self, aktiv):
        halozatok = helyi_halozatok()
        if not halozatok:
            self.lan_status = "nincs helyi hálózat"
            return None
        talalt = {}
        if aktiv:
            talalt.update(aktiv_kereses(halozatok))
        for ip, mac in arp_tabla().items():
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                continue
            if any(a in net for net, _s, _n in halozatok) and not ip.endswith(".255"):
                talalt.setdefault(ip, mac)
        sajat = sajat_macok()
        return {ip: mac for ip, mac in talalt.items() if mac not in sajat}

    def _lan_check(self, aktiv=False):
        talalt = self._lan_scan(aktiv)
        if talalt is None:
            return
        most = time.time()
        st = self._lan_state
        elso = st is None
        if elso:
            st = self._lan_state = {"devices": {}, "gateways": {}}
        devs = st["devices"]
        self._lan_online = {}
        uj = []
        with self._lan_lock:
            for ip, mac in talalt.items():
                self._lan_online[mac] = ip
                d = devs.get(mac)
                if d is None:
                    d = devs[mac] = {"first": most, "name": "", "label": "", "ips": []}
                    if not elso:
                        uj.append((ip, mac))
                d["last"] = most
                if ip not in d["ips"]:
                    d["ips"] = ([ip] + d["ips"])[:5]
                else:
                    d["ips"] = [ip] + [x for x in d["ips"] if x != ip]
        # nevek (forditott DNS) az uj / meg nev nelkuli eszkozokre - legfeljebb 10 / kor
        nevtelen = [(ip, mac) for ip, mac in talalt.items() if not devs[mac].get("name")][:10]
        for ip, mac in nevtelen:
            n = eszkoz_nev(ip)
            if n:
                devs[mac]["name"] = n
        # --- ARP-mergezes / router-csere ---
        self._lan_gateway_check(talalt)
        if elso:
            log_line("[LAN] alapallapot: %d eszkoz ismertnek jelolve (%s)" % (
                len(devs), ", ".join(str(n) for n, _s, _a in helyi_halozatok())))
        for ip, mac in uj:
            self._lan_alert_new(ip, mac)
        self._lan_save()
        self.lan_status = "aktív"

    def _lan_gateway_check(self, talalt):
        gws = getattr(self, "_lan_gw_cache", None)
        if gws is None or time.time() - getattr(self, "_lan_gw_ts", 0) > 600:
            gws = self._lan_gw_cache = atjarok()
            self._lan_gw_ts = time.time()
        st = self._lan_state
        mentett = st.setdefault("gateways", {})
        for gw in gws:
            mac = talalt.get(gw) or send_arp(gw)
            if not mac:
                continue
            regi = mentett.get(gw)
            if regi and regi != mac:
                self.alert("127.0.0.1", "[LAN] ARP-MERGEZES GYANU (MITM)! A router (%s) MAC-cime megvaltozott: "
                           "%s -> %s. Ha nem cserelted a routert, valaki a halozaton a forgalmad koze "
                           "allhat! Javasolt: router ujrainditasa, ismeretlen eszkozok kitiltasa." % (gw, regi, mac),
                           always=True)
            mentett[gw] = mac
            # egy MASIK IP is a router MAC-jet hasznalja?
            masik = [ip for ip, m in talalt.items() if m == mac and ip != gw]
            jelzett = st.setdefault("dup_jelzett", [])
            for ip in masik:
                k = "%s|%s|%s" % (gw, ip, mac)
                if k not in jelzett:
                    jelzett.append(k)
                    self.alert("127.0.0.1", "[LAN] FIGYELEM: a(z) %s IP-cim a router (%s) MAC-cimet hasznalja (%s). "
                               "Ez lehet a router masik cime (pl. mesh/AP mod), de ARP-mergezes is!" % (ip, gw, mac),
                               always=True)

    def _lan_alert_new(self, ip, mac):
        d = self._lan_state["devices"][mac]
        self.lan_new = getattr(self, "lan_new", 0) + 1
        megj = []
        if mac_veletlen(mac):
            megj.append("veletlenszeru (privat) MAC - valoszinuleg telefon / tablet / laptop")
        msg = "[LAN] UJ ESZKOZ A HALOZATON: %s (MAC %s)%s%s | Ha nem ismered: router admin feluleten tiltsd ki, " \
              "es csereld a Wi-Fi jelszot. Elnevezes: /lannev" % (
                  ip, mac, (" nev: %s" % d["name"]) if d.get("name") else "",
                  (" | " + "; ".join(megj)) if megj else "")
        self._lan_recent = ([{"ts": time.time(), "ip": ip, "mac": mac, "name": d.get("name", "")}]
                            + list(getattr(self, "_lan_recent", [])))[:20]
        self.alert("127.0.0.1", msg, always=True)

    def _lan_loop(self):
        utolso_aktiv = 0.0
        while not self._lan_stop_ev.is_set():
            try:
                cfg = lan_cfg()
                if cfg["FIGYELES"] == "BE" and self.is_on() and not self.is_paused():
                    aktiv = cfg["AKTIV"] == "BE" and (time.time() - utolso_aktiv >= LAN_ACTIVE)
                    if aktiv and hasattr(self, "game_active") and self.game_active():
                        aktiv = False   # [v2.9.0] jatek kozben nincs teljes halozat-kereses
                    if aktiv:
                        utolso_aktiv = time.time()
                    self._lan_check(aktiv=aktiv)
                elif cfg["FIGYELES"] != "BE":
                    self.lan_status = "kikapcsolva"
            except Exception as e:
                log_line("[LAN] figyelo hiba: %s" % e)
            self._lan_stop_ev.wait(LAN_PASSIVE)

    def _lan_start(self):
        if getattr(self, "_lan_thread", None) and self._lan_thread.is_alive():
            return
        self._lan_lock = threading.RLock()
        self._lan_state = self._lan_load()
        self._lan_online = {}
        self.lan_new = getattr(self, "lan_new", 0)
        self.lan_status = "indulás…"
        self._lan_recent = getattr(self, "_lan_recent", [])
        self._lan_started = time.time()
        lan_cfg()
        self._lan_stop_ev = threading.Event()
        self._lan_thread = threading.Thread(target=self._lan_loop, name="lan", daemon=True)
        self._lan_thread.start()
        log_line("[LAN] eszkoz-figyeles aktiv (ARP 30 mp, teljes kereses 10 perc)")

    def _lan_stop(self):
        ev = getattr(self, "_lan_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ lista / elnevezes
    def lan_devices(self):
        """[(sorszam, mac, eszkoz, online_ip)] - online elol, aztan utoljara latott szerint."""
        st = getattr(self, "_lan_state", None) or {"devices": {}}
        on = getattr(self, "_lan_online", {}) or {}
        with self._lan_lock:
            devs = dict(st["devices"])
        sor = sorted(devs, key=lambda m: (m not in on, -devs[m].get("last", 0)))
        return [(i, m, devs[m], on.get(m)) for i, m in enumerate(sor, 1)]

    def lan_rename(self, mi, nev):
        lst = self.lan_devices()
        mi = (mi or "").strip().lower()
        cel = None
        for i, m, _d, _ip in lst:
            if mi == str(i) or norm_mac(mi) == m:
                cel = m
        if not cel:
            return False, "Nincs ilyen eszkoz: %s (lista: /lan)" % mi
        with self._lan_lock:
            self._lan_state["devices"][cel]["label"] = (nev or "").strip()[:40]
        self._lan_save()
        return True, "%s elnevezve: %s" % (cel, nev.strip()[:40])

    def lan_summary(self):
        if getattr(self, "lan_status", "") == "kikapcsolva":
            return "Kikapcsolva (lan.txt)"
        st = getattr(self, "_lan_state", None) or {"devices": {}}
        reszek = ["Ismert: %d" % len(st["devices"]), "Most elérhető: %d" % len(getattr(self, "_lan_online", {}) or {}),
                  "Új (futam): %d" % getattr(self, "lan_new", 0)]
        rec = getattr(self, "_lan_recent", [])
        if rec:
            reszek.append("Utolsó: %s %s" % (rec[0]["ip"], time.strftime("%m-%d %H:%M", time.localtime(rec[0]["ts"]))))
        return " | ".join(reszek)

    def lan_text(self):
        sorok = ["LAN-eszkozok (elnevezes: /lannev <szam> <nev>):"]
        for i, m, d, ip in self.lan_devices()[:40]:
            nev = d.get("label") or d.get("name") or "?"
            sorok.append("%d. %s %s %s%s%s" % (
                i, "●" if ip else "○", (ip or (d.get("ips") or ["-"])[0]), nev[:28],
                " [veletlen MAC]" if mac_veletlen(m) else "",
                "" if ip else "  (utoljara: %s)" % time.strftime("%m-%d %H:%M", time.localtime(d.get("last", 0)))))
        gws = (getattr(self, "_lan_state", None) or {}).get("gateways") or {}
        if gws:
            sorok.append("Router: " + ", ".join("%s = %s" % (g, m) for g, m in gws.items()))
        return "\n".join(sorok)
