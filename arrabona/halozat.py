# -*- coding: utf-8 -*-
"""Arrabona Guard - DNS- es PROXY-figyeles (GuardCore mixin). [v2.8.0]

Forgalom-eltereles ellen. 30 mp-enkent osszeveti a mentett allapottal:
  - DNS-szerverek adapterenkent: kezi (NameServer) es a routertol kapott
    (DhcpNameServer) - ha a ROUTER kezd idegen DNS-t osztani: router-feltores gyanu,
  - NRPT (Name Resolution Policy Table): egyes domainek titkos atiranyitasa,
  - Proxy: WinINet (ProxyEnable/ProxyServer), AUTOMATIKUS KONFIGURACIOS SZKRIPT (PAC:
    AutoConfigURL - klasszikus banki trojai modszer), WinHTTP proxy, HTTP(S)_PROXY
    kornyezeti valtozok, Firefox sajat proxy-beallitasa.
A DNS-szerverek besorolasa: ismert szolgaltato / helyi (router) / ISMERETLEN nyilvanos /
a FEED-ben vagy a feketelistan szereplo.
Javitas: dns_auto() - az adapter vissza automatikus (DHCP) DNS-re; proxy_off() - proxy ki.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import glob
import ipaddress
import json as _json
import os
import re
import subprocess
import threading
import time
import winreg
from .common import (APPDATA_DIR, is_private_ip, load_blacklist, log_line)

NET_STATE_FILE = os.path.join(APPDATA_DIR, "dns_proxy_alap.json")
NET_BACKUP_FILE = os.path.join(APPDATA_DIR, "proxy_mentes.json")
NET_TRUST_FILE = os.path.join(APPDATA_DIR, "dns_elfogadott.json")   # mar latott (elfogadott) DNS-cimek
NET_POLL = 30.0
_W64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
_HKLM, _HKCU = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
_TCPIP4 = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
_TCPIP6 = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces"
_NETCLASS = r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
_NRPT = (r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig",
         r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig")
_INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_WINHTTP = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
_ENV_HKLM = r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
_KIHAGY_ADAPTER = ("tailscale", "vethernet", "virtualbox", "vmware", "loopback", "wsl", "hyper-v",
                   "zerotier", "wireguard", "openvpn", "nordlynx", "proton")

_ISMERT_DNS = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare (kartevoszuro)",
    "1.0.0.2": "Cloudflare (kartevoszuro)", "1.1.1.3": "Cloudflare (csaladi)", "1.0.0.3": "Cloudflare (csaladi)",
    "8.8.8.8": "Google", "8.8.4.4": "Google", "9.9.9.9": "Quad9", "149.112.112.112": "Quad9",
    "9.9.9.11": "Quad9", "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
    "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard", "76.76.2.0": "Control D", "76.76.10.0": "Control D",
    "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing", "100.100.100.100": "Tailscale",
    "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare", "2001:4860:4860::8888": "Google",
    "2001:4860:4860::8844": "Google", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
}


# ---------------------------------------------------------------- registry segedek
def _ertekek(gy, ut):
    try:
        k = winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | _W64)
    except OSError:
        return None
    out = {}
    try:
        i = 0
        while True:
            try:
                n, v, _t = winreg.EnumValue(k, i)
            except OSError:
                break
            i += 1
            out[n] = v
    finally:
        winreg.CloseKey(k)
    return out


def _alkulcsok(gy, ut):
    try:
        k = winreg.OpenKey(gy, ut, 0, winreg.KEY_READ | _W64)
    except OSError:
        return []
    out = []
    try:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(k, i))
            except OSError:
                break
            i += 1
    finally:
        winreg.CloseKey(k)
    return out


def _dns_lista(v):
    if isinstance(v, (list, tuple)):
        v = " ".join(str(x) for x in v)
    return [x for x in re.split(r"[,\s]+", str(v or "").strip()) if x]


def adapter_nev(guid):
    v = _ertekek(_HKLM, "%s\\%s\\Connection" % (_NETCLASS, guid)) or {}
    return str(v.get("Name") or guid)


def winhttp_proxy():
    """A WinHttpSettings binaris ertekbol a proxy (ures = kozvetlen)."""
    v = (_ertekek(_HKLM, _WINHTTP) or {}).get("WinHttpSettings")
    if not isinstance(v, (bytes, bytearray)) or len(v) < 16:
        return ""
    try:
        flags = int.from_bytes(v[8:12], "little")
        if not flags & 2:
            return ""
        n = int.from_bytes(v[12:16], "little")
        return v[16:16 + n].decode("ascii", errors="ignore")
    except Exception:
        return ""


def firefox_proxy():
    out = {}
    for prof in glob.glob(os.path.join(os.environ.get("APPDATA", ""), r"Mozilla\Firefox\Profiles", "*")):
        try:
            with open(os.path.join(prof, "prefs.js"), "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    m = re.match(r'user_pref\("(network\.proxy\.(type|http|ssl|socks|autoconfig_url))",\s*(.+?)\);', ln)
                    if m:
                        out["%s|%s" % (os.path.basename(prof).split(".", 1)[-1], m.group(1))] = m.group(3).strip('"')
        except OSError:
            continue
    return out


def netcfg_snapshot():
    """{kulcs: ertek-szoveg}"""
    s = {}
    # --- DNS adapterenkent ---
    for tcpip, verz in ((_TCPIP4, "IPv4"), (_TCPIP6, "IPv6")):
        for guid in _alkulcsok(_HKLM, tcpip):
            nev = adapter_nev(guid)
            if any(k in nev.lower() for k in _KIHAGY_ADAPTER):
                continue
            v = _ertekek(_HKLM, "%s\\%s" % (tcpip, guid)) or {}
            kezi = _dns_lista(v.get("NameServer"))
            dhcp = _dns_lista(v.get("DhcpNameServer"))
            if kezi:
                s["DNS|%s|%s|kezi" % (nev, verz)] = ",".join(kezi)
            if dhcp:
                s["DNS|%s|%s|router" % (nev, verz)] = ",".join(dhcp)
    glob_dns = _dns_lista((_ertekek(_HKLM, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters") or {}).get("NameServer"))
    if glob_dns:
        s["DNS|(globalis)|IPv4|kezi"] = ",".join(glob_dns)
    # --- NRPT ---
    for ut in _NRPT:
        for sz in _alkulcsok(_HKLM, ut):
            v = _ertekek(_HKLM, "%s\\%s" % (ut, sz)) or {}
            s["NRPT|%s" % sz] = "%s -> %s" % (" ".join(_dns_lista(v.get("Name"))),
                                               " ".join(_dns_lista(v.get("GenericDNSServers"))) or "egyeb beallitas")
    # --- WinINet proxy (felhasznalo) ---
    ie = _ertekek(_HKCU, _INET) or {}
    if ie.get("ProxyEnable"):
        s["PROXY|Windows proxy"] = str(ie.get("ProxyServer") or "?")
    if ie.get("AutoConfigURL"):
        s["PROXY|Automatikus konfiguracios szkript (PAC)"] = str(ie["AutoConfigURL"])
    hp = _ertekek(_HKLM, r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings") or {}
    if hp.get("AutoConfigURL") or hp.get("ProxyServer"):
        s["PROXY|Hazirend proxy"] = str(hp.get("AutoConfigURL") or hp.get("ProxyServer"))
    wh = winhttp_proxy()
    if wh:
        s["PROXY|WinHTTP (rendszer)"] = wh
    for gy, gn, ut in ((_HKCU, "felhasznalo", "Environment"), (_HKLM, "rendszer", _ENV_HKLM)):
        env = _ertekek(gy, ut) or {}
        for n, v in env.items():
            if n.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
                s["PROXY|Kornyezeti valtozo %s (%s)" % (n.upper(), gn)] = str(v)
    for k, v in firefox_proxy().items():
        s["PROXY|Firefox %s" % k] = v
    return s


# ---------------------------------------------------------------- besorolas
def dns_besorol(ip, rossz=None, elfogadott=()):
    """(szint, szoveg): 0 ismert/helyi/elfogadott, 1 ismeretlen nyilvanos, 2 rossz (FEED/feketelista)."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return 1, "%s (ervenytelen cim!)" % ip
    if rossz:
        return 2, "%s - %s!" % (ip, rossz)
    if ip in _ISMERT_DNS:
        return 0, "%s (%s)" % (ip, _ISMERT_DNS[ip])
    if is_private_ip(ip) or ip.lower().startswith(("fe80", "fd", "fc")):
        return 0, "%s (helyi / router)" % ip
    if ip in elfogadott:
        return 0, "%s (korabban mar latott vagy jelzett - elfogadva)" % ip
    return 1, "%s (ISMERETLEN nyilvanos DNS)" % ip


def proxy_helyi(ertek):
    """Helyi proxy (127.0.0.1 / localhost) - jellemzoen szuro / VPN / fejlesztoi eszkoz."""
    e = (ertek or "").lower()
    return bool(re.search(r"(^|[=/;\s])(127\.0\.0\.1|localhost|\[::1\])(:|\b)", e))


class NetCfgMixin(object):
    """DNS- es proxy-figyeles. A GuardCore resze (mixin)."""

    def _net_load(self):
        try:
            with open(NET_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                return d if isinstance(d, dict) else None
        except (OSError, ValueError):
            return None

    def _net_save(self):
        try:
            tmp = NET_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._net_known, f, ensure_ascii=False, indent=1)
            os.replace(tmp, NET_STATE_FILE)
        except OSError as e:
            log_line("[DNS/PROXY] mentesi hiba: %s" % e)

    def _net_rossz(self, ip):
        try:
            if ip in load_blacklist():
                return "FEKETELISTAS"
            if hasattr(self, "_feed_index") and ip in self._feed_index():
                return "ISMERT ROSSZ HALOZAT (FEED)"
        except Exception:
            pass
        return None

    def _net_ertekel(self, kulcs, ertek):
        """(szint 0-2, magyar leiras) egy beallitashoz."""
        if kulcs.startswith("DNS|"):
            elf = getattr(self, "_net_trusted", set())
            darabok = [dns_besorol(ip, self._net_rossz(ip), elf) for ip in ertek.split(",") if ip]
            szint = max([d[0] for d in darabok] or [0])
            return szint, ", ".join(d[1] for d in darabok)
        if kulcs.startswith("NRPT|"):
            return 2, "domain-atiranyitas: %s" % ertek
        if kulcs.startswith("PROXY|"):
            if "network.proxy.type" in kulcs:
                return (0 if ertek in ("0", "5") else 1), "Firefox proxy-mod: %s (%s)" % (
                    ertek, {"0": "nincs", "1": "KEZI", "2": "PAC-SZKRIPT", "4": "automatikus keresés",
                            "5": "rendszer"}.get(ertek, "?"))
            if "Firefox" in kulcs:
                return 1, "%s (csak akkor ervenyes, ha a Firefox proxy-modja 1 vagy 2)" % ertek
            if proxy_helyi(ertek):
                return 1, "helyi proxy: %s (szuro / VPN / fejlesztoi eszkoz lehet)" % ertek
            return 2, "%s" % ertek
        return 1, ertek

    def _net_check(self, indulas=False):
        most = netcfg_snapshot()
        regi = self._net_known
        if regi is None:
            self._net_known = most
            self._net_save()
            # a mar hasznalt (nem feketelistas) DNS-cimek elfogadottak - pl. a szolgaltato DNS-e
            for k, v in most.items():
                if k.startswith("DNS|"):
                    for ip in v.split(","):
                        if ip and not self._net_rossz(ip):
                            self._net_trusted.add(ip)
            self._net_trust_save()
            log_line("[DNS/PROXY] alapallapot: %d beallitas, elfogadott DNS: %s" % (
                len(most), ", ".join(sorted(self._net_trusted)) or "-"))
            for k, v in most.items():
                szint, leiras = self._net_ertekel(k, v)
                if szint >= 1 and not (k.startswith("PROXY|Firefox") and szint < 2):
                    self.alert("127.0.0.1", "[DNS/PROXY] Mar most is %s beallitas: %s = %s" % (
                        "GYANUS" if szint >= 2 else "figyelemre melto", self._net_cim(k), leiras), always=True)
            self.net_status = "aktív"
            return
        if most == regi:
            self.net_status = "aktív"
            return
        for k, v in most.items():
            if regi.get(k) != v:
                self._net_alert(k, regi.get(k), v, indulas)
        for k in regi:
            if k not in most:
                if k.startswith("PROXY|") or k.startswith("NRPT|"):
                    log_line("[DNS/PROXY] megszunt: %s (%s)" % (self._net_cim(k), regi[k]))
                else:
                    log_line("[DNS/PROXY] DNS-beallitas megszunt: %s (%s)" % (self._net_cim(k), regi[k]))
        self._net_known = most
        self._net_save()
        self.net_status = "aktív"

    @staticmethod
    def _net_cim(k):
        r = k.split("|")
        if r[0] == "DNS":
            return "DNS (%s, %s, %s)" % (r[1], r[2], "routertol kapott" if r[3] == "router" else "kezi beallitas")
        if r[0] == "NRPT":
            return "NRPT-szabaly %s" % r[1]
        return r[1] if len(r) > 1 else k

    def _net_alert(self, k, regi, uj, indulas):
        szint, leiras = self._net_ertekel(k, uj)
        mi = "UJ" if regi is None else "MEGVALTOZOTT"
        router = k.endswith("|router")
        if szint >= 2:
            fej = "NAGYON GYANUS"
        elif szint == 1:
            fej = "GYANUS"
        else:
            fej = "Info"
        if k.startswith("DNS|"):
            if router and szint >= 1:
                targy = "A ROUTER IDEGEN DNS-T OSZT (router-feltores / DNS-elterites gyanu)"
            else:
                targy = "DNS-szerver %s" % ("beallitva" if regi is None else "megvaltozott")
        elif k.startswith("NRPT|"):
            targy = "UJ NRPT-SZABALY (domainek titkos atiranyitasa)"
        else:
            targy = "PROXY %s" % ("BEKAPCSOLVA" if regi is None else "MEGVALTOZOTT")
        self.net_changes = getattr(self, "net_changes", 0) + 1
        self._net_recent = ([{"ts": time.time(), "k": self._net_cim(k), "uj": uj, "szint": szint}]
                            + list(getattr(self, "_net_recent", [])))[:20]
        msg = "[DNS/PROXY] %s: %s%s - %s: %s%s" % (
            fej, targy, " (a Guard leallasa alatt)" if indulas else "", self._net_cim(k), leiras,
            (" (elotte: %s)" % regi) if regi else "")
        if szint >= 1:
            if k.startswith("DNS|") and not router:
                msg += " | Javitas: Javitas ablak > Halozat, vagy Telegram /dnsauto"
            elif k.startswith("PROXY|") and "Firefox" not in k:
                msg += " | Javitas: Javitas ablak > Halozat, vagy Telegram /proxyki"
            elif router:
                msg += " | Lepj be a router admin feluletere: DNS-beallitas + admin jelszo csere!"
        if szint == 0 and k.startswith("DNS|"):
            log_line(msg)    # ismert szolgaltato / router: csak naplo, nem riasztas
            return
        self.alert("127.0.0.1", msg, always=True)
        if k.startswith("DNS|") and szint == 1:
            # egyszer szoltunk rola: ha marad / visszajon, ne riasszon ujra
            for ip in uj.split(","):
                if ip:
                    self._net_trusted.add(ip)
            self._net_trust_save()

    def _net_trust_save(self):
        try:
            with open(NET_TRUST_FILE, "w", encoding="utf-8") as f:
                _json.dump(sorted(self._net_trusted), f)
        except OSError:
            pass

    # ------------------------------------------------------------ javitas
    def dns_auto(self, ki="felulet"):
        """Minden KEZI DNS-beallitasu (nem VPN) adapter vissza automatikus (DHCP) DNS-re."""
        adapterek = sorted({k.split("|")[1] for k in (self._net_known or {}) if k.startswith("DNS|")
                            and k.endswith("|kezi") and k.split("|")[1] != "(globalis)"})
        if not adapterek:
            return False, "Nincs kezi DNS-beallitas - minden adapter mar automatikus."
        kesz, hiba = [], []
        for a in adapterek:
            ok = True
            for verz in ("ipv4", "ipv6"):
                try:
                    r = subprocess.run(["netsh", "interface", verz, "set", "dnsservers", "name=%s" % a,
                                        "source=dhcp"], capture_output=True, timeout=30)
                    if r.returncode != 0 and verz == "ipv4":
                        ok = False
                except Exception:
                    ok = ok and verz != "ipv4"
            (kesz if ok else hiba).append(a)
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=20)
        except Exception:
            pass
        self._net_known = netcfg_snapshot()
        self._net_save()
        szoveg = "Automatikus DNS visszaallitva: %s%s" % (", ".join(kesz) or "-",
                                                          ("; NEM sikerult: %s (rendszergazda kell)" % ", ".join(hiba))
                                                          if hiba else "")
        log_line("[JAVITAS] %s (%s)" % (szoveg, ki))
        return bool(kesz), szoveg

    def proxy_off(self, ki="felulet"):
        """Windows proxy + PAC ki, WinHTTP proxy reset. Az elozo ertekek mentve (proxy_mentes.json)."""
        mentes = {"ts": time.time(), "ie": {}, "winhttp": winhttp_proxy()}
        reszek = []
        try:
            with winreg.OpenKey(_HKCU, _INET, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as k:
                for n in ("ProxyEnable", "ProxyServer", "AutoConfigURL", "ProxyOverride"):
                    try:
                        mentes["ie"][n] = winreg.QueryValueEx(k, n)[0]
                    except OSError:
                        pass
                winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                try:
                    winreg.DeleteValue(k, "AutoConfigURL")
                    reszek.append("PAC-szkript torolve")
                except OSError:
                    pass
                reszek.append("Windows proxy kikapcsolva")
        except OSError as e:
            reszek.append("Windows proxy: hiba (%s)" % e)
        if mentes["winhttp"]:
            try:
                r = subprocess.run(["netsh", "winhttp", "reset", "proxy"], capture_output=True, timeout=30)
                reszek.append("WinHTTP proxy %s" % ("visszaallitva" if r.returncode == 0 else
                                                     "NEM allithato (rendszergazda kell)"))
            except Exception:
                pass
        try:
            with open(NET_BACKUP_FILE, "w", encoding="utf-8") as f:
                _json.dump(mentes, f, ensure_ascii=False, indent=1, default=str)
        except OSError:
            pass
        self._net_known = netcfg_snapshot()
        self._net_save()
        maradt = [self._net_cim(k) for k in self._net_known if k.startswith("PROXY|")]
        if maradt:
            reszek.append("megmaradt (kezzel kell): %s" % ", ".join(maradt))
        szoveg = "Proxy: " + "; ".join(reszek) + ". Elozo ertekek: proxy_mentes.json"
        log_line("[JAVITAS] %s (%s)" % (szoveg, ki))
        return True, szoveg

    # ------------------------------------------------------------ ciklus / kijelzes
    def _net_loop(self):
        elso = True
        while not self._net_stop_ev.is_set():
            try:
                if self.is_on() and not self.is_paused():
                    self._net_check(indulas=elso)
                    elso = False
            except Exception as e:
                log_line("[DNS/PROXY] figyelo hiba: %s" % e)
            self._net_stop_ev.wait(NET_POLL)

    def _net_start(self):
        if getattr(self, "_net_thread", None) and self._net_thread.is_alive():
            return
        self._net_known = self._net_load()
        try:
            with open(NET_TRUST_FILE, "r", encoding="utf-8") as f:
                self._net_trusted = set(_json.load(f))
        except (OSError, ValueError, TypeError):
            self._net_trusted = set()
        self.net_changes = getattr(self, "net_changes", 0)
        self.net_status = "indulás…"
        self._net_recent = getattr(self, "_net_recent", [])
        self._net_started = time.time()
        self._net_stop_ev = threading.Event()
        self._net_thread = threading.Thread(target=self._net_loop, name="dnsproxy", daemon=True)
        self._net_thread.start()
        log_line("[DNS/PROXY] figyeles aktiv: DNS (kezi + router), NRPT, proxy, PAC, WinHTTP, Firefox")

    def _net_stop(self):
        ev = getattr(self, "_net_stop_ev", None)
        if ev is not None:
            ev.set()

    def net_rows(self):
        """[(cim, ertek-leiras, szint)] a feluletnek / Telegramnak."""
        out = []
        for k in sorted(self._net_known or {}):
            szint, leiras = self._net_ertekel(k, self._net_known[k])
            out.append((self._net_cim(k), leiras, szint))
        return out

    def net_summary(self):
        known = getattr(self, "_net_known", None) or {}
        dns = sorted({ip for k, v in known.items() if k.startswith("DNS|") for ip in v.split(",") if ":" not in ip})
        proxy = [k for k in known if k.startswith("PROXY|") and "network.proxy.type" not in k]
        gy = sum(1 for _c, _l, sz in self.net_rows() if sz >= 1) if known else 0
        reszek = ["DNS: %s" % (", ".join(dns[:3]) or "-"), "Proxy: %s" % ("NINCS" if not proxy else "%d db" % len(proxy)),
                  "Változás: %d" % getattr(self, "net_changes", 0)]
        if gy:
            reszek.append("⚠ figyelendő: %d" % gy)
        return " | ".join(reszek)

    def net_text(self):
        sorok = ["DNS es proxy (javitas: /dnsauto, /proxyki):"]
        for cim, leiras, szint in self.net_rows():
            sorok.append("%s %s: %s" % ("!!" if szint >= 2 else ("! " if szint == 1 else "  "), cim, leiras))
        if not any(k.startswith("PROXY|") for k in (self._net_known or {})):
            sorok.append("  Proxy: nincs beallitva (rendben)")
        return "\n".join(sorok)
