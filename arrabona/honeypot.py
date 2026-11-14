# -*- coding: utf-8 -*-
"""Arrabona Guard - Honeypot modul (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import socket
import subprocess
import threading
import time
from .common import (
    BLACKLIST_FILE,
    HONEYPOT_FILE,
    is_private_ip,
    load_whitelist,
    log_line,
)

class HoneypotMixin(object):
    """Honeypot: csaliportok.
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""

    # --- [CSALI]/[ÉLES] jelzés a célport alapján (honeypot dekor portjai) ---
    CSALI_PORTOK = (23, 3389, 1433, 5900, 445)

    def _csali_tag(self, port):
        # [v1.9.2] Csak az a port "csali", amin a honeypot TENYLEG figyel.
        # Korabban fix lista volt (23, 3389, 1433, 5900, 445), igy pl. a 445-os
        # port [CSALI]-nak latszott, holott ott a valodi Windows SMB fut.
        try:
            nyitott = getattr(self, "_honey_ports_open", None)
            if nyitott is None:
                nyitott = set()
            return "[CSALI]" if int(port) in nyitott else "[ÉLES]"
        except (TypeError, ValueError):
            return "[ÉLES]"

    # ---------------------- HONEYPOT ----------------------
    def _load_honey_ports(self):
        ports = []
        try:
            with open(HONEYPOT_FILE, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if ln.upper() in ("KI", "OFF"):
                        return []
                    try:
                        p = int(ln)
                        if 1 <= p <= 65535 and p not in ports:
                            ports.append(p)
                    except ValueError:
                        pass
        except OSError:
            ports = [23, 445, 3389, 1433, 5900]
        return ports

    _HONEY_BANNERS = {
        23:   b"\r\nUbuntu 20.04.3 LTS\r\n\r\nlogin: ",
        5900: b"RFB 003.008\n",
    }

    def _honeypot_worker(self, srv, port):
        while not self._honey_stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            ip = ""
            try:
                ip = addr[0]
            except Exception:
                pass
            deep = False
            if ip:
                deep = self._honeypot_talk(conn, port)
            try:
                conn.close()
            except OSError:
                pass
            if ip:
                self.honeypot_event(ip, port, deep)

    def _honeypot_talk(self, conn, port):
        # 5. feladat: fake banner kuldes (ahol a protokoll a szerverrel kezd),
        # majd varakozas. Ha a szkennelo ezutan ADATOT is kuld, az mely-erintes
        # -> magasabb pontszam, gyorsabb eszkalacio (24h -> vegleges).
        try:
            conn.settimeout(3)
        except OSError:
            return False
        banner = self._HONEY_BANNERS.get(port)
        if banner:
            try:
                conn.sendall(banner)
            except OSError:
                return False
        try:
            data = conn.recv(256)
            return len(data) > 0
        except Exception:
            return False

    def honeypot_event(self, ip, port, deep=False):
        try:
            if is_private_ip(ip):
                return
            if ip in load_whitelist():
                return
            if ip in self.own_ips() or self.is_own_prefix(ip):
                return
            now_t = time.time()
            last = getattr(self, "_honey_last", {})
            if now_t - last.get(ip, 0) < 60:
                return
            last[ip] = now_t
            self._honey_last = last
            bl = self._load_blocks()
            old_cat = None
            if bl.get(ip) and not bl[ip].get("gone", 0):
                old_cat = self._cat_of(bl[ip])
            prev = bl.get(ip, {}) if not bl.get(ip, {}).get("gone", 0) else {}
            bo = 4 if deep else 2
            cnt = prev.get("count", 0) + bo
            if cnt >= 3:
                try:
                    with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
                        f.write(ip + "\n")
                except OSError:
                    pass
                bl[ip] = {"count": cnt, "perm": True, "cat": "perm", "deep": bool(deep)}
                dur_txt = "V\u00c9GLEGES"
            else:
                bl[ip] = {"count": cnt, "until": now_t + 24 * 3600, "cat": "24h", "deep": bool(deep)}
                dur_txt = "24 \u00f3r\u00e1s"
            self._save_blocks(bl)
            cat = bl[ip].get("cat")
            if old_cat and old_cat != cat:
                self.apply_master_rule(old_cat)
            self.apply_master_rule(cat)
            self.alert(ip, self._csali_tag(port) + " HONEYPOT BLOKK (%s%s): " % (dur_txt, ", M\u00c9LY \u00c9RINT\u00c9S" if deep else "") + ip + " [%d. port]" % port, always=True)
        except Exception:
            pass

    def start_honeypot(self):
        if getattr(self, "_honey_on", False):
            return
        ports = self._load_honey_ports()
        if not ports:
            log_line("Honeypot: kikapcsolva (honeypot.txt).")
            return

        self._honey_on = True
        import time as _tm
        self._honey_started = _tm.time()
        self._honey_stop = threading.Event()
        self._honey_srvs = []
        nyitva = []
        for port in ports:
            opened = False
            for fam in (socket.AF_INET, socket.AF_INET6):
                s = None
                try:
                    s = socket.socket(fam, socket.SOCK_STREAM)
                    if fam == socket.AF_INET6:
                        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                    s.bind(("", port))
                    s.listen(8)
                    s.settimeout(1.0)
                    self._honey_srvs.append(s)
                    opened = True
                    threading.Thread(target=self._honeypot_worker, args=(s, port), daemon=True).start()
                except OSError:
                    if s:
                        try:
                            s.close()
                        except OSError:
                            pass
            if opened:
                try:
                    # [v1.9.2] elobb a regi azonos nevu szabaly torlese: korabban
                    # minden inditas egy ujabb ArrabonaHoney_<port> szabalyt adott
                    # hozza (kemeny leallitasnal a stop_honeypot nem takarit).
                    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                    "name=ArrabonaHoney_%d" % port],
                                   capture_output=True, timeout=15)
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    "name=ArrabonaHoney_%d" % port, "dir=in", "action=allow",
                                    "protocol=TCP", "localport=%d" % port],
                                   capture_output=True, timeout=15)
                except Exception:
                    pass
                nyitva.append(port)
            else:
                log_line("Honeypot: %d. port foglalt, kihagyva." % port)
        # [v1.9.2] a [CSALI] cimke CSAK a tenylegesen megnyitott csaliportokra jar
        self._honey_ports_open = set(nyitva)
        if nyitva:
            log_line("Honeypot akt\u00edv: " + ", ".join(str(p) for p in nyitva))
            self.out.put(("status", "Honeypot akt\u00edv: " + ", ".join(str(p) for p in nyitva)))

    def stop_honeypot(self):
        self._honey_on = False
        ev = getattr(self, "_honey_stop", None)
        if ev is not None:
            ev.set()
        for s in getattr(self, "_honey_srvs", []):
            try:
                s.close()
            except OSError:
                pass
        self._honey_srvs = []
        self._honey_ports_open = set()
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-NetFirewallRule -DisplayName 'ArrabonaHoney_*' | Remove-NetFirewallRule"],
                           capture_output=True, timeout=60)
        except Exception:
            pass
