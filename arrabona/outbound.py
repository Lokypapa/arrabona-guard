# -*- coding: utf-8 -*-
"""Arrabona Guard - Kimeno kapcsolatok figyelese (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import subprocess
import time
from .common import (_IpRangeIndex, is_private_ip)

class OutboundMixin(object):
    """Kimeno kapcsolatok figyelese.
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""

    # ================= [v1.9.4] KIMENO KAPCSOLATOK FIGYELESE =================
    def _feed_index(self):
        """A FEED tartomanyok keresoindexe; csak akkor epul ujra, ha a FEED valtozott."""
        nets = getattr(self, "_feed_loaded", None) or set()
        if getattr(self, "_feed_idx_src", None) is not nets:
            self._feed_idx = _IpRangeIndex(nets)
            self._feed_idx_src = nets
        return self._feed_idx

    def _proc_info(self, pid):
        """(nev, utvonal) a PID-hez, 60 mp-es gyorsitotarral."""
        if pid is None:
            return ("ismeretlen program", "")
        if pid == 4:
            return ("System (Windows kernel)", "")
        cache = getattr(self, "_proc_cache", None)
        if cache is None:
            cache = self._proc_cache = {}
        now = time.time()
        hit = cache.get(pid)
        if hit and now - hit[2] < 60:
            return hit[0], hit[1]
        nev, ut = "PID %s" % pid, ""
        try:
            import psutil
            pr = psutil.Process(pid)
            nev = pr.name() or nev
            try:
                ut = pr.exe() or ""
            except Exception:
                ut = ""
        except Exception:
            pass
        if len(cache) > 2000:
            cache.clear()
        cache[pid] = (nev, ut, now)
        return nev, ut

    def _rossz_ip(self, ip, blacklist):
        """Miert rossz az IP? 'FEED' / 'feketelista' / None."""
        if not ip or is_private_ip(ip):
            return None
        if ip in blacklist:
            return "feketelista"
        if ip in self._feed_index():
            return "FEED (ismert rossz halozat)"
        return None

    def _out_alert(self, ip, port, pid, allapot, forras):
        nev, ut = self._proc_info(pid)
        kulcs = "%s|%s|%s" % (nev.lower(), ip, allapot)
        last = getattr(self, "_out_last", None)
        if last is None:
            last = self._out_last = {}
        now = time.time()
        if now - last.get(kulcs, 0) < 3600:
            return False   # ugyanaz a program + IP orankent egyszer
        last[kulcs] = now
        if allapot == "blokkolva":
            self.out_blocked = getattr(self, "out_blocked", 0) + 1
            fej = "KIMENO KAPCSOLAT BLOKKOLVA"
            veg = "A tuzfal megfogta - de a program gyanus, erdemes megnezni!"
        elif allapot == "bejovo":
            self.out_open = getattr(self, "out_open", 0) + 1
            fej = "ROSSZ IP KAPCSOLODOTT BE (nyitott kapcsolat)"
            veg = "Egy szolgaltatasod elfogadta a kapcsolatat!"
        else:
            self.out_open = getattr(self, "out_open", 0) + 1
            fej = "KIMENO KAPCSOLAT ROSSZ IP FELE (NYITOTT!)"
            veg = "Kartevo 'hazatelefonalas' gyanu - ellenorizd a programot!"
        msg = "[KIMENO] %s: %s%s -> %s:%s | %s. %s" % (
            fej, nev, (" (%s)" % ut) if ut else "", ip, port, forras, veg)
        if pid is not None:
            msg += " (PID %s)" % pid
        # [v2.4.0] a program digitalis alairasa
        if ut:
            try:
                from .alairas import sig_one, sig_szoveg, sig_veszely
                sig = sig_one(ut)
                if hasattr(self, "vt_kerd"):
                    self.vt_kerd(ut, "Rossz IP-re kapcsolódó program: %s" % nev[:40])   # [v2.11.0]
                if sig:
                    msg += " | Alairas: %s" % sig_szoveg(sig, ekezet=False)
                    if sig_veszely(sig) == 2:
                        msg = msg.replace("[KIMENO] ", "[KIMENO] NAGYON GYANUS (modositott program)! ", 1)
                    elif sig_veszely(sig) == 1:
                        msg = msg.replace("[KIMENO] ", "[KIMENO] ALAIRATLAN PROGRAM! ", 1)
            except Exception:
                pass
        self.alert(ip, msg, always=True)
        return True

    def _out_drops_process(self, blacklist, whitelist):
        """A tuzfalnaplo kimeno DROP-jai: csak a rossz IP-k fele riasztunk."""
        q = getattr(self, "_out_drop_q", None)
        if not q:
            return 0
        self._out_drop_q = []
        db = 0
        for dst, port, pid, proto in q:
            if dst in whitelist:
                continue
            forras = self._rossz_ip(dst, blacklist)
            if not forras:
                continue   # egyeb (pl. sajat) kimeno tiltas: nem a mi dolgunk
            if self._out_alert(dst, port, pid, "blokkolva", forras):
                db += 1
        return db

    def _out_conn_scan(self, blacklist, whitelist):
        """Nyitott kapcsolatok atnezese: ESTABLISHED / SYN_SENT rossz IP fele.
        True, ha a psutil elerheto volt (kulonben a regi netstat-ut fut)."""
        try:
            import psutil
            rows = psutil.net_connections(kind="inet")
        except Exception:
            return False
        figyelt = {"ESTABLISHED", "SYN_SENT", "SYN_RECV"}
        listen = set()
        for c in rows:
            try:
                if c.status == "LISTEN" and c.laddr:
                    listen.add(c.laddr[1])
            except Exception:
                pass
        for c in rows:
            try:
                ra = c.raddr
                if not ra or c.status not in figyelt:
                    continue
                ip, port = ra[0], ra[1]
                if ip.startswith("::ffff:"):
                    ip = ip[7:]
                if ip in whitelist:
                    continue
                forras = self._rossz_ip(ip, blacklist)
                if not forras:
                    continue
                bejovo = bool(c.laddr) and c.laddr[1] in listen
                self._out_alert(ip, port, c.pid, "bejovo" if bejovo else "nyitott", forras)
            except Exception:
                continue
        return True

    def check_blacklist_connections(self, blacklist, whitelist):
        # [v1.9.4] Elsodlegesen az uj, programnevet is mutato kapcsolat-atnezes
        # (FEED + feketelista); a regi netstat-ut csak psutil nelkul fut.
        if self._out_conn_scan(blacklist, whitelist):
            return
        if not blacklist:
            return
        try:
            import psutil
        except ImportError:
            psutil = None
        rows = []
        if psutil is not None:
            try:
                rows = psutil.net_connections(kind="tcp")
            except Exception:
                rows = []
        if rows:
            for c in rows:
                ra = c[4] if len(c) > 4 else None
                if not ra:
                    continue
                foreign = "%s:%s" % (ra[0], ra[1])
                if ra[0] in whitelist:
                    continue
                if ra[0] in blacklist:
                    _nowc = time.time()
                    _lastc = getattr(self, "_blconn_last", {})
                    if _nowc - _lastc.get(foreign, 0.0) >= 600.0:
                        _lastc[foreign] = _nowc
                        self._blconn_last = _lastc
                        self.alert(ra[0],
                                   "FEKETELIST\u00c1S IP csatlakozott: %s (%s)" %
                                   (ra[0], foreign), always=True)
            return
        # psutil nem elerheto: regi netstat ut
        try:
            out = subprocess.run(["netstat", "-n"],
                                 capture_output=True, timeout=10)
            text = out.stdout.decode("utf-8", errors="replace")
        except Exception:
            return
        for line in text.splitlines():
            m = line.split()
            if len(m) >= 4 and m[0] == "TCP":
                foreign = m[2]
                if ":" in foreign:
                    ip = foreign.rsplit(":", 1)[0]
                    if ip in whitelist:
                        continue
                    if ip in blacklist:
                        self.alert(ip,
                                    "FEKETELIST\u00c1S IP csatlakozott: %s (%s)" %
                                    (ip, foreign), always=True)
