# -*- coding: utf-8 -*-
"""Arrabona Guard - FEED modul (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import os
from .common import (
    FEED_HOURS_DEFAULT,
    FEED_MAX_PER_RULE,
    FEED_RULE_PREFIX,
    FEED_TIMEOUT,
    FEED_URLS,
    LOG_FILE,
    _uniq_stamp,
    is_bogon_net,
    kimeno_blokk_on,
)

class FeedMixin(object):
    """FEED: ismert rossz IP-tartomanyok (Spamhaus, FireHOL) letoltese es tiltasa.
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""


    # ============ KOZOSSEGI BLOCKLIST FEED (Spamhaus DROP + FireHOL Level-1) ============
    def _feed_log(self, msg):
        """Feed-esemenyek naplozasa a sajat formatumban."""
        try:
            import datetime
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] FEED: %s%s" % (stamp, msg, chr(10)))
        except Exception:
            pass

    def _feed_dir(self):
        import os
        base = os.path.join(os.environ.get("APPDATA", ""), "ArrabonaGuard")
        os.makedirs(base, exist_ok=True)
        return base

    def _feed_path(self, fname):
        import os
        return os.path.join(self._feed_dir(), fname)

    def _feed_parse_cidr(self, token):
        import ipaddress
        try:
            return ipaddress.ip_network(token, strict=False)
        except ValueError:
            return None

    def _feed_download_source(self, name, url, fmt):
        """Egy forras letoltese es CIDR-k kiszedese. Hiba eseten a regi lista marad."""
        import json
        import urllib.request
        nets = []
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ArrabonaGuard/2.0"})
            with urllib.request.urlopen(req, timeout=FEED_TIMEOUT) as r:
                data = r.read().decode("utf-8", errors="ignore")
        except Exception as e:
            self._feed_log("letoltes HIBA: %s (%s) - az elozo lista marad ervenyben" % (name, e))
            return []
        if fmt == "json":
            # Spamhaus JSON -> "cidr" mezok; az ASN-bejegyzesek "type" mezovel
            # rendelkeznek (elo fordul: select(.type == null)), azokat kihagyjuk.
            items = []
            try:
                items = json.loads(data)
            except ValueError:
                for line in data.splitlines():
                    line = line.strip().rstrip(",")
                    if not line or line in ("[", "]"):
                        continue
                    try:
                        items.append(json.loads(line))
                    except ValueError:
                        pass
            for obj in items:
                if isinstance(obj, dict) and "cidr" in obj and "type" not in obj:
                    net = self._feed_parse_cidr(str(obj["cidr"]))
                    if net is not None:
                        nets.append(net)
        else:
            # Egyszeru szoveges lista (FireHOL netset):
            # komment: # vagy ; - az elso token a CIDR vagy IP.
            for line in data.splitlines():
                line = line.strip()
                if not line or line[0] in "#;":
                    continue
                token = line.split()[0].split(";")[0].strip()
                net = self._feed_parse_cidr(token)
                if net is not None:
                    nets.append(net)

        import time as _tm
        self._feed_last_dl = _tm.time()
        self._feed_log("letoltes OK: %s (%d tartomany)" % (name, len(nets)))
        return nets

    def _feed_own_public_ips(self):
        """A sajat publikus IP-cimek (IPv4 + IPv6), hogy sose blokkoljuk magunkat."""
        import urllib.request
        ips = set()
        for url in ("https://api.ipify.org", "https://api6.ipify.org", "https://api64.ipify.org"):
            try:
                with urllib.request.urlopen(url, timeout=10) as r:
                    ip = r.read().decode("utf-8").strip()
                    if ip:
                        ips.add(ip)
            except Exception:
                pass
        return ips

    def _feed_filter(self, nets):
        """Kiszedi a sajat publikus IP-ket fedo es a feed_ignore.txt-s tartomanyokat."""
        import ipaddress
        own = []
        for o in self._feed_own_public_ips():
            try:
                own.append(ipaddress.ip_address(o))
            except ValueError:
                pass
        ignore = []
        try:
            with open(self._feed_path("feed_ignore.txt"), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line[0] in "#;":
                        continue
                    net = self._feed_parse_cidr(line)
                    if net is not None:
                        ignore.append(net)
        except Exception:
            pass
        eredmeny = []
        kihagy_own = 0
        kihagy_ign = 0
        kihagy_bogon = 0
        for n in nets:
            # [v1.9.1] A FireHOL Level-1 "bogon" tartomanyokat is tartalmaz
            # (10/8, 192.168/16, 172.16/12, 100.64/10 ...). Ezek blokkolasa
            # a sajat LAN-t es a Tailscale-t is kizarna -> SOHA nem blokkoljuk.
            if is_bogon_net(n):
                kihagy_bogon += 1
                continue
            if own and any(o.version == n.version and o in n for o in own):
                kihagy_own += 1
                continue
            if ignore and any(g.version == n.version and n.overlaps(g) for g in ignore):
                kihagy_ign += 1
                continue
            eredmeny.append(n)
        if kihagy_bogon:
            self._feed_log("LAN/bogon vedelem: %d privat/fenntartott tartomany kihagyva" % kihagy_bogon)
        if kihagy_own:
            self._feed_log("sajat publikus IP vedelme: %d tartomany kihagyva" % kihagy_own)
        if kihagy_ign:
            self._feed_log("feed_ignore.txt: %d tartomany kihagyva" % kihagy_ign)
        return eredmeny

    def _feed_old_rule_names(self):
        import json
        try:
            with open(self._feed_path("feed_state.json"), "r", encoding="utf-8") as f:
                return json.load(f).get("rules", [])
        except Exception:
            return []

    def _feed_delete_rule(self, nev):
        import subprocess
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            "name=%s" % nev], capture_output=True, timeout=30)
        except Exception:
            pass

    def _feed_create_rules(self, nets):
        """Mester-szabalyok letrehozasa: 100 CIDR darabonkent, IPv4 es IPv6 kulon."""
        import json
        import subprocess
        import time as _time
        v4 = sorted({str(n) for n in nets if n.version == 4})
        v6 = sorted({str(n) for n in nets if n.version == 6})
        pecsat = _uniq_stamp(_time.strftime("%Y%m%d_%H%M%S"), self._feed_old_rule_names())
        nevek = []
        sorszam = 0
        # [v1.9.4] Kimeno tiltas is: a FEED-listas halozatok (Spamhaus DROP,
        # FireHOL L1 - a bogonok MAR kiszurve!) fele a gep sem kapcsolodhat.
        # Igy egy kartevo nem tud "hazatelefonalni" ismert rossz szerverre.
        iranyok = [("in", "")]
        self._feed_out_on = kimeno_blokk_on()
        if self._feed_out_on:
            iranyok.append(("out", "OUT_"))
        for tartomanyok in (v4, v6):
            for i in range(0, len(tartomanyok), FEED_MAX_PER_RULE):
                darab = tartomanyok[i:i + FEED_MAX_PER_RULE]
                sorszam += 1
                for irany, jel in iranyok:
                    nev = "%s%s%s_%d" % (FEED_RULE_PREFIX, jel, pecsat, sorszam)
                    try:
                        r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                            "name=%s" % nev, "dir=%s" % irany, "action=block",
                                            "remoteip=%s" % ",".join(darab)],
                                           capture_output=True, text=True, timeout=120)
                        if r.returncode == 0:
                            nevek.append(nev)
                        else:
                            self._feed_log("tuzfal szabaly HIBA (%s)" % nev)
                    except Exception as e:
                        self._feed_log("tuzfal szabaly HIBA (%s): %s" % (nev, e))
        try:
            with open(self._feed_path("feed_state.json"), "w", encoding="utf-8") as f:
                json.dump({"rules": nevek,
                           "updated": _time.strftime("%Y-%m-%d %H:%M:%S"),
                           "networks": len(nets)}, f, indent=2)
        except Exception:
            pass
        return nevek

    def _feed_load_cached(self, name):
        """Egy forras cache-elt tartomanynak betoltese (offline indulashoz)."""
        nets = []
        try:
            with open(self._feed_path("feed_cache_%s.txt" % name), "r", encoding="utf-8") as f:
                for line in f:
                    net = self._feed_parse_cidr(line.strip())
                    if net is not None:
                        nets.append(net)
        except Exception:
            pass
        return nets

    def _feed_apply(self, nets):
        """Szures + tuzfal-szabalyok csereje (regi torlese csak utoljara)."""
        nets = self._feed_filter(nets)
        if not nets:
            self._feed_log("szures utan 0 tartomany - NEM torlom a regit, nem irok ujat")
            return False
        # ElOSZOR az uj szabalyok, UTANA a regiek torlese (sose legyen vedelem-nelkuli allapot)
        regi_nevek = self._feed_old_rule_names()
        uj_nevek = self._feed_create_rules(nets)
        for nev in regi_nevek:
            if nev not in uj_nevek:
                self._feed_delete_rule(nev)
        self._feed_loaded = set(nets)
        self._feed_log("FRISSITVE: %d rosszindulatu tartomany blokkolva (%s), %d tuzfal-szabaly (%s*)" % (
            len(nets), "bejovo + kimeno" if getattr(self, "_feed_out_on", False) else "csak bejovo",
            len(uj_nevek), FEED_RULE_PREFIX))
        return True

    def _feed_refresh(self):
        """Az osszes forras kiertekelese a sajat ciklusa szerint."""
        import time as _time
        most = _time.time()
        osszes = []
        valtozott = False
        if not hasattr(self, "_feed_last_ok"):
            self._feed_last_ok = {}
            # Restart-allasztozo: az utolso sikeres letoltes idejet a
            # cache-fajl korabol szurjuk le - a Spamhaus igy naponta csak
            # egyszer toltodik le akkor is, ha kozben ujrainditjuk (pl. tema).
            for _fn, _fu, _fmt, _fh in FEED_URLS:
                try:
                    self._feed_last_ok[_fn] = os.path.getmtime(
                        self._feed_path("feed_cache_%s.txt" % _fn))
                except OSError:
                    pass
        for name, url, fmt, hours in FEED_URLS:
            hours = hours or FEED_HOURS_DEFAULT
            utolso = self._feed_last_ok.get(name, 0)
            if most - utolso < hours * 3600:
                # Meg nem jar a frissites: a cache-elt tartomanyt hasznaljuk.
                cached = self._feed_load_cached(name)
                if not cached:
                    self._feed_log("%s: meg nincs cache, kotelezo frissites elindul" % name)
                else:
                    osszes.extend(cached)
                    continue
            nets = self._feed_download_source(name, url, fmt)
            if nets:
                try:
                    with open(self._feed_path("feed_cache_%s.txt" % name), "w", encoding="utf-8") as f:
                        for n in sorted(nets, key=str):
                            f.write(str(n) + chr(10))
                except Exception:
                    pass
                self._feed_last_ok[name] = most
                osszes.extend(nets)
                valtozott = True
            else:
                # Hibas letoltes: a regi cache marad az adott forrasnal.
                osszes.extend(self._feed_load_cached(name))
        if not osszes:
            self._feed_log("URES/HIBAS minden forras - nem valtoztatok semmin")
            return
        if not valtozott and getattr(self, "_feed_loaded", None):
            return  # semmi uj, a tuzfal-szabalyok mar kesz
        self._feed_last_dl = most
        self._feed_apply(list(set(osszes)))

    def _feed_loop(self):
        try:
            while not self._feed_stop_ev.is_set():
                self._feed_busy = True
                try:
                    self._feed_refresh()
                    self._feed_ok = True
                except Exception as e:
                    self._feed_log("hiba a frissitesben: %s" % e)
                    self._feed_ok = False
                finally:
                    self._feed_busy = False
                    import time as _tft
                    self._feed_done_at = _tft.strftime('%H:%M:%S')
                # A legrovidebb forras-ciklusig varunk (FireHOL: 4 ora),
                # de minden ciklusban a Spamhaus mar csak napi 1x toltodik le.
                self._feed_stop_ev.wait(FEED_HOURS_DEFAULT * 3600)
        except Exception as e:
            self._feed_log("feed szal problema: %s" % e)

    def _feed_start(self):
        import os
        import threading
        if getattr(self, "_feed_thread", None) and self._feed_thread.is_alive():
            return
        # feed_ignore.txt letrehozasa elso alkalommal magyar segitssel
        try:
            p = self._feed_path("feed_ignore.txt")
            if not os.path.exists(p):
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# Egy sor egy IP vagy CIDR, amit a FEED sosem blokkolhat." + chr(10))
                    f.write("# Pelda: 37.76.18.86 vagy 8.8.8.0/24" + chr(10))
        except Exception:
            pass
        # Cache-ek betoltese AZONNAL (offline/gepi indulaskor is vedekezik)
        try:
            osszes = []
            for name, url, fmt, hours in FEED_URLS:
                osszes.extend(self._feed_load_cached(name))
            if osszes:
                self._feed_apply(list(set(osszes)))
        except Exception:
            pass
        # Frissito hatter-szal: azonnal egyszer, utana ciklusosan,
        # de forrasonkenti idozitessel (Spamhaus: napi 1x, FireHOL: 4 orankent)
        self._feed_stop_ev = threading.Event()
        self._feed_thread = threading.Thread(target=self._feed_loop, name="feed", daemon=True)
        self._feed_thread.start()

        import time as _tm
        self._feed_started = _tm.time()
        self._feed_last_dl = _tm.time()
        self._feed_log("feed modul aktivalva: %d forras (Spamhaus napi 1x, FireHOL 4 orankent)" % len(FEED_URLS))

    def _feed_stop(self):
        ev = getattr(self, "_feed_stop_ev", None)
        if ev is not None:
            ev.set()

    def feed_refresh_now(self):
        # Kezi (gombbol inditott) FEED-frissites: minden forras ujratoltese
        if getattr(self, "_feed_busy", False):
            self._feed_log("mar fut a frissites, gomb kihagyva")
            return False
        def _manual_feed():
            self._feed_busy = True
            try:
                self._feed_last_ok = {}
                self._feed_refresh()
                self._feed_ok = True
            except Exception as e:
                self._feed_log("hiba a kezi frissitesben: %s" % e)
                self._feed_ok = False
            finally:
                self._feed_busy = False
        import threading
        threading.Thread(target=_manual_feed, name="feed-manual", daemon=True).start()
        self._feed_log("kezi frissites indult (gomb)")
        return True
