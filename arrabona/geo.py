# -*- coding: utf-8 -*-
"""Arrabona Guard - GEO-blokk modul (GuardCore mixin)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import subprocess
from .common import (
    FEED_TIMEOUT,
    GEO_CACHE,
    GEO_CFG,
    GEO_HOURS,
    GEO_MAX_PER_RULE,
    GEO_POLL,
    GEO_RULE_PREFIX,
    GEO_STATE,
    GEO_URLS,
    LOG_FILE,
    _uniq_stamp,
)

class GeoMixin(object):
    """GEO: orszagblokk (geoblock.txt).
    A GuardCore resze (mixin): a metodusok a self-en keresztul
    egymast es a GuardCore tobbi reszet is elerik."""


    # ================ GEO-BLOKK (feketelista: geoblock.txt orszagkodok) ================
    def _geo_log(self, msg):
        try:
            import datetime
            stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] GEO: %s%s" % (stamp, msg, chr(10)))
        except Exception:
            pass

    def _geo_load_countries(self):
        """geoblock.txt beolvasasa; elso alkalommal letrejon alaplistaval."""
        import os
        p = self._feed_path(GEO_CFG)
        if not os.path.exists(p):
            try:
                with open(p, "w", encoding="utf-8") as f:
                    f.write("# Geo-blokk feketelista: soronkent egy ISO orszagkod (pl. CN)." + chr(10))
                    f.write("# Ures lista (csak komment) = nincs orszag-blokkolas." + chr(10))
                    f.write("# Modositas utan 5 percen belul automatikusan ervenybe lep." + chr(10))
                    f.write("# Kezdo javaslat — barmikor atirhato:" + chr(10))
                    f.write("CN" + chr(10))
                    f.write("RU" + chr(10))
                    f.write("KP" + chr(10))
                    f.write("VN" + chr(10))
                    f.write("IR" + chr(10))
                self._geo_log("konfig letrejott: %s (CN, RU, KP, VN, IR)" % GEO_CFG)
            except Exception as e:
                self._geo_log("konfg iras hiba: %s" % e)
        kodok = set()
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    t = line.strip().upper()
                    if not t or t[0] in "#;" or "," in t:
                        continue
                    if len(t) == 2 and t.isalpha():
                        kodok.add(t)
        except Exception as e:
            self._geo_log("konfig olvasas hiba: %s" % e)
        return kodok

    def _geo_fetch(self, url):
        """Egy adatbazis-fajl letoltese sha256-checksum ellenorzessel."""
        import hashlib
        import urllib.request
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "ArrabonaGuard/2.0"})
            with urllib.request.urlopen(req, timeout=FEED_TIMEOUT) as r:
                data = r.read()
        except Exception as e:
            self._geo_log("letoltes HIBA: %s (%s)" % (url.rsplit("/", 1)[-1], e))
            return None
        c_url = url.replace("/download/latest/", "/download/checksum/") + ".sha256"
        try:
            req2 = urllib.request.Request(c_url, headers={"User-Agent": "ArrabonaGuard/2.0"})
            with urllib.request.urlopen(req2, timeout=15) as r2:
                elvart = r2.read().decode("utf-8").strip().lower().split()[0]
            if elvart and hashlib.sha256(data).hexdigest() != elvart:
                self._geo_log("sha256 ELUTASITVA: %s" % url.rsplit("/", 1)[-1])
                return None
        except Exception:
            pass  # checksum nem elerheto - a HTTPS-marvedelemre tamaszkodunk
        return data

    def _geo_parse(self, data, kodok):
        """CSV szetbonasas: CIDR es start-end formatum egyarant; csak a
        tiltott orszagok tartomanyait tartjuk meg."""
        import ipaddress
        orszag_nets = {}
        for line in data.decode("utf-8", errors="ignore").splitlines():
            t = line.strip()
            if not t or t[0] in "#;":
                continue
            mezek = [x.strip().strip(chr(34)) for x in t.split(",")]
            kod = mezek[-1].upper()
            if kod not in kodok:
                continue
            nets = []
            if "/" in t:
                for mez in mezek[:-1]:
                    if "/" in mez:
                        try:
                            nets.append(ipaddress.ip_network(mez, strict=False))
                        except ValueError:
                            pass
            elif len(mezek) >= 3:
                try:
                    nets = list(ipaddress.summarize_address_range(
                        ipaddress.ip_address(mezek[0]), ipaddress.ip_address(mezek[1])))
                except ValueError:
                    nets = []
            if nets:
                orszag_nets.setdefault(kod, []).extend(nets)
        return orszag_nets

    def _geo_download(self, kodok):
        """Minden verziora (v4, v6) probalja a forrasokat egyenkent."""
        ered = {}
        nevek = {4: "ipv4", 6: "ipv6"}
        for ver, urls in GEO_URLS.items():
            talalt = None
            for url in urls:
                data = self._geo_fetch(url)
                if not data:
                    continue
                parsed = self._geo_parse(data, kodok)
                darab = sum(len(v) for v in parsed.values())
                if not darab:
                    self._geo_log("%s lista: 0 illo tartomany, kovetkezo forras" % nevek[ver])
                    continue
                self._geo_log("letoltes OK: %s (%d tartomany a tiltott orszagokhoz)" % (nevek[ver], darab))
                talalt = parsed
                break
            if talalt:
                for k, v in talalt.items():
                    ered.setdefault(k, []).extend(v)
            else:
                self._geo_log("%s lista hianyzik - a cache marad ervenyben" % nevek[ver])
        return ered

    def _geo_write_cache(self, orszag_nets):
        try:
            with open(self._feed_path(GEO_CACHE), "w", encoding="utf-8") as f:
                for kod, nets in sorted(orszag_nets.items()):
                    for n in sorted(nets, key=str):
                        f.write("%s,%s%s" % (kod, n, chr(10)))
        except Exception:
            pass

    def _geo_load_cache(self, kodok):
        import ipaddress
        ered = {}
        try:
            with open(self._feed_path(GEO_CACHE), "r", encoding="utf-8") as f:
                for line in f:
                    darab = line.strip().split(",", 1)
                    if len(darab) != 2:
                        continue
                    kod, cidr = darab[0].upper(), darab[1].strip()
                    if kod not in kodok:
                        continue
                    try:
                        ered.setdefault(kod, []).append(ipaddress.ip_network(cidr, strict=False))
                    except ValueError:
                        pass
        except Exception:
            pass
        return ered

    def _geo_old_rule_names(self):
        import json
        try:
            with open(self._feed_path(GEO_STATE), "r", encoding="utf-8") as f:
                return json.load(f).get("rules", [])
        except Exception:
            return []

    def _geo_delete_rule(self, nev):
        import subprocess
        try:
            subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                            "name=%s" % nev], capture_output=True, timeout=30)
        except Exception:
            pass

    def _geo_create_rules(self, kod, nets, pecsat):
        """Egy orszag tuzfal-szabalyai: ArrabonaGeo_<KOD>_<idobelyeg>_<n>, 100 CIDR/rule.
        [v1.9.1] Az idobelyeg miatt az uj nevek SOSEM egyeznek a regiekkel,
        igy a regi szabalyok biztosan torlodnek (korabban duplikalodtak)."""
        import subprocess
        nevek = []
        sorszam = 0
        for i in range(0, len(nets), GEO_MAX_PER_RULE):
            sorszam += 1
            nev = "%s%s_%s_%d" % (GEO_RULE_PREFIX, kod, pecsat, sorszam)
            darab = [str(n) for n in nets[i:i + GEO_MAX_PER_RULE]]
            try:
                r = subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    "name=%s" % nev, "dir=in", "action=block",
                                    "remoteip=%s" % ",".join(darab)],
                                   capture_output=True, text=True, timeout=120)
                if r.returncode == 0:
                    nevek.append(nev)
                else:
                    self._geo_log("tuzfal szabaly HIBA (%s)" % nev)
            except Exception as e:
                self._geo_log("tuzfal szabaly HIBA (%s): %s" % (nev, e))
        return nevek

    def _geo_remove_all(self):
        for nev in self._geo_old_rule_names():
            self._geo_delete_rule(nev)
        try:
            import json
            with open(self._feed_path(GEO_STATE), "w", encoding="utf-8") as f:
                json.dump({"rules": []}, f)
        except Exception:
            pass

    def _geo_apply(self, orszag_nets):
        """Tuzfal-szabalyok csereje: elobb ujak, utolso lepeskent regik torlese.
        A sajat publikus IP-k es a feed_ignore.txt itt is vedve vannak."""
        import ipaddress
        import json
        import time as _time
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
                    try:
                        ignore.append(ipaddress.ip_network(line, strict=False))
                    except ValueError:
                        pass
        except Exception:
            pass
        regi_nevek = self._geo_old_rule_names()
        uj_nevek = []
        osszes_tartomany = 0
        pecsat = _uniq_stamp(_time.strftime("%Y%m%d_%H%M%S"), regi_nevek)
        for kod, nets in sorted(orszag_nets.items()):
            tiszta = []
            for n in nets:
                if own and any(o in n for o in own):
                    self._geo_log("SAJAT IP VILLAMA: %s kihagyva (%s)" % (n, kod))
                    continue
                if ignore and any(n.overlaps(g) for g in ignore):
                    continue
                tiszta.append(n)
            tiszta = list(set(tiszta))
            osszes_tartomany += len(tiszta)
            uj_nevek.extend(self._geo_create_rules(kod, tiszta, pecsat))
        # Regi szabalyok torlese. A netsh "delete rule name=X" az OSSZES azonos
        # nevu szabalyt torli, igy a korabbi verzio felhalmozott duplikatumai is
        # egy lepesben eltunnek.
        for nev in set(regi_nevek):
            if nev not in uj_nevek:
                self._geo_delete_rule(nev)
        # [v1.9.1] Egyszeri takaritas: a regi (idobelyeg nelkuli) nevu szabalyok,
        # amik esetleg mar nincsenek a geo_state.json-ban sem.
        if not getattr(self, "_geo_legacy_cleaned", False):
            self._geo_legacy_cleaned = True
            try:
                ps = ("Get-NetFirewallRule -DisplayName '%s*' -ErrorAction SilentlyContinue | "
                      "Where-Object { $_.DisplayName -match '^%s[A-Z]{2}_[0-9]+$' } | "
                      "Remove-NetFirewallRule") % (GEO_RULE_PREFIX, GEO_RULE_PREFIX)
                subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, timeout=300)
            except Exception as e:
                self._geo_log("regi szabaly-takaritas hiba: %s" % e)
        try:
            with open(self._feed_path(GEO_STATE), "w", encoding="utf-8") as f:
                json.dump({"rules": uj_nevek,
                           "updated": _time.strftime("%Y-%m-%d %H:%M:%S"),
                           "networks": osszes_tartomany}, f, indent=2)
        except Exception:
            pass
        self._geo_loaded = True
        self._geo_log("FRISSITVE: %d orszag, osszesen %d tartomany, %d tuzfal-szabaly (%s*)" % (
            len(orszag_nets), osszes_tartomany, len(uj_nevek), GEO_RULE_PREFIX))
        for kod in sorted(orszag_nets.keys()):
            self._geo_log("  - %s: %d tartomany" % (kod, len(orszag_nets[kod])))

    def geo_refresh_now(self):
        # Kezi (gombbol inditott) GEO-frissites
        if getattr(self, "_geo_busy", False):
            self._geo_log("mar fut a frissites, gomb kihagyva")
            return False
        def _manual_geo():
            self._geo_busy = True
            try:
                self._geo_refresh()
            except Exception as e:
                self._geo_log("hiba a kezi frissitesben: %s" % e)
            finally:
                self._geo_busy = False
        import threading
        threading.Thread(target=_manual_geo, name="geo-manual", daemon=True).start()
        self._geo_log("kezi frissites indult (gomb)")
        return True

    def _geo_refresh(self):
        kodok = self._geo_load_countries()
        if not kodok:
            self._geo_remove_all()
            self._geo_log("ures orszaglista - geo-blokk kikapcsolva, szabalyok torolve")
            return
        orszag_nets = self._geo_download(kodok)
        if orszag_nets:
            self._geo_ok = True
            self._geo_write_cache(orszag_nets)
        else:
            self._geo_ok = False
            orszag_nets = self._geo_load_cache(kodok)
            if not orszag_nets:
                self._geo_log("sem friss adat, sem cache - nincs geo-blokk most")
                return
        import time as _gnt
        self._geo_next_at = _gnt.time() + GEO_HOURS * 3600
        self._geo_apply(orszag_nets)

    def _geo_loop(self):
        import os
        import time as _time
        # GEO-persist: a geo_state.json korabol visszaolvassuk az utolso
        # sikeres frissites idejet, a geoblock.txt aktualis mtime-javal
        # inditunk. A restart ilyenkor NEM tolt le ujra (temavaltaskor sem).
        utolso_friss = 0.0
        utolso_mtime = -1.0
        try:
            utolso_friss = os.path.getmtime(self._feed_path(GEO_STATE))
        except Exception:
            utolso_friss = 0.0
        try:
            utolso_mtime = os.path.getmtime(self._feed_path(GEO_CFG))
        except Exception:
            utolso_mtime = -1.0
        if utolso_friss > 0.0:
            self._geo_next_at = utolso_friss + GEO_HOURS * 3600
        if utolso_mtime > 0.0 and utolso_friss > 0.0:
            self._geo_log("geo-persist: utolso frissites %.1f ora ezelott, "
                          "config valtozatlan - letoltes atugorva" %
                          ((_time.time() - utolso_friss) / 3600.0))
        try:
            while not self._geo_stop_ev.is_set():
                try:
                    mtime = os.path.getmtime(self._feed_path(GEO_CFG))
                except Exception:
                    mtime = -1.0
                most = _time.time()
                if mtime != utolso_mtime or most - utolso_friss >= GEO_HOURS * 3600:
                    self._geo_busy = True
                    try:
                        self._geo_refresh()
                    except Exception as e:
                        self._geo_log("hiba a frissitesben: %s" % e)
                        self._geo_ok = False
                    finally:
                        self._geo_busy = False
                        import time as _tgt
                        self._geo_done_at = _tgt.strftime('%H:%M:%S')
                    utolso_friss = _time.time()
                    utolso_mtime = mtime
                self._geo_stop_ev.wait(GEO_POLL)
        except Exception as e:
            self._geo_log("geo szal problema: %s" % e)

    def _geo_start(self):
        import threading
        if getattr(self, "_geo_thread", None) and self._geo_thread.is_alive():
            return
        self._geo_stop_ev = threading.Event()
        self._geo_thread = threading.Thread(target=self._geo_loop, name="geo", daemon=True)
        self._geo_thread.start()

        import time as _tm
        self._geo_started = _tm.time()
        self._geo_log("geo modul aktivalva: feketelista mod (%s)" % GEO_CFG)

    def _geo_stop(self):
        ev = getattr(self, "_geo_stop_ev", None)
        if ev is not None:
            ev.set()
