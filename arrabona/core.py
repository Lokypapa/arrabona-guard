# -*- coding: utf-8 -*-
"""Arrabona Guard - GuardCore: a vedelmi motor (fo ciklus, riasztas, blokkolas) - a mixinekbol osszerakva."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import subprocess
import threading
import time
from .common import (
    ALERT_COOLDOWN,
    BLACKLIST_FILE,
    BLOCK_FILE,
    BLOCK_PREFIX,
    CHECK_INTERVAL,
    FW_LOG,
    FW_THRESHOLD,
    FW_WINDOW,
    NETSTAT_INTERVAL,
    PORT_SCORE_THRESHOLD,
    PORT_WEIGHTS,
    enable_fw_logging,
    is_admin,
    is_private_ip,
    load_blacklist,
    load_whitelist,
    log_line,
    trim_log,
)
from .geoip import (geo_country_bg)
from .watchdog import (WatchdogMixin, heartbeat_write)
from .telegram import (tg_gombok_auto, tg_poll_start, tg_send)
from .feed import (FeedMixin)
from .geo import (GeoMixin)
from .honeypot import (HoneypotMixin)
from .logon import (LogonMixin)
from .defender import (DefenderMixin)
from .outbound import (OutboundMixin)
from .usb import (UsbMixin)
from .hosts import (HostsMixin)
from .startup import (StartupMixin)
from .javitas import (FixMixin)
from .csali import (CsaliMixin)
from .bongeszo import (BrowserMixin)
from .lan import (LanMixin)
from .halozat import (NetCfgMixin)
from .jatek import (GameModeMixin)
from .extrak import (ExtrasMixin)
from .folyamat import (FolyamatMixin)
from .lopas import (LopasMixin)
from .vagolap import (VagolapMixin)
from .letoltes import (LetoltesMixin)
from .frissites import (FrissitesMixin)
from .upnp import (UpnpMixin)
from .kiszivargas import (KiszivargasMixin)
from .utemezett import (UtemezettMixin)

class GuardCore(FeedMixin, GeoMixin, HoneypotMixin, LogonMixin, DefenderMixin, OutboundMixin, WatchdogMixin,
                UsbMixin, HostsMixin, StartupMixin, FixMixin, CsaliMixin,
                BrowserMixin, LanMixin, NetCfgMixin, GameModeMixin,
                ExtrasMixin, FolyamatMixin, LopasMixin, VagolapMixin, LetoltesMixin,
                FrissitesMixin, UpnpMixin, KiszivargasMixin, UtemezettMixin):
    def __init__(self, out_queue):
        self.out = out_queue
        tg_poll_start(self)
        self.paused_until = 0.0
        self.monitoring_on = True
        self.last_alert = {}
        self.fw_hits = {}
        self.fw_offset = 0
        self.alert_count = 0
        self.lan_skipped = 0        # kimutralt belso (LAN) DROP-ok
        self.blocked_drops = 0      # [v1.9.1] mar blokkolt IP-k eldobott csomagjai (csendes)
        self.sec_events = 0         # [v1.9.3] biztonsagi riasztasok (4624/4720/4732/1102/104)
        self.out_blocked = 0        # [v1.9.4] rossz IP fele kimeno, a tuzfal megfogta
        self.out_open = 0           # [v1.9.4] rossz IP-vel NYITOTT kapcsolat (veszelyesebb)
        self.wd_status = "ellenőrzés…"  # [v1.9.5] orkutya allapota a feluletre
        # [v1.9.6] Windows Defender
        self.def_status = None          # utolso allapot-lekerdezes (szotar)
        self.def_rt_off = False         # valos ideju vedelem KI (aktiv Defender mellett)
        self.def_detections = 0         # 1116-os eszlelesek a futam alatt
        self.def_scan_running = None    # "Gyors" / "Teljes", ha vizsgalat fut
        self.def_updating = False
        # [v2.1.0] USB-figyeles
        self.usb_new = 0                # uj (soha nem latott) USB-eszkozok a futam alatt
        self.usb_status = "indulás…"
        # [v2.2.0] hosts-fajl + inditopult figyeles
        self.hosts_changes = 0
        self.hosts_status = "indulás…"
        self.startup_changes = 0
        self.startup_status = "indulás…"
        # [v2.5.0] ransomware-csapda
        self.csali_hits = 0
        self.csali_status = "indulás…"
        # [v2.6.0] bongeszo-bovitmenyek
        self.bong_changes = 0
        self.bong_status = "indulás…"
        # [v2.7.0] LAN-eszkozok
        self.lan_new = 0
        self.lan_status = "indulás…"
        # [v2.8.0] DNS / proxy
        self.net_changes = 0
        self.net_status = "indulás…"
        # [v2.12.0] folyamatfigyeles
        self.proc_new = 0
        self.proc_alerts = 0
        self.proc_status = "indulás…"
        # [v2.13.0] infostealer-csapda
        self.lopas_hits = 0
        self.lopas_status = "indulás…"
        # [v2.14.0] vagolap-vedelem
        self.vagolap_hits = 0
        self.vagolap_status = "indulás…"
        # [v2.15.0] letoltesek vizsgalata
        self.dl_db = 0
        self.dl_gyanus = 0
        self.letoltes_status = "indulás…"
        # [v2.16.0] elavult programok (winget), router UPnP-portok, adatkiszivargas
        self.frissites_status = "indulás…"
        self.upnp_status = "indulás…"
        self.upnp_new = 0
        self.kisz_status = "indulás…"
        self.kisz_alerts = 0
        # [v2.17.0] utemezett feladatok
        self.ut_status = "indulás…"
        self.ut_alerts = 0
        self.lock = threading.Lock()
        self._blocks_lock = threading.Lock()
        self.admin = is_admin()
        self._stop_ev = threading.Event()

    def pause(self, minutes):
        with self.lock:
            self.paused_until = time.time() + minutes * 60
        self.out.put(("status", "Szünet %d percre indítva." % minutes))

    def pause_off(self):
        with self.lock:
            self.paused_until = 0.0

    def monitor_off(self):
        with self.lock:
            self.monitoring_on = False
        self.out.put(("status", "Figyelés kikapcsolva."))

    def monitor_on(self):
        with self.lock:
            self.monitoring_on = True
        self.out.put(("status", "Figyelés visszakapcsolva."))

    def is_paused(self):
        with self.lock:
            return time.time() < self.paused_until

    def pause_left(self):
        with self.lock:
            return max(0.0, self.paused_until - time.time())

    def is_on(self):
        with self.lock:
            return self.monitoring_on

    def stop(self):
        self._feed_stop()
        self._geo_stop()
        self._logon_stop()
        self._usb_stop()
        self._hosts_stop()
        self._startup_stop()
        self._csali_stop()
        self._bong_stop()
        self._lan_stop()
        self._net_stop()
        self._jatek_stop()
        self._extra_stop()
        self._proc_stop()
        self._lopas_stop()
        self._vagolap_stop()
        self._letoltes_stop()
        self._frissites_stop()
        self._upnp_stop()
        self._kiszivargas_stop()
        self._utemezett_stop()
        self._stop_ev.set()

    def alert(self, ip, msg, always=False, gombok=None):
        t = time.time()
        if not always and (t - self.last_alert.get(ip, 0.0)) < ALERT_COOLDOWN:
            return
        self.last_alert[ip] = t
        with self.lock:
            self.alert_count += 1
        try:
            self.game_note_alert()   # [v2.9.0] jatek kozbeni (csendes) riasztasok szama
        except Exception:
            pass
        # GeoIP országkód hozzáfűzése (LAN -> "[LAN]")
        cc = geo_country_bg(ip)
        if cc:
            msg = "%s [%s]" % (msg, cc)
        log_line(msg)
        # Telegram push riasztas: kulds a telefonra (ha a konfig fajl letezik).
        try:
            # [v2.10.0] gombok: a hivo adja meg, vagy a riasztas tipusabol kitalaljuk
            try:
                sorok = gombok if gombok is not None else tg_gombok_auto(self, ip, msg)
                if gombok and not any(d == "ok" for sor in gombok for _t, d in sor):
                    sorok = list(gombok) + [[("✅ Rendben / én voltam", "ok")]]
            except Exception:
                sorok = None
            threading.Thread(target=tg_send, args=(msg, sorok), daemon=True).start()
        except Exception:
            pass
        self.out.put(("alert", (ip, msg)))

    def read_fw_drops(self):
        """
        Új DROP sorok beolvasása. A tűzfalnaplóban MINDEN eldobott
        csomag szerepel — bármelyik porton (SSH, RDP, SMB, WoW,
        MySQL...). A PRIVÁT (LAN) forráscímeket kimutraljuk.
        """
        try:
            size = os.path.getsize(FW_LOG)
        except OSError:
            return []
        if size < self.fw_offset:
            # Naploforgatas tortent: 0-rol olvasunk, semmi nem ugrik el.
            self.fw_offset = 0
            self._fw_skip = False
        if self.fw_offset == 0 and getattr(self, "_fw_skip", True):
            self._fw_skip = False
            # Első olvasás indításkor: a meglévő régi naplótartalmat ugjuk át,
            # nehogy ujrindítás után visszajátssza a régi DROP-okat.
            self.fw_offset = size
            return []
        if size <= self.fw_offset:
            return []
        try:
            with open(FW_LOG, "rb") as f:
                f.seek(self.fw_offset)
                raw2 = f.read(size - self.fw_offset)
            # Naploforgatas-ellenallo olvasas: csak a TELJES sorokat
            # dolgozzuk fel. A fara csonka utolso sor (forgatas/idolysis
            # pillanata) a kovetkezo korben jon ujra - nem veszik el.
            cut = raw2.rfind(b"\n")
            if cut < 0:
                return []  # meg nincs egy teljes sor sem
            data = raw2[:cut + 1].decode("utf-8", errors="replace")
            self.fw_offset += cut + 1
        except OSError:
            return []

        ips = []
        for line in data.splitlines():
            parts = line.split()
            if "SEND" in parts:
                # [v1.9.4] KIMENO eldobott csomag: a gepunkrol indult kapcsolat,
                # amit a tuzfal megfogott (pl. a kimeno FEED-szabaly). Kulon sorba
                # tesszuk; a fo ciklus kiertekeli, melyik program probalkozott.
                # Mezok: ... dst-ip(5) ... dst-port(7) ... path(16) pid(17)
                if len(parts) >= 8 and parts[2].upper() == "DROP":
                    pid = None
                    if len(parts) >= 18:
                        try:
                            pid = int(parts[17])
                        except ValueError:
                            pid = None
                    q = getattr(self, "_out_drop_q", None)
                    if q is None:
                        q = self._out_drop_q = []
                    if len(q) < 5000:
                        q.append((parts[5], parts[7], pid, parts[3].upper()))
                continue
            if len(parts) >= 8 and parts[2].upper() == "DROP":
                src_ip = parts[4]
                dst_port = parts[7]   # célport
                if is_private_ip(src_ip):
                    with self.lock:
                        self.lan_skipped += 1
                    continue
                proto = parts[3].upper() if len(parts) > 3 else ""
                syn_only = False
                if proto == "TCP" and len(parts) >= 10:
                    # [v1.9.1] pfirewall.log mezok: date time action protocol src-ip
                    # dst-ip src-port dst-port size tcpflags tcpsyn tcpack ...
                    # A jelzobitek a tcpflags (parts[9]) mezoben vannak (pl. "S",
                    # "AS"); a tcpsyn/tcpack mezo sorszam, NEM bit (korabbi hiba).
                    # SYN csomag ACK nelkul: SYN-flood / spoof alairas
                    flags = parts[9].upper()
                    syn_only = flags != "-" and "S" in flags and "A" not in flags
                ips.append((src_ip, dst_port, syn_only))  # IP+port pár
        return ips

    def own_ips(self):
        """Sajat gep IP-cimei - ezeket SOHA nem blokkoljuk."""
        import time
        now = time.time()
        if getattr(self, "_own_ips_cache", None) and now - self._own_ips_ts < 300:
            return self._own_ips_cache
        ips = {"127.0.0.1", "::1"}
        try:
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                 "Get-NetIPAddress -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress"],
                                capture_output=True, timeout=20)
            for line in out.stdout.decode("utf-8", errors="replace").splitlines():
                t = line.strip()
                if "%" in t:
                    t = t.split("%")[0]
                if t:
                    ips.add(t)
        except Exception:
            pass
        # --- Publikus IPv4 lekerese (NAT hairpin miatt: sajat IP-t SOHA nem blokkoljuk) ---
        pub = getattr(self, "_public_ip", None)
        pub_ts = getattr(self, "_public_ip_ts", 0.0)
        if not pub or (now - pub_ts) >= 3600:
            try:
                import urllib.request
                p = urllib.request.urlopen("https://api.ipify.org", timeout=10)
                p = p.read().decode("utf-8", errors="replace").strip()
                if p:
                    pub = p
                    self._public_ip = p
                    self._public_ip_ts = now
                    log_line("Publikus IP frissitve: " + p)
            except Exception:
                pass
        if pub:
            ips.add(pub)

        self._own_ips_cache = ips
        self._own_ips_ts = now
        return ips

    def is_own_prefix(self, ip):
        """True, ha az IP a sajat otthoni IPv6-prefixunkben van (pl. telefon, masik gep)."""
        if not ip or ':' not in ip:
            return False
        pref = ip.lower().split(':')[:4]
        for o in self.own_ips():
            if ':' in o and not o.lower().startswith('fe'):
                if o.lower().split(':')[0:4] == pref:
                    return True
        return False

    def _load_blocks(self):
        with self._blocks_lock:
            try:
                with open(BLOCK_FILE, "r", encoding="utf-8") as f:
                    return _json.load(f)
            except Exception:
                try:
                    import shutil as _sh
                    _sh.copy2(BLOCK_FILE + ".bak", BLOCK_FILE)
                    with open(BLOCK_FILE, "r", encoding="utf-8") as f:
                        return _json.load(f)
                except Exception:
                    return {}

    def _save_blocks(self, bl):
        with self._blocks_lock:
            try:
                import shutil as _sh
                try:
                    _sh.copy2(BLOCK_FILE, BLOCK_FILE + ".bak")
                except Exception:
                    pass
                tmp = BLOCK_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    _json.dump(bl, f)
                os.replace(tmp, BLOCK_FILE)
            except Exception:
                pass

    def _cat_of(self, e):
        """Blokk-bejegyzes kategoriaja (regi, cat nelkuli bejegyzesekbol is)."""
        if not e:
            return None
        if e.get("cat"):
            return e["cat"]
        if e.get("perm"):
            return "perm"
        u = e.get("until", 0)
        if u:
            return "24h" if (u - time.time()) > 6 * 3600 else "1h"
        return None

    _MASTER_LOCK = threading.Lock()

    def apply_master_rule(self, cat):
        """Adott kategoria MESTER-szabalyanak ujraepitese - RESMENTES cserevel.
        Sorrend: 1) uj IP-halmaz IDEIGLENES neven epul fel (a regi meg ved),
                 2) regi szabaly torlodik (ekkor mar az ideiglenes ved mindent),
                 3) vegso nevu szabaly epul, 4) az ideiglenes torlodik.
        Az IP-lista 80-as darabokban megy, hogy a netsh parancssor ne csorduljon tul.
        Kategoriak: 1h / 24h / perm -> ArrabonaBlock_1h / _24h / _Perm."""
        try:
            bl = self._load_blocks()
            ips = sorted([ip for ip, e in bl.items()
                         if not e.get("gone", 0) and self._cat_of(e) == cat])
            name = BLOCK_PREFIX + ("Perm" if cat == "perm" else cat)
            tmp = name + "__tmp"
            with self._MASTER_LOCK:
                if not ips:
                    # Nincs IP: csak a regi es esetleges ideiglenes szabaly torlese.
                    for torlendo in (name, tmp):
                        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                        "name=%s" % torlendo],
                                       capture_output=True, timeout=15)
                    return
                # Beallapotty ideiglenes szabaly takaritasa (ha valami megszakadt).
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                "name=%s" % tmp],
                               capture_output=True, timeout=15)
                # 1) uj halmaz ideiglenes nevven felall
                for i in range(0, len(ips), 80):
                    resz = ips[i:i + 80]
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    "name=%s" % tmp, "dir=in", "action=block",
                                    "remoteip=%s" % ",".join(resz)],
                                   capture_output=True, timeout=15)
                # 2) regi szabaly torlese: az ideiglenes ekkorra mar teljes vedeny
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                "name=%s" % name],
                               capture_output=True, timeout=15)
                # 3) vegso nevu szabaly epulese
                for i in range(0, len(ips), 80):
                    resz = ips[i:i + 80]
                    subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                    "name=%s" % name, "dir=in", "action=block",
                                    "remoteip=%s" % ",".join(resz)],
                                   capture_output=True, timeout=15)
                # 4) ideiglenes szabaly takaritasa
                subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule",
                                "name=%s" % tmp],
                               capture_output=True, timeout=15)
        except Exception:
            pass

    def remove_block_rule(self, ip):
        """Mester-szabalyos modban: IP feloldasa a JSON-ban + mester-szabaly ujraepitese."""
        try:
            bl = self._load_blocks()
            e = bl.get(ip, {})
            if e and not e.get("gone", 0):
                e["gone"] = time.time()
                self._save_blocks(bl)
            cat = self._cat_of(e) if e else None
            if cat:
                self.apply_master_rule(cat)
        except Exception:
            pass

    def expire_blocks(self):
        """Lejart ideiglenes blokkok torlese + 24 oranal regebbi elozmenyek takaritasa."""
        bl = self._load_blocks()
        now_t = time.time()
        changed = False
        for ip in list(bl.keys()):
            e = bl[ip]
            if e.get("perm"):
                continue
            u = e.get("until", 0)
            if u and u <= now_t:
                cat = self._cat_of(e)
                e.pop("until", None)
                e["gone"] = now_t
                changed = True
                log_line("Ideiglenes blokk lejart, feloldva: " + ip)
                if cat:
                    self.apply_master_rule(cat)
            elif e.get("gone", 0) and now_t - e["gone"] > 24 * 3600:
                del bl[ip]
                changed = True
        if changed:
            self._save_blocks(bl)

    def block_ip(self, ip):
        """IP automatikus tiltasa tuzfalszaballyal."""
        try:
            if ip in load_whitelist():
                return
            if ip in self.own_ips():
                log_line("SAJAT IP, kihagyva: " + ip)
                return
            bl_pre = self._load_blocks()
            old_cat = None
            if bl_pre.get(ip) and not bl_pre[ip].get("gone", 0):
                # Van mar blokk, de a tamadas ISMETelt: a regi kategoria
                # mester-szabalyat is ujraepitjuk, hogy az IP athuzodaljon.
                old_cat = self._cat_of(bl_pre[ip])
            # --- ESZKALACIO: 1. blokk 1 ora, 2. blokk 24 ora, 3.+ vegleges ---
            bl = self._load_blocks()
            now_t = time.time()
            cnt = bl.get(ip, {}).get("count", 0) + 1
            if cnt >= 3:
                try:
                    with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
                        f.write(ip + "\n")
                except OSError:
                    pass
                bl[ip] = {"count": cnt, "perm": True, "cat": "perm"}
                dur_txt = "VEGLEGES"
            else:
                hours = 1 if cnt == 1 else 24
                bl[ip] = {"count": cnt, "until": now_t + hours * 3600,
                          "cat": "24h" if cnt == 2 else "1h"}
                dur_txt = "%d oras" % hours
            self._save_blocks(bl)
            cat = bl[ip].get("cat")
            if old_cat and old_cat != cat:
                self.apply_master_rule(old_cat)
            self.apply_master_rule(cat)
            self.alert(ip, "IP AUTOMATIKUSAN BLOKKOLVA (%s): " % dur_txt + ip, always=True)
        except Exception:
            pass

    def block_ip_perm(self, ip, ok="kezi"):
        """[v1.9.3] IP azonnali VEGLEGES tiltasa (Telegram /block, feketelistas
        IP sikeres belepese). LAN, Tailscale, sajat es whitelist IP-t soha."""
        try:
            if (ip in load_whitelist() or is_private_ip(ip)
                    or ip in self.own_ips() or self.is_own_prefix(ip)):
                log_line("Vegleges blokk elutasitva (belso/sajat/whitelist): " + ip)
                return False
            bl = self._load_blocks()
            regi = bl.get(ip) if isinstance(bl.get(ip), dict) else {}
            old_cat = self._cat_of(regi) if regi and not regi.get("gone", 0) else None
            cnt = max(3, int(regi.get("count", 0) or 0) + 1)
            bl[ip] = {"count": cnt, "perm": True, "cat": "perm"}
            self._save_blocks(bl)
            try:
                if ip not in load_blacklist():
                    with open(BLACKLIST_FILE, "a", encoding="utf-8") as f:
                        f.write(ip + "\n")
            except OSError:
                pass
            if old_cat and old_cat != "perm":
                self.apply_master_rule(old_cat)
            self.apply_master_rule("perm")
            self.alert(ip, "IP VEGLEGESEN BLOKKOLVA (%s): %s" % (ok, ip), always=True)
            return True
        except Exception as e:
            log_line("Vegleges blokk hiba (%s): %s" % (ip, e))
            return False

    def unblock_all(self):
        """Osszes Arrabona blokk torlese (teves riasztas eseten)."""
        try:
            subprocess.run(["powershell", "-NoProfile", "-Command",
                            "Get-NetFirewallRule -DisplayName '%s*' | Remove-NetFirewallRule" % BLOCK_PREFIX],
                           capture_output=True, timeout=60)
            bl = self._load_blocks()
            now_t = time.time()
            for ip in list(bl.keys()):
                if not bl[ip].get("gone"):
                    bl[ip]["gone"] = now_t
            self._save_blocks(bl)
            log_line("Minden Arrabona blokk feloldva.")
            self.out.put(("status", "Minden Arrabona blokk feloldva."))
        except Exception:
            pass

    def _daily_report_check(self):
        """Napi riport: 24 orankent osszegzes a naplobol -> Telegram + naplo."""
        try:
            import json as _json
            adat = os.path.join(os.environ.get("APPDATA", ""), "ArrabonaGuard")
            stf = os.path.join(adat, "riport_state.json")
            utolso = 0.0
            try:
                with open(stf, "r", encoding="utf-8") as fh:
                    utolso = float(_json.load(fh).get("last", 0.0))
            except Exception:
                pass
            most = time.time()
            if most - utolso < 24 * 3600:
                return
            # naplo beolvasasa, utolso 24 ora sorai
            naplo = os.path.join(adat, "guard_naplo.txt")
            soriasis = time.strftime("%Y-%m-%d %H:%M", time.localtime(most - 24 * 3600))
            riaszt = blokk = ps = hp = e4625 = bizt = kimeno = defe = usbu = hostsv = indulo = csapda = bong = lanuj = arpm = dnsp = folyk = lopk = vagk = letk = upn = kisz = utf = 0
            try:
                with open(naplo, "r", encoding="utf-8", errors="ignore") as fh:
                    for ln in fh:
                        if len(ln) < 21 or ln[0] != "[":
                            continue
                        if ln[:16] < soriasis:
                            continue
                        if "RIASZTAS" in ln or "alert" in ln.lower() or "PORTSCAN" in ln or "Gyanus" in ln:
                            riaszt += 1
                        if "BLOKK" in ln.upper():
                            blokk += 1
                        if "PORTSCAN" in ln:
                            ps += 1
                        if "HONEYPOT" in ln.upper():
                            hp += 1
                        if "4625" in ln:
                            e4625 += 1
                        if "[BIZTONSAG]" in ln and ("4624" in ln or "4720" in ln or "4732" in ln
                                                    or "1102" in ln or "104 ESEMENY" in ln):
                            bizt += 1
                        if "[KIMENO]" in ln:
                            kimeno += 1
                        if "[USB] UJ USB-" in ln:
                            usbu += 1
                        if "[HOSTS] " in ln and ("megvaltozott" in ln or "GYANUS" in ln or "ELTUNT" in ln):
                            hostsv += 1
                        if "[INDITOPULT] " in ln and ("UJ INDULO" in ln or "MODOSULT" in ln
                                                       or "TOROLVE" in ln or "GYANUS" in ln):
                            indulo += 1
                        if "[CSAPDA] ZSAROLOVIRUS" in ln:
                            csapda += 1
                        if "[BONGESZO] " in ln and ("BONGESZO-BOVITMENY" in ln or "JOGOSULTSAGOT" in ln
                                                     or "GYANUS" in ln):
                            bong += 1
                        if "[LAN] UJ ESZKOZ" in ln:
                            lanuj += 1
                        if "[LAN] ARP-MERGEZES" in ln:
                            arpm += 1
                        if "[DNS/PROXY] " in ln and "GYANUS" in ln:
                            dnsp += 1
                        if "[FOLYAMAT] " in ln and " FOLYAMAT" in ln and "Gyanus:" in ln:
                            folyk += 1
                        if "[INFOLOPAS] " in ln and " olvasta: " in ln:
                            lopk += 1
                        if "[VAGOLAP] " in ln and " kicserelte " in ln:
                            vagk += 1
                        if "[LETOLTES] " in ln and " LETOLTES: " in ln:
                            letk += 1
                        if "[UPNP] " in ln and "NYITOTT PORT A ROUTEREN" in ln:
                            upn += 1
                        if "[KISZIVARGAS] " in ln and " FELTOLTES: " in ln:
                            kisz += 1
                        if "[UTEMEZETT] " in ln and "UTEMEZETT FELADAT:" in ln:
                            utf += 1
                        if "[DEFENDER] KARTEVO ESZLELVE" in ln:
                            defe += 1
            except Exception:
                pass
            uzenet = ("📊 Napi riport - Arrabona Guard\n"
                      "Idoszak: utolso 24 ora\n"
                      "Riasztasok: %d\nBlokkolasi esemenyek: %d\n"
                      "Portscan: %d\nHoneypot kopogasok: %d\n"
                      "4625 bejelentkezesi esemenyek: %d\n"
                      "Biztonsagi esemenyek (sikeres kulso belepes, uj fiok,\n"
                      "  admin csoport, naplotorles): %d\n"
                      "Kimeno kapcsolat rossz IP fele: %d\n"
                      "Defender kartevo-eszlelesek: %d\n"
                      "Uj USB-eszkozok: %d\n"
                      "Hosts-fajl valtozasok: %d\n"
                      "Inditopult-valtozasok: %d\n"
                      "Ransomware-csapda riasztasok: %d\n"
                      "Bongeszo-bovitmeny valtozasok: %d\n"
                      "Uj eszkoz a LAN-on: %d\n"
                      "ARP-mergezes gyanu: %d\n"
                      "Gyanus DNS/proxy valtozas: %d\n"
                      "Gyanus folyamatok: %d\n"
                      "Adatlopas-gyanu (infostealer): %d\n"
                      "Vagolap cim-csere (clipper): %d\n"
                      "Gyanus letoltes: %d\n"
                      "Uj nyitott port a routeren (UPnP): %d\n"
                      "Gyanus feltoltes (adatkiszivargas): %d\n"
                      "Gyanus / rejtett utemezett feladat: %d") % (riaszt, blokk, ps, hp, e4625, bizt, kimeno, defe,
                                                usbu, hostsv, indulo, csapda, bong, lanuj, arpm, dnsp, folyk, lopk, vagk,
                                                letk, upn, kisz, utf)
            try:
                _fl = self.frissites_lista()
                if _fl:
                    uzenet += "\nElavult programok: %d (kiemelt: %d) - /frissitesek" % (
                        len(_fl), sum(1 for _x in _fl if _x.get("kat")))
            except Exception:
                pass
            try:
                uzenet += "\nDefender: " + self.defender_summary(rovid=True)
            except Exception:
                pass
            tg_send(uzenet)
            log_line("NAPI RIPORT elkuldve (Telegram): r=%d b=%d ps=%d hp=%d 4625=%d" %
                     (riaszt, blokk, ps, hp, e4625))
            try:
                with open(stf, "w", encoding="utf-8") as fh:
                    _json.dump({"last": most}, fh)
            except Exception:
                pass
        except Exception:
            pass

    def _gc_dicts(self, now=None):
        """[v1.9.2] Memoria-takaritas: a csak novekvo IP-szotarakbol kidobja
        a mar lejart bejegyzeseket (hetekig futva tobb ezer szkenner-IP
        gyult ossze bennuk). 10 percenkent fut a fo ciklusbol."""
        now = now or time.time()
        torolt = 0

        def _ido_szotar(d, kor):
            # {kulcs: idobelyeg} - a "kor" mp-nel regebbiek mennek
            n = 0
            if not isinstance(d, dict):
                return 0
            for k, t in list(d.items()):
                try:
                    if now - float(t) > kor:
                        d.pop(k, None)
                        n += 1
                except (TypeError, ValueError):
                    d.pop(k, None)
                    n += 1
            return n

        torolt += _ido_szotar(getattr(self, "last_alert", None), 3600.0)
        torolt += _ido_szotar(getattr(self, "_bl_alert_last", None), 3600.0)
        torolt += _ido_szotar(getattr(self, "_honey_last", None), 3600.0)
        torolt += _ido_szotar(getattr(self, "_blconn_last", None), 3600.0)
        torolt += _ido_szotar(getattr(self, "_succ_last", None), 3600.0)
        torolt += _ido_szotar(getattr(self, "_out_last", None), 7200.0)
        # fw_hits: {ip: [(port, t, suly), ...]}
        fh = getattr(self, "fw_hits", None)
        if isinstance(fh, dict):
            for ip, lst in list(fh.items()):
                if not lst or all(now - t >= FW_WINDOW for (_p, t, _w) in lst):
                    fh.pop(ip, None)
                    torolt += 1
        # _syn_hits: {ip: [t, ...]}
        sh = getattr(self, "_syn_hits", None)
        if isinstance(sh, dict):
            for ip, lst in list(sh.items()):
                if not lst or all(now - t >= 60.0 for t in lst):
                    sh.pop(ip, None)
                    torolt += 1
        if torolt >= 100:
            log_line("Memoria-takaritas: %d lejart IP-bejegyzes torolve" % torolt)
        return torolt

    def run(self):
        self._feed_start()
        self._geo_start()
        self._logon_start()
        try:
            self._usb_start()
        except Exception as e:
            log_line("[USB] inditasi hiba: %s" % e)
        try:
            self._hosts_start()
        except Exception as e:
            log_line("[HOSTS] inditasi hiba: %s" % e)
        try:
            self._startup_start()
        except Exception as e:
            log_line("[INDITOPULT] inditasi hiba: %s" % e)
        try:
            self._csali_start()
        except Exception as e:
            log_line("[CSAPDA] inditasi hiba: %s" % e)
        try:
            self._bong_start()
        except Exception as e:
            log_line("[BONGESZO] inditasi hiba: %s" % e)
        try:
            self._lan_start()
        except Exception as e:
            log_line("[LAN] inditasi hiba: %s" % e)
        try:
            self._net_start()
        except Exception as e:
            log_line("[DNS/PROXY] inditasi hiba: %s" % e)
        try:
            self._jatek_start()
        except Exception as e:
            log_line("[JATEK] inditasi hiba: %s" % e)
        try:
            self._extra_start()
        except Exception as e:
            log_line("[EXTRA] inditasi hiba: %s" % e)
        try:
            self._proc_start()
        except Exception as e:
            log_line("[FOLYAMAT] inditasi hiba: %s" % e)
        try:
            self._lopas_start()
        except Exception as e:
            log_line("[INFOLOPAS] inditasi hiba: %s" % e)
        try:
            self._vagolap_start()
        except Exception as e:
            log_line("[VAGOLAP] inditasi hiba: %s" % e)
        try:
            self._letoltes_start()
        except Exception as e:
            log_line("[LETOLTES] inditasi hiba: %s" % e)
        try:
            self._frissites_start()
        except Exception as e:
            log_line("[FRISSITES] inditasi hiba: %s" % e)
        try:
            self._upnp_start()
        except Exception as e:
            log_line("[UPNP] inditasi hiba: %s" % e)
        try:
            self._kiszivargas_start()
        except Exception as e:
            log_line("[KISZIVARGAS] inditasi hiba: %s" % e)
        try:
            self._utemezett_start()
        except Exception as e:
            log_line("[UTEMEZETT] inditasi hiba: %s" % e)
        trim_log()
        self.start_honeypot()  # indulaskori naplotakaritas
        fw_ok = enable_fw_logging()
        self.fw_ok = fw_ok   # [v2.11.0] a biztonsagi pontszamhoz
        self.out.put(("status", "Indulás. Tűzfalnapló: %s" %
                      ("aktív" if fw_ok else
                       "nem elérhető (rendszergazda kell hozzá)")))
        self.out.put(("fw_ok", fw_ok))

        last_netstat = 0.0
        while not self._stop_ev.wait(CHECK_INTERVAL):
            # [v1.9.5] eletjel + orkutya: szunetben / kikapcsolt figyelesnel is
            _hb_now = time.time()
            if _hb_now - getattr(self, "_last_hb", 0.0) >= 60.0:
                self._last_hb = _hb_now
                heartbeat_write()
            if _hb_now - getattr(self, "_last_wd", 0.0) >= 600.0:
                self._last_wd = _hb_now
                try:
                    self._watchdog_check()
                except Exception as e:
                    log_line("[ORKUTYA] hiba: %s" % e)
            if self.is_paused() or not self.is_on():
                continue

            now = time.time()
            if now - last_netstat >= NETSTAT_INTERVAL:
                last_netstat = now
                blacklist = load_blacklist()
                whitelist = load_whitelist()
                self.check_blacklist_connections(blacklist, whitelist)
            if getattr(self, "_out_drop_q", None):
                try:
                    self._out_drops_process(load_blacklist(), load_whitelist())
                except Exception as e:
                    log_line("[KIMENO] feldolgozasi hiba: %s" % e)
            if now - getattr(self, "_last_expire", 0.0) >= 60.0:
                self._last_expire = now
                self.expire_blocks()
            if now - getattr(self, "_last_riport", 0.0) >= 300.0:
                self._last_riport = now
                self._daily_report_check()
            if now - getattr(self, "_last_gc", 0.0) >= 600.0:
                self._last_gc = now
                self._gc_dicts(now)
            drops = self.read_fw_drops()
            # [v1.9.1] A blokklistat korenkent EGYSZER olvassuk be (nem minden
            # DROP sornal), es ebbol az aktiv blokk alatt allo IP-k halmaza.
            aktiv_blokk = set()
            if drops:
                try:
                    aktiv_blokk = {b_ip for b_ip, b_e in self._load_blocks().items()
                                   if isinstance(b_e, dict) and not b_e.get("gone", 0)}
                except Exception:
                    aktiv_blokk = set()
            for ip_port in drops:
                ip, port, syn_only = ip_port  # unpack IP+port
                if ip in whitelist:
                    continue
                if ip in aktiv_blokk:
                    # [v1.9.1] Mar blokkolt IP (1h/24h/vegleges): a tuzfal dobja a
                    # csomagjait, ez a vedelem MUKODESE, nem uj tamadas. Csendben
                    # szamoljuk - nincs riasztas, nincs Telegram-aradat, nincs
                    # ujabb eszkalacio a sajat blokkja miatt.
                    with self.lock:
                        self.blocked_drops += 1
                    continue
                if ip in blacklist:
                    # dedup kapu: ugyanerre az IP-re 60 mp-enkent max 1 riasztas,
                    # a tuzfal ugyanis minden dobutt csomagnal uj sort ir a naploba
                    _last = getattr(self, "_bl_alert_last", {})
                    if now - _last.get(ip, 0.0) >= 60.0:
                        _last[ip] = now
                        self._bl_alert_last = _last
                        self.alert(ip, self._csali_tag(port) + " FEKETELISTÁS IP dobta a tűzfalat: " + ip,
                                   always=True)
                    continue
                if ip in self.own_ips():
                    continue
                if self.is_own_prefix(ip):
                    with self.lock:
                        self.lan_skipped += 1
                    continue
                # Portok gyűjtése csúszó időablakban
                # --- Spoofolt SYN-flood figyelese (TCP, SYN=1 ACK=0) ---
                if syn_only:
                    sh = getattr(self, "_syn_hits", None)
                    if sh is None:
                        sh = self._syn_hits = {}
                    ts = sh.setdefault(ip, [])
                    ts.append(now)
                    ts[:] = [t for t in ts if now - t < 60.0]
                    if len(ts) >= 30:
                        # 30 SYN-csak csomag 60 mp alatt egy forrastol
                        ts.clear()
                        self.alert(ip, self._csali_tag(port) + " SYN-FLOOD gyanu: %s - 30 SYN / 60 mp" % ip, always=True)
                        self.block_ip(ip)
                        aktiv_blokk.add(ip)
                        continue
                entries = [(p, t, w) for (p, t, w) in self.fw_hits.get(ip, []) if now - t < FW_WINDOW]
                entries.append((port, now, PORT_WEIGHTS.get(int(port) if str(port).isdigit() else -1, 1)))
                self.fw_hits[ip] = entries
                # PORTSCAN DETEKCIÓ: 5+ különböző port / FW_WINDOW mp
                score = sum(w for (p, t, w) in entries)
                unique_ports = set(p for (p, t, w) in entries)
                if len(unique_ports) >= 5:
                    self.fw_hits[ip] = []
                    self.alert(ip, self._csali_tag(port) + " PORTSCAN DETEKTELVE! %s - %d különböző port / %d mp" %
                               (ip, len(unique_ports), int(FW_WINDOW)), always=True)
                    self.block_ip(ip)
                    aktiv_blokk.add(ip)
                # Hagyományos threshold: ha sok DROP (de csak 1 porton)
                elif score >= PORT_SCORE_THRESHOLD:
                    self.fw_hits[ip] = []
                    self.alert(ip, self._csali_tag(port) + " Gyanus provalkozas! %s - %.0f pont / %d mp" %
                               (ip, score, int(FW_WINDOW)))
                    self.block_ip(ip)
                    aktiv_blokk.add(ip)
                elif len(entries) >= FW_THRESHOLD:
                    self.fw_hits[ip] = []
                    self.alert(ip, self._csali_tag(port) + " Gyanús próbálkozás! %s - %d DROP / %d mp" %
                               (ip, FW_THRESHOLD, int(FW_WINDOW)))
                    self.block_ip(ip)
                    aktiv_blokk.add(ip)
