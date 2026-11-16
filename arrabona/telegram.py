# -*- coding: utf-8 -*-
"""Arrabona Guard - Telegram: riasztas kuldese es parancsok (/status /blokkok /block /unblock /defender /scan...)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import os
import threading
from .common import (log_line)

TG_CFG_CACHE = None

def tg_send(msg, gombok=None):
    """Telegram push riasztas: a konfigot fajlbol olvassa (token, chat_id) minden kuldeskor.
    gombok (v2.10.0): [[("felirat", "callback_data"), ...], ...] - gombsorok az uzenet alatt."""
    global TG_CFG_CACHE
    try:
        cfg_path = os.path.join(os.environ.get("APPDATA", ""), "ArrabonaGuard", "telegram.txt")
        if not os.path.exists(cfg_path):
            return
        mt = os.path.getmtime(cfg_path)
        if TG_CFG_CACHE is None or TG_CFG_CACHE[0] != mt:
            tok, cid = "", ""
            with open(cfg_path, "r", encoding="utf-8-sig") as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln.startswith("#") or "=" not in ln:
                        continue
                    k, _, v = ln.partition("=")
                    k = k.strip().lower()
                    if k == "token":
                        tok = v.strip()
                    elif k == "chat_id":
                        cid = v.strip()
            TG_CFG_CACHE = (mt, tok, cid)
        _, tok, cid = TG_CFG_CACHE
        if not tok or not cid:
            return
        import urllib.request, urllib.parse
        params = {"chat_id": cid, "text": msg[:4000]}
        if gombok:
            import json as _j
            params["reply_markup"] = _j.dumps({"inline_keyboard": [
                [{"text": t, "callback_data": d[:64]} for t, d in sor] for sor in gombok if sor]})
        data = urllib.parse.urlencode(params).encode("utf-8")
        req = urllib.request.Request("https://api.telegram.org/bot%s/sendMessage" % tok, data=data)
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass

TG_POLL_ON = False

def _tg_cfg():
    """telegram.txt friss olvasasa (token, chat_id)."""
    tok, cid = "", ""
    try:
        p = os.path.join(os.environ.get("APPDATA", ""), "ArrabonaGuard", "telegram.txt")
        with open(p, "r", encoding="utf-8-sig") as fh:
            for ln in fh:
                ln = ln.strip()
                if ln.startswith("#") or "=" not in ln:
                    continue
                k, _, v = ln.partition("=")
                k = k.strip().lower()
                if k == "token":
                    tok = v.strip()
                elif k == "chat_id":
                    cid = v.strip()
    except Exception:
        pass
    return tok, cid

def _tg_api(tok, method, params=None):
    import urllib.request, urllib.parse, json as _j
    data = None
    if params:
        data = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request("https://api.telegram.org/bot%s/%s" % (tok, method), data=data)
    with urllib.request.urlopen(req, timeout=35) as r:
        return _j.loads(r.read().decode("utf-8", "replace"))

def _tg_reply(tok, cid, msg):
    try:
        _tg_api(tok, "sendMessage", {"chat_id": cid, "text": msg[:4000]})
    except Exception:
        pass

def _tg_status_text(core):
    import time as _t
    sorok = ["Arrabona Guard statusz:"]
    sorok.append("Figyeles: %s" % ("AKTIV" if core.monitoring_on else "KIKAPCSOLVA"))
    if core.paused_until > _t.time():
        sorok.append("Szunet: meg %d perc" % int((core.paused_until - _t.time()) / 60))
    try:
        with core.lock:
            sorok.append("Riasztasok (futam): %d" % core.alert_count)
    except Exception:
        pass
    try:
        bl = core._load_blocks()
        akt = [ip for ip, v in bl.items() if isinstance(v, dict) and not v.get("gone")]
        sorok.append("Aktiv blokkok: %d" % len(akt))
    except Exception:
        pass
    sorok.append("Orkutya: %s" % getattr(core, "wd_status", "?"))
    try:
        sorok.append("Defender: %s" % core.defender_summary(rovid=True))
    except Exception:
        pass
    return "\n".join(sorok)

def _tg_blokkok_text(core):
    import time as _t
    try:
        bl = core._load_blocks()
    except Exception:
        return "Blokklista nem olvashato."
    sorok = []
    for ip, v in bl.items():
        if isinstance(v, dict) and not v.get("gone"):
            cat = v.get("cat", "?")
            until = v.get("until", 0)
            if until and until > _t.time():
                sorok.append("%s [%s] lejar: %s" % (ip, cat, _t.strftime("%m-%d %H:%M", _t.localtime(until))))
            else:
                sorok.append("%s [%s]" % (ip, cat))
    if not sorok:
        return "Nincs aktiv blokk."
    return "Aktiv blokkok (%d):\n" % len(sorok) + "\n".join(sorok[:30])

def _tg_handle(core, tok, cid, text):
    import time as _t
    text = (text or "").strip()
    if text.startswith("/unblock"):
        parts = text.split()
        if len(parts) < 2 or not parts[1]:
            _tg_reply(tok, cid, "Hasznalat: /unblock <IP>")
            return
        # [v1.9.2] IP-ellenorzes: csak ervenyes IPv4/IPv6 cimet fogadunk el
        try:
            import ipaddress as _ipa
            ip = str(_ipa.ip_address(parts[1].strip()))
        except ValueError:
            _tg_reply(tok, cid, "Ervenytelen IP-cim: %s\nHasznalat: /unblock <IP>" % parts[1][:60])
            return
        bl_check = {}
        try:
            bl_check = core._load_blocks()
        except Exception:
            pass
        e_check = bl_check.get(ip)
        if not (isinstance(e_check, dict) and not e_check.get("gone", 0)):
            _tg_reply(tok, cid, "%s nincs az aktiv blokkok kozott." % ip)
            return
        try:
            core.remove_block_rule(ip)
        except Exception:
            pass
        try:
            bl = core._load_blocks()
            if ip in bl:
                bl[ip] = {"gone": _t.time()}
                core._save_blocks(bl)
        except Exception:
            pass
        log_line("TG parancs: unblock %s" % ip)
        _tg_reply(tok, cid, "%s feloldva (tuzfal + blokklista)." % ip)
        return
    if text.startswith("/block") and not text.startswith("/blokkok"):
        # [v1.9.3] /block <IP> - azonnali vegleges tiltas (pl. egy 4624-es
        # "sikeres belepes kulso IP-rol" riasztas utan, ha nem te voltal)
        parts = text.split()
        if len(parts) < 2 or not parts[1]:
            _tg_reply(tok, cid, "Hasznalat: /block <IP>")
            return
        try:
            import ipaddress as _ipa
            ip = str(_ipa.ip_address(parts[1].strip()))
        except ValueError:
            _tg_reply(tok, cid, "Ervenytelen IP-cim: %s\nHasznalat: /block <IP>" % parts[1][:60])
            return
        log_line("TG parancs: block %s" % ip)
        if core.block_ip_perm(ip, "Telegram /block"):
            _tg_reply(tok, cid, "%s VEGLEGESEN blokkolva (tuzfal + feketelista).\nFeloldas: /unblock %s" % (ip, ip))
        else:
            _tg_reply(tok, cid, "%s nem blokkolhato (belso/LAN/Tailscale, sajat vagy whitelistes cim)." % ip)
        return
    # [v1.9.6] Windows Defender parancsok
    if text.startswith("/stopscan") or text.startswith("/megszakit"):
        # [v2.2.0] a futo Defender-vizsgalat megszakitasa
        log_line("TG parancs: stopscan")
        _ok, szoveg = core.defender_scan_cancel("Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/scanfull") or text.startswith("/scan"):
        tipus = "full" if text.startswith("/scanfull") else "quick"
        log_line("TG parancs: %s" % text.split()[0])
        if core.defender_scan(tipus):
            _tg_reply(tok, cid, "%s Defender-vizsgalat elinditva. Ha kesz, jelzek.%s" % (
                "Teljes" if tipus == "full" else "Gyors",
                " (A teljes vizsgalat orakig is tarthat.)" if tipus == "full" else ""))
        else:
            _tg_reply(tok, cid, "Mar fut egy vizsgalat: %s." % core.def_scan_running)
        return
    if text.startswith("/defupdate"):
        log_line("TG parancs: defupdate")
        if core.defender_update():
            _tg_reply(tok, cid, "Defender definiciofrissites elinditva...")
        else:
            _tg_reply(tok, cid, "A frissites mar folyamatban van.")
        return
    if text.startswith("/usb"):
        # [v2.1.0] legutobbi uj USB-eszkozok
        log_line("TG parancs: usb")
        _tg_reply(tok, cid, core.usb_recent_text())
        return
    # [v2.11.0] pontszam, VirusTotal, Windows Update
    if text.startswith("/pontszam") or text.startswith("/pont"):
        log_line("TG parancs: pontszam")
        _tg_reply(tok, cid, core.score_text())
        return
    if text.startswith("/vt"):
        ut = text[3:].strip().strip('"')
        if not ut:
            _tg_reply(tok, cid, "Hasznalat: /vt C:\\ut\\program.exe")
            return
        log_line("TG parancs: vt %s" % ut[:120])
        _tg_reply(tok, cid, core.vt_check_now(ut)[0])
        return
    if text.startswith("/guardverzio") or text.startswith("/verzio"):
        # [v2.18.0] sajat verzio + uj kiadas keresese
        from . import updater
        updater.keres(kezi=True)
        _tg_reply(tok, cid, updater.allapot_szoveg())
        return
    if text.startswith("/guardfrissit"):
        ok, sz = _guard_frissit_inditas(tok, cid)
        _tg_reply(tok, cid, ("⬆ " if ok else "⚠ ") + sz)
        return
    if text.startswith("/winupdate") or (text.startswith("/frissites") and not text.startswith("/frissitesek")):
        log_line("TG parancs: winupdate")
        _tg_reply(tok, cid, "Windows Update:\n" + core.wu_summary().replace(" | ", "\n"))
        return
    if text.startswith("/jatek"):
        # [v2.9.0] jatek mod
        parts = text.split()
        if len(parts) < 2:
            _a, sz = core.game_info()
            _tg_reply(tok, cid, "Jatek mod: %s\nAllitas: /jatek be | ki | auto" % sz)
            return
        log_line("TG parancs: jatek %s" % parts[1])
        _ok, szoveg = core.game_set_mode(parts[1])
        _tg_reply(tok, cid, szoveg)
        return
    # [v2.8.0] DNS / proxy
    if text.startswith("/dnsauto"):
        log_line("TG parancs: dnsauto")
        _ok, szoveg = core.dns_auto("Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/proxyki"):
        log_line("TG parancs: proxyki")
        _ok, szoveg = core.proxy_off("Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/dns") or text.startswith("/proxy") or text.startswith("/halozat"):
        log_line("TG parancs: dns")
        _tg_reply(tok, cid, core.net_text())
        return
    if text.startswith("/lannev"):
        # [v2.7.0] LAN-eszkoz elnevezese
        parts = text.split(None, 2)
        if len(parts) < 3:
            _tg_reply(tok, cid, "Hasznalat: /lannev <sorszam vagy MAC> <nev>\nA sorszamokat a /lan mutatja.")
            return
        log_line("TG parancs: lannev %s" % parts[1])
        _ok, szoveg = core.lan_rename(parts[1], parts[2])
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/lan"):
        log_line("TG parancs: lan")
        _tg_reply(tok, cid, core.lan_text())
        return
    if text.startswith("/bovitmeny") or text.startswith("/bongeszo"):
        # [v2.6.0] bongeszo-bovitmenyek
        log_line("TG parancs: bovitmenyek")
        _tg_reply(tok, cid, core.browser_text())
        return
    # [v2.5.0] ransomware-csapda
    if text.startswith("/csali") or text.startswith("/csapda"):
        log_line("TG parancs: csapda")
        _tg_reply(tok, cid, core.csali_text())
        return
    if text.startswith("/leallit") or text.startswith("/folytat"):
        parts = text.split()
        if len(parts) < 2 or not parts[1].isdigit():
            _tg_reply(tok, cid, "Hasznalat: %s <PID>" % parts[0])
            return
        log_line("TG parancs: %s %s" % (parts[0], parts[1]))
        _fp = int(parts[1]) in (getattr(core, "_proc_suspended", None) or {})   # [v2.12.0]
        if parts[0].startswith("/leallit"):
            _ok, szoveg = (core.folyamat_kill(int(parts[1]), None, "Telegram") if _fp
                           else core.csali_kill(int(parts[1]), "Telegram"))
        else:
            _ok, szoveg = (core.folyamat_resume(int(parts[1]), None, "Telegram") if _fp
                           else core.csali_resume(int(parts[1]), "Telegram"))
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/folyamatreset"):
        # [v2.12.0]
        n = core.folyamat_untrust_all()
        log_line("TG parancs: folyamatreset")
        _tg_reply(tok, cid, "Megbizhato-lista torolve (%d tetel). Mostantol ujra mindenre szol." % n)
        return
    if text.startswith("/frissitesek"):
        # [v2.16.0] elavult programok (winget); "/frissitesek most" = azonnali lekerdezes
        log_line("TG parancs: frissitesek")
        if "most" in text.lower() or core.frissites_lista() is None:
            _tg_reply(tok, cid, "Lekerdezem a wingettel (1-2 perc)…")

            def _fr_hatter():
                try:
                    _ok, szoveg = core.frissites_check(ertesit=False, ki="Telegram")
                except Exception as e:
                    szoveg = "Hiba: %s" % e
                _tg_reply(tok, cid, szoveg)
            # hatterszalon: a winget percekig is futhat, kozben a tobbi parancs is menjen
            threading.Thread(target=_fr_hatter, daemon=True).start()
        else:
            _tg_reply(tok, cid, core.frissites_text())
        return
    if text.startswith("/frissit"):
        # [v2.16.0] /frissit <szam | azonosito | kiemelt | mind>
        mi = text[len("/frissit"):].strip()
        if not mi:
            _tg_reply(tok, cid, "Hasznalat: /frissit <szam> | /frissit kiemelt | /frissit mind\nLista: /frissitesek")
            return
        log_line("TG parancs: frissit %s" % mi[:60])
        _ok, szoveg = core.frissites_upgrade(mi, ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/upnpzar"):
        # [v2.16.0]
        parts = text.split()
        if len(parts) < 2:
            _tg_reply(tok, cid, "Hasznalat: /upnpzar <szam>\nA szamokat a /upnp mutatja.")
            return
        log_line("TG parancs: upnpzar %s" % parts[1])
        _ok, szoveg = core.upnp_zar(parts[1], ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/upnp") or text.startswith("/portok"):
        # [v2.16.0]
        log_line("TG parancs: upnp")
        _tg_reply(tok, cid, core.upnp_text())
        return
    if text.startswith("/feladattiltas") or text.startswith("/feladatengedely"):
        # [v2.17.0]
        parts = text.split(None, 1)
        if len(parts) < 2:
            _tg_reply(tok, cid, "Hasznalat: %s <szam>\nA szamokat a /feladatok mutatja." % parts[0])
            return
        log_line("TG parancs: %s %s" % (parts[0], parts[1][:80]))
        if parts[0].startswith("/feladattiltas"):
            _ok, szoveg = core.ut_tilt(parts[1], ki="Telegram")
        else:
            _ok, szoveg = core.ut_enged(parts[1], ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/feladatok") or text.startswith("/utemezett"):
        # [v2.17.0] "/feladatok most" = azonnali atnezes
        log_line("TG parancs: feladatok")
        if "most" in text.lower():
            _tg_reply(tok, cid, "Atnezem az utemezett feladatokat…")

            def _ut_hatter():
                try:
                    _ok, szoveg = core.ut_scan(ki="Telegram")
                except Exception as e:
                    szoveg = "Hiba: %s" % e
                _tg_reply(tok, cid, szoveg[:4000])
            threading.Thread(target=_ut_hatter, daemon=True).start()
        else:
            _tg_reply(tok, cid, core.ut_text()[:4000])
        return
    if text.startswith("/kiszivargas") or text.startswith("/feltoltes"):
        # [v2.16.0]
        log_line("TG parancs: kiszivargas")
        _tg_reply(tok, cid, core.kisz_text())
        return
    if text.startswith("/letoltes"):
        # [v2.15.0]
        log_line("TG parancs: letoltes")
        _tg_reply(tok, cid, core.letoltes_text())
        return
    if text.startswith("/naplo"):
        # [v2.15.0] /naplo [szo] - kereses a naploban (szo nelkul: 24 ora riasztasai)
        from .ui_extra import naplo_kereses_tg
        log_line("TG parancs: naplo")
        _tg_reply(tok, cid, naplo_kereses_tg(text[len("/naplo"):].strip())[:4000])
        return
    if text.startswith("/vagolap"):
        # [v2.14.0]
        log_line("TG parancs: vagolap")
        _tg_reply(tok, cid, core.vagolap_text())
        return
    if text.startswith("/lopas") or text.startswith("/infostealer"):
        # [v2.13.0]
        log_line("TG parancs: lopas")
        _tg_reply(tok, cid, core.lopas_text())
        return
    if text.startswith("/folyamat"):
        log_line("TG parancs: folyamat")
        _tg_reply(tok, cid, core.proc_text())
        return
    if text.startswith("/alairas"):
        # [v2.4.0] egy fajl digitalis alairasa
        ut = text[len("/alairas"):].strip().strip('"')
        if not ut:
            _tg_reply(tok, cid, "Hasznalat: /alairas C:\\ut\\program.exe")
            return
        from .alairas import sig_one
        log_line("TG parancs: alairas %s" % ut[:120])
        si = sig_one(ut) or {}
        _tg_reply(tok, cid, "%s\nAllapot: %s (%s)\nKiado: %s%s" % (
            ut, si.get("allapot", "?"), si.get("status") or "-", si.get("kiado") or "-",
            "\nKatalogus-alairas (Windows-osszetevo)" if si.get("katalogus") else ""))
        return
    # [v2.3.0] javitas: karanten + hosts-visszaallitas
    if text.startswith("/indulotiltas"):
        parts = text.split()
        if len(parts) < 2:
            _tg_reply(tok, cid, "Hasznalat: /indulotiltas <szam vagy nev> [kill]\nA szamokat a /indulo listaja mutatja.")
            return
        leallit = parts[-1].lower() in ("kill", "stop", "leallit")
        mi = " ".join(parts[1:-1] if leallit else parts[1:])
        kulcs = core.startup_find(mi)
        if not kulcs:
            _tg_reply(tok, cid, "Nincs ilyen (vagy tobb azonos nevu) bejegyzes: %s\nNezd meg: /indulo" % mi[:60])
            return
        log_line("TG parancs: indulotiltas %s" % mi)
        _ok, szoveg = core.startup_disable(kulcs, leallit=leallit, ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/karanten"):
        log_line("TG parancs: karanten")
        _tg_reply(tok, cid, core.quarantine_text())
        return
    if text.startswith("/visszaallit"):
        parts = text.split()
        if len(parts) < 2:
            _tg_reply(tok, cid, "Hasznalat: /visszaallit <azonosito>\nAz azonositokat a /karanten mutatja.")
            return
        log_line("TG parancs: visszaallit %s" % parts[1])
        _ok, szoveg = core.quarantine_restore(parts[1], ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/hostsvissza"):
        mod = "alap" if "alap" in text.lower() else "elozo"
        log_line("TG parancs: hostsvissza %s" % mod)
        _ok, szoveg = core.hosts_restore(mod, ki="Telegram")
        _tg_reply(tok, cid, szoveg)
        return
    if text.startswith("/hosts"):
        # [v2.2.0] hosts-fajl
        log_line("TG parancs: hosts")
        _tg_reply(tok, cid, core.hosts_text())
        return
    if text.startswith("/indulo") or text.startswith("/startup"):
        # [v2.2.0] inditopult (a /start ele kell, kulonben a sugot adna)
        log_line("TG parancs: indulo")
        _tg_reply(tok, cid, core.startup_text())
        return
    if text.startswith("/defender"):
        log_line("TG parancs: defender")
        _tg_reply(tok, cid, "Windows Defender:\n" + core.defender_summary().replace(" | ", "\n"))
        return
    if text.startswith("/blokkok"):
        log_line("TG parancs: blokkok")
        _tg_reply(tok, cid, _tg_blokkok_text(core))
        return
    if text.startswith("/passzar"):
        # [v2.21.0] Arrabona Pass zarolasa tavolrol
        log_line("TG parancs: passzar")
        ok, sz = core.pass_zarol("Telegram parancs")
        _tg_reply(tok, cid, ("🔒 " if ok else "⚠ ") + sz)
        return
    if text.startswith("/pass"):
        log_line("TG parancs: pass")
        _tg_reply(tok, cid, core.pass_text())
        return
    if text.startswith("/status"):
        log_line("TG parancs: status")
        _tg_reply(tok, cid, _tg_status_text(core))
        return
    if text.startswith("/segitseg") or text.startswith("/help") or text.startswith("/start"):
        _tg_reply(tok, cid, "Arrabona Guard parancsok:\n/status - allapot\n/blokkok - aktiv blokkok\n/block <IP> - vegleges blokk\n/unblock <IP> - blokk feloldasa\n"
                     "/defender - Defender allapot\n/scan - gyors vizsgalat\n/scanfull - teljes vizsgalat\n"
                     "/stopscan - futo vizsgalat megszakitasa\n"
                     "/defupdate - definiciofrissites\n/usb - uj USB-eszkozok\n"
                     "/hosts - hosts fajl\n/hostsvissza [alap] - hosts visszaallitasa\n"
                     "/indulo - inditopult (indulo programok)\n/indulotiltas <szam> [kill] - karantenba\n"
                     "/karanten - karanten\n/visszaallit <azonosito> - visszaallitas karantenbol\n"
                     "/alairas <ut> - fajl digitalis alairasa\n"
                     "/csapda - ransomware-csapda\n/leallit <PID> - megallitott folyamat leallitasa\n"
                     "/folytat <PID> - megallitott folyamat folytatasa\n"
                     "/folyamat - gyanus folyamatok\n/folyamatreset - megbizhato-lista torlese\n"
                     "/lopas - infostealer-csapda (jelszo-/suti-lopas)\n"
                     "/vagolap - vagolap-vedelem (tarcacim-csere)\n"
                     "/letoltes - letoltesek vizsgalata\n/naplo [szo] - kereses a naploban\n"
                     "/bovitmenyek - bongeszo-bovitmenyek\n"
                     "/lan - eszkozok a halozaton\n/lannev <szam> <nev> - eszkoz elnevezese\n"
                     "/dns - DNS es proxy beallitasok\n/dnsauto - automatikus DNS visszaallitasa\n"
                     "/proxyki - proxy kikapcsolasa\n/jatek be|ki|auto - jatek mod\n"
                     "/pontszam - biztonsagi pontszam + tippek\n/vt <ut> - VirusTotal-ellenorzes\n"
                     "/winupdate - Windows Update allapota\n"
                     "/frissitesek [most] - elavult programok (winget)\n"
                     "/frissit <szam|kiemelt|mind> - program frissitese\n"
                     "/upnp - nyitott portok a routeren (UPnP)\n/upnpzar <szam> - port bezarasa\n"
                     "/kiszivargas - feltoltes-figyeles (adatlopas)\n"
                     "/feladatok [most] - gyanus utemezett feladatok\n"
                     "/feladattiltas <szam> - feladat letiltasa\n/feladatengedely <szam> - feladat engedelyezese\n"
                     "/pass - Arrabona Pass esemenyek\n/passzar - Arrabona Pass zarolasa tavolrol\n"
                     "/guardverzio - Guard verzio + uj kiadas keresese\n/guardfrissit - Guard frissitese az uj verziora")

def _guard_frissit_inditas(tok, cid):
    """[v2.18.0] Guard-frissites Telegramrol: kereses, majd hatterben letoltes + telepites."""
    from . import updater
    if updater.UJ_VERZIO is None:
        updater.keres(kezi=True)
    uj = updater.UJ_VERZIO
    if not uj:
        return (False, "Nincs újabb verzió (most: v%s)." % updater.VERSION)
    if updater.KILEPES_HOOK is None:
        return (False, "A felület még nem állt fel - próbáld pár perc múlva.")
    if updater.frissites_folyamatban():
        return (False, "A frissítés már folyamatban van.")

    def _hatter():
        ok, sz = updater.telepites(updater.KILEPES_HOOK)
        if not ok:
            _tg_reply(tok, cid, "⚠ Guard-frissítés: " + sz)

    threading.Thread(target=_hatter, daemon=True).start()
    return (True, "v%s letöltése és ellenőrzése elindult - siker esetén a Guard újraindul, "
                  "és szól, ha kész." % uj["ver"])


TG_VARAZSLO_AKTIV = False   # [v2.18.0] a beallito varazslo alatt a parancsfigyeles szunetel


def _tg_poll_loop(core):
    import time as _t
    offset = 0
    while True:
        if TG_VARAZSLO_AKTIV:
            _t.sleep(2)
            continue
        tok, cid = _tg_cfg()
        if not tok or not cid:
            _t.sleep(30)
            continue
        try:
            params = {"timeout": 25}
            if offset:
                params["offset"] = offset
            ans = _tg_api(tok, "getUpdates", params)
            for upd in ans.get("result", []):
                uid = upd.get("update_id") or 0
                if uid >= offset:
                    offset = uid + 1
                cq = upd.get("callback_query")
                if cq:
                    # [v2.10.0] gombnyomas - csak a sajat chatbol
                    if str(((cq.get("message") or {}).get("chat") or {}).get("id", "")) == cid:
                        try:
                            _tg_callback(core, tok, cid, cq)
                        except Exception as e:
                            log_line("[TELEGRAM] gomb-feldolgozasi hiba: %s" % e)
                    continue
                msg = upd.get("message") or {}
                chat = str((msg.get("chat") or {}).get("id", ""))
                if chat != cid:
                    continue  # idegen chat: nem fogadunk parancsot
                text = msg.get("text", "")
                if text:
                    try:
                        _tg_handle(core, tok, cid, text)
                    except Exception:
                        pass
        except Exception:
            _t.sleep(10)

# ===================== [v2.10.0] TELEGRAM-GOMBOK =====================
_TG_ACT_FILE = os.path.join(os.environ.get("APPDATA", ""), "ArrabonaGuard", "telegram_gombok.json")
_TG_ACT_LOCK = threading.Lock()
_TG_ACT = None


def _act_load():
    global _TG_ACT
    if _TG_ACT is None:
        try:
            import json as _j
            with open(_TG_ACT_FILE, "r", encoding="utf-8") as f:
                _TG_ACT = _j.load(f)
        except Exception:
            _TG_ACT = {}
    return _TG_ACT


def tg_action(kind, payload):
    """Hosszu adat (pl. inditopult-kulcs) gombhoz: rovid token -> "a:<token>".
    Fajlba mentve, igy a Guard ujrainditasa utan is mukodik (7 napig)."""
    import json as _j
    import random as _r
    import time as _t
    with _TG_ACT_LOCK:
        d = _act_load()
        most = _t.time()
        for k in [k for k, v in d.items() if most - v.get("ts", 0) > 7 * 86400]:
            d.pop(k, None)
        tok = "".join(_r.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(8))
        d[tok] = {"kind": kind, "payload": payload, "ts": most}
        try:
            with open(_TG_ACT_FILE, "w", encoding="utf-8") as f:
                _j.dump(d, f, ensure_ascii=False)
        except OSError:
            pass
    return "a:" + tok


def tg_gombok_auto(core, ip, msg):
    """A riasztas szovegebol / IP-jebol kitalalt gombsorok (None = nincs gomb)."""
    import re as _re
    from .common import is_private_ip
    sorok = []
    m = msg or ""
    pid = _re.search(r"PID (\d+)", m)
    if m.startswith("[CSAPDA]") and "MEGALLITVA" in m and pid:
        sorok.append([("⛔ Leállítás + teljes vizsgálat", "k:%s:full" % pid.group(1)),
                      ("▶ Folytatás (én voltam)", "r:%s" % pid.group(1))])
        return sorok      # itt a ket gomb maga a dontes, "Rendben" nem kell
    if m.startswith("[HOSTS]") and ("megvaltozott" in m or "GYANUS" in m):
        sorok.append([("↩ Hosts visszaállítása", "hv")])
    elif m.startswith("[DNS/PROXY]") and "GYANUS" in m:
        if "PROXY BEKAPCSOLVA" in m or "PROXY MEGVALTOZOTT" in m:
            sorok.append([("⛔ Proxy kikapcsolása", "px")])
        elif "kezi beallitas" in m:
            sorok.append([("↩ Automatikus DNS", "da")])
    elif m.startswith("[DEFENDER]") and ("KARTEVO ESZLELVE" in m or "NEM SIKERULT" in m):
        sorok.append([("🛡 Teljes vizsgálat", "sf")])
    elif (m.startswith("[KIMENO]") or m.startswith("[USB] ") and "PENDRIVE-ROL" in m) and pid:
        sorok.append([("⛔ Program leállítása", "k:%s" % pid.group(1))])
    # IP-s riasztas: kulso IP blokkolasa / feloldasa
    if ip and ip != "127.0.0.1" and not is_private_ip(ip):
        try:
            import ipaddress as _ipa
            _ipa.ip_address(ip)
            if "VEGLEGESEN BLOKKOLVA" in m:
                sorok.append([("🔓 Feloldás", "u:%s" % ip)])
            elif "BLOKKOLVA" in m:
                sorok.append([("🚫 Végleges blokk", "b:%s" % ip), ("🔓 Feloldás", "u:%s" % ip)])
            else:
                sorok.append([("🚫 Végleges blokk", "b:%s" % ip)])
        except ValueError:
            pass
    if not sorok:
        return None
    sorok.append([("✅ Rendben / én voltam", "ok")])
    return sorok


def _tg_unblock(core, ip):
    import time as _t
    bl = core._load_blocks()
    e = bl.get(ip)
    if not (isinstance(e, dict) and not e.get("gone", 0)):
        return "%s nincs az aktiv blokkok kozott." % ip
    core.remove_block_rule(ip)
    try:
        bl = core._load_blocks()
        if ip in bl:
            bl[ip] = {"gone": _t.time()}
            core._save_blocks(bl)
    except Exception:
        pass
    return "%s feloldva." % ip


def _tg_callback(core, tok, cid, cq):
    """Gombnyomas vegrehajtasa; a gombok eltunnek, az uzenet ala kerul az eredmeny."""
    data = cq.get("data") or ""
    uz = cq.get("message") or {}
    log_line("TG gomb: %s" % data)
    try:
        _tg_api(tok, "answerCallbackQuery", {"callback_query_id": cq.get("id"), "text": "Dolgozom…"})
    except Exception:
        pass
    kind, _, arg = data.partition(":")
    if kind == "ok":
        eredm = "✅ Nyugtázva (rendben)"
    elif kind == "b":
        eredm = ("🚫 %s VÉGLEGESEN blokkolva" % arg if core.block_ip_perm(arg, "Telegram gomb")
                 else "⚠ %s nem blokkolható (belső / saját / whitelist)" % arg)
    elif kind == "u":
        eredm = "🔓 " + _tg_unblock(core, arg)
    elif kind == "k":
        pid, _, extra = arg.partition(":")
        ok, sz = core.csali_kill(int(pid), "Telegram gomb")
        if ok and extra == "full":
            core.defender_scan("full")
            sz += " Teljes vizsgalat elinditva."
        eredm = ("⛔ " if ok else "⚠ ") + sz
    elif kind == "r":
        ok, sz = core.csali_resume(int(arg), "Telegram gomb")
        eredm = ("▶ " if ok else "⚠ ") + sz
    elif kind in ("pk", "pr"):
        # [v2.12.0] folyamatfigyeles: pk:<pid>:<ctime>[:full] / pr:<pid>:<ctime>
        r = arg.split(":")
        pid, ct = int(r[0]), (int(r[1]) if len(r) > 1 and r[1].isdigit() else None)
        if kind == "pk":
            ok, sz = core.folyamat_kill(pid, ct, "Telegram gomb")
            if ok and len(r) > 2 and r[2] == "full":
                core.defender_scan("full")
                sz += " Teljes vizsgalat elinditva."
            eredm = ("⛔ " if ok else "⚠ ") + sz
        else:
            ok, sz = core.folyamat_resume(pid, ct, "Telegram gomb")
            eredm = ("▶ " if ok else "⚠ ") + sz
    elif kind == "hv":
        ok, sz = core.hosts_restore("elozo", ki="Telegram gomb")
        eredm = ("↩ " if ok else "⚠ ") + sz
    elif kind == "da":
        ok, sz = core.dns_auto("Telegram gomb")
        eredm = ("↩ " if ok else "⚠ ") + sz
    elif kind == "px":
        ok, sz = core.proxy_off("Telegram gomb")
        eredm = ("⛔ " if ok else "⚠ ") + sz
    elif kind == "wg":
        # [v2.16.0] winget: wg:kiemelt / wg:mind
        ok, sz = core.frissites_upgrade(arg, ki="Telegram gomb")
        eredm = ("⬆ " if ok else "⚠ ") + sz
    elif kind == "gu":
        # [v2.18.0] Arrabona Guard frissitese (GitHub Release)
        ok, sz = _guard_frissit_inditas(tok, cid)
        eredm = ("⬆ " if ok else "⚠ ") + sz
    elif kind == "pl":
        # [v2.21.0] Arrabona Pass zarolasa
        ok, sz = core.pass_zarol("Telegram gomb")
        eredm = ("🔒 " if ok else "⚠ ") + sz
    elif kind == "sf":
        r = core.defender_scan("full")
        eredm = "🛡 Teljes vizsgálat elindítva." if r else "⚠ Már fut egy vizsgálat: %s" % core.def_scan_running
    elif kind == "a":
        with _TG_ACT_LOCK:
            act = _act_load().pop(arg, None)
        if not act:
            eredm = "⚠ Ez a gomb már nem érvényes (már használtad, vagy 7 napnál régebbi) - használd a parancsot."
        elif act["kind"] == "q":
            kulcs = act["payload"]
            if kulcs not in (getattr(core, "_startup_known", None) or {}):
                eredm = "⚠ Ez az induló bejegyzés már nincs meg (közben eltávolították?)."
            else:
                ok, sz = core.startup_disable(kulcs, leallit=True, ki="Telegram gomb")
                eredm = ("🗄 " if ok else "⚠ ") + sz
        elif act["kind"] == "pt":
            pl = act["payload"] or {}
            ok, sz = core.folyamat_trust(pl.get("kulcs"), pl.get("leiras", ""), ki="Telegram gomb")
            eredm = "✅ " + sz
        elif act["kind"] == "lk":
            ok, sz = core.lopas_kivetel((act["payload"] or {}).get("exe"), ki="Telegram gomb")
            eredm = ("✅ " if ok else "⚠ ") + sz
        elif act["kind"] == "uz":
            # [v2.16.0] UPnP-port bezarasa (+ program leallitasa)
            pl = act["payload"] or {}
            ok, sz = core.upnp_zar(pl, pid=pl.get("pid"), ctime=pl.get("ctime"), ki="Telegram gomb")
            eredm = ("⛔ " if ok else "⚠ ") + sz
        elif act["kind"] == "ut":
            pl = act["payload"] or {}
            ok, sz = core.upnp_kivetel(pl.get("desc"), pl.get("ext"), ki="Telegram gomb")
            eredm = ("✅ " if ok else "⚠ ") + sz
        elif act["kind"] in ("ud", "uq", "uk"):
            # [v2.17.0] utemezett feladat: letiltas / + karanten / megbizhato
            pl = act["payload"] or {}
            if act["kind"] == "ud":
                ok, sz = core.ut_tilt(pl.get("ut"), ki="Telegram gomb")
                eredm = ("⏸ " if ok else "⚠ ") + sz
            elif act["kind"] == "uq":
                ok, sz = core.ut_karanten(pl.get("ut"), pl.get("fajl"), ki="Telegram gomb")
                eredm = ("🗄 " if ok else "⚠ ") + sz
            else:
                ok, sz = core.ut_megbizhato(pl.get("ut"), ki="Telegram gomb")
                eredm = ("✅ " if ok else "⚠ ") + sz
        elif act["kind"] == "kt":
            ok, sz = core.kisz_kivetel((act["payload"] or {}).get("exe"), ki="Telegram gomb")
            eredm = ("✅ " if ok else "⚠ ") + sz
        elif act["kind"] == "pq":
            pl = act["payload"] or {}
            ok, sz = core.folyamat_quarantine(pl.get("fajl"), pl.get("pid"), pl.get("ctime"), ki="Telegram gomb")
            eredm = ("🗄 " if ok else "⚠ ") + sz
        else:
            eredm = "⚠ Ismeretlen művelet."
    else:
        eredm = "⚠ Ismeretlen gomb."
    # az eredeti uzenet + eredmeny, gombok nelkul
    try:
        _tg_api(tok, "editMessageText", {"chat_id": cid, "message_id": uz.get("message_id"),
                                         "text": ((uz.get("text") or "") + "\n\n" + eredm)[:4000]})
    except Exception:
        _tg_reply(tok, cid, eredm)


def tg_poll_start(core):
    global TG_POLL_ON
    if TG_POLL_ON:
        return
    TG_POLL_ON = True
    threading.Thread(target=_tg_poll_loop, args=(core,), daemon=True).start()
