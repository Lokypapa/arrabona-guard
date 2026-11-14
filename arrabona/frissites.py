# -*- coding: utf-8 -*-
"""Arrabona Guard - ELAVULT PROGRAMOK FIGYELESE (winget) (GuardCore mixin). [v2.16.0]

A regi, sebezheto programverziok a leggyakoribb behatolasi pontok (bongeszo, 7-Zip,
WinRAR, Discord, Java, PDF-olvaso...). A Windows sajat csomagkezelojevel (winget)
hetente lekerdezi, mi frissitheto, es Telegramon szol. A biztonsag szempontjabol
kiemelt programokat (internetrol jovo adatot / fajlt nyitnak meg) kulon jeloli.

  - frissites.txt: FIGYELES BE/KI, NAPOK 7 (milyen surun), KIHAGY <azonosito vagy nevreszlet>
  - Telegram: /frissitesek [most], /frissit <szam | azonosito | kiemelt | mind>
  - Gombok a heti uzenet alatt: "Kiemeltek frissitese" / "Mind frissitese"
A frissitest SOHA nem inditja magatol - csak ha te kered (gomb / parancs).
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import re
import shutil
import subprocess
import threading
import time
from .common import (APPDATA_DIR, log_line)

FRISSITES_CFG_FILE = os.path.join(APPDATA_DIR, "frissites.txt")
FRISSITES_STATE_FILE = os.path.join(APPDATA_DIR, "frissites_allapot.json")
ELSO_KESLELTETES = 180          # indulas utan ennyi mp-cel nez elso alkalommal (ha esedekes)
LISTA_TIMEOUT = 240
FRISSIT_TIMEOUT = 20 * 60

# (kategoria, minta az azonositora / nevre) - ezek elavult valtozata a legveszelyesebb
_KIEMELT = (
    ("böngésző", re.compile(r"chrome|firefox|msedge|microsoft\.edge\b|brave|opera|vivaldi|librewolf|waterfox|"
                            r"torproject|tor browser|chromium|thorium|floorp|zen-?browser", re.I)),
    ("tömörítő", re.compile(r"7zip|7-zip|winrar|rarlab|peazip|bandizip|nanazip|winzip", re.I)),
    ("csevegő", re.compile(r"discord|telegram|whatsapp|signal|zoom|teams|skype|slack|viber|element", re.I)),
    ("Java", re.compile(r"java|\bjre\b|\bjdk\b|temurin|openjdk|corretto|zulu|oracle\.jdk", re.I)),
    ("PDF-olvasó", re.compile(r"acrobat|adobe\.reader|foxit|sumatra|pdf-?xchange|pdfgear", re.I)),
    ("médialejátszó", re.compile(r"vlc|videolan|k-?lite|codec|mpc-hc|mpc-be|potplayer|winamp|foobar|"
                                 r"aimp|kodi|mpv", re.I)),
    ("távoli elérés", re.compile(r"anydesk|teamviewer|rustdesk|parsec|putty|winscp|filezilla|mobaxterm|"
                                 r"vnc|openvpn|wireguard|tailscale|nomachine|sunshine|moonlight", re.I)),
    ("fejlesztő / szkript", re.compile(r"python|nodejs|node\.js|openjs|git\.git|^git$|notepad\+\+|"
                                       r"notepadplusplus|vscode|visualstudiocode|php|ruby|perl", re.I)),
    ("irodai", re.compile(r"libreoffice|onlyoffice|wps|microsoft\.office|thunderbird|mailbird", re.I)),
    ("képszerkesztő / néző", re.compile(r"irfanview|xnview|gimp|paint\.net|imageglass|faststone", re.I)),
)
_FEJLEC_SOR = re.compile(r"^\s*-{8,}\s*$")
_ID_OK = re.compile(r"^\S{2,}$")


def frissites_cfg():
    cfg = {"FIGYELES": "BE", "NAPOK": 7, "KIHAGY": []}
    try:
        if not os.path.exists(FRISSITES_CFG_FILE):
            os.makedirs(APPDATA_DIR, exist_ok=True)
            with open(FRISSITES_CFG_FILE, "w", encoding="utf-8") as f:
                f.write("# Arrabona Guard - elavult programok figyelese (winget) (v2.16.0)\n"
                        "FIGYELES BE\n"
                        "# NAPOK <n> = ennyi naponta kerdezi le (alap: 7 = hetente)\n"
                        "NAPOK 7\n"
                        "# KIHAGY <azonosito vagy nevreszlet> = ezt ne jelezze (tobb sor is lehet), pl.:\n"
                        "# KIHAGY Valve.Steam\n")
        with open(FRISSITES_CFG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith("#"):
                    continue
                r = ln.split(None, 1)
                k, v = r[0].upper(), (r[1].strip() if len(r) > 1 else "")
                if k == "KIHAGY" and v:
                    cfg["KIHAGY"].append(v.lower())
                elif k == "NAPOK" and v.isdigit() and 1 <= int(v) <= 60:
                    cfg["NAPOK"] = int(v)
                elif k == "FIGYELES" and v.upper() in ("BE", "KI", "ON", "OFF"):
                    cfg["FIGYELES"] = "KI" if v.upper() in ("KI", "OFF") else "BE"
    except Exception:
        pass
    return cfg


def winget_exe():
    p = shutil.which("winget")
    if p:
        return p
    p = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "WindowsApps", "winget.exe")
    return p if os.path.exists(p) else None


def _dekodol(b):
    if not b:
        return ""
    for enc in ("utf-8", "cp852", "mbcs"):
        try:
            return b.decode(enc)
        except (UnicodeDecodeError, LookupError):
            pass
    return b.decode("utf-8", errors="replace")


def _sorok(szoveg):
    """A winget a folyamatjelzot \\r-rel irja felul: soronkent csak az utolso \\r utani resz kell."""
    out = []
    for ln in (szoveg or "").replace("﻿", "").split("\n"):
        ln = ln.rstrip("\r")
        if "\r" in ln:
            ln = ln.rsplit("\r", 1)[1]
        out.append(ln.rstrip())
    return out


def winget_parse(szoveg):
    """A 'winget upgrade' tablazata(i) -> [{"nev","id","verzio","elerheto","forras","explicit"}].
    Oszlophatarok a fejlecbol (nyelvfuggetlen: Name/Név, Id/Azonosító...). A masodik tablazat
    ("csak kifejezett megadassal frissitheto") elemeit is visszaadja, explicit=True jelolessel."""
    sorok = _sorok(szoveg)
    out = []
    tabla = 0
    i = 0
    while i < len(sorok):
        if not _FEJLEC_SOR.match(sorok[i]) or i == 0:
            i += 1
            continue
        fejlec = sorok[i - 1]
        kezdok = [m.start() for m in re.finditer(r"\S+", fejlec)]
        tabla += 1
        i += 1
        if len(kezdok) < 4:
            continue
        kezdok = kezdok[:5]
        while i < len(sorok) and sorok[i].strip():
            ln = sorok[i]
            if _FEJLEC_SOR.match(ln):
                break
            mezok = []
            for j, k in enumerate(kezdok):
                v = ln[k:kezdok[j + 1]] if j + 1 < len(kezdok) else ln[k:]
                mezok.append(v.strip())
            while len(mezok) < 5:
                mezok.append("")
            nev, pid, ver, eler, forras = mezok[:5]
            if len(kezdok) == 4:      # Forras oszlop nelkul
                forras = ""
            if pid and _ID_OK.match(pid) and ver and eler and len(ln) > kezdok[2]:
                out.append({"nev": nev or pid, "id": pid, "verzio": ver, "elerheto": eler,
                            "forras": forras, "explicit": tabla > 1})
            i += 1
    # egy csomag ketszer (mindket tablaban) ne szerepeljen
    lat, uniq = set(), []
    for r in out:
        if r["id"].lower() not in lat:
            lat.add(r["id"].lower())
            uniq.append(r)
    return uniq


def kiemelt(r):
    """A csomag biztonsagi kategoriaja (pl. "böngésző"), vagy "" ha nem kiemelt."""
    s = "%s %s" % (r.get("id", ""), r.get("nev", ""))
    for kat, rx in _KIEMELT:
        if rx.search(s):
            return kat
    return ""


def _winget_verzio(exe):
    try:
        r = subprocess.run([exe, "--version"], capture_output=True, timeout=30)
        m = re.search(r"(\d+)\.(\d+)", _dekodol(r.stdout))
        return (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    except Exception:
        return (0, 0)


def _hex(rc):
    try:
        return "0x%08X" % (rc & 0xFFFFFFFF)
    except Exception:
        return str(rc)


_RC_MAGYAR = {0x8A15002B: "nincs alkalmazható frissítés (a program maga frissül, vagy más telepítő kell)",
              0x8A150056: "a telepített változat más módon került fel - kézzel kell frissíteni",
              0x8A150011: "a telepítő hash-e nem egyezik (a winget biztonsági okból nem futtatta)",
              0x8A15010B: "a program fut - zárd be, és próbáld újra",
              0x8A150101: "a program fut - zárd be, és próbáld újra",
              0x8A15000F: "a csomagforrás nem érhető el (internet?)",
              0x8A150014: "nincs ilyen csomag (közben eltávolították?)",
              0x8A150109: "újraindítás kell a befejezéshez"}


class FrissitesMixin(object):
    """Elavult programok figyelese (winget). A GuardCore resze (mixin)."""

    # ------------------------------------------------------------ allapot-fajl
    def _fr_load(self):
        try:
            with open(FRISSITES_STATE_FILE, "r", encoding="utf-8") as f:
                d = _json.load(f)
                if isinstance(d, dict):
                    return d
        except (OSError, ValueError):
            pass
        return {"last": 0, "lista": None, "ertesitett": []}

    def _fr_save(self):
        try:
            tmp = FRISSITES_STATE_FILE + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                _json.dump(self._fr_state, f, ensure_ascii=False, indent=1)
            os.replace(tmp, FRISSITES_STATE_FILE)
        except OSError as e:
            log_line("[FRISSITES] mentesi hiba: %s" % e)

    # ------------------------------------------------------------ lekerdezes
    def _fr_args(self, exe):
        if not hasattr(self, "_fr_wver"):
            self._fr_wver = _winget_verzio(exe)
        return ["--disable-interactivity"] if self._fr_wver >= (1, 4) else []

    def _fr_lekerdez(self):
        """(lista, hiba) - lista: a frissitheto csomagok (a KIHAGY-ottak nelkul)."""
        exe = winget_exe()
        if not exe:
            return None, "a winget nem érhető el (Microsoft Store: 'Alkalmazástelepítő' / App Installer)"
        args = [exe, "upgrade", "--include-unknown", "--accept-source-agreements"] + self._fr_args(exe)
        try:
            r = subprocess.run(args, capture_output=True, timeout=LISTA_TIMEOUT)
        except subprocess.TimeoutExpired:
            return None, "a winget nem válaszolt %d mp alatt" % LISTA_TIMEOUT
        except Exception as e:
            return None, "winget-hiba: %s" % e
        szoveg = _dekodol(r.stdout)
        lista = winget_parse(szoveg)
        rc = r.returncode & 0xFFFFFFFF
        if not lista and rc not in (0, 0x8A150014) and not re.search(r"-{8,}", szoveg):
            # nincs tablazat ES hibakod: valodi hiba (pl. a csomagforras nem erheto el)
            # (0x8A150014 = "nincs talalat" -> ez a "minden naprakesz" eset)
            utolso = [s for s in _sorok(szoveg) if s.strip()][-1:] or [""]
            return None, "winget hibakód %s %s" % (_hex(rc), utolso[0][:120])
        kihagy = self._fr_cfg["KIHAGY"]
        lista = [x for x in lista if not any(k in x["id"].lower() or k in x["nev"].lower() for k in kihagy)]
        for x in lista:
            x["kat"] = kiemelt(x)
        # kiemeltek elol, aztan nev szerint
        lista.sort(key=lambda x: (not x["kat"], x["nev"].lower()))
        return lista, None

    def frissites_check(self, ertesit=True, ki="automatikus"):
        """Lekerdezes + (ertesit=True eseten) Telegram-uzenet. Visszaad: (ok, szoveg)."""
        if not self._fr_check_lock.acquire(blocking=False):
            return False, "Már fut egy lekérdezés - pár perc múlva nézd: /frissitesek"
        try:
            self.frissites_status = "lekérdezés…"
            lista, hiba = self._fr_lekerdez()
            most = time.time()
            if hiba:
                self.frissites_status = "hiba: %s" % hiba
                self._fr_hiba = hiba
                log_line("[FRISSITES] lekerdezesi hiba: %s" % hiba)
                # 6 ora mulva ujra probalja (nem egy het mulva)
                self._fr_state["retry"] = most + 6 * 3600
                self._fr_save()
                return False, "Nem sikerült lekérdezni: %s" % hiba
            self._fr_hiba = None
            regi = set(self._fr_state.get("ertesitett") or [])
            self._fr_state.update({"last": most, "lista": lista, "retry": 0})
            self.frissites_status = "aktív"
            kiem = [x for x in lista if x["kat"]]
            log_line("[FRISSITES] winget (%s): %d frissitheto program, ebbol %d kiemelt%s" % (
                ki, len(lista), len(kiem), (": " + ", ".join("%s %s->%s" % (x["nev"], x["verzio"], x["elerheto"])
                                                              for x in kiem[:15])) if kiem else ""))
            if ertesit:
                self._fr_ertesit(lista, regi)
            self._fr_state["ertesitett"] = ["%s|%s" % (x["id"], x["elerheto"]) for x in lista]
            self._fr_save()
            return True, self.frissites_text()
        finally:
            self._fr_check_lock.release()

    def _fr_ertesit(self, lista, regi):
        from .telegram import tg_send
        if not lista:
            tg_send("✅ [FRISSITES] Heti ellenőrzés: minden program naprakész (winget).")
            return
        kiem = [x for x in lista if x["kat"]]
        fej = ("⚠ [FRISSITES] ELAVULT PROGRAMOK: %d frissíthető, ebből %d BIZTONSÁGI SZEMPONTBÓL KIEMELT"
               % (len(lista), len(kiem)) if kiem else
               "[FRISSITES] Heti ellenőrzés: %d program frissíthető (egyik sem kiemelt)" % len(lista))
        sorok = [fej]
        for i, x in enumerate(lista[:30], 1):
            uj = "%s|%s" % (x["id"], x["elerheto"]) not in regi
            sorok.append("%d. %s %s → %s%s%s" % (i, x["nev"][:34], x["verzio"][:16], x["elerheto"][:16],
                                                 (" [%s ⚠]" % x["kat"]) if x["kat"] else "", " 🆕" if uj else ""))
        if len(lista) > 30:
            sorok.append("… és még %d (lista: /frissitesek)" % (len(lista) - 30))
        sorok.append("A régi böngésző / tömörítő / csevegő a leggyakoribb behatolási pont - "
                     "a kiemelteket érdemes MOST frissíteni. Egyenként: /frissit <szám>")
        gombok = []
        if kiem:
            gombok.append([("⬆ Kiemeltek frissítése (%d)" % len(kiem), "wg:kiemelt")])
        gombok.append([("⬆ Mind frissítése (%d)" % len(lista), "wg:mind")])
        gombok.append([("✅ Rendben, később", "ok")])
        log_line("[FRISSITES] %s" % fej.replace("⚠ [FRISSITES] ", "").replace("[FRISSITES] ", ""))
        tg_send("\n".join(sorok), gombok)
        try:
            self.out.put(("status", "Elavult programok: %d (kiemelt: %d) - Telegram: /frissitesek" % (
                len(lista), len(kiem))))
        except Exception:
            pass

    # ------------------------------------------------------------ frissites (csak kerésre)
    def frissites_upgrade(self, mi, ki="Telegram"):
        """mi: 'mind' / 'kiemelt' / sorszam / azonosito. A hatterben fut; a vegen Telegram-osszegzes.
        Visszaad: (ok, szoveg) - az inditas eredmenye."""
        lista = self._fr_state.get("lista") or []
        mi = (mi or "").strip()
        if mi.lower() in ("mind", "all", "minden"):
            cel = list(lista)
        elif mi.lower() in ("kiemelt", "kiemeltek", "fontos"):
            cel = [x for x in lista if x.get("kat")]
        elif mi.isdigit():
            if not 1 <= int(mi) <= len(lista):
                return False, "Nincs ilyen sorszám (1-%d). Lista: /frissitesek" % len(lista)
            cel = [lista[int(mi) - 1]]
        else:
            cel = [x for x in lista if x["id"].lower() == mi.lower()]
            if not cel and mi:
                cel = [{"id": mi, "nev": mi, "verzio": "?", "elerheto": "?", "kat": "", "explicit": True}]
        if not cel:
            return False, "Nincs mit frissíteni (lista: /frissitesek)."
        if getattr(self, "_fr_upg_thread", None) and self._fr_upg_thread.is_alive():
            return False, "Már fut egy frissítés - megvárom, utána kérd újra."
        exe = winget_exe()
        if not exe:
            return False, "A winget nem érhető el."
        self._fr_upg_thread = threading.Thread(target=self._fr_upgrade_run, args=(exe, cel, ki),
                                               name="frissites-upgrade", daemon=True)
        self._fr_upg_thread.start()
        return True, "Frissítés elindítva: %d program (%s). A végén szólok." % (
            len(cel), ", ".join(x["nev"][:24] for x in cel[:6]) + (" …" if len(cel) > 6 else ""))

    def _fr_upgrade_run(self, exe, cel, ki):
        from .telegram import tg_send
        log_line("[FRISSITES] frissites indul (%s): %s" % (ki, ", ".join(x["id"] for x in cel)))
        self.frissites_status = "frissítés fut (%d)…" % len(cel)
        jo, rossz = [], []
        for x in cel:
            args = [exe, "upgrade", "--id", x["id"], "--exact", "--silent", "--accept-package-agreements",
                    "--accept-source-agreements", "--include-unknown"] + self._fr_args(exe)
            try:
                r = subprocess.run(args, capture_output=True, timeout=FRISSIT_TIMEOUT)
                rc = r.returncode & 0xFFFFFFFF
                if rc == 0:
                    jo.append(x["nev"])
                    log_line("[FRISSITES] frissitve: %s (%s -> %s)" % (x["id"], x["verzio"], x["elerheto"]))
                else:
                    ok = _RC_MAGYAR.get(rc, "hibakód %s" % _hex(rc))
                    rossz.append("%s: %s" % (x["nev"][:30], ok))
                    log_line("[FRISSITES] NEM sikerult: %s - %s" % (x["id"], ok))
            except subprocess.TimeoutExpired:
                rossz.append("%s: időtúllépés (%d perc)" % (x["nev"][:30], FRISSIT_TIMEOUT // 60))
            except Exception as e:
                rossz.append("%s: %s" % (x["nev"][:30], e))
        self.frissites_status = "aktív"
        try:
            self.frissites_check(ertesit=False, ki="frissites utan")
        except Exception:
            pass
        maradt = len(self._fr_state.get("lista") or [])
        sorok = ["⬆ [FRISSITES] Kész: %d sikeres, %d sikertelen. Még frissíthető: %d" % (len(jo), len(rossz), maradt)]
        if jo:
            sorok.append("Sikeres: " + ", ".join(jo[:20]))
        if rossz:
            sorok.append("Nem sikerült:")
            sorok.extend("  " + s for s in rossz[:15])
        tg_send("\n".join(sorok))
        try:
            self.out.put(("status", sorok[0].replace("⬆ [FRISSITES] ", "Programfrissítés: ")))
        except Exception:
            pass

    # ------------------------------------------------------------ ciklus
    def _fr_loop(self):
        if self._fr_stop_ev.wait(ELSO_KESLELTETES):
            return
        while True:
            try:
                self._fr_cfg = frissites_cfg()
                if self._fr_cfg["FIGYELES"] != "BE":
                    self.frissites_status = "kikapcsolva (frissites.txt)"
                elif not winget_exe():
                    self.frissites_status = "nem elérhető (nincs winget)"
                else:
                    if self.frissites_status.startswith(("kikapcsolva", "indulás", "nem elérhető")):
                        self.frissites_status = "aktív"
                    esedekes = (time.time() - float(self._fr_state.get("last") or 0) >= self._fr_cfg["NAPOK"] * 86400
                                and time.time() >= float(self._fr_state.get("retry") or 0))
                    jatek = False
                    try:
                        jatek = self.game_active()
                    except Exception:
                        pass
                    if esedekes and not jatek and self.is_on():
                        self.frissites_check(ertesit=True)
            except Exception as e:
                log_line("[FRISSITES] hiba: %s" % e)
            if self._fr_stop_ev.wait(600):
                return

    def _frissites_start(self):
        if getattr(self, "_fr_thread", None) and self._fr_thread.is_alive():
            return
        self._fr_cfg = frissites_cfg()
        self._fr_state = self._fr_load()
        self._fr_check_lock = threading.Lock()
        self._fr_hiba = None
        self.frissites_status = "indulás…"
        self._fr_t0 = time.time()
        self._fr_stop_ev = threading.Event()
        self._fr_thread = threading.Thread(target=self._fr_loop, name="frissites", daemon=True)
        self._fr_thread.start()

    def _frissites_stop(self):
        ev = getattr(self, "_fr_stop_ev", None)
        if ev is not None:
            ev.set()

    # ------------------------------------------------------------ megjelenites
    def frissites_lista(self):
        """None = meg nem volt lekerdezes; kulonben a lista."""
        st = getattr(self, "_fr_state", None) or {}
        return st.get("lista")

    def frissites_summary(self):
        s = getattr(self, "frissites_status", "?")
        lista = self.frissites_lista()
        if lista is None:
            if s.startswith("indulás") or s == "aktív":
                t1 = getattr(self, "_fr_t0", time.time()) + ELSO_KESLELTETES
                hatra = int((t1 - time.time()) // 60)
                return "Első lekérdezés: %s%s" % (time.strftime("%H:%M", time.localtime(t1)),
                                                  (" (még %d perc)" % (hatra + 1)) if hatra >= 0 else " (folyamatban…)")
            return s
        kiem = sum(1 for x in lista if x.get("kat"))
        last = float(self._fr_state.get("last") or 0)
        reszek = ["Frissíthető: %d" % len(lista)]
        if kiem:
            reszek.append("Kiemelt: %d ⚠" % kiem)
        elif not lista:
            reszek = ["Minden naprakész ✔"]
        if last:
            reszek.append("Utolsó: %s" % time.strftime("%m-%d %H:%M", time.localtime(last)))
            reszek.append("Következő: %s" % time.strftime("%m-%d", time.localtime(
                last + self._fr_cfg["NAPOK"] * 86400)))
        if s != "aktív" and not s.startswith("indulás"):
            reszek.append(s)
        return " | ".join(reszek)

    def frissites_ok(self):
        """None = nincs adat; True = nincs elavult kiemelt program."""
        lista = self.frissites_lista()
        if lista is None:
            return None
        return not any(x.get("kat") for x in lista)

    def frissites_text(self):
        lista = self.frissites_lista()
        sorok = ["ELAVULT PROGRAMOK (winget): %s" % self.frissites_summary().replace(" | ", ", ")]
        if lista is None:
            sorok.append("Meg nem volt lekerdezes. Most: /frissitesek most")
            return "\n".join(sorok)
        for i, x in enumerate(lista[:40], 1):
            sorok.append("%d. %s  %s -> %s%s%s" % (i, x["nev"][:36], x["verzio"][:16], x["elerheto"][:16],
                                                  (" [%s !]" % x["kat"]) if x.get("kat") else "",
                                                  " (kezi)" if x.get("explicit") else ""))
        if lista:
            sorok.append("Frissites: /frissit <szam> | /frissit kiemelt | /frissit mind")
        sorok.append("Kihagyas: frissites.txt -> KIHAGY <azonosito>")
        return "\n".join(sorok)
