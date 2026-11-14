# -*- coding: utf-8 -*-
"""Arrabona Guard - kenyelmi funkciok a feluleten. [v2.15.0]

  - BEALLITASOK MENTESE / VISSZAALLITASA: az osszes beallito- es ismert-lista fajl
    (whitelist, feketelista, folyamat.txt, telegram.txt, ismert USB / LAN eszkozok,
    megbizhato programok...) egyetlen ZIP-be; visszaallitas elott a mostani allapotrol
    is keszul egy biztonsagi mentes.
  - KERESHETO NAPLO: szures szovegre, modulra, idoszakra; csak riasztasok; exportalas.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import datetime
import os
import re
import time
import tkinter as tk
import tkinter.filedialog as _fd
import tkinter.messagebox as _mb
import zipfile
from tkinter import ttk
from .common import (APP_NAME, APPDATA_DIR, COLORS, LOG_FILE, VERSION, log_line)

# futas kozbeni allapot / gyorsitotar / naplo: NEM resze a mentesnek
_KIHAGY = {"guard_naplo.txt", "heartbeat.txt", "mutex_dupla_naplo.txt", "kilepes.flag", "restart.flag",
           "telegram_gombok.json", "riport_state.json", "virustotal_cache.json", "csali_allapot.json",
           "infolopas_csalik.json", "blokkok.json", "watchdog.vbs",
           "frissites_allapot.json"}
_MODULOK = (("Minden sor", ""), ("Csak riasztások", "!RIASZTAS"), ("Folyamatfigyelés", "[FOLYAMAT]"),
            ("Infostealer-csapda", "[INFOLOPAS]"), ("Vágólap", "[VAGOLAP]"), ("Letöltések", "[LETOLTES]"),
            ("Adatkiszivárgás", "[KISZIVARGAS]"), ("Router-portok (UPnP)", "[UPNP]"),
            ("Elavult programok", "[FRISSITES]"),
            ("Ütemezett feladatok", "[UTEMEZETT]"),
            ("Defender", "[DEFENDER]"), ("Ransomware-csapda", "[CSAPDA]"), ("Indítópult", "[INDITOPULT]"),
            ("USB", "[USB]"), ("LAN-eszközök", "[LAN]"), ("DNS / proxy", "[DNS/PROXY]"),
            ("Bejelentkezés / fiókok", "[BIZTONSAG]"), ("Kimenő kapcsolatok", "[KIMENO]"),
            ("Blokkolás", "BLOKK"), ("Honeypot", "HONEYPOT"), ("VirusTotal", "[VIRUSTOTAL]"),
            ("Telegram", "TG "), ("Hibák", "hiba"))
_IDOK = (("Utolsó 1 óra", 3600), ("Utolsó 24 óra", 86400), ("Utolsó 7 nap", 7 * 86400), ("Teljes napló", 0))
_RIASZTAS = re.compile(r"GYANUS|KRITIKUS|VESZELYES|KARTEVO|BLOKKOLVA|PORTSCAN|HONEYPOT|FEKETELIST|"
                       r"SYN-FLOOD|ARP-MERGEZES|ZSAROLOVIRUS|CLIPPER|ADATLOPO|JELSZOLOPAS|UJ ESZKOZ|UJ USB|"
                       r"UJ INDULO|TOROLVE|4625|SIKERES KULSO|UJ KIVETEL|KIKAPCSOLVA|NEM FUTOTT|ROSSZ IP|"
                       r"NYITOTT PORT|VESZELYES PORT|FELTOLTES:|ELAVULT PROGRAMOK|UTEMEZETT FELADAT:", re.I)


def _gomb(parent, text, cmd, szin=None):
    b = tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=szin or COLORS['ok'], fg="#ffffff", activebackground=szin or COLORS['ok'],
                  activeforeground="#ffffff", cursor="hand2", padx=10, pady=3)
    b.pack(side=tk.LEFT, padx=(0, 6))
    return b


# ===================================================================== mentes / visszaallitas
def mentheto_fajlok():
    out = []
    try:
        for n in sorted(os.listdir(APPDATA_DIR)):
            p = os.path.join(APPDATA_DIR, n)
            if (os.path.isfile(p) and n.lower() not in _KIHAGY and not n.startswith("_visszaallitas_elott")
                    and os.path.splitext(n)[1].lower() in (".txt", ".json") and os.path.getsize(p) < 20 * 1024 * 1024):
                out.append(p)
    except OSError:
        pass
    return out


def beallitas_zip(cel):
    """Visszaad: a mentett fajlok szama."""
    fajlok = mentheto_fajlok()
    with zipfile.ZipFile(cel, "w", zipfile.ZIP_DEFLATED) as z:
        for p in fajlok:
            z.write(p, os.path.basename(p))
        z.writestr("_arrabona_mentes.txt", "Arrabona Guard v%s beallitas-mentes\n%s\n%d fajl\n" % (
            VERSION, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), len(fajlok)))
    return len(fajlok)


def beallitas_ellenoriz(forras):
    """A mentes-ZIP ellenorzese. Visszaad: (ok, [nevek] vagy hibaszoveg)."""
    try:
        with zipfile.ZipFile(forras) as z:
            nevek = [i.filename for i in z.infolist() if not i.is_dir()]
            if "_arrabona_mentes.txt" not in nevek:
                return False, "Ez nem Arrabona Guard beállítás-mentés (hiányzik a _arrabona_mentes.txt)."
            jo = []
            for i in z.infolist():
                n = i.filename
                if n == "_arrabona_mentes.txt" or i.is_dir():
                    continue
                # csak sima fajlnev (nincs mappa / ..), csak .txt / .json, eszszeru meret
                if ("/" in n or "\\" in n or ".." in n or n.lower() in _KIHAGY
                        or os.path.splitext(n)[1].lower() not in (".txt", ".json") or i.file_size > 20 * 1024 * 1024):
                    continue
                jo.append(n)
            return True, jo
    except (zipfile.BadZipFile, OSError) as e:
        return False, "Nem olvasható ZIP: %s" % e


def beallitas_kibont(forras, nevek):
    with zipfile.ZipFile(forras) as z:
        for n in nevek:
            adat = z.read(n)
            tmp = os.path.join(APPDATA_DIR, n + ".tmp")
            with open(tmp, "wb") as f:
                f.write(adat)
            os.replace(tmp, os.path.join(APPDATA_DIR, n))


def backup_settings(app):
    alap = "ArrabonaGuard_beallitasok_%s.zip" % time.strftime("%Y%m%d_%H%M")
    cel = _fd.asksaveasfilename(parent=app.root, title="Beállítások mentése", initialfile=alap,
                                defaultextension=".zip", filetypes=[("ZIP", "*.zip")])
    if not cel:
        return
    try:
        n = beallitas_zip(cel)
    except Exception as e:
        _mb.showerror(APP_NAME, "A mentés nem sikerült:\n%s" % e, parent=app.root)
        return
    log_line("[BEALLITAS] mentes: %s (%d fajl)" % (cel, n))
    _mb.showinfo(APP_NAME, ("Kész: %d beállítás-fájl elmentve ide:\n%s\n\n"
                            "⚠ A mentés tartalmazza a Telegram-tokent és a VirusTotal-kulcsot is (ha be vannak "
                            "állítva) - tárold biztonságos helyen, ne oszd meg senkivel.") % (n, cel), parent=app.root)


def restore_settings(app):
    forras = _fd.askopenfilename(parent=app.root, title="Beállítások visszaállítása",
                                 filetypes=[("Arrabona mentés (ZIP)", "*.zip")])
    if not forras:
        return
    ok, nevek = beallitas_ellenoriz(forras)
    if not ok:
        _mb.showerror(APP_NAME, nevek, parent=app.root)
        return
    if not nevek:
        _mb.showwarning(APP_NAME, "A mentésben nincs visszaállítható fájl.", parent=app.root)
        return
    if not _mb.askyesno(APP_NAME, ("%d fájl visszaállítása?\n\n%s%s\n\nA mostani beállításokról előtte biztonsági "
                                   "mentés készül (_visszaallitas_elott_….zip a Guard mappájában), utána a Guard "
                                   "újraindul.") % (len(nevek), ", ".join(nevek[:12]), " …" if len(nevek) > 12 else ""),
                        parent=app.root):
        return
    try:
        elotte = os.path.join(APPDATA_DIR, "_visszaallitas_elott_%s.zip" % time.strftime("%Y%m%d_%H%M%S"))
        beallitas_zip(elotte)
        beallitas_kibont(forras, nevek)
    except Exception as e:
        _mb.showerror(APP_NAME, "A visszaállítás nem sikerült:\n%s" % e, parent=app.root)
        return
    log_line("[BEALLITAS] visszaallitva: %s (%d fajl), elozo allapot: %s" % (forras, len(nevek), elotte))
    _mb.showinfo(APP_NAME, "Visszaállítva (%d fájl). A Guard most újraindul." % len(nevek), parent=app.root)
    app._restart_app()


# ===================================================================== kereso naplo
def naplo_sorok(max_bajt=8 * 1024 * 1024):
    try:
        with open(LOG_FILE, "rb") as f:
            f.seek(0, 2)
            meret = f.tell()
            f.seek(max(0, meret - max_bajt))
            adat = f.read()
    except OSError:
        return []
    t = adat.decode("utf-8", errors="replace")
    sorok = [s for s in t.splitlines() if s.strip()]
    if meret > max_bajt and sorok:
        sorok = sorok[1:]          # az elso (csonka) sor
    return sorok


def szur(sorok, szoveg="", modul="", mp=0, most=None):
    most = most or time.time()
    hatar = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(most - mp)) if mp else ""
    sz = (szoveg or "").lower().strip()
    out = []
    for s in sorok:
        if hatar and (len(s) < 21 or s[0] != "[" or s[1:20] < hatar):
            continue
        if modul == "!RIASZTAS":
            if not _RIASZTAS.search(s):
                continue
        elif modul == "hiba":
            if " hiba" not in s.lower() and "sikertelen" not in s.lower():
                continue
        elif modul and modul not in s:
            continue
        if sz and sz not in s.lower():
            continue
        out.append(s)
    return out


def open_log_dialog(app):
    regi = getattr(app, "_log_dlg", None)
    if regi is not None and regi.winfo_exists():
        regi.lift()
        return
    dlg = tk.Toplevel(app.root)
    app._log_dlg = dlg
    dlg.title("%s — Napló keresés" % APP_NAME)
    dlg.configure(bg=COLORS['bg'])
    dlg.geometry("1100x600")
    dlg.minsize(760, 360)

    def _close():
        try:
            dlg.bind_all("<MouseWheel>", app._on_mousewheel)
        except Exception:
            pass
        dlg.destroy()
    dlg.protocol("WM_DELETE_WINDOW", _close)
    dlg.bind_all("<MouseWheel>", lambda e: None)

    sav = tk.Frame(dlg, bg=COLORS['bg'])
    sav.pack(fill=tk.X, padx=10, pady=(10, 4))
    tk.Label(sav, text="Keresés:", bg=COLORS['bg'], fg=COLORS['text'], font=("Segoe UI", 9)).pack(side=tk.LEFT)
    v_sz = tk.StringVar()
    e = tk.Entry(sav, textvariable=v_sz, font=("Segoe UI", 10), width=28)
    e.pack(side=tk.LEFT, padx=(4, 10))
    v_mod = tk.StringVar(value=_MODULOK[1][0])
    cb_mod = ttk.Combobox(sav, textvariable=v_mod, values=[m[0] for m in _MODULOK], state="readonly", width=24)
    cb_mod.pack(side=tk.LEFT, padx=(0, 8))
    v_ido = tk.StringVar(value=_IDOK[1][0])
    cb_ido = ttk.Combobox(sav, textvariable=v_ido, values=[i[0] for i in _IDOK], state="readonly", width=14)
    cb_ido.pack(side=tk.LEFT, padx=(0, 8))
    v_info = tk.StringVar(value="")

    keret = tk.Frame(dlg, bg=COLORS['panel'])
    keret.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)
    txt = tk.Text(keret, wrap="none", font=("Consolas", 9), bg=COLORS['panel'], fg=COLORS['text'],
                  relief="flat", bd=0, padx=6, pady=4)
    sy = tk.Scrollbar(keret, orient="vertical", command=txt.yview)
    sx = tk.Scrollbar(keret, orient="horizontal", command=txt.xview)
    txt.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
    sy.pack(side=tk.RIGHT, fill=tk.Y)
    sx.pack(side=tk.BOTTOM, fill=tk.X)
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    txt.bind("<MouseWheel>", lambda ev: txt.yview_scroll(int(-ev.delta / 120), "units"))
    txt.tag_configure("talalat", background="#f9e79f", foreground="#000000")
    txt.tag_configure("riaszt", foreground=COLORS['bad'])
    allapot = {"sorok": [], "szurt": []}

    def _frissit(ujraolvas=False):
        if ujraolvas or not allapot["sorok"]:
            allapot["sorok"] = naplo_sorok()
        modul = dict(_MODULOK).get(v_mod.get(), "")
        mp = dict(_IDOK).get(v_ido.get(), 0)
        szurt = szur(allapot["sorok"], v_sz.get(), modul, mp)
        allapot["szurt"] = szurt
        txt.configure(state="normal")
        txt.delete("1.0", tk.END)
        mutat = szurt[-3000:]          # a legfrissebb 3000 sor (a teljes lista exportalhato)
        for s in reversed(mutat):      # legfrissebb felul
            txt.insert(tk.END, s + "\n", ("riaszt",) if _RIASZTAS.search(s) else ())
        sz = v_sz.get().strip()
        if sz:
            start = "1.0"
            while True:
                pos = txt.search(sz, start, stopindex=tk.END, nocase=True)
                if not pos:
                    break
                vege = "%s+%dc" % (pos, len(sz))
                txt.tag_add("talalat", pos, vege)
                start = vege
        txt.configure(state="disabled")
        v_info.set("%d találat (%d sorból)%s" % (len(szurt), len(allapot["sorok"]),
                                                 " - a legfrissebb 3000 látszik" if len(szurt) > 3000 else ""))

    def _export():
        cel = _fd.asksaveasfilename(parent=dlg, title="Szűrt napló mentése", defaultextension=".txt",
                                    initialfile="arrabona_naplo_%s.txt" % time.strftime("%Y%m%d_%H%M"),
                                    filetypes=[("Szöveg", "*.txt")])
        if not cel:
            return
        try:
            with open(cel, "w", encoding="utf-8") as f:
                f.write("\n".join(allapot["szurt"]) + "\n")
            v_info.set("Elmentve: %s (%d sor)" % (cel, len(allapot["szurt"])))
        except OSError as ex:
            _mb.showerror(APP_NAME, "Nem sikerült: %s" % ex, parent=dlg)

    _gomb(sav, "🔎 Keresés", lambda: _frissit())
    _gomb(sav, "🔄 Újraolvasás", lambda: _frissit(True))
    _gomb(sav, "💾 Export", _export, COLORS['warn'])
    e.bind("<Return>", lambda ev: _frissit())
    cb_mod.bind("<<ComboboxSelected>>", lambda ev: _frissit())
    cb_ido.bind("<<ComboboxSelected>>", lambda ev: _frissit())
    tk.Label(dlg, textvariable=v_info, bg=COLORS['bg'], fg=COLORS['text_soft'], font=("Segoe UI", 9),
             anchor="w").pack(fill=tk.X, padx=12, pady=(0, 8))
    e.focus_set()
    _frissit(True)


def naplo_kereses_tg(kifejezes, db=15):
    """Telegram /naplo <szo>: az utolso talalatok."""
    if kifejezes:
        talalat = szur(naplo_sorok(4 * 1024 * 1024), kifejezes, "", 7 * 86400)
    else:
        talalat = szur(naplo_sorok(4 * 1024 * 1024), "", "!RIASZTAS", 86400)
    if not talalat:
        return "Nincs talalat%s." % ((" erre: %s (utolso 7 nap)" % kifejezes) if kifejezes else " (utolso 24 ora riasztasai)")
    fej = ("Utolso %d talalat erre: %s" % (min(db, len(talalat)), kifejezes) if kifejezes
           else "Utolso 24 ora riasztasai (%d, az utolso %d):" % (len(talalat), min(db, len(talalat))))
    return fej + "\n" + "\n".join(s[:300] for s in talalat[-db:])
