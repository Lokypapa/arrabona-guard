# -*- coding: utf-8 -*-
"""Arrabona Guard - Javitas ablak (Indítópult / Karantén / Hosts). [v2.3.0]"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import threading
import time
import tkinter as tk
import tkinter.messagebox as _mb
from tkinter import ttk
from .common import (APP_NAME, COLORS)
from .hosts import (HOSTS_BACKUP_FILE, hosts_erzekeny, hosts_parse)


def _gomb(parent, text, cmd, szin=None, fg="#ffffff"):
    b = tk.Button(parent, text=text, command=cmd, font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=szin or COLORS['ok'], fg=fg, activebackground=szin or COLORS['ok'],
                  activeforeground=fg, cursor="hand2", padx=10, pady=4)
    b.pack(side=tk.LEFT, padx=(0, 6))
    return b


def open_fix_dialog(app, lap=0):
    """app: GuardApp. lap: 0 = Indítópult, 1 = Karantén, 2 = Hosts, 3 = Hálózat (DNS / proxy),
    4 = Ütemezett feladatok (v2.17.0)."""
    core = app.core
    regi = getattr(app, "_fix_dlg", None)
    if regi is not None and regi.winfo_exists():
        regi.lift()
        try:
            regi._nb.select(lap)
        except Exception:
            pass
        return
    dlg = tk.Toplevel(app.root)
    app._fix_dlg = dlg
    dlg.title("%s — Javítás" % APP_NAME)
    dlg.configure(bg=COLORS['bg'])
    dlg.transient(app.root)
    dlg.geometry("900x520")
    dlg.minsize(700, 380)

    def _close():
        try:
            dlg.bind_all("<MouseWheel>", app._on_mousewheel)
        except Exception:
            pass
        dlg.destroy()
    dlg.protocol("WM_DELETE_WINDOW", _close)
    # a Treeview sajat gorgetest kap, a foablak gorgoje ne fogja el
    dlg.bind_all("<MouseWheel>", lambda e: None)

    st = ttk.Style(dlg)
    st.configure("Fix.Treeview", background=COLORS['panel'], fieldbackground=COLORS['panel'],
                 foreground=COLORS['text'], rowheight=22, font=("Segoe UI", 9))
    st.configure("Fix.Treeview.Heading", font=("Segoe UI", 9, "bold"))

    head = tk.Frame(dlg, bg=COLORS['brand'])
    head.pack(fill=tk.X)
    tk.Label(head, text="🧰  Javítás — indítópult, karantén, hosts, ütemezett feladatok", font=("Segoe UI", 11, "bold"),
             fg="white", bg=COLORS['brand']).pack(side=tk.LEFT, padx=12, pady=8)
    v_allapot = tk.StringVar(value="")
    tk.Label(dlg, textvariable=v_allapot, font=("Segoe UI", 9), fg=COLORS['text'], bg=COLORS['bg'],
             anchor="w", justify="left", wraplength=860).pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=(0, 8))

    nb = ttk.Notebook(dlg)
    dlg._nb = nb
    nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

    def _hatter(fn, utana):
        """fn() hatterszalon (PowerShell / registry), utana(eredmeny) a felulet szalan."""
        v_allapot.set("Dolgozom…")

        def _fut():
            try:
                er = fn()
            except Exception as ex:
                er = (False, "Hiba: %s" % ex)
            try:
                app.root.after(0, lambda: utana(er))
            except Exception:
                pass
        threading.Thread(target=_fut, name="javitas", daemon=True).start()

    def _tree(parent, oszlopok):
        fr = tk.Frame(parent, bg=COLORS['panel'])
        fr.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        tv = ttk.Treeview(fr, columns=[o[0] for o in oszlopok], show="headings", style="Fix.Treeview",
                          selectmode="browse")
        for nev, cim, szel, nyujt in oszlopok:
            tv.heading(nev, text=cim, anchor="w")
            tv.column(nev, width=szel, stretch=nyujt, anchor="w")
        sb = ttk.Scrollbar(fr, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=sb.set)
        tv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        tv.tag_configure("gyanus", foreground=COLORS['bad'])
        return tv

    # ================= 1) INDÍTÓPULT =================
    lap1 = tk.Frame(nb, bg=COLORS['panel'])
    nb.add(lap1, text="  Indítópult  ")
    tv1 = _tree(lap1, [("n", "#", 36, False), ("hely", "Hely", 150, False), ("nev", "Név", 170, False),
                       ("cmd", "Parancs", 280, True), ("sig", "Aláírás", 180, False),
                       ("gy", "Gyanús", 170, False)])
    kulcsok = {}

    def _tolt1():
        tv1.delete(*tv1.get_children())
        kulcsok.clear()
        for i, k, e, okok in core.startup_entries():
            iid = tv1.insert("", "end", values=(i, e["hely"], e["nev"], e.get("cmd") or "", "ellenőrzés…",
                                                "; ".join(okok) if okok else ""),
                             tags=("gyanus",) if okok else ())
            kulcsok[iid] = k
        # [v2.4.0] alairasok hatterben (PowerShell, nehany mp), utana az oszlop kitoltese
        sorrend = dict(kulcsok)

        def _sig_kesz(sigs):
            from .alairas import sig_szoveg, sig_veszely
            for iid, k in sorrend.items():
                if not tv1.exists(iid):
                    continue
                si = sigs.get(k)
                ert = list(tv1.item(iid, "values"))
                ert[4] = sig_szoveg(si) if si else "—"
                v = sig_veszely(si)
                if v == 2 or (v == 1 and ert[5]):
                    ert[5] = (ert[5] + "; " if ert[5] else "") + ("érvénytelen aláírás" if v == 2 else "aláíratlan")
                    tv1.item(iid, values=ert, tags=("gyanus",))
                else:
                    tv1.item(iid, values=ert)

        def _sig_fut():
            try:
                sigs = core.startup_signatures()
            except Exception:
                sigs = {}
            try:
                app.root.after(0, lambda: _sig_kesz(sigs) if dlg.winfo_exists() else None)
            except Exception:
                pass
        threading.Thread(target=_sig_fut, name="alairas", daemon=True).start()
    lab1 = tk.Frame(lap1, bg=COLORS['panel'])
    lab1.pack(fill=tk.X, padx=6, pady=(0, 6))
    v_kill = tk.BooleanVar(value=True)

    def _tiltas():
        sel = tv1.selection()
        if not sel:
            v_allapot.set("Előbb jelölj ki egy bejegyzést.")
            return
        ertekek = tv1.item(sel[0], "values")
        kulcs = kulcsok.get(sel[0])
        szoveg = ("Karanténba teszed ezt az indulóprogramot?\n\n%s / %s\n%s\n\n"
                  "Nem törlődik végleg: a Karantén fülön bármikor visszaállíthatod." % (
                      ertekek[1], ertekek[2], str(ertekek[3])[:200]))
        if ertekek[1] == "HKLM\\Winlogon":
            szoveg += "\n\nWinlogon: az érték az alapértelmezettre áll vissza (nem törlődik)."
        if not _mb.askyesno(APP_NAME, szoveg, parent=dlg):
            return
        leallit = v_kill.get()
        _hatter(lambda: core.startup_disable(kulcs, leallit=leallit, ki="felület"),
                lambda er: (v_allapot.set(er[1]), _tolt1(), _tolt2(),
                            app.add_log(er[1], "warning" if er[0] else "alert")))
    _gomb(lab1, "⛔ Karanténba (letiltás)", _tiltas, COLORS['bad'])
    tk.Checkbutton(lab1, text="a futó példányát is leállítom", variable=v_kill, bg=COLORS['panel'],
                   fg=COLORS['text'], selectcolor=COLORS['panel'], activebackground=COLORS['panel'],
                   activeforeground=COLORS['text'], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(4, 12))
    _gomb(lab1, "🔄 Frissítés", _tolt1, COLORS['panel_head'], COLORS['text'])
    tk.Label(lab1, text="Piros = gyanús minta / érvénytelen aláírás. Windows-programot a Guard nem állít le.",
             font=("Segoe UI", 8), fg=COLORS['text_soft'], bg=COLORS['panel']).pack(side=tk.RIGHT)

    # ================= 2) KARANTÉN =================
    lap2 = tk.Frame(nb, bg=COLORS['panel'])
    nb.add(lap2, text="  Karantén  ")
    tv2 = _tree(lap2, [("id", "Azonosító", 140, False), ("ido", "Mikor", 110, False),
                       ("hely", "Hely", 150, False), ("nev", "Név", 170, False), ("cmd", "Parancs", 300, True)])

    def _tolt2():
        tv2.delete(*tv2.get_children())
        for r in core.quarantine_list():
            tv2.insert("", "end", iid=r["id"], values=(
                r["id"], time.strftime("%m-%d %H:%M", time.localtime(r["ts"])), r["hely"], r["nev"],
                r.get("cmd") or ""))
    lab2 = tk.Frame(lap2, bg=COLORS['panel'])
    lab2.pack(fill=tk.X, padx=6, pady=(0, 6))

    def _vissza():
        sel = tv2.selection()
        if not sel:
            v_allapot.set("Előbb jelölj ki egy karantén-tételt.")
            return
        if not _mb.askyesno(APP_NAME, "Visszaállítod az indítópultba?\n\n%s" % " / ".join(
                tv2.item(sel[0], "values")[2:4]), parent=dlg):
            return
        qid = sel[0]
        _hatter(lambda: core.quarantine_restore(qid, ki="felület"),
                lambda er: (v_allapot.set(er[1]), _tolt1(), _tolt2(),
                            app.add_log(er[1], "info" if er[0] else "alert")))
    _gomb(lab2, "↩ Visszaállítás", _vissza)
    _gomb(lab2, "🔄 Frissítés", _tolt2, COLORS['panel_head'], COLORS['text'])

    # ================= 3) HOSTS =================
    lap3 = tk.Frame(nb, bg=COLORS['panel'])
    nb.add(lap3, text="  Hosts  ")
    tv3 = _tree(lap3, [("host", "Cím (hostnév)", 320, True), ("ip", "IP", 160, False),
                       ("gy", "Megjegyzés", 260, False)])
    v_elozo = tk.StringVar(value="")

    def _tolt3():
        tv3.delete(*tv3.get_children())
        e = (getattr(core, "_hosts_state", None) or {}).get("entries") or {}
        for h in sorted(e):
            erz = hosts_erzekeny(h)
            tv3.insert("", "end", values=(h, e[h], "érzékeny cím!" if erz else ""),
                       tags=("gyanus",) if erz else ())
        try:
            with open(HOSTS_BACKUP_FILE, "rb") as f:
                n = len(hosts_parse(f.read()))
            v_elozo.set("Előző változat: %d bejegyzés" % n)
        except OSError:
            v_elozo.set("Nincs elmentett előző változat")
    lab3 = tk.Frame(lap3, bg=COLORS['panel'])
    lab3.pack(fill=tk.X, padx=6, pady=(0, 6))

    def _hosts(mod):
        cim = "az ELŐZŐ változatra" if mod == "elozo" else "a Windows ALAPÉRTELMEZETT (üres) hosts fájljára"
        if not _mb.askyesno(APP_NAME, "Visszaállítod a hosts fájlt %s?\n\nA mostani tartalom megmarad "
                            "előző változatként, így ez is visszacsinálható." % cim, parent=dlg):
            return
        _hatter(lambda: core.hosts_restore(mod, ki="felület"),
                lambda er: (v_allapot.set(er[1]), _tolt3(),
                            app.add_log(er[1], "warning" if er[0] else "alert")))
    _gomb(lab3, "↩ Előző változat visszaállítása", lambda: _hosts("elozo"))
    _gomb(lab3, "🧹 Alapértelmezett hosts", lambda: _hosts("alap"), COLORS['warn'])
    tk.Label(lab3, textvariable=v_elozo, font=("Segoe UI", 8), fg=COLORS['text_soft'],
             bg=COLORS['panel']).pack(side=tk.RIGHT)

    # ================= 4) HÁLÓZAT (DNS / proxy) [v2.8.0] =================
    lap4 = tk.Frame(nb, bg=COLORS['panel'])
    nb.add(lap4, text="  Hálózat (DNS / proxy)  ")
    tv4 = _tree(lap4, [("mi", "Beállítás", 330, False), ("ert", "Érték", 420, True)])

    def _tolt4():
        tv4.delete(*tv4.get_children())
        try:
            sorok = core.net_rows()
        except Exception:
            sorok = []
        for cim, leiras, szint in sorok:
            tv4.insert("", "end", values=(cim, leiras), tags=("gyanus",) if szint >= 1 else ())
        if not any(c for c, _l, _s in sorok if not c.startswith("DNS")):
            tv4.insert("", "end", values=("Proxy", "nincs beállítva (rendben)"))
    lab4 = tk.Frame(lap4, bg=COLORS['panel'])
    lab4.pack(fill=tk.X, padx=6, pady=(0, 6))

    def _net(fn, kerdes):
        if not _mb.askyesno(APP_NAME, kerdes, parent=dlg):
            return
        _hatter(lambda: fn("felület"),
                lambda er: (v_allapot.set(er[1]), _tolt4(), app.add_log(er[1], "warning" if er[0] else "info")))
    _gomb(lab4, "↩ Automatikus DNS (minden adapter)",
          lambda: _net(core.dns_auto, "Minden kézi DNS-beállítást visszaállítasz automatikusra (a routertől kapottra)?\n\n"
                                       "Ha szándékosan állítottál be pl. 1.1.1.1-et, az is visszaáll."))
    _gomb(lab4, "⛔ Proxy kikapcsolása", lambda: _net(core.proxy_off, "Kikapcsolod a Windows proxyt és a PAC-szkriptet?\n\n"
                                                                     "Az előző értékek mentésre kerülnek (proxy_mentes.json)."),
          COLORS['bad'])
    _gomb(lab4, "🔄 Frissítés", _tolt4, COLORS['panel_head'], COLORS['text'])

    # ================= 5) ÜTEMEZETT FELADATOK [v2.17.0] =================
    lap5 = tk.Frame(nb, bg=COLORS['panel'])
    nb.add(lap5, text="  Ütemezett feladatok  ")
    tv5 = _tree(lap5, [("n", "#", 36, False), ("ut", "Feladat", 230, False), ("cmd", "Parancs", 250, True),
                       ("ind", "Indul", 120, False), ("all", "Állapot", 70, False), ("sig", "Aláírás", 150, False),
                       ("gy", "Gyanús", 220, False)])
    v_mind = tk.BooleanVar(value=False)
    ut_iid = {}

    def _tolt5():
        from .utemezett import _TRIGGER_NEV, _windows_fajl
        from .alairas import sig_szoveg
        tv5.delete(*tv5.get_children())
        ut_iid.clear()
        lst = list(getattr(core, "_ut_lista", []) or [])
        n = 0
        for r_ut, ok in list(getattr(core, "_ut_rejtett", []) or []):
            n += 1
            tv5.insert("", "end", values=(n, r_ut, "(a Feladatütemező nem mutatja)", "-", "REJTETT", "-", ok),
                       tags=("gyanus",))
        for d in lst:
            gy = bool(d.get("szint")) and not d.get("kivetel")
            if not v_mind.get() and not gy and d["ut"].lower().startswith("\\microsoft\\"):
                continue
            n += 1
            f = d.get("fajl") or ""
            sig = "Windows" if f and _windows_fajl(f) else (sig_szoveg(d.get("sig")) if d.get("sig") else "—")
            iid = tv5.insert("", "end", values=(
                n, d["ut"], core._ut_parancs(d), ", ".join(_TRIGGER_NEV.get(t, t) for t in d["triggers"]) or "kézi",
                "Be" if d["enabled"] else "KI", sig,
                ("; ".join(d["okok"]) if gy else ("megbízható (kivétel)" if d.get("kivetel") else ""))),
                tags=("gyanus",) if gy and d["enabled"] else ())
            ut_iid[iid] = d
        if not lst:
            tv5.insert("", "end", values=("", "Még nem volt átnézés - nyomd meg: Átnézés most", "", "", "", "", ""))

    def _ut_kijelolt():
        sel = tv5.selection()
        d = ut_iid.get(sel[0]) if sel else None
        if not d:
            v_allapot.set("Előbb jelölj ki egy feladatot (a rejtett feladat itt nem kezelhető - Defender teljes vizsgálat).")
        return d

    def _ut_muv(fn, kerdes):
        d = _ut_kijelolt()
        if not d:
            return
        if kerdes and not _mb.askyesno(APP_NAME, kerdes % d["ut"], parent=dlg):
            return
        _hatter(lambda: fn(d), lambda er: (v_allapot.set(er[1]), _tolt5(), _tolt2(),
                                           app.add_log(er[1], "warning" if er[0] else "alert")))
    lab5 = tk.Frame(lap5, bg=COLORS['panel'])
    lab5.pack(fill=tk.X, padx=6, pady=(0, 6))
    _gomb(lab5, "⏸ Letiltás", lambda: _ut_muv(lambda d: core.ut_tilt(d["ut"], ki="felület"),
                                              "Letiltod ezt az ütemezett feladatot?\n\n%s\n\nBármikor visszakapcsolható."),
          COLORS['bad'])
    _gomb(lab5, "▶ Engedélyezés", lambda: _ut_muv(lambda d: core.ut_enged(d["ut"], ki="felület"), None),
          COLORS['panel_head'], COLORS['text'])
    _gomb(lab5, "🗄 Letiltás + program karanténba",
          lambda: _ut_muv(lambda d: core.ut_karanten(d["ut"], d.get("fajl"), ki="felület"),
                          "Letiltod a feladatot ÉS karanténba teszed a programját?\n\n%s\n\n"
                          "A Karantén fülön visszaállítható."), COLORS['bad'])
    _gomb(lab5, "✅ Megbízható", lambda: _ut_muv(lambda d: core.ut_megbizhato(d["ut"], ki="felület"),
                                                 "Megbízhatónak jelölöd?\n\n%s\n\nErre a feladatra többet nem szól."),
          COLORS['panel_head'], COLORS['text'])
    _gomb(lab5, "🔍 Átnézés most", lambda: _hatter(lambda: core.ut_scan(ki="felület"),
                                                  lambda er: (v_allapot.set(core.ut_summary()), _tolt5())),
          COLORS['panel_head'], COLORS['text'])
    tk.Checkbutton(lab5, text="Microsoft-feladatok is", variable=v_mind, command=lambda: _tolt5(), bg=COLORS['panel'],
                   fg=COLORS['text'], selectcolor=COLORS['panel'], activebackground=COLORS['panel'],
                   activeforeground=COLORS['text'], font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(4, 0))

    _tolt1()
    _tolt2()
    _tolt3()
    _tolt4()
    try:
        _tolt5()
    except Exception as e:
        v_allapot.set("Ütemezett feladatok: %s" % e)
    nb.select(lap)
