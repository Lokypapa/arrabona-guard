# -*- coding: utf-8 -*-
"""Arrabona Guard - Felulet: GuardApp (tkinter dashboard + talca)."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import os
import queue
from tkinter import scrolledtext
import sys
import time
import tkinter as tk
from tkinter import ttk
from . import instance
from .common import (
    APP_NAME,
    BLACKLIST_FILE,
    COLORS,
    DIST_EXE,
    ENTRY_SCRIPT,
    INSTALL_EXE,
    Image,
    ImageDraw,
    ImageTk,
    LOG_FILE,
    POPUP_MS,
    UPDATE_CHECK_MS,
    VERSION,
    WHITELIST_FILE,
    _HUE_SHIFT_GREEN,
    _is_dark,
    _theme_file,
    app_dir,
    log_line,
    autostart_enabled,
    autostart_set,
    date_str,
    load_blacklist,
    load_whitelist,
    now_str,
    play_alert_sound,
    pystray,
)
from .watchdog import (quit_flag_set)
from .instance import (acquire_single_instance, mark_restart, release_single_instance)
from . import updater          # [v2.18.0] GitHub-frissites
from . import telegram_setup   # [v2.18.0] Telegram-beallito varazslo
from . import pass_inditas     # [v2.19.0] Arrabona Pass inditasa

# ------------------------- Ikon -------------------------

def recolor_to_green(img):
    """Lila pixelek zöldre forgatása hue-rotációval; fehér/szürke marad."""
    try:
        hsv = img.convert("HSV")
        h, s, v = hsv.split()
        h = h.point(lambda p: (p + _HUE_SHIFT_GREEN) % 256)
        return Image.merge("HSV", (h, s, v)).convert("RGBA")
    except Exception:
        return img


def draw_fallback_logo():
    """Tartalék logó: fehér lekerekített négyzet, ZÖLD pajzs, fehér A."""
    img = Image.new("RGBA", (256, 256), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    d.rounded_rectangle([(8, 8), (248, 248)], radius=48,
                        fill=(255, 255, 255, 255))

    cx = 128
    d.polygon([(cx, 36), (208, 68), (208, 140), (cx, 214),
               (48, 140), (48, 68)],
              fill=(39, 174, 96, 255))

    a_w = 13
    d.line([(94, 176), (128, 92)], fill=(255, 255, 255, 255), width=a_w)
    d.line([(128, 92), (162, 176)], fill=(255, 255, 255, 255), width=a_w)
    d.line([(106, 148), (150, 148)], fill=(255, 255, 255, 255), width=a_w)
    return img


def load_icon_image(big=False):
    size = 256 if big else 64
    app_path = app_dir()

    ico_path = os.path.join(app_path, "logo_tray.png")
    if os.path.exists(ico_path):
        try:
            img = Image.open(ico_path).convert("RGBA")
            return img.resize((size, size), Image.LANCZOS)
        except Exception:
            pass

    png_path = os.path.join(app_path, "logo_zold_uj.png")
    if os.path.exists(png_path):
        try:
            img = Image.open(png_path).convert("RGBA")
            return img.resize((size, size), Image.LANCZOS)
        except Exception:
            pass

    return draw_fallback_logo().resize((size, size), Image.LANCZOS)


# ------------------------- GUI-segédek -------------------------

def make_panel(parent, title="", title_var=None, mark="✔",
               mark_color=None):
    if mark_color is None:
        mark_color = COLORS['ok']

    panel = tk.Frame(parent, bg=COLORS['panel'],
                     highlightbackground=COLORS['divider'],
                     highlightthickness=1)
    head = tk.Frame(panel, bg=COLORS['panel_head'])
    head.pack(fill=tk.X)
    mark_label = tk.Label(head, text=mark, font=("Segoe UI", 14, "bold"),
                          fg=mark_color, bg=COLORS['panel_head'],
                          width=3)
    mark_label.pack(side=tk.LEFT, pady=4)
    if title_var is not None:
        title_label = tk.Label(head, textvariable=title_var,
                               font=("Segoe UI", 12, "bold"),
                               fg=COLORS['text'], bg=COLORS['panel_head'],
                               anchor="w")
    else:
        title_label = tk.Label(head, text=title,
                               font=("Segoe UI", 12, "bold"),
                               fg=COLORS['text'], bg=COLORS['panel_head'],
                               anchor="w")
    title_label.pack(side=tk.LEFT, padx=(0, 8), pady=4)

    sep = tk.Frame(panel, bg=COLORS['divider'], height=1)
    sep.pack(fill=tk.X)

    rows = tk.Frame(panel, bg=COLORS['panel'])
    rows.pack(fill=tk.X, padx=14, pady=8)
    return panel, rows, title_label, mark_label


def add_row(rows, label, value_var, value_fg=None, small_mark=True):
    if value_fg is None:
        value_fg = COLORS['ok']
    r = tk.Frame(rows, bg=COLORS['panel'])
    r.pack(fill=tk.X, pady=1)
    if small_mark:
        tk.Label(r, text="✔", font=("Segoe UI", 9),
                 fg=COLORS['ok'], bg=COLORS['panel'],
                 width=2).pack(side=tk.LEFT)
    tk.Label(r, text=label, font=("Segoe UI", 10),
             fg=COLORS['text'], bg=COLORS['panel'],
             anchor="w").pack(side=tk.LEFT)
    lbl = tk.Label(r, textvariable=value_var, font=("Segoe UI", 10, "bold"),
                   fg=value_fg, bg=COLORS['panel'], anchor="e")
    lbl.pack(side=tk.RIGHT)
    return lbl


# ------------------------- GUI -------------------------

class GuardApp:
    def __init__(self, core):
        self.core = core
        self.root = tk.Tk()
        self.root.title("%s v%s" % (APP_NAME, VERSION))
        self.root.geometry("980x620")
        self.root.minsize(760, 420)
        self.root.configure(bg=COLORS['bg'])
        self.root.protocol("WM_DELETE_WINDOW", self.hide_window)
        # [v2.18.1] gomb- / idozito-hibak a hibanaploba (eddig csak a nem lathato konzolra mentek)
        self.root.report_callback_exception = lambda t, e, tb: common.hiba_naplozas("felulet", t, e, tb)
        self._build_update_status()

        # saját ablakikon (zöldre színezve)
        self._icon_photo = ImageTk.PhotoImage(
            load_icon_image(big=True).resize((32, 32), Image.LANCZOS))
        self.root.iconphoto(True, self._icon_photo)

        # ===== ZÖLD MÁRKA-CSÍK (fix fent) =====
        brand = tk.Frame(self.root, bg=COLORS['brand'], height=76)
        brand.pack(fill=tk.X)
        brand.pack_propagate(False)

        bl = tk.Frame(brand, bg=COLORS['brand'])
        bl.pack(side=tk.LEFT, padx=14)
        self.brand_logo = ImageTk.PhotoImage(
            load_icon_image(big=False).resize((60, 60), Image.LANCZOS))
        tk.Label(bl, image=self.brand_logo, bg=COLORS['brand']).pack(side=tk.LEFT,
                                                                     padx=(0, 10))
        tk.Label(bl, text=APP_NAME.upper(), font=("Segoe UI", 15, "bold"),
                 fg='white', bg=COLORS['brand']).pack(side=tk.LEFT)

        # [v2.19.0] Arrabona Pass inditasa (jobb felul, a zold csikon)
        pass_btn = tk.Button(brand, text="🔑  Arrabona Pass", command=self.open_pass,
                             font=("Segoe UI", 10, "bold"), fg='white',
                             bg=COLORS['brand_dark'], activebackground='#176b3b',
                             activeforeground='white', relief=tk.FLAT, bd=0,
                             cursor="hand2", padx=14, pady=6)
        pass_btn.pack(side=tk.RIGHT, padx=16)

        # ===== ALSÓ GOMB SOR (fix az ablak alján — mindig látható) =====
        # ===== FRISSITES-JELZO SAV (3. feladat) =====
        self.update_banner = tk.Frame(self.root, bg="#e67e22")
        self.update_banner_lbl = tk.Label(self.update_banner, text="Frissítés elérhető!",
                 font=("Segoe UI", 10, "bold"), fg="white",
                 bg="#e67e22")
        self.update_banner_lbl.pack(side=tk.LEFT, padx=(14, 8), pady=7)
        self.update_banner_btn = tk.Button(self.update_banner, text="Telepítés és újraindítás",
                  command=self.apply_update,
                  font=("Segoe UI", 9, "bold"), fg="white", bg="#b5561a",
                  relief=tk.FLAT, bd=0, cursor="hand2", padx=10, pady=3,
                  activebackground="#9a4a16",
                  activeforeground="white")
        self.update_banner_btn.pack(side=tk.LEFT, pady=7)
        self.update_shown = False
        self.update_notified = False
        self._upd_dist = False      # helyi (fejlesztoi) build van
        self.root.after(8000, self.check_for_update)
        # [v2.18.0] GitHub-frissites + Telegram-varazslo
        updater.KILEPES_HOOK = lambda: self.root.after(0, self._kilepes_frissitesre)
        self.root.after(updater.ELSO_KERESES_MS, self._gh_kereses_ciklus)
        self.root.after(4000, self._elso_inditas_teendok)

        self.bar_wrap = tk.Frame(self.root, bg=COLORS['bg'])
        bar_wrap = self.bar_wrap
        bar_wrap.pack(side=tk.BOTTOM, fill=tk.X, padx=16, pady=(0, 14))
        bar1 = tk.Frame(bar_wrap, bg=COLORS['bg'])
        bar1.pack(fill=tk.X, anchor="w")
        bar2 = tk.Frame(bar_wrap, bg=COLORS['bg'])
        bar2.pack(fill=tk.X, anchor="w", pady=(8, 0))

        def mkbtn(parent, text, cmd):
            # --- dinamikus effekt: hover + benyomás (mélység) ---
            def on_enter(e):
                b.config(fg=COLORS['brand'])
            def on_leave(e):
                b.config(fg=COLORS['text'], relief=tk.FLAT, bd=0)
            def on_press(e):
                # besüppedő hatás
                b.config(relief=tk.SUNKEN, bd=2)
            def on_release(e):
                b.config(relief=tk.FLAT, bd=0)
            b = tk.Button(parent, text=text, command=cmd,
                          font=("Segoe UI", 9, "bold"),
                          bg=parent.cget('bg'),  # átlátszó (inherit parent bg)
                          fg=COLORS['text'],
                          relief=tk.FLAT, bd=0, cursor="hand2",
                          padx=14, pady=7,
                          highlightthickness=0,
                          activebackground=parent.cget('bg'),
                          activeforeground=COLORS['brand'])
            b.pack(side=tk.LEFT, padx=(0, 8))
            b.bind("<Enter>", on_enter)
            b.bind("<Leave>", on_leave)
            b.bind("<ButtonPress-1>", on_press)
            b.bind("<ButtonRelease-1>", on_release)
            return b

        # 1. sor: vezérlés
        mkbtn(bar1, "⏸ Szünet 10 perc", lambda: self.core.pause(10))
        mkbtn(bar1, "⏲ Szünet 1 óra", lambda: self.core.pause(60))
        mkbtn(bar1, "▶ Folytatás", self.resume_all)
        mkbtn(bar1, "🧪 Teszt riasztás", self.test_alert)
        self.game_btn = mkbtn(bar1, "🎮 Játék mód: AUTO", self.toggle_game_mode)   # [v2.9.0]
        self.theme_btn = mkbtn(bar1, ("\u2600\ufe0f Vil\u00e1gos m\u00f3d" if _is_dark() else "\U0001F319 S\u00f6t\u00e9t m\u00f3d"), self.toggle_theme)

        # 2. sor: kikapcsolás, listák + autostart
        mkbtn(bar2, "🔴 Figyelés kikapcsolása", self.core.monitor_off)
        mkbtn(bar2, "📄 Feketelista megnyitása", lambda: os.startfile(BLACKLIST_FILE))
        mkbtn(bar2, "📄 Whitelist megnyitása", lambda: os.startfile(WHITELIST_FILE))
        mkbtn(bar2, "📜 Előzmények", self.show_history)
        mkbtn(bar2, "📱 Telegram", self.open_telegram_setup)   # [v2.18.0]
        mkbtn(bar2, "ℹ Névjegy", self.show_about)              # [v2.18.1]

        self.auto_var = tk.BooleanVar(value=autostart_enabled())
        chk = tk.Checkbutton(bar2, text="Automatikus indítás",
                             variable=self.auto_var,
                             command=self.toggle_autostart,
                             bg=COLORS['bg'], fg=COLORS['text'], selectcolor=('#ffffff' if not _is_dark() else '#3a3a44'), activebackground=COLORS['bg'], activeforeground=COLORS['text'], highlightthickness=0, bd=0,
                             font=("Segoe UI", 9, "bold"))
        chk.pack(side=tk.LEFT, padx=(16, 0))

        # ===== GÖRGETHETŐ FŐ TARTALOM (canvas + görgő) =====
        self.canvas = tk.Canvas(self.root, bg=COLORS['bg'],
                                highlightthickness=0)
        self.vsb = tk.Scrollbar(self.root, orient="vertical",
                                command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")

        self.scroll_frame = tk.Frame(self.canvas, bg=COLORS['bg'])
        self._content_win = self.canvas.create_window(
            (0, 0), window=self.scroll_frame, anchor="nw")
        # a tartalom mindig olyan széles legyen, mint a canvas
        self.scroll_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")))
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(
                self._content_win, width=e.width))
        # egérgörgővel is lehet tekerni
        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)

        # ===== FŐ TARTALOM (a görgető területen belül) =====
        content = tk.Frame(self.scroll_frame, bg=COLORS['bg'])
        content.pack(fill=tk.BOTH, expand=True, padx=16, pady=14)

        left = tk.Frame(content, bg=COLORS['bg'])
        right = tk.Frame(content, bg=COLORS['bg'])
        # [v2.15.3] a jobb oldali Esemenyek panel kerul ELOSZOR elhelyezesre, igy mindig megkapja
        # a sajat szelesseget; korabban a kartyak szovegenek hosszabbodasaval (betoltes utan)
        # a bal oldal "kiszoritotta", es a naplo egy betunyi oszlopra szukult
        right.pack(side=tk.RIGHT, fill=tk.Y)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 14))

        # --- dinamikus változók ---
        self.v_title  = tk.StringVar(value="Az Ön rendszere védett")
        self.v_stat   = tk.StringVar(value="Betöltés…")
        self.v_fw     = tk.StringVar(value="Ellenőrzés…")
        self.v_bl     = tk.StringVar(value="…")
        self.v_wl     = tk.StringVar(value="…")
        self.v_lan    = tk.StringVar(value="0")
        self.v_blkd   = tk.StringVar(value="0")
        self.v_out    = tk.StringVar(value="0 / 0")
        self.v_wd     = tk.StringVar(value="ellenőrzés…")
        self.v_last   = tk.StringVar(value=date_str())
        self.v_pause  = tk.StringVar(value="Nincs szünetben")
        self.v_alert  = tk.StringVar(value="0")
        self.v_ver    = tk.StringVar(value="v%s" % VERSION)
        self.v_auto   = tk.StringVar(value="?")

        # ===== 1. NAGY ÁLLAPOTPANEL (dinamikus cím) =====
        p1, rows1, self.p1_title, self.p1_mark = make_panel(
            left, title_var=self.v_title)
        p1.pack(fill=tk.X)

        # ===== 4. FELADAT: MODUL-KARTYAK (zold/piros pont + uptime) =====
        self.cards = tk.Frame(left, bg=COLORS['bg'])
        self.mod_vars = {}

        card_idx = [0]

        def mkcard(key, nev):
            # 2x2 racs: minden kartya szeles helyet kap, nem kell nyujtani
            r, col = divmod(card_idx[0], 2)
            card_idx[0] += 1
            c = tk.Frame(self.cards, bg=COLORS['panel'],
                         highlightbackground=COLORS['divider'],
                         highlightthickness=1)
            c.grid(row=r, column=col, sticky="nsew",
                   padx=(0, 8), pady=(12, 6))
            self.cards.columnconfigure(col, weight=1, uniform="kartya")  # [v2.15.3] egyforma oszlopok
            dot = tk.Label(c, text="\u25cf", font=("Segoe UI", 12, "bold"),
                           fg="#e74c3c", bg=COLORS['panel'])
            dot.pack(side=tk.LEFT, padx=(8, 4), pady=(6, 0))
            tk.Label(c, text=nev, font=("Segoe UI", 10, "bold"),
                     fg=COLORS['text'], bg=COLORS['panel'],
                     anchor="w").pack(side=tk.LEFT, pady=(6, 0))
            info = tk.StringVar(value="indulás…")
            self.mod_vars[key] = [dot, info]
            lbl = tk.Label(c, textvariable=info, font=("Segoe UI", 8),
                           fg=COLORS['text_soft'], bg=COLORS['panel'], anchor="w",
                           justify="left", wraplength=200)
            lbl.pack(fill=tk.X, padx=8, pady=(0, 6))

            # [v2.15.3] a sortores a kartya tenyleges szelessegehez igazodik (nem tolja szet az ablakot)
            def _wrap(e, l=lbl):
                w = max(120, e.width - 8)
                if abs(int(l.cget("wraplength") or 0) - w) > 4:
                    l.configure(wraplength=w)
            lbl.bind("<Configure>", _wrap)

        mkcard("feed", "FEED")
        mkcard("geo", "GEO")
        mkcard("logon", "Belépésfigyelés")
        mkcard("honey", "Honeypot")
        mkcard("defender", "Windows Defender")
        mkcard("usb", "USB-eszközök")
        mkcard("hosts", "Hosts-fájl")          # [v2.2.0]
        mkcard("startup", "Indítópult")        # [v2.2.0]
        mkcard("csapda", "Ransomware-csapda")  # [v2.5.0]
        mkcard("bongeszo", "Böngésző-bővítmények")  # [v2.6.0]
        mkcard("lan", "Hálózati eszközök (LAN)")    # [v2.7.0]
        mkcard("dnsproxy", "DNS és proxy")           # [v2.8.0]
        mkcard("winupdate", "Windows Update")        # [v2.11.0]
        mkcard("pontszam", "Biztonsági pontszám")    # [v2.11.0]
        mkcard("folyamat", "Folyamatfigyelés")       # [v2.12.0]
        mkcard("lopas", "Infostealer-csapda")        # [v2.13.0]
        mkcard("vagolap", "Vágólap-védelem")          # [v2.14.0]
        mkcard("letoltes", "Letöltések vizsgálata")   # [v2.15.0]
        mkcard("frissites", "Elavult programok")       # [v2.16.0]
        mkcard("upnp", "Router nyitott portjai (UPnP)")  # [v2.16.0]
        mkcard("kiszivargas", "Adatkiszivárgás-figyelés")  # [v2.16.0]
        mkcard("utemezett", "Ütemezett feladatok")     # [v2.17.0]
        # a gombsorok a kartyak UTANI sorokba kerulnek (a kartyak szama valtozhat)
        self._card_rows = (card_idx[0] + 1) // 2
        # a kartyasor a nagy allapotpanel FOLE kerul
        # Kézi frissítés gombok (FEED + GEO)
        fb = tk.Frame(self.cards, bg=COLORS['bg'])
        fb.grid(row=self._card_rows, column=0, columnspan=2, sticky="ew", padx=(0, 8), pady=(0, 6))
        tk.Button(fb, text="\U0001F504 FEED frissítés most",
                  font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=COLORS['ok'], fg="#ffffff", activebackground=COLORS['ok'],
                  activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                  command=lambda: self.core.feed_refresh_now()
                  ).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(fb, text="\U0001F30D GEO frissítés most",
                  font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=COLORS['ok'], fg="#ffffff", activebackground=COLORS['ok'],
                  activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                  command=lambda: self.core.geo_refresh_now()
                  ).pack(side=tk.LEFT, padx=(0, 6))
        # [v1.9.6] Defender gyors vizsgalat
        tk.Button(fb, text="\U0001F6E1 Defender gyors vizsgálat",
                  font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=COLORS['ok'], fg="#ffffff", activebackground=COLORS['ok'],
                  activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                  command=self._defender_scan_ui
                  ).pack(side=tk.LEFT, padx=(0, 6))
        # [v2.11.0] masodik gombsor: jelszo-ellenorzes + pontszam
        fb2 = tk.Frame(self.cards, bg=COLORS['bg'])
        fb2.grid(row=self._card_rows + 1, column=0, columnspan=2, sticky="ew", padx=(0, 8), pady=(0, 6))
        for _txt, _cmd in (("\U0001F511 Kiszivárgott jelszó-ellenőrzés", self.open_pwned_dialog),
                           ("\U0001F3C5 Pontszám részletei", self.show_score)):
            tk.Button(fb2, text=_txt, font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                      bg=COLORS['ok'], fg="#ffffff", activebackground=COLORS['ok'],
                      activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                      command=_cmd).pack(side=tk.LEFT, padx=(0, 6))
        # [v2.15.0] harmadik gombsor: kereso naplo + beallitasok mentese / visszaallitasa
        fb3 = tk.Frame(self.cards, bg=COLORS['bg'])
        fb3.grid(row=self._card_rows + 2, column=0, columnspan=2, sticky="ew", padx=(0, 8), pady=(0, 6))
        for _txt, _cmd in (("\U0001F50E Napló keresés", self.open_log_dialog),
                           ("\U0001F4BE Beállítások mentése", self.backup_settings),
                           ("\U0001F4C2 Visszaállítás", self.restore_settings)):
            tk.Button(fb3, text=_txt, font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                      bg=COLORS['ok'], fg="#ffffff", activebackground=COLORS['ok'],
                      activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                      command=_cmd).pack(side=tk.LEFT, padx=(0, 6))
        # [v2.3.0] Javitas ablak: indítópult-karantén + hosts-visszaállítás
        tk.Button(fb, text="\U0001F9F0 Javítás / karantén",
                  font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                  bg=COLORS['warn'], fg="#ffffff", activebackground=COLORS['warn'],
                  activeforeground="#ffffff", cursor="hand2", padx=10, pady=3,
                  command=self.open_fix_dialog
                  ).pack(side=tk.LEFT)
        # [v2.1.3] Folyamatpanel: futo / epp befejezett Defender-vizsgalat lepesei
        self._build_scan_panel()
        self.cards.pack(fill=tk.X, before=p1)

        big = tk.Frame(rows1, bg=COLORS['panel'])
        big.pack(fill=tk.X, pady=(2, 6))
        self.big_mark = tk.Label(big, text="✔", font=("Segoe UI", 34, "bold"),
                                 fg=COLORS['ok'], bg=COLORS['panel'], width=3)
        self.big_mark.pack(side=tk.LEFT)
        self.big_title = tk.Label(big, textvariable=self.v_stat,
                                  font=("Segoe UI", 17, "bold"),
                                  fg=COLORS['ok'], bg=COLORS['panel'])
        self.big_title.pack(side=tk.LEFT, pady=4)

        add_row(rows1, "Figyelés", self.v_stat)
        add_row(rows1, "Tűzfal figyelés (DROP napló)", self.v_fw)
        add_row(rows1, "Feketelistázott IP-k", self.v_bl)
        add_row(rows1, "Whitelist (figyelmen kívül)", self.v_wl)
        add_row(rows1, "Belső hálózati DROP-ok (kimutralva)", self.v_lan)
        add_row(rows1, "Blokkolt IP-k elnyelt csomagjai", self.v_blkd)
        add_row(rows1, "Rossz IP felé: blokkolva / nyitott", self.v_out)
        add_row(rows1, "Utolsó ellenőrzés", self.v_last)
        add_row(rows1, "Szünet", self.v_pause)
        self.v_game = tk.StringVar(value="…")
        add_row(rows1, "Játék mód (csendes)", self.v_game)
        add_row(rows1, "Auto-indítás Windowszal", self.v_auto)
        add_row(rows1, "Őrkutya (újraindítás, ha leáll)", self.v_wd)

        # ===== 2. BEHATOLÁSI KÍSÉRLETEK PANEL =====
        p2, rows2, _, _ = make_panel(left, "Behatolási kísérletek")

        # ===== 6. FELADAT: STATISZTIKA - UTOLSO 7 NAP =====
        ps = tk.Frame(left, bg=COLORS['panel'],
                      highlightbackground=COLORS['divider'],
                      highlightthickness=1)
        # p2 meg nincs becsomagolva itt -> nem hasznalunk before=p2,
        # a panel-egymasutani sorrend ugyis helyes marad
        ps.pack(fill=tk.X, pady=(12, 0))
        ph = tk.Frame(ps, bg=COLORS['panel_head'])
        ph.pack(fill=tk.X)
        tk.Label(ph, text="Statisztika — utolsó 7 nap",
                 font=("Segoe UI", 11, "bold"), fg=COLORS['text'],
                 bg=COLORS['panel_head'], anchor="w",
                 padx=12, pady=6).pack(side=tk.LEFT)
        body_s = tk.Frame(ps, bg=COLORS['panel'])
        body_s.pack(fill=tk.X, padx=12, pady=(6, 10))
        self.stats_canvas = tk.Canvas(body_s, height=66, bg=COLORS['panel'],
                                     highlightthickness=0)
        self.stats_canvas.pack(fill=tk.X)
        self._stats_vals = [0] * 7
        self.stats_canvas.bind(
            "<Configure>",
            lambda e: self.root.after_idle(self._draw_stats))
        srow = tk.Frame(body_s, bg=COLORS['panel'])
        srow.pack(fill=tk.X, pady=(6, 0))
        self.v_risk = tk.StringVar(value="…")
        self.v_s_al = tk.StringVar(value="…")
        self.l_risk = tk.Label(srow, textvariable=self.v_risk,
                               font=("Segoe UI", 9, "bold"),
                               bg=COLORS['panel'], fg=COLORS['ok'],
                               anchor="w")
        self.l_risk.pack(side=tk.LEFT)
        tk.Label(srow, textvariable=self.v_s_al,
                 font=("Segoe UI", 9), fg=COLORS['text_soft'],
                 bg=COLORS['panel'], anchor="e").pack(side=tk.RIGHT)
        p2.pack(fill=tk.X, pady=(12, 0))
        add_row(rows2, "Riasztások száma (indulás óta)", self.v_alert)
        add_row(rows2, "Figyelt portok", tk.StringVar(
            value="ÖSSZES — minden eldobott csomag"))
        tk.Label(rows2, text="A Guard a tűzfal minden DROP-ját látja, "
                             "bármelyik porton (SSH, RDP, SMB, WoW, MySQL…). "
                             "Riasztáskor az IP országa is megjelenik "
                             "(pl. [RU], [DE]); a belső (LAN) forgalom "
                             "automatikusan ki van hagyva.",
                 font=("Segoe UI", 9), fg=COLORS['text_soft'],
                 bg=COLORS['panel'], wraplength=430,
                 justify="left").pack(anchor="w", pady=(4, 2))

        # ===== 3. VERZIÓ / LICENC PANEL =====
        p3, rows3, _, _ = make_panel(left, "Verzió és licensz")
        p3.pack(fill=tk.X, pady=(12, 0))
        add_row(rows3, "Program verzió", self.v_ver)
        add_row(rows3, "Elfelejthetetlen szervervédelem", tk.StringVar(
            value="Arrabona • ∞ licenc ✔"))

        # ===== JOBB OLDAL: eseménynapló =====
        p4 = tk.Frame(right, bg=COLORS['panel'],
                      highlightbackground=COLORS['divider'], highlightthickness=1)
        p4.pack(fill=tk.BOTH, expand=True)
        head4 = tk.Frame(p4, bg=COLORS['panel_head'])
        head4.pack(fill=tk.X)
        tk.Label(head4, text="🔔 Események", font=("Segoe UI", 12, "bold"),
                 fg=COLORS['text'], bg=COLORS['panel_head'],
                 anchor="w", padx=12, pady=6).pack(side=tk.LEFT)

        self.log = scrolledtext.ScrolledText(p4, state="disabled",
                                             font=("Consolas", 9),
                                             bg=COLORS['panel'],
                                             fg=COLORS['text'],
                                             relief=tk.FLAT,
                                             padx=10, pady=8, width=44)
        self.log.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        self.tag_configure_colors()

        self.root.after(250, self.pump_queue)
        self.root.after(500, self.tick_status)
        self.root.after(20000, self.tick_stats)
        self.root.after(3000, self.tick_mods)
        self.root.after(1000, self._tick_scan)

    # ---- [v2.1.3] Folyamatpanel ----
    def _build_scan_panel(self):
        sp = tk.Frame(self.cards, bg=COLORS['panel'],
                      highlightbackground=COLORS['ok'], highlightthickness=2)
        self._scan_panel = sp
        self._scan_title = tk.Label(sp, text="", font=("Segoe UI", 10, "bold"),
                                    fg=COLORS['text'], bg=COLORS['panel'], anchor="w")
        self._scan_title.pack(fill=tk.X, padx=10, pady=(8, 2))
        self._scan_steps = tk.Label(sp, text="", font=("Segoe UI", 9),
                                    fg=COLORS['text'], bg=COLORS['panel'],
                                    anchor="w", justify="left")
        self._scan_steps.pack(fill=tk.X, padx=14, pady=(0, 4))
        self._scan_bar = ttk.Progressbar(sp, mode="indeterminate", maximum=100)
        self._scan_bar.pack(fill=tk.X, padx=10, pady=(2, 4))
        alja = tk.Frame(sp, bg=COLORS['panel'])
        alja.pack(fill=tk.X, padx=10, pady=(0, 8))
        # [v2.2.0] Megszakitas gomb (csak futo vizsgalatnal latszik)
        self._scan_cancel_btn = tk.Button(alja, text="\u23f9 Megszakítás",
                                          font=("Segoe UI", 9, "bold"), relief="flat", bd=0,
                                          bg=COLORS['bad'], fg="#ffffff",
                                          activebackground=COLORS['bad'], activeforeground="#ffffff",
                                          disabledforeground="#f0d0cc",
                                          cursor="hand2", padx=10, pady=3,
                                          command=self._scan_cancel_ui)
        self._scan_cancel_shown = False
        self._scan_note = tk.Label(alja, text="", font=("Segoe UI", 8),
                                   fg=COLORS['text_soft'], bg=COLORS['panel'], anchor="w",
                                   justify="left", wraplength=520)
        self._scan_note.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self._scan_anim = False
        self._scan_shown = False

    def _scan_cancel_ui(self):
        """[v2.2.0] Megszakitas gomb: megerosites, majd hatterszalon leallitas."""
        import threading
        import tkinter.messagebox as _mb
        inf = self.core.scan_progress()
        if not inf or not inf["running"]:
            return
        if not _mb.askyesno(APP_NAME, "Biztosan megszakítod a(z) „%s” vizsgálatot?\n\n"
                            "A már átnézett részben talált kártevőkről így is szólok, "
                            "de a maradékot a Defender nem nézi át." % inf["name"], parent=self.root):
            return
        self._scan_cancel_btn.configure(state="disabled", text="Megszakítás…", cursor="arrow")

        def _fut():
            ok, szoveg = self.core.defender_scan_cancel("felület")
            try:
                self.root.after(0, lambda: self.add_log(szoveg, "warning" if ok else "info"))
            except Exception:
                pass
        threading.Thread(target=_fut, name="scan-cancel", daemon=True).start()

    def _scan_panel_text(self, inf):
        """(cim, lepesek szovege, megjegyzes, szin) a folyamatpanelhez."""
        sorok = []
        for szoveg, ts in inf["steps"]:
            sorok.append("✔  %s   %s" % (szoveg, time.strftime("%H:%M:%S", time.localtime(ts))))
        if inf["running"] and inf.get("cancel"):
            sorok.append("⏳  Vizsgálat leállítása…   eltelt: %s" % inf["elapsed"])
            sorok.append("○  Eredmény")
            jegyzet = "A Defender leállítása néhány másodpercig tarthat."
            szin = COLORS['warn']
        elif inf["running"]:
            sorok.append("⏳  Defender-vizsgálat fut…   eltelt: %s" % inf["elapsed"])
            sorok.append("○  Eredmény")
            jegyzet = ("A Defender nem jelzi a százalékot — a mozgó sáv azt mutatja, hogy dolgozik. "
                       "Ha kész, Telegramon is szólok.")
            szin = COLORS['ok']
        elif inf.get("cancel"):
            sorok.append("⏹  Defender-vizsgálat megszakítva   időtartam: %s" % inf["elapsed"])
            jel = "✘" if inf["ok"] is False else "⚠"
            sorok.append("%s  Eredmény: %s" % (jel, inf["result"] or "?"))
            jegyzet = "A panel 2 perc múlva eltűnik. Új vizsgálat: Defender gyors vizsgálat gomb."
            szin = COLORS['bad'] if inf["ok"] is False else COLORS['warn']
        else:
            sorok.append("✔  Defender-vizsgálat lefutott   időtartam: %s" % inf["elapsed"])
            jel = "✔" if inf["ok"] else ("✘" if inf["ok"] is False else "⚠")
            sorok.append("%s  Eredmény: %s" % (jel, inf["result"] or "?"))
            jegyzet = "A panel 2 perc múlva eltűnik."
            szin = COLORS['ok'] if inf["ok"] else (COLORS['bad'] if inf["ok"] is False else COLORS['warn'])
        cim = "\U0001F6E1  Defender-vizsgálat: %s" % inf["name"]
        return cim, "\n".join(sorok), jegyzet, szin

    def _tick_scan(self):
        try:
            inf = self.core.scan_progress()
            if inf is None:
                if self._scan_shown:
                    self._scan_panel.grid_remove()
                    self._scan_shown = False
                if self._scan_anim:
                    self._scan_bar.stop(); self._scan_anim = False
                if self._scan_cancel_shown:
                    self._scan_cancel_btn.pack_forget()
                    self._scan_cancel_shown = False
            else:
                cim, lepesek, jegyzet, szin = self._scan_panel_text(inf)
                self._scan_title.configure(text=cim)
                self._scan_steps.configure(text=lepesek)
                self._scan_note.configure(text=jegyzet)
                self._scan_panel.configure(highlightbackground=szin)
                if not self._scan_shown:
                    self._scan_panel.grid(row=self._card_rows + 3, column=0, columnspan=2, sticky="ew",
                                          padx=(0, 8), pady=(4, 8))
                    self._scan_shown = True
                # [v2.2.0] Megszakitas gomb: csak futo vizsgalatnal
                if inf["running"] and not self._scan_cancel_shown:
                    self._scan_cancel_btn.pack(side=tk.RIGHT, padx=(8, 0), before=self._scan_note)
                    self._scan_cancel_shown = True
                elif not inf["running"] and self._scan_cancel_shown:
                    self._scan_cancel_btn.pack_forget()
                    self._scan_cancel_shown = False
                if inf["running"] and not inf.get("cancel"):
                    self._scan_cancel_btn.configure(state="normal", text="\u23f9 Megszakítás", cursor="hand2")
                if inf["running"] and not self._scan_anim:
                    self._scan_bar.configure(mode="indeterminate")
                    self._scan_bar.start(15)
                    self._scan_anim = True
                elif not inf["running"]:
                    if self._scan_anim:
                        self._scan_bar.stop(); self._scan_anim = False
                    self._scan_bar.configure(mode="determinate", value=100)
        except Exception:
            pass
        self.root.after(1000, self._tick_scan)

    # ---- görgetés ----

    def _on_mousewheel(self, event):
        # Ha az eseménynapló (Text) fölött görgetünk, a napló
        # magától scrolloz — oda nem nyúlunk bele.
        if isinstance(event.widget, tk.Text):
            return
        if event.delta > 0:
            self.canvas.yview_scroll(-3, "units")
        else:
            self.canvas.yview_scroll(3, "units")

    # ---- napló ----

    def tag_configure_colors(self):
        self.log.tag_config("info", foreground=COLORS['text'])
        self.log.tag_config("success", foreground=COLORS['ok'])
        self.log.tag_config("warning", foreground=COLORS['warn'])
        self.log.tag_config("alert", foreground=COLORS['bad'],
                            font=("Consolas", 9, "bold"))

    def add_log(self, text, level="info"):
        self.log.configure(state="normal")
        self.log.insert(tk.END, "[%s] %s\n" % (now_str(), text), level)
        self.log.see(tk.END)
        self.log.configure(state="disabled")

    # ---- események ----

    def show_history(self):
        # Elozmenyek ablak: a guard_naplo.txt elo nezete, 3 masodpercenkent frissul
        win = tk.Toplevel(self.root)
        win.title("Előzmények — Arrabona Guard")
        win.geometry("760x520")
        win.configure(bg="white")
        txt = tk.Text(win, bg="white", fg="#222222", font=("Consolas", 9),
                      relief=tk.FLAT, state=tk.DISABLED)
        sb = tk.Scrollbar(win, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        txt.tag_configure("alert", foreground="#cc2222")  # piros: blokk/riasztas sorok

        def refresh():
            try:
                if not win.winfo_exists():
                    return
            except Exception:
                return
            try:
                with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()[-500:]
            except Exception:
                lines = ["(meg nincs naplo)"]
            txt.config(state=tk.NORMAL)
            txt.delete("1.0", "end")
            for ln in lines:
                if ("BLOKKOLVA" in ln) or ("PORTSCAN" in ln) or ("riaszt" in ln.lower()):
                    txt.insert("end", ln, "alert")
                else:
                    txt.insert("end", ln)
            txt.see("end")
            txt.config(state=tk.DISABLED)
            win.after(3000, refresh)

        refresh()

    def test_alert(self):
        # Valodi riasztasi utvonal tesztje: core.alert() -> naplo + Telegram push + GUI.
        try:
            self.core.alert("127.0.0.1", "TESZT riasztas - minden mukodik! Nyomd meg a gombot: ha az uzenet "
                            "ala kiirja, hogy nyugtazva, a Telegram-gombok is mukodnek.", always=True,
                            gombok=[[("✅ Teszt gomb — nyomd meg!", "ok")]])
        except Exception:
            pass
        self.show_popup("TESZT", "Teszt riasztas - minden mukodik!")
        play_alert_sound()

    def resume_all(self):
        self.core.pause_off()
        self.core.monitor_on()
        self.add_log("Figyelés folytatva.", "success")

    def toggle_autostart(self):
        if autostart_set(self.auto_var.get()):
            self.add_log("Auto-indítás: %s" %
                         ("BE" if self.auto_var.get() else "KI"), "success")
        else:
            self.auto_var.set(autostart_enabled())
            # [v2.18.2] a feladatot csak a telepito hozza letre
            self.add_log("Nem sikerült állítani az auto-indítást: az ütemezett feladat hiányzik - "
                         "futtasd újra az Arrabona Guard telepítőjét.", "warning")
            try:
                import tkinter.messagebox as mb
                mb.showwarning(APP_NAME, "Az automatikus indítás feladata hiányzik.\n\n"
                               "Futtasd újra az Arrabona Guard telepítőjét (a beállításaid megmaradnak), "
                               "az létrehozza.")
            except Exception:
                pass

    # ---- felugró értesítés (toast) ----

    def show_popup(self, tag, text):
        pop = tk.Toplevel(self.root)
        pop.overrideredirect(True)
        pop.attributes("-topmost", True)
        pop.configure(bg=COLORS['brand'])

        inner = tk.Frame(pop, bg=COLORS['panel'])
        inner.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)

        head = tk.Frame(inner, bg=COLORS['panel_head'])
        head.pack(fill=tk.X)
        self._pop_logo = ImageTk.PhotoImage(
            load_icon_image(big=False).resize((48, 48), Image.LANCZOS))
        tk.Label(head, image=self._pop_logo, bg=COLORS['panel_head']).pack(
            side=tk.LEFT, padx=(10, 6), pady=6)
        tk.Label(head, text="%s — %s" % (APP_NAME, tag),
                 fg=COLORS['brand'], bg=COLORS['panel_head'],
                 font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, pady=6)

        lbl = tk.Label(inner, text=text, fg=COLORS['text'], bg=COLORS['panel'],
                       font=("Segoe UI", 10), wraplength=320, justify="left")
        lbl.pack(anchor="w", padx=14, pady=(6, 12))

        pop.update_idletasks()
        sw = pop.winfo_screenwidth()
        sh = pop.winfo_screenheight()
        w = pop.winfo_reqwidth()
        h = pop.winfo_reqheight()
        pop.geometry("+%d+%d" % (sw - w - 24, sh - h - 64))

        def flash(step):
            if step < 6:
                pop.configure(bg=COLORS['brand'] if step % 2 == 0 else '#ffffff')
                pop.after(100, lambda: flash(step + 1))

        # Villogas kivezve: a popup mostantol mozdulatlan marad (nincs kepernyo-villantas)
        pop.after(POPUP_MS, pop.destroy)

    # ---- queue ----


    def open_unblock_dialog(self):
        """Pipalhato blokkolt IP lista; a felhasznalo donti el, mit oldunk fel."""
        import re as _re
        if getattr(self, "_unblock_dlg", None) is not None and self._unblock_dlg.winfo_exists():
            self._unblock_dlg.lift()
            return
        try:
            # Forras: blokkok.json (az igazsagforras), a tuzfal mar nem ip-onkenti szabaly
            bl = self.core._load_blocks()
            ips = sorted([ip for ip, e in bl.items() if not e.get("gone", 0)])
        except Exception as e:
            self.add_log("Blokklista lekerdese sikertelen: %s" % e, "alert")
            return
        if not ips:
            self.add_log("Nincs blokkolt IP, nincs mit feloldani.", "info")
            return
        dlg = tk.Toplevel(self.root)
        self._unblock_dlg = dlg
        dlg.title("Blokkok feloldasa")
        dlg.configure(bg="white")
        dlg.transient(self.root)
        dlg.geometry("480x430")
        def _close():
            try:
                # gorgofix: ne ures binding, hanem a foablak kezeloje jon vissza
                dlg.bind_all("<MouseWheel>", self._on_mousewheel)
            except Exception:
                pass
            dlg.destroy()
        dlg.protocol("WM_DELETE_WINDOW", _close)
        head = tk.Frame(dlg, bg=COLORS['panel_head'])
        head.pack(fill=tk.X)
        tk.Label(head, text="Blokkolt IP-k (%d db)" % len(ips),
                 fg=COLORS['brand'], bg=COLORS['panel_head'],
                 font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT, padx=12, pady=8)
        tk.Label(head, text="Jelold ki, melyeket oldjuk fel",
                 fg=COLORS['text'], bg=COLORS['panel_head'],
                 font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=12)
        body = tk.Frame(dlg, bg="white")
        body.pack(fill=tk.BOTH, expand=True, padx=10, pady=(8, 0))
        cv = tk.Canvas(body, bg="white", highlightthickness=0)
        sb = tk.Scrollbar(body, orient="vertical", command=cv.yview)
        inner = tk.Frame(cv, bg="white")
        inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
        cv.create_window((0, 0), window=inner, anchor="nw")
        cv.configure(yscrollcommand=sb.set)
        cv.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        dlg.bind_all("<MouseWheel>", lambda e: cv.yview_scroll(int(-e.delta / 120), "units"))
        vars_by_ip = {}
        for ip in ips:
            v = tk.BooleanVar(value=False)
            vars_by_ip[ip] = v
            tk.Checkbutton(inner, text=ip, variable=v, bg="white",
                           anchor="w", font=("Segoe UI", 10)
                           ).pack(fill=tk.X, padx=8, pady=1)
        foot = tk.Frame(dlg, bg="white")
        foot.pack(fill=tk.X, padx=10, pady=10)
        def _sel(on):
            for v in vars_by_ip.values():
                v.set(on)
        def _do_unblock(all_ips):
            chosen = list(ips) if all_ips else [ip for ip, v in vars_by_ip.items() if v.get()]
            if not chosen:
                self.add_log("Nincs kijelolt IP.", "info")
                return
            bl = self.core._load_blocks()
            now_t = time.time()
            touched = set()
            ok_n = 0
            for ip in chosen:
                e = bl.get(ip)
                if e and not e.get("gone", 0):
                    touched.add(self.core._cat_of(e))
                    e["gone"] = now_t
                    ok_n += 1
            self.core._save_blocks(bl)
            for cat in touched:
                if cat:
                    self.core.apply_master_rule(cat)
            self.add_log("%d blokk feloldva." % ok_n, "info")
            _close()
        tk.Button(foot, text="Osszes kijelolese",
                  command=lambda: _sel(True),
                  bg=COLORS['panel_head'], fg=COLORS['text'], bd=0, padx=10, pady=5,
                  font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(foot, text="Kijeloltek feloldasa",
                  command=lambda: _do_unblock(False),
                  bg=COLORS['brand'], fg="white", bd=0, padx=12, pady=5,
                  font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=6)
        tk.Button(foot, text="Mindet feloldom",
                  command=lambda: _do_unblock(True),
                  bg="#f5a01e", fg="#3a2400", bd=0, padx=12, pady=5,
                  font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT, padx=6)
        tk.Button(foot, text="Bezaras", command=_close,
                  bg="#bdbdbd", fg="white", bd=0, padx=12, pady=5,
                  font=("Segoe UI", 9)).pack(side=tk.RIGHT, padx=6)

    def pump_queue(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                if kind == "status":
                    self.add_log(data, "info")
                elif kind == "alert":
                    ip, msg = data
                    self.add_log("!! " + msg, "alert")
                    self.v_alert.set(str(self.core.alert_count))
                    self._quiet_alert(msg)  # csendes riasztas: alsav piros sav, nincs felugro ablak
                    if not self.core.game_active():   # [v2.9.0] jatek kozben nincs hang
                        play_alert_sound()
                elif kind == "ransom":
                    if self.core.game_active():
                        # [v2.9.0] jatek kozben nem ugrik fel (a folyamat addig is meg van allitva)
                        self._jatek_ransom = getattr(self, "_jatek_ransom", []) + [data]
                        self.add_log("Zsarolóvírus-gyanú játék közben: a döntés-ablak a játék után jön "
                                     "(a folyamat addig is meg van állítva; Telegram: /leallit %s)" % data["pid"], "alert")
                    else:
                        self._ransom_dialog(data)   # [v2.5.0]
                elif kind == "game_end":
                    self._game_end(data)
                elif kind == "unblock_ui":
                    self.open_unblock_dialog()
                elif kind == "fw_ok":
                    ok = data
                    self.v_fw.set("Aktív ✔" if ok else "Nem aktív ✘")
        except queue.Empty:
            pass
        self.root.after(250, self.pump_queue)

    # ---- állapot-frissítés ----

    def tick_status(self):
        left = self.core.pause_left()
        bl = load_blacklist()
        wl = load_whitelist()

        self.v_bl.set("%d db" % len(bl))
        self.v_wl.set("%d db" % len(wl))
        self.v_lan.set(str(self.core.lan_skipped))
        self.v_blkd.set(str(self.core.blocked_drops))
        self.v_out.set("%d / %d" % (getattr(self.core, "out_blocked", 0),
                                    getattr(self.core, "out_open", 0)))
        self.v_alert.set(str(self.core.alert_count))
        self.v_auto.set("Bekapcsolva ✔" if autostart_enabled() else "Kikapcsolva")
        self.v_wd.set(getattr(self.core, "wd_status", "?"))
        self.v_last.set(date_str())

        if not self.core.is_on():
            self.v_title.set("Az Ön rendszere NINCS védelt")
            self.p1_mark.configure(text="✘", fg=COLORS['bad'])
            self.p1_title.configure(fg=COLORS['bad'])
            self.v_stat.set("Figyelés kikapcsolva")
            self.big_title.configure(fg=COLORS['bad'])
            self.big_mark.configure(text="✘", fg=COLORS['bad'])
        elif left > 0:
            mm = int(left // 60)
            ss = int(left % 60)
            self.v_title.set("Figyelés szünetben")
            self.p1_mark.configure(text="⏸", fg=COLORS['warn'])
            self.p1_title.configure(fg=COLORS['warn'])
            self.v_stat.set("Szünetben (%02d:%02d)" % (mm, ss))
            self.v_pause.set("Hátralévő: %02d:%02d" % (mm, ss))
            self.big_title.configure(fg=COLORS['warn'])
            self.big_mark.configure(text="⏸", fg=COLORS['warn'])
        elif getattr(self.core, "def_rt_off", False):
            # [v1.9.6] a Defender valos ideju vedelme KI van kapcsolva
            self.v_title.set("Figyelem: a Defender valós idejű védelme KI van kapcsolva")
            self.p1_mark.configure(text="⚠", fg=COLORS['warn'])
            self.p1_title.configure(fg=COLORS['warn'])
            self.v_stat.set("Defender KI")
            self.v_pause.set("Nincs szünetben")
            self.big_title.configure(fg=COLORS['warn'])
            self.big_mark.configure(text="⚠", fg=COLORS['warn'])
        elif not self.core.admin:
            # [v1.9.2] Rendszergazdai jog nelkul a tuzfal-szabalyok (blokk,
            # FEED, GEO, honeypot) nem jonnek letre es a tuzfalnaplo sem
            # kapcsolhato be -> NEM irhatjuk ki, hogy "vedett".
            self.v_title.set("Korlátozott védelem — nincs rendszergazdai jog")
            self.p1_mark.configure(text="⚠", fg=COLORS['warn'])
            self.p1_title.configure(fg=COLORS['warn'])
            self.v_stat.set("Korlátozott")
            self.v_pause.set("Nincs szünetben")
            self.big_title.configure(fg=COLORS['warn'])
            self.big_mark.configure(text="⚠", fg=COLORS['warn'])
        else:
            self.v_title.set("Az Ön rendszere védett")
            self.p1_mark.configure(text="✔", fg=COLORS['ok'])
            self.p1_title.configure(fg=COLORS['text'])
            self.v_stat.set("Aktív")
            self.v_pause.set("Nincs szünetben")
            self.big_title.configure(fg=COLORS['ok'])
            self.big_mark.configure(text="✔", fg=COLORS['ok'])

        self.root.after(1000, self.tick_status)

    # ---- ablak / tálca ----

    def show_score(self):
        """[v2.11.0] Biztonsagi pontszam reszletei."""
        import tkinter.messagebox as _mb
        try:
            _mb.showinfo(APP_NAME + " — Biztonsági pontszám", self.core.score_text(), parent=self.root)
        except Exception as e:
            self.add_log("Pontszám hiba: %s" % e, "alert")

    def open_pwned_dialog(self):
        """[v2.11.0] Kiszivargott jelszo-ellenorzes (HIBP, k-anonimitas). A jelszo nem kerul naploba."""
        import threading
        dlg = tk.Toplevel(self.root)
        dlg.title("%s — Kiszivárgott jelszó-ellenőrzés" % APP_NAME)
        dlg.configure(bg=COLORS['panel'])
        dlg.transient(self.root)
        dlg.resizable(False, False)
        tk.Label(dlg, text=("Írd be a jelszót. A gép NEM küldi el: csak az ujjlenyomatának (SHA-1) első 5\n"
                            "karakterét kérdezi le a Have I Been Pwned adatbázisból (k-anonimitás).\n"
                            "A jelszó nem kerül naplóba, és az ablak bezárásakor törlődik."),
                 font=("Segoe UI", 9), fg=COLORS['text'], bg=COLORS['panel'], justify="left"
                 ).pack(anchor="w", padx=14, pady=(12, 8))
        v = tk.StringVar()
        e = tk.Entry(dlg, textvariable=v, show="•", font=("Segoe UI", 11), width=36)
        e.pack(padx=14, anchor="w")
        e.focus_set()
        eredm = tk.Label(dlg, text="", font=("Segoe UI", 10, "bold"), bg=COLORS['panel'], fg=COLORS['text'],
                         wraplength=460, justify="left")
        eredm.pack(anchor="w", padx=14, pady=8)

        def _kesz(n):
            if n is None:
                eredm.configure(text="Nem sikerült lekérdezni (nincs internet?).", fg=COLORS['warn'])
            elif n == 0:
                eredm.configure(text="✔ Ez a jelszó egyetlen ismert adatszivárgásban sem szerepel.", fg=COLORS['ok'])
            else:
                eredm.configure(text=("✘ EZ A JELSZÓ %s ADATSZIVÁRGÁSBAN SZEREPEL! Ne használd sehol — "
                                      "cseréld le mindenhol, ahol ezt használod." % format(n, ",").replace(",", " ")),
                                fg=COLORS['bad'])

        def _ellenoriz(_ev=None):
            jelszo = v.get()
            v.set("")
            if not jelszo:
                return
            eredm.configure(text="Ellenőrzés…", fg=COLORS['text'])
            from .extrak import pwned_count

            def _fut():
                n = pwned_count(jelszo)
                self.root.after(0, lambda: _kesz(n))
            threading.Thread(target=_fut, daemon=True).start()
        e.bind("<Return>", _ellenoriz)
        gs = tk.Frame(dlg, bg=COLORS['panel'])
        gs.pack(fill=tk.X, padx=14, pady=(0, 12))
        tk.Button(gs, text="Ellenőrzés", command=_ellenoriz, bg=COLORS['brand'], fg="white", bd=0,
                  padx=12, pady=5, font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        tk.Button(gs, text="Bezárás", command=lambda: (v.set(""), dlg.destroy()), bg="#bdbdbd", fg="white", bd=0,
                  padx=12, pady=5, font=("Segoe UI", 9)).pack(side=tk.RIGHT)
        dlg.protocol("WM_DELETE_WINDOW", lambda: (v.set(""), dlg.destroy()))

    def toggle_game_mode(self):
        """[v2.9.0] AUTO -> BE -> KI -> AUTO"""
        from .jatek import jatek_cfg
        kov = {"AUTO": "BE", "BE": "KI", "KI": "AUTO"}[jatek_cfg()["MOD"]]
        _ok, sz = self.core.game_set_mode(kov)
        self.game_btn.config(text="🎮 Játék mód: %s" % kov)
        self.add_log(sz.replace("Jatek mod", "Játék mód"), "info")
        self._tray_menu_refresh(force=True)

    @staticmethod
    def _tray_game_mode():
        from .jatek import jatek_cfg
        try:
            return jatek_cfg()["MOD"]
        except Exception:
            return "AUTO"

    def _tray_game_title(self, item=None):
        """[v2.9.1] A talca-menu "Jatek mod" pontjanak cime: allas + aktiv-e most."""
        mod = self._tray_game_mode()
        aktiv = False
        try:
            aktiv = self.core.game_active()
        except Exception:
            pass
        return "Játék mód: %s%s" % (mod, " — most aktív 🎮" if aktiv else "")

    def _tray_game_set(self, mod):
        _ok, sz = self.core.game_set_mode(mod)
        self.add_log(sz.replace("Jatek mod", "Játék mód"), "info")
        self._tray_menu_refresh(force=True)

    def _tray_menu_refresh(self, force=False):
        """A talca-menu ujraepitese, ha a jatek mod allasa / aktivitasa valtozott
        (a pystray a menu szovegeit es pipait csak ujraepiteskor ertekeli ki)."""
        try:
            allas = (self._tray_game_mode(), self.core.game_active())
            if force or allas != getattr(self, "_tray_game_last", None):
                self._tray_game_last = allas
                if getattr(self, "icon", None) is not None:
                    self.icon.update_menu()
        except Exception:
            pass

    def _game_end(self, inf):
        """[v2.9.0] jatek vege: osszegzes, egy hangjelzes ha volt riasztas, elhalasztott ablakok."""
        self.add_log("🎮 Játék mód vége (%d perc). Közben %d riasztás érkezett%s." % (
            inf["perc"], inf["alerts"],
            (", %d elhalasztott vizsgálat most sorban indul" % inf["scans"]) if inf["scans"] else ""),
            "warning" if inf["alerts"] else "info")
        if inf["alerts"]:
            play_alert_sound()
        for data in getattr(self, "_jatek_ransom", []):
            try:
                self._ransom_dialog(data)
            except Exception:
                pass
        self._jatek_ransom = []

    def _ransom_dialog(self, inf):
        """[v2.5.0] Zsarolovirus-gyanu: a megallitott folyamatrol a felhasznalo dont."""
        import threading
        pid, nev = inf["pid"], inf["name"]
        folyamat = inf.get("tipus") == "folyamat"   # [v2.12.0] folyamatfigyeles: KRITIKUS folyamat
        if folyamat:
            _ct = inf.get("ctime")
            kill_fn = lambda p, k: self.core.folyamat_kill(p, _ct, k)
            resume_fn = lambda p, k: self.core.folyamat_resume(p, _ct, k)
        else:
            kill_fn, resume_fn = self.core.csali_kill, self.core.csali_resume
        dlg = tk.Toplevel(self.root)
        dlg.title("%s — %s" % (APP_NAME, "KRITIKUS FOLYAMAT" if folyamat else "ZSAROLÓVÍRUS-GYANÚ"))
        dlg.configure(bg=COLORS['bad'])
        dlg.attributes("-topmost", True)
        dlg.resizable(False, False)
        belso = tk.Frame(dlg, bg=COLORS['panel'])
        belso.pack(fill=tk.BOTH, expand=True, padx=3, pady=3)
        tk.Label(belso, text="⚠  KRITIKUS FOLYAMAT!" if folyamat else "⚠  ZSAROLÓVÍRUS-GYANÚ!",
                 font=("Segoe UI", 15, "bold"),
                 fg=COLORS['bad'], bg=COLORS['panel']).pack(anchor="w", padx=16, pady=(14, 4))
        if folyamat:
            szoveg0 = ("Veszélyes műveletet próbált egy program:\n%s\n\n"
                       "A folyamatot MEGÁLLÍTOTTAM:\n%s  (PID %d, szülő: %s)\n%s\nParancs: %s\n\n"
                       "Ha nem ismered, vagy nem te indítottad most: Leállítás, utána teljes "
                       "Defender-vizsgálat. Ha te voltál: Folytatás."
                       % (inf.get("where", "")[:400], nev, pid, inf.get("szulo") or "-",
                          inf.get("exe") or "", (inf.get("cmd") or "")[:300]))
        else:
            szoveg0 = None
        tk.Label(belso, text=szoveg0 or ("Valami hozzányúlt a csalifájlokhoz (ezekhez ember nem nyúl):\n%s\n\n"
                              "A legtöbbet író folyamatot MEGÁLLÍTOTTAM:\n%s  (PID %d)\n%s\n\n"
                              "Ha nem ismered, vagy nem te csináltál most valamit a fájlokkal: Leállítás,\n"
                              "utána teljes Defender-vizsgálat. Ha te voltál (pl. mappát töröltél): Folytatás.")
                 % (inf.get("where", "")[:300], nev, pid, inf.get("exe") or ""),
                 font=("Segoe UI", 10), fg=COLORS['text'], bg=COLORS['panel'], justify="left",
                 wraplength=560).pack(anchor="w", padx=16)
        v = tk.StringVar(value="")
        gombok = tk.Frame(belso, bg=COLORS['panel'])
        gombok.pack(fill=tk.X, padx=16, pady=14)

        def _do(fn, teljes=False):
            for b in gombok.winfo_children():
                b.configure(state="disabled")

            def _fut():
                ok, szoveg = fn(pid, "felület")
                if ok and teljes:
                    self.core.defender_scan("full")

                def _kesz():
                    self.add_log(szoveg, "warning" if ok else "alert")
                    v.set(szoveg)
                    tk.Button(gombok, text="Bezárás", command=dlg.destroy, font=("Segoe UI", 9),
                              bg="#bdbdbd", fg="white", bd=0, padx=12, pady=6).pack(side=tk.RIGHT)
                self.root.after(0, _kesz)
            threading.Thread(target=_fut, daemon=True).start()
        tk.Button(gombok, text="⛔ Leállítás + teljes vizsgálat", font=("Segoe UI", 10, "bold"),
                  bg=COLORS['bad'], fg="white", bd=0, padx=14, pady=6, cursor="hand2",
                  command=lambda: _do(kill_fn, True)).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(gombok, text="▶ Folytatás (én voltam)", font=("Segoe UI", 10),
                  bg=COLORS['panel_head'], fg=COLORS['text'], bd=0, padx=14, pady=6, cursor="hand2",
                  command=lambda: _do(resume_fn)).pack(side=tk.LEFT)
        tk.Label(belso, textvariable=v, font=("Segoe UI", 9, "bold"), fg=COLORS['text'],
                 bg=COLORS['panel'], wraplength=560, justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        dlg.protocol("WM_DELETE_WINDOW", lambda: None)   # dontes nelkul ne lehessen bezarni
        try:
            self.show_window()
        except Exception:
            pass
        dlg.lift()
        dlg.focus_force()

    # [v2.15.0] kereso naplo + beallitasok mentese / visszaallitasa (ui_extra.py)
    def open_log_dialog(self):
        from .ui_extra import open_log_dialog
        open_log_dialog(self)

    def backup_settings(self):
        from .ui_extra import backup_settings
        backup_settings(self)

    def restore_settings(self):
        from .ui_extra import restore_settings
        restore_settings(self)

    def open_fix_dialog(self, lap=0):
        """[v2.3.0] Javitas ablak (Indítópult / Karantén / Hosts)."""
        from .ui_javitas import open_fix_dialog
        try:
            open_fix_dialog(self, lap)
        except Exception as e:
            self.add_log("A Javítás ablak nem nyílt meg: %s" % e, "alert")

    def _defender_scan_ui(self):
        if self.core.defender_scan("quick"):
            self.add_log("Defender gyors vizsgálat elindítva — ha kész, jelzek (Telegramon is).", "info")
        else:
            self.add_log("Már fut egy Defender-vizsgálat: %s." % self.core.def_scan_running, "warning")

    def hide_window(self):
        self.root.withdraw()
        self.add_log("Ablak a tálcára rejtve (dupla klikk a logora = visszahozás).")

    def show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()


    # ============ FOLYAMATJELZŐ ALSOR (frissítés-állapot) ============
    def _build_update_status(self):
        import tkinter as tk
        # Frissites-allapot sav es KULON piros riasztas-sav:
        # a riasztas soha nem takarja ki a frissites-informaciot.
        self._upd_lbl = tk.Label(self.root, text="", anchor="w",
                                 font=("Segoe UI", 9),
                                 bg="#eef1f5", fg="#555555")
        self._upd_lbl.pack(side=tk.BOTTOM, fill=tk.X)
        self._alert_lbl = tk.Label(self.root, text="", anchor="w",
                                   font=("Segoe UI", 9, "bold"),
                                   bg="#c62828", fg="#ffffff")
        self._alert_shown = False
        self._poll_update_status()

    def _quiet_alert(self, msg):
        """Csendes riasztas: kulon piros sav 30 mp-re, nincs popup, nem nyul a frissites-savhoz."""
        import time as _t
        self._alert_msg = msg
        self._alert_until = _t.time() + 30

    def _poll_update_status(self):
        import time as _t
        try:
            # --- 1. Kulon riasztas-sav: csak akkor lathato, ha aktiv ---
            if getattr(self, "_alert_until", 0) > _t.time():
                self._alert_lbl.config(
                    text="  RIASZTAS: %s" % getattr(self, "_alert_msg", ""))
                if not getattr(self, "_alert_shown", False):
                    self._alert_lbl.pack(side=tk.BOTTOM, before=self._upd_lbl, fill=tk.X)
                    self._alert_shown = True
            elif getattr(self, "_alert_shown", False):
                self._alert_lbl.pack_forget()
                self._alert_shown = False
            # --- 2. Valos frissites-allapot (a riasztastol fuggetlenul mindig latszik) ---
            busy = []
            if getattr(self.core, "_feed_busy", False):
                busy.append("FEED")
            if getattr(self.core, "_geo_busy", False):
                busy.append("GEO")
            if busy:
                self._upd_lbl.config(
                    text="  Frissítés folyamatban: %s ..." % ", ".join(busy),
                    fg="#b26a00", bg="#fff6e0")
            else:
                darabok = []
                mind_ok = True
                for nev, ok_key, done_key in (
                        ("FEED", "_feed_ok", "_feed_done_at"),
                        ("GEO", "_geo_ok", "_geo_done_at")):
                    ok = getattr(self.core, ok_key, None)
                    kesz = getattr(self.core, done_key, "-")
                    if ok is None:
                        darabok.append("%s: még nem futott" % nev)
                        mind_ok = False
                    elif ok:
                        darabok.append("%s kész: %s" % (nev, kesz))
                    else:
                        darabok.append("%s HIBA (%s) - cache érvényes" % (nev, kesz))
                        mind_ok = False
                if mind_ok:
                    self._upd_lbl.config(text="  " + "   |   ".join(darabok),
                                         fg="#2e7d32", bg="#eef5ee")
                else:
                    self._upd_lbl.config(text="  " + "   |   ".join(darabok),
                                         fg="#8a5a00", bg="#fff3e0")
        except Exception:
            pass
        try:
            self.root.after(1000, self._poll_update_status)
        except Exception:
            pass
    def build_tray(self):
        core = self.core

        def _open(icon=None, item=None):
            self.root.after(0, self.show_window)

        def _pause10(icon=None, item=None):
            core.pause(10)

        def _pause60(icon=None, item=None):
            core.pause(60)

        def _off(icon=None, item=None):
            core.monitor_off()

        def _resume(icon=None, item=None):
            self.resume_all()

        def _quit(icon=None, item=None):
            def _megerosites():
                import tkinter.messagebox as _mb
                try:
                    ok = _mb.askyesno(APP_NAME,
                        "Biztosan kilépsz?" + chr(10) + chr(10) +
                        "A kilépéssel a VÉDELEM TELJESEN LEÁLL:" + chr(10) +
                        "tűzfal-figyelés, honeypot, feed és geo-blokk!" + chr(10) + chr(10) +
                        "Valóban kilépsz?")
                except Exception:
                    ok = True
                if not ok:
                    return
                # [v1.9.5] szandekos kilepes: az orkutya NE inditsa ujra
                quit_flag_set()
                core.pause_off()
                core.stop()
                icon.stop()
                self.root.after(0, self.root.destroy)
            self.root.after(0, _megerosites)

        def _unblock(icon=None, item=None):
            self.core.unblock_all()
        menu = pystray.Menu(
            pystray.MenuItem("Megnyitás", _open, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Szünet 10 percre", _pause10),
            pystray.MenuItem("Szünet 1 órára", _pause60),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Figyelés kikapcsolása", _off),
            pystray.MenuItem("Figyelés folytatása", _resume),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Blokkok feloldása", lambda s: self.q.put(("unblock_ui", None))),
            # [v2.9.1] Jatek mod almenu: a cim mutatja az allast (+ ha most aktiv), pipa az aktualison
            pystray.MenuItem(self._tray_game_title, pystray.Menu(
                pystray.MenuItem("AUTO (automatikus)", lambda s: self.root.after(0, lambda: self._tray_game_set("AUTO")),
                                 checked=lambda item: self._tray_game_mode() == "AUTO", radio=True),
                pystray.MenuItem("BE (mindig csendes)", lambda s: self.root.after(0, lambda: self._tray_game_set("BE")),
                                 checked=lambda item: self._tray_game_mode() == "BE", radio=True),
                pystray.MenuItem("KI", lambda s: self.root.after(0, lambda: self._tray_game_set("KI")),
                                 checked=lambda item: self._tray_game_mode() == "KI", radio=True),
            )),
            pystray.Menu.SEPARATOR,
            # [v2.18.0]
            pystray.MenuItem("Frissítés keresése", lambda s: self.root.after(0, lambda: self.gh_kereses(kezi=True))),
            pystray.MenuItem("Telegram beállítása…", lambda s: self.root.after(0, self.open_telegram_setup)),
            pystray.MenuItem("Arrabona Pass (jelszókezelő)", lambda s: self.root.after(0, self.open_pass)),  # [v2.19.0]
            pystray.MenuItem("Kilépés", _quit),
        )
        import ctypes
        _sm = ctypes.windll.user32.GetSystemMetrics(49)  # SM_CXSMICON
        if not _sm or _sm < 12: _sm = 16
        try:
            tray_src = Image.open(os.path.join(app_dir(), "logo_tray.png")).convert("RGBA")
        except Exception:
            tray_src = load_icon_image(big=True)   # [v2.18.0] hianyzo logo ne akassza meg az indulast
        tray_src = tray_src.crop(tray_src.getbbox())
        _t = tray_src
        while _t.width > _sm * 2: _t = _t.resize((_t.width // 2, _t.height // 2), Image.LANCZOS)
        tray_img = _t.resize((_sm, _sm), Image.LANCZOS)
        from PIL import ImageFilter
        tray_img = tray_img.filter(ImageFilter.UnsharpMask(radius=0.8, percent=180, threshold=3))
        self._tray_base = tray_img.copy()
        self.icon = pystray.Icon(APP_NAME, tray_img,
               "%s v%s" % (APP_NAME, VERSION), menu)
        self.icon.run_detached()
        self.update_tray_title()

    # ===== 3. FELADAT: FRISSITES-FIGYELO =====
    def _upd_log(self, msg):
        import time as _t
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write("[%s] %s\n" % (_t.strftime("%Y-%m-%d %H:%M:%S"), msg))
        except OSError:
            pass

    def check_for_update(self):
        try:
            self._upd_dist = (os.path.isfile(DIST_EXE) and os.path.isfile(INSTALL_EXE)
                   and os.path.getmtime(DIST_EXE) >
                       os.path.getmtime(INSTALL_EXE) + 5)
            van = self._upd_dist or updater.UJ_VERZIO is not None
            if self._upd_dist:
                self.update_banner_lbl.config(text="Frissítés elérhető: új build a dist mappában!")
            elif updater.UJ_VERZIO is not None and not updater.frissites_folyamatban():
                self.update_banner_lbl.config(
                    text="Új verzió érhető el: v%s (most: v%s)" % (updater.UJ_VERZIO["ver"], VERSION))
            if van and not self.update_shown:
                self.update_banner.pack(fill=tk.X, before=self.bar_wrap)
                self.update_shown = True
                if not self.update_notified:
                    self.update_notified = True
                    self._upd_log("Frissítés elérhető: %s" % (
                        "új build a dist mappában." if self._upd_dist
                        else "v%s (GitHub)" % updater.UJ_VERZIO["ver"]))
            elif not van and self.update_shown:
                self.update_banner.pack_forget()
                self.update_shown = False
                self.update_notified = False
        except Exception as e:
            self._upd_log("Frissítés-ellenőrzés hiba: %s" % e)
        self.root.after(UPDATE_CHECK_MS, self.check_for_update)

    # ===== [v2.18.0] GITHUB-FRISSITES =====
    def _gh_kereses_ciklus(self):
        self.gh_kereses(kezi=False)
        self.root.after(updater.KERESES_MS, self._gh_kereses_ciklus)

    def gh_kereses(self, kezi=False):
        """Hatterben lekerdezi a legujabb kiadast; kezi=True: az eredmenyt ablakban is mutatja."""
        def _hatter():
            van, sz = updater.keres(kezi=kezi)
            uzenet = updater.telegram_ertesites_kell() if van else None
            if uzenet:
                try:
                    from .telegram import tg_send
                    tg_send(uzenet, gombok=[[("⬆ Telepítés most", "gu:")]])
                except Exception:
                    pass
            def _ui():
                self.check_for_update_once()
                if kezi:
                    import tkinter.messagebox as mb
                    if van and mb.askyesno(APP_NAME, sz + "\n\nTelepíted most?"):
                        self.apply_github_update(kerdes=False)
                    elif not van:
                        mb.showinfo(APP_NAME, sz)
            try:
                self.root.after(0, _ui)
            except Exception:
                pass
        import threading as _th
        _th.Thread(target=_hatter, daemon=True).start()

    def check_for_update_once(self):
        """A frissites-sav azonnali ujraszamolasa (az idozito nelkul)."""
        try:
            van = self._upd_dist or updater.UJ_VERZIO is not None
            if updater.UJ_VERZIO is not None and not self._upd_dist:
                self.update_banner_lbl.config(
                    text="Új verzió érhető el: v%s (most: v%s)" % (updater.UJ_VERZIO["ver"], VERSION))
            if van and not self.update_shown:
                self.update_banner.pack(fill=tk.X, before=self.bar_wrap)
                self.update_shown = True
            elif not van and self.update_shown:
                self.update_banner.pack_forget()
                self.update_shown = False
        except Exception:
            pass

    def apply_github_update(self, kerdes=True):
        import tkinter.messagebox as mb
        uj = updater.UJ_VERZIO
        if not uj:
            mb.showinfo(APP_NAME, "Nincs újabb verzió.")
            return
        if updater.frissites_folyamatban():
            return
        if kerdes:
            jegyzet = uj["notes"].strip()
            if len(jegyzet) > 700:
                jegyzet = jegyzet[:700] + "…"
            if not mb.askyesno(APP_NAME,
                               "Új verzió: v%s (most: v%s)\n\n%s\n\n"
                               "A Guard letölti és ellenőrzi (SHA-256) a telepítőt,\n"
                               "telepíti, majd automatikusan újraindul.\n\nMehet?"
                               % (uj["ver"], VERSION, jegyzet or "(nincs leírás)")):
                return
        self.update_banner_btn.config(state=tk.DISABLED)
        self.update_banner_lbl.config(text="v%s letöltése..." % uj["ver"])

        def _halad(sz):
            try:
                self.root.after(0, lambda: self.update_banner_lbl.config(
                    text="v%s letöltése: %d%%" % (uj["ver"], sz)))
            except Exception:
                pass

        def _hatter():
            ok, sz = updater.telepites(updater.KILEPES_HOOK, _halad)
            if not ok:
                def _hiba():
                    self.update_banner_btn.config(state=tk.NORMAL)
                    self.check_for_update_once()
                    self._upd_log("GitHub-frissítés HIBA: %s" % sz)
                    mb.showerror(APP_NAME, "A frissítés nem sikerült:\n%s" % sz)
                self.root.after(0, _hiba)
        import threading as _th
        _th.Thread(target=_hatter, daemon=True).start()

    def _kilepes_frissitesre(self):
        """A telepito elindult: kilepunk, hogy le tudja cserelni a fajlokat.
        Az orkutya NE inditsa ujra kozben (kilepes.flag) - a telepito inditja ujra a Guardot."""
        self._upd_log("Frissítés: telepítő elindítva, a Guard kilép.")
        try:
            quit_flag_set()
        except Exception:
            pass
        try:
            release_single_instance()
        except Exception:
            pass
        self._kilepes_frissites = True
        try:
            self.root.destroy()
        except Exception:
            os._exit(0)

    def _elso_inditas_teendok(self):
        """Frissites utani visszajelzes + elso indulaskor a Telegram-varazslo felajanlasa."""
        try:
            sz = updater.ujraindult_frissites_utan()
            if sz:
                self.add_log(sz, "success" if sz.startswith("✅") else "warning")
                from .telegram import tg_send
                import threading as _th
                _th.Thread(target=tg_send, args=(sz,), daemon=True).start()
        except Exception:
            pass
        try:
            if telegram_setup.felajanlas_kell():
                telegram_setup.felajanlo_ablak(self.root, self.open_telegram_setup)
        except Exception as e:
            self._upd_log("Telegram-varázsló hiba: %s" % e)

    def open_pass(self):
        """[v2.19.0] Arrabona Pass (jelszokezelo) inditasa - kulon programkent."""
        import tkinter.messagebox as mb
        from tkinter import filedialog
        p = pass_inditas.keres()
        if not p:
            if not mb.askyesno(APP_NAME, "Nem találom az Arrabona Pass programot.\n\n"
                               "Megmutatod, hol van?\n(Arrabona Pass.exe vagy arrabona_pass.py)",
                               parent=self.root):
                return
            p = filedialog.askopenfilename(
                parent=self.root, title="Hol van az Arrabona Pass?",
                filetypes=[("Arrabona Pass", "*.exe *.py"), ("Minden fájl", "*.*")])
            if not p:
                return
            p = os.path.normpath(p)
            pass_inditas.mentes(p)
        try:
            pass_inditas.indit(p)
            self.add_log("Arrabona Pass elindítva.")
        except Exception as ex:
            mb.showerror(APP_NAME, "Nem sikerült elindítani az Arrabona Passt:\n%s" % ex,
                         parent=self.root)

    def show_about(self):
        """[v2.18.1] Nevjegy: verzio, GitHub, frissites keresese, hibanaplo."""
        import webbrowser
        from .common import GITHUB_REPO, HIBA_LOG, APPDATA_DIR
        if getattr(self, "_about_win", None) is not None:
            try:
                self._about_win.deiconify()
                self._about_win.lift()
                return
            except Exception:
                self._about_win = None
        w = tk.Toplevel(self.root)
        self._about_win = w
        w.title("Névjegy - %s" % APP_NAME)
        w.configure(bg=COLORS['panel'])
        w.resizable(False, False)

        def _bezar():
            self._about_win = None
            w.destroy()
        w.protocol("WM_DELETE_WINDOW", _bezar)
        fej = tk.Frame(w, bg=COLORS['brand'])
        fej.pack(fill=tk.X)
        try:
            self._about_logo = ImageTk.PhotoImage(load_icon_image(big=False).resize((48, 48), Image.LANCZOS))
            tk.Label(fej, image=self._about_logo, bg=COLORS['brand']).pack(side=tk.LEFT, padx=(14, 8), pady=10)
        except Exception:
            pass
        tk.Label(fej, text="%s\nv%s" % (APP_NAME.upper(), VERSION), justify="left",
                 font=("Segoe UI", 13, "bold"), fg="white", bg=COLORS['brand']).pack(side=tk.LEFT, pady=10)
        tart = tk.Frame(w, bg=COLORS['panel'])
        tart.pack(fill=tk.BOTH, padx=18, pady=12)

        def sor(txt, **kw):
            tk.Label(tart, text=txt, justify="left", anchor="w", wraplength=420,
                     font=kw.pop("font", ("Segoe UI", 10)), fg=kw.pop("fg", COLORS['text']),
                     bg=COLORS['panel'], **kw).pack(anchor="w", fill=tk.X, pady=(0, 4))
        sor("Ingyenes PC-védelmi program Windowsra, nyilvános forráskóddal.")
        sor("© 2026 Lokypapa - minden jog fenntartva. Ingyenesen használható; a kód másolása,\n"
            "módosítása, terjesztése csak engedéllyel. Garancia nélkül, a Windows Defender mellé.",
            fg=COLORS['text_soft'], font=("Segoe UI", 9))
        link = tk.Label(tart, text="github.com/%s" % GITHUB_REPO, font=("Segoe UI", 10, "underline"),
                        fg=COLORS['link'], bg=COLORS['panel'], cursor="hand2")
        link.pack(anchor="w", pady=(4, 2))
        link.bind("<Button-1>", lambda e: webbrowser.open("https://github.com/%s" % GITHUB_REPO))
        allapot = tk.Label(tart, text=updater.allapot_szoveg().split("\n", 2)[-1] if updater.UTOLSO_KERESES
                           else "Frissítés: még nem kereste.", justify="left", anchor="w",
                           font=("Segoe UI", 9), fg=COLORS['text_soft'], bg=COLORS['panel'])
        allapot.pack(anchor="w", pady=(6, 10))
        gombok = tk.Frame(tart, bg=COLORS['panel'])
        gombok.pack(anchor="w", fill=tk.X)

        def gomb(txt, cmd, fo=False):
            b = tk.Button(gombok, text=txt, command=cmd, relief=tk.FLAT, cursor="hand2", padx=10, pady=4,
                          font=("Segoe UI", 9, "bold" if fo else "normal"),
                          fg="white" if fo else COLORS['text'], bg=COLORS['brand'] if fo else COLORS['panel_head'],
                          activebackground=COLORS['brand_dark'] if fo else COLORS['divider'])
            b.pack(side=tk.LEFT, padx=(0, 6))
            return b
        gomb("Frissítés keresése", lambda: (_bezar(), self.gh_kereses(kezi=True)), fo=True)
        gomb("Kiadások", lambda: webbrowser.open("https://github.com/%s/releases" % GITHUB_REPO))
        gomb("Hiba bejelentése", lambda: webbrowser.open("https://github.com/%s/issues/new" % GITHUB_REPO))
        gomb("Mappa", lambda: os.startfile(APPDATA_DIR))
        if os.path.exists(HIBA_LOG) and os.path.getsize(HIBA_LOG) > 0:
            sor("")
            sor("⚠ Van bejegyzés a hibanaplóban - hibabejelentéshez csatold (személyes adatot nem tartalmaz, "
                "de átküldés előtt nézd át):", fg=COLORS['warn'], font=("Segoe UI", 9))
            tk.Button(tart, text="Hibanapló megnyitása", command=lambda: os.startfile(HIBA_LOG),
                      relief=tk.FLAT, cursor="hand2", padx=10, pady=3, font=("Segoe UI", 9)).pack(anchor="w")
        try:
            w.transient(self.root)
            w.lift()
            w.focus_force()
        except Exception:
            pass

    def open_telegram_setup(self):
        try:
            telegram_setup.TelegramVarazslo(self.root)
        except Exception as e:
            import tkinter.messagebox as mb
            mb.showerror(APP_NAME, "A Telegram-beállító nem nyílt meg:\n%s" % e)

    def apply_update(self):
        import tkinter.messagebox as mb
        import shutil as sh
        import subprocess as sp
        # [v2.18.0] nincs helyi build -> GitHub-kiadas telepitese
        if not self._upd_dist and updater.UJ_VERZIO is not None:
            self.apply_github_update()
            return
        if not (os.path.isfile(DIST_EXE) and os.path.isfile(INSTALL_EXE)):
            mb.showerror(APP_NAME, "A frissítendő fájl nem található:\n%s" % DIST_EXE)
            return
        if not mb.askyesno(APP_NAME,
                           "Új build telepítése a dist mappából?\n\n"
                           "A Guard kicseréli a telepített fájlt,\n"
                           "majd automatikusan újraindul."):
            return
        try:
            old = INSTALL_EXE + ".old"
            if os.path.exists(old):
                os.remove(old)           # elozo csere maradekanak takaritasa
            os.rename(INSTALL_EXE, old)  # a futó exe athelyezheto, felulirozni nem
            sh.copyfile(DIST_EXE, INSTALL_EXE)
            self._upd_log("Frissítés telepítve, újraindítás...")
            # tiszta kornyezet: a PyInstaller _MEIPASS2 valtozojat NEM orokolheti,
            # kulonben az uj processz az oreg ideiglenes mappajat hasznalna,
            # amit az oreg kilepese utan torolnek (base_library.zip hiba)
            # [v2.12.3] PyInstaller 6+: a _PYI_* valtozok miatt az uj peldany a REGI
            # peldany ideiglenes (_MEI...) mappajat hasznalta - amit a regi kilepeskor
            # torol ("base_library.zip" / "No module named expat" hiba). Teljesen fuggetlen indulas:
            upd_env = {k: v for k, v in os.environ.items()
                       if not (k.upper().startswith("_MEI") or k.upper().startswith("_PYI"))}
            upd_env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
            # [v1.9.1] mutex elengedese + jelzes, hogy az uj peldany ne lepjen ki
            mark_restart()
            release_single_instance()
            sp.Popen([INSTALL_EXE], env=upd_env,
                     cwd=os.path.dirname(INSTALL_EXE))
            # [v2.12.1] a regi peldany TENYLEG lepjen ki: korabban csak a felulet zarult be,
            # a talca-ikon szala eletben tartotta a folyamatot (dupla Guard a talcan,
            # dupla figyeles / Telegram). A run() a mainloop utan leallit mindent.
            self._kilepes_frissites = True
            self.root.destroy()
        except Exception as e:
            self._upd_log("Frissítés telepítési HIBA: %s" % e)
            # [v1.9.1] sikertelen frissites: a mutexet visszavesszuk, tovabb futunk
            if instance._INSTANCE_MUTEX is None:
                acquire_single_instance()
            mb.showerror(APP_NAME, "Nem sikerült a frissítés:\n%s" % e)

    # ===== 4. FELADAT: MODUL-KARTYA FRISSITES (3 mp-enkent) =====
    def toggle_theme(self):
        import tkinter.messagebox as mb
        # tema mentese, majd ujrainditas hogy minden widget uj szinnel epuljon
        try:
            uj_tema = 'light' if _is_dark() else 'dark'
            with open(_theme_file(), 'w', encoding='utf-8') as f:
                f.write(uj_tema)
        except Exception as e:
            mb.showwarning(APP_NAME, 'Tema mentese sikertelen: %s' % e)
            return
        self._restart_app()

    def _restart_app(self):
        import tkinter.messagebox as mb
        import subprocess as sp
        # [v1.9.1] mutex elengedese + restart.flag, hogy az uj peldany
        # ne lassa foglaltnak a mutexet es ne lepjen ki csendben
        mark_restart()
        release_single_instance()
        try:
            if getattr(sys, 'frozen', False):
                # Telepitett exe: a biztonsagos ujrainditas az autostart feladaton
                # keresztul tortenik - a szulo a Windows Scheduler szolgaltatas,
                # amely nem hal el a PyInstaller onefile szulo-ellenorzese elott.
                import time as _t
                def _rstlog(msg):
                    try:
                        _f = open(LOG_FILE, 'a', encoding='utf-8')
                        _f.write('[%s] RESTART: %s\n' % (_t.strftime('%Y-%m-%d %H:%M:%S'), msg))
                        _f.close()
                    except Exception:
                        pass
                ok = False
                try:
                    r = sp.run(['schtasks', '/run', '/tn', 'ArrabonaGuard AutoStart'],
                               capture_output=True, timeout=10,
                               creationflags=sp.CREATE_NO_WINDOW)
                    _rstlog('schtasks returncode=%s stderr=%s' % (r.returncode, (r.stderr or b'').decode('utf-8', 'replace').strip()))
                    ok = (r.returncode == 0)
                except Exception as e:
                    _rstlog('schtasks kivtel: %s' % e)
                if not ok:
                    # Biztonsagos fallback: explorer.exe-n ati inditas - fuggetlen szulo,
                    # jol lathato ablak, UAC kezelve (a kozvetlen Popen a PyInstaller miatt veszelyes)
                    exe = os.path.normpath(sys.executable)
                    sp.Popen(['explorer.exe', exe], creationflags=sp.CREATE_NO_WINDOW)
                    _rstlog('fallback explorer.exe inditas: %s' % exe)
                _rstlog('regi peldany leall, tema mentve')
            else:
                env = dict(os.environ)
                for _k in ('_MEIPASS2', '_MEIPASS'):
                    env.pop(_k, None)
                sp.Popen([sys.executable, ENTRY_SCRIPT], env=env)
        except Exception as e:
            # [v1.9.1] sikertelen ujrainditas: a mutexet visszavesszuk, tovabb futunk
            if instance._INSTANCE_MUTEX is None:
                acquire_single_instance()
            mb.showerror(APP_NAME, 'Ujrainditas sikertelen: %s' % e)
            return
        self.root.destroy()
        # regi folyamat biztos kilepese (tray + ikonmaradekok elkerulese)
        os._exit(0)

    def tick_mods(self):
        import time as _t
        core = self.core

        def alive(attr):
            t = getattr(core, attr, None)
            return bool(t and t.is_alive())

        def upt(attr):
            t0 = getattr(core, attr, 0)
            if not t0:
                return "?"
            s = int(_t.time() - t0)
            h, m = s // 3600, (s % 3600) // 60
            if h:
                return "%dó %02dp" % (h, m)
            if m:
                return "%d p" % m
            return "%d mp" % s

        def set(key, on, text):
            var = self.mod_vars.get(key)
            if not var:
                return
            var[0].config(fg=COLORS['ok'] if on else "#e74c3c")
            var[1].set(text)

        # FEED: uptime + utolso es kovetkezo letoltes (FireHOL: 4 orankent)
        feed_on = alive("_feed_thread")
        last_ok = getattr(core, "_feed_last_dl", 0)
        if feed_on and last_ok:
            nxt = _t.localtime(last_ok + 4 * 3600)
            set("feed", feed_on,
                "Uptime: %s | Legutóbbi: %s | Következő: ~%02d:%02d"
                % (upt("_feed_started"),
                   _t.strftime("%H:%M", _t.localtime(last_ok)),
                   nxt.tm_hour, nxt.tm_min))
        else:
            set("feed", feed_on, "Uptime: %s | letöltésre vár…" % upt("_feed_started"))

        # FEED: hátralévő idő a következő automatikus frissítésig
        if feed_on and last_ok:
            _hs = max(0, int(last_ok + 4 * 3600 - _t.time()))
            _hatra = "%dó %02dp" % (_hs // 3600, (_hs % 3600) // 60)
            _fv = self.mod_vars.get("feed")
            if _fv:
                _fv[1].set(_fv[1].get() + (" | Még %s" % _hatra))
        # GEO: orszag-feketelista
        set("geo", alive("_geo_thread"),
            "Ország-blokk | Uptime: %s" % upt("_geo_started"))

        # GEO: hátralévő idő a következő automatikus frissítésig
        _gnext = getattr(core, "_geo_next_at", 0)
        if alive("_geo_thread") and _gnext:
            _gs = max(0, int(_gnext - _t.time()))
            _gh = "%dó %02dp" % (_gs // 3600, (_gs % 3600) // 60)
            _gv = self.mod_vars.get("geo")
            if _gv:
                _gv[1].set(_gv[1].get() + " | Frissítés %s múlva" % _gh)
        # 4625: SMB + RDP brute-force figyeles
        # [v1.9.3] + sikeres kulso belepes, uj fiok, admin csoport, naplotorles
        _sec_db = getattr(core, "sec_events", 0)
        set("logon", alive("_logon_thread") and alive("_persist_thread"),
            "Sikertelen + sikeres belépés, fiókok, naplótörlés | "
            "Biztonsági esemény: %d | Uptime: %s" % (_sec_db, upt("_logon_started")))

        # Honeypot
        honey_on = bool(getattr(core, "_honey_on", False))
        if honey_on:
            ports = len(getattr(core, "_honey_srvs", []) or [])
            set("honey", True, "%d port figyelve | Uptime: %s"
                % (ports, upt("_honey_started")))
        else:
            set("honey", False, "Kikapcsolva")

        # [v1.9.6] Windows Defender
        _dst = getattr(core, "def_status", None) or {}
        _dmode = (_dst.get("mode") or "normal").lower()
        _don = bool(_dst.get("rt")) and (_dmode == "normal" or "edr" in _dmode)
        set("defender", _don, core.defender_summary(rovid=True))

        # [v2.1.0] USB-figyeles
        _ut = getattr(core, "_usb_thread", None)
        set("usb", bool(_ut and _ut.is_alive()) and getattr(core, "usb_status", "") == "aktív",
            core.usb_summary())

        # [v2.2.0] Hosts-fajl + inditopult
        _ht = getattr(core, "_hosts_thread", None)
        set("hosts", bool(_ht and _ht.is_alive()) and str(getattr(core, "hosts_status", "")).startswith("aktív"),
            core.hosts_summary())
        _st = getattr(core, "_startup_thread", None)
        set("startup", bool(_st and _st.is_alive()) and getattr(core, "startup_status", "") == "aktív",
            core.startup_summary())

        # [v2.5.0] Ransomware-csapda
        _ct = getattr(core, "_csali_thread", None)
        set("csapda", bool(_ct and _ct.is_alive()) and not getattr(core, "_csali_suspended", None),
            core.csali_summary())

        # [v2.6.0] Bongeszo-bovitmenyek
        _bt = getattr(core, "_bong_thread", None)
        set("bongeszo", bool(_bt and _bt.is_alive()) and getattr(core, "bong_status", "") == "aktív",
            core.browser_summary())

        # [v2.7.0] LAN-eszkozok
        _lt = getattr(core, "_lan_thread", None)
        set("lan", bool(_lt and _lt.is_alive()) and getattr(core, "lan_status", "") == "aktív",
            core.lan_summary())

        # [v2.11.0] Windows Update + pontszam
        try:
            set("winupdate", core.wu_ok(), core.wu_summary())
            _p, _t = core.security_score()
            _hiany = [n for ok, s, n, _tp in _t if not ok and s > 0]
            set("pontszam", _p >= 80, "%d/100%s" % (_p, (" | Hiányzik: " + ", ".join(_hiany[:3])) if _hiany else
                                                        " | Minden rendben ✔"))
        except Exception:
            pass
        # [v2.12.0] folyamatfigyeles
        try:
            _pt = getattr(core, "_proc_thread", None)
            set("folyamat", bool(_pt and _pt.is_alive()) and getattr(core, "proc_status", "") == "aktív"
                and not getattr(core, "_proc_suspended", None), core.proc_summary())
        except Exception:
            pass
        # [v2.13.0] infostealer-csapda
        try:
            _lpt = getattr(core, "_lp_thread", None)
            set("lopas", bool(_lpt and _lpt.is_alive()) and getattr(core, "lopas_status", "") == "aktív",
                core.lopas_summary())
        except Exception:
            pass
        # [v2.14.0] vagolap-vedelem
        try:
            _vgt = getattr(core, "_vg_thread", None)
            set("vagolap", bool(_vgt and _vgt.is_alive()) and getattr(core, "vagolap_status", "") == "aktív",
                core.vagolap_summary())
        except Exception:
            pass
        # [v2.15.0] letoltesek
        try:
            _dlt = getattr(core, "_dl_thread", None)
            set("letoltes", bool(_dlt and _dlt.is_alive()) and getattr(core, "letoltes_status", "") == "aktív",
                core.letoltes_summary())
        except Exception:
            pass
        # [v2.16.0] elavult programok / UPnP / adatkiszivargas
        try:
            _frt = getattr(core, "_fr_thread", None)
            set("frissites", bool(_frt and _frt.is_alive()) and core.frissites_ok() is not False
                and not str(getattr(core, "frissites_status", "")).startswith(("hiba", "kikapcsolva", "nem")),
                core.frissites_summary())
        except Exception:
            pass
        try:
            _upt = getattr(core, "_up_thread", None)
            set("upnp", bool(_upt and _upt.is_alive()) and getattr(core, "upnp_status", "") == "aktív"
                and core.upnp_ok() is not False, core.upnp_summary())
        except Exception:
            pass
        try:
            _kzt = getattr(core, "_kz_thread", None)
            set("kiszivargas", bool(_kzt and _kzt.is_alive()) and getattr(core, "kisz_status", "") == "aktív",
                core.kisz_summary())
        except Exception:
            pass
        # [v2.17.0] utemezett feladatok
        try:
            _utt = getattr(core, "_ut_thread", None)
            set("utemezett", bool(_utt and _utt.is_alive()) and core.ut_ok() is not False
                and not str(getattr(core, "ut_status", "")).startswith(("nem", "kikapcsolva")), core.ut_summary())
        except Exception:
            pass
        # [v2.9.0] jatek mod
        try:
            from .jatek import jatek_cfg
            _ga, _gs = core.game_info()
            self.v_game.set(_gs)
            self.game_btn.config(text="🎮 Játék mód: %s" % jatek_cfg()["MOD"])
            self._tray_menu_refresh()
        except Exception:
            pass
        # [v2.8.0] DNS / proxy
        _nt = getattr(core, "_net_thread", None)
        set("dnsproxy", bool(_nt and _nt.is_alive()) and getattr(core, "net_status", "") == "aktív"
            and "⚠" not in core.net_summary(), core.net_summary())

        self.root.after(3000, self.tick_mods)

    # ===== 6. FELADAT: STATISZTIKA ES SPARKLINE FRISSITES =====
    def tick_stats(self):
        import re as _re
        import datetime as _dt
        # --- napi riasztas-szamlalas a naplobol (utolso 7 nap) ---
        counts = {}
        try:
            with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    m = _re.match(r"\[(\d{4}-\d{2}-\d{2}) ", ln)
                    if not m:
                        continue
                    nap = m.group(1)
                    a, r = counts.get(nap, (0, 0))
                    if "AUTOMATIKUSAN BLOKKOLVA" in ln:
                        a += 1; r += 3
                    elif "HONEYPOT BLOKK" in ln:
                        a += 1; r += 2
                    elif "PORTSCAN DETEKTELVE" in ln:
                        a += 1; r += 2
                    elif ("Gyanus" in ln) or ("Gyanús" in ln):
                        a += 1; r += 1
                    counts[nap] = (a, r)
        except OSError:
            pass
        ma = _dt.date.today()
        days = [(ma - _dt.timedelta(days=i)).isoformat() for i in range(6, -1, -1)]
        adat = [counts.get(d, (0, 0)) for d in days]
        self._stats_vals = [x[0] for x in adat]
        risk = adat[-1][1]          # mai kockazati pontszam (24 ora)
        heti = sum(self._stats_vals)
        self.v_risk.set("Kockázat (24 óra): %d pont" % risk)
        szin = COLORS['ok'] if risk <= 4 else (
            "#e67e22" if risk <= 14 else "#e74c3c")
        self.l_risk.config(fg=szin)
        self.v_s_al.set("Heti riasztások: %d" % heti)
        self._draw_stats()
        self.root.after(20000, self.tick_stats)

    def _draw_stats(self):
        # kis oszlop-diagram (sparkline) a 7 napi riasztasszamrol
        import datetime as _dt
        cv = getattr(self, "stats_canvas", None)
        if cv is None:
            return
        try:
            cv.delete("all")
            W = cv.winfo_width()
            if W < 40:
                W = 430
            H = 66
            mx = max(self._stats_vals + [1])
            bw = (W - 10) / 7.0
            napok = ["Hé", "Ke", "Sze", "Cs", "Pé", "Szo", "Va"]
            for i in range(7):
                d = _dt.date.today() - _dt.timedelta(days=6 - i)
                x = 5 + i * bw
                h = (H - 24) * self._stats_vals[i] / float(mx)
                fillc = COLORS['brand'] if self._stats_vals[i] else COLORS['divider']
                cv.create_rectangle(x + 2, H - 18 - h, x + bw - 3, H - 18,
                                    fill=fillc, outline="")
                cv.create_text(x + bw / 2, H - 8, text=napok[d.weekday()],
                               font=("Segoe UI", 7), fill=COLORS['text_soft'])
                if self._stats_vals[i]:
                    cv.create_text(x + bw / 2, H - 22 - h,
                                   text=str(self._stats_vals[i]),
                                   font=("Segoe UI", 7, "bold"),
                                   fill=COLORS['text'])
        except Exception:
            pass

    def update_tray_title(self):
        try:
            col = None  # eredeti ikon: vedelem aktiv
            if not self.core.is_on():
                col = (214, 40, 40)  # piros: kikapcsolva
                txt = '%s v%s - Figyelés kikapcsolva' % (APP_NAME, VERSION)
            elif self.core.is_paused():
                col = (245, 160, 30)  # narancssarga: szunet
                left = int(self.core.pause_left())
                txt = '%s v%s - Szünet (%d:%02d perc van hátra)' % (APP_NAME, VERSION, left // 60, left % 60)
            else:
                if not self.core.admin:
                    col = (245, 160, 30)  # [v1.9.2] narancs: korlatozott (nincs admin jog)
                    txt = '%s v%s - Korlátozott védelem (nincs admin jog)' % (APP_NAME, VERSION)
                else:
                    txt = '%s v%s - Védelem aktív' % (APP_NAME, VERSION)
            if txt != getattr(self, '_last_tray_txt', ''):
                self.icon.title = txt
                self._last_tray_txt = txt
                if col != getattr(self, '_tray_col', None):
                    self._tray_col = col
                    if col is None:
                        self.icon.icon = self._tray_base.copy()
                    else:
                        img = self._tray_base.copy()
                        # HSV-arcom: eloenk piros/narancs, a feher betu es az arnyalatok maradnak
                        import colorsys as _cs
                        _th = _cs.rgb_to_hsv(col[0] / 255.0, col[1] / 255.0, col[2] / 255.0)[0] * 255.0
                        _al = img.split()[3]
                        _hsv = img.convert("RGB").convert("HSV")
                        _hc, _sc, _vc = _hsv.split()
                        _hc = _hc.point(lambda p: int(_th))
                        _sc = _sc.point(lambda p: p if p <= 30 else max(p, 200))
                        _vc = _vc.point(lambda p: min(255, int(p * 1.10)))
                        img = Image.merge("HSV", (_hc, _sc, _vc)).convert("RGB").convert("RGBA")
                        img.putalpha(_al)
                        self.icon.icon = img
        except Exception:
            pass
        self.root.after(1000, self.update_tray_title)
    def run(self):
        self.build_tray()
        self.root.mainloop()
        # [v2.12.1] a felulet bezarult (kilepes / frissites): a folyamat is lepjen ki.
        # A talca-ikon (pystray) szala nem daemon, enelkul a regi peldany a talcan maradt.
        try:
            self.icon.stop()
        except Exception:
            pass
        try:
            self.core.stop()
        except Exception:
            pass
        try:
            log_line("Kilepes%s." % (" (frissites utan)" if getattr(self, "_kilepes_frissites", False) else ""))
        except Exception:
            pass
        # onefile exe: a PyInstaller bootloader (szulo) ettol fuggetlenul kitakaritja a temp-mappat
        os._exit(0)
