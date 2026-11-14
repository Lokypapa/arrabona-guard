# -*- coding: utf-8 -*-
"""Arrabona Guard - TELEGRAM-BEALLITO VARAZSLO. [v2.18.0]

Minden felhasznalo a SAJAT botjat kapcsolja ossze (a kiadott programban nincs token):
  1. @BotFather -> /newbot -> a kapott tokent bemasolja
  2. a Guard ellenorzi (getMe), majd a felhasznalo /start-ot ir a botjanak
  3. a Guard ebbol kiolvassa a chat ID-t, megerositteti ("Ez te vagy?"), elmenti a
     telegram.txt-be es proba-uzenetet kuld.
Elso indulaskor felajanlja (Beallitom / Kesobb / Nem kerem); kesobb: "📱 Telegram" gomb
vagy talca-menu.
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import json as _json
import os
import re
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from .common import (APP_NAME, APPDATA_DIR, COLORS, VERSION, log_line)
from . import telegram as _tg

TG_FILE = os.path.join(APPDATA_DIR, "telegram.txt")
FELAJANLAS_FILE = os.path.join(APPDATA_DIR, "telegram_varazslo.txt")
_TOKEN_MINTA = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,60}$")
VARAKOZAS_MP = 300          # ennyi ideig varunk a /start uzenetre

_NYITVA = None              # egyszerre csak egy varazslo-ablak


# ----------------------- seged -----------------------

def _api(tok, metodus, params=None, timeout=15):
    data = urllib.parse.urlencode(params).encode("utf-8") if params else None
    req = urllib.request.Request("https://api.telegram.org/bot%s/%s" % (tok, metodus), data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        try:
            return _json.loads(e.read().decode("utf-8", "replace"))
        except Exception:
            return {"ok": False, "error_code": e.code, "description": str(e)}


def beallitva():
    tok, cid = _tg._tg_cfg()
    return bool(tok and cid)


def felajanlas_kell():
    """Elso indulaskor: nincs beallitva es nem mondta, hogy 'Nem kerem'."""
    if beallitva():
        return False
    try:
        with open(FELAJANLAS_FILE, "r", encoding="utf-8") as f:
            return "SOHA" not in f.read().upper()
    except OSError:
        return True


def _soha():
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
        with open(FELAJANLAS_FILE, "w", encoding="utf-8") as f:
            f.write("# Ne ajanlja fel indulaskor a Telegram-beallitast (a gombbal barmikor beallithato)\nSOHA\n")
    except OSError:
        pass


def mentes(tok, cid):
    os.makedirs(APPDATA_DIR, exist_ok=True)
    if os.path.exists(TG_FILE):
        try:
            os.replace(TG_FILE, TG_FILE + ".bak")
        except OSError:
            pass
    tmp = TG_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# Arrabona Guard - Telegram-ertesitesek (a varazslo irta, %s)\n"
                "# A token titkos: aki ismeri, uzenhet a botodon keresztul. Ne oszd meg!\n"
                "token=%s\nchat_id=%s\n" % (time.strftime("%Y-%m-%d %H:%M"), tok, cid))
    os.replace(tmp, TG_FILE)


def kikapcsolas():
    if os.path.exists(TG_FILE):
        os.replace(TG_FILE, TG_FILE + ".bak")


# ----------------------- elso inditas: felajanlas -----------------------

def felajanlo_ablak(root, megnyit_fv):
    w = tk.Toplevel(root)
    w.title(APP_NAME)
    w.configure(bg=COLORS['panel'])
    w.resizable(False, False)
    w.transient(root)
    tk.Label(w, text="📱 Értesítések a telefonodra?", font=("Segoe UI", 13, "bold"),
             fg=COLORS['text'], bg=COLORS['panel']).pack(anchor="w", padx=20, pady=(18, 6))
    tk.Label(w, justify="left", wraplength=420, font=("Segoe UI", 10),
             fg=COLORS['text_soft'], bg=COLORS['panel'],
             text="Az Arrabona Guard Telegramon azonnal szólni tud, ha támadás, gyanús program "
                  "vagy kártevő jelenik meg - és a telefonodról gombokkal dönthetsz (blokkolás, "
                  "leállítás, karantén).\n\nA beállítás kb. 2 perc, egy saját, ingyenes "
                  "Telegram-botot kell hozzá létrehozni - lépésről lépésre végigvezetünk.").pack(
        anchor="w", padx=20)
    sor = tk.Frame(w, bg=COLORS['panel'])
    sor.pack(fill=tk.X, padx=20, pady=18)

    def _beallit():
        w.destroy()
        megnyit_fv()

    def _kesobb():
        w.destroy()

    def _nem():
        _soha()
        w.destroy()

    tk.Button(sor, text="Beállítom", command=_beallit, font=("Segoe UI", 10, "bold"),
              fg="white", bg=COLORS['brand'], activebackground=COLORS['brand_dark'],
              activeforeground="white", relief=tk.FLAT, padx=14, pady=5, cursor="hand2").pack(side=tk.LEFT)
    tk.Button(sor, text="Később", command=_kesobb, font=("Segoe UI", 10), relief=tk.FLAT,
              padx=12, pady=5, cursor="hand2").pack(side=tk.LEFT, padx=8)
    tk.Button(sor, text="Nem kérem", command=_nem, font=("Segoe UI", 10), relief=tk.FLAT,
              padx=12, pady=5, cursor="hand2").pack(side=tk.LEFT)
    tk.Label(w, text="Később is beállíthatod: „📱 Telegram” gomb vagy a tálca-menü.",
             font=("Segoe UI", 8), fg=COLORS['text_soft'], bg=COLORS['panel']).pack(
        anchor="w", padx=20, pady=(0, 14))
    w.protocol("WM_DELETE_WINDOW", _kesobb)
    try:
        w.lift()
        w.focus_force()
    except Exception:
        pass


# ----------------------- a varazslo -----------------------

class TelegramVarazslo:
    def __init__(self, root):
        global _NYITVA
        if _NYITVA is not None:
            try:
                _NYITVA.w.deiconify()
                _NYITVA.w.lift()
                return
            except Exception:
                pass
        _NYITVA = self
        self.root = root
        self.tok = ""
        self.bot_nev = ""
        self.cid = ""
        self.offset = 0
        self._fut = False
        self.w = tk.Toplevel(root)
        self.w.title("%s - Telegram beállítása" % APP_NAME)
        self.w.configure(bg=COLORS['panel'])
        self.w.geometry("560x470")
        self.w.minsize(520, 440)
        self.w.protocol("WM_DELETE_WINDOW", self.bezar)
        fej = tk.Frame(self.w, bg=COLORS['brand'], height=46)
        fej.pack(fill=tk.X)
        fej.pack_propagate(False)
        self.fej_lbl = tk.Label(fej, text="", font=("Segoe UI", 12, "bold"), fg="white", bg=COLORS['brand'])
        self.fej_lbl.pack(side=tk.LEFT, padx=16)
        self.tart = tk.Frame(self.w, bg=COLORS['panel'])
        self.tart.pack(fill=tk.BOTH, expand=True, padx=20, pady=12)
        _tg.TG_VARAZSLO_AKTIV = True
        self.lap_token()

    # --- kozos ---
    def _uj_lap(self, cim):
        self._fut = False
        for c in self.tart.winfo_children():
            c.destroy()
        self.fej_lbl.config(text=cim)

    def _szoveg(self, txt, **kw):
        lbl = tk.Label(self.tart, text=txt, justify="left", anchor="w", wraplength=500,
                       font=kw.pop("font", ("Segoe UI", 10)), fg=kw.pop("fg", COLORS['text']),
                       bg=COLORS['panel'])
        lbl.pack(anchor="w", fill=tk.X, **kw)
        return lbl

    def _gomb(self, szulo, txt, cmd, fo=False):
        if fo:
            b = tk.Button(szulo, text=txt, command=cmd, font=("Segoe UI", 10, "bold"), fg="white",
                          bg=COLORS['brand'], activebackground=COLORS['brand_dark'],
                          activeforeground="white", relief=tk.FLAT, padx=14, pady=5, cursor="hand2")
        else:
            b = tk.Button(szulo, text=txt, command=cmd, font=("Segoe UI", 10), relief=tk.FLAT,
                          padx=12, pady=5, cursor="hand2")
        b.pack(side=tk.LEFT, padx=(0, 8))
        return b

    def _ui(self, fv):
        try:
            self.w.after(0, fv)
        except Exception:
            pass

    def bezar(self):
        global _NYITVA
        self._fut = False
        _tg.TG_VARAZSLO_AKTIV = False
        _NYITVA = None
        try:
            self.w.destroy()
        except Exception:
            pass

    # --- 1. lap: bot letrehozasa + token ---
    def lap_token(self):
        self._uj_lap("1 / 3  -  Saját bot létrehozása")
        if beallitva():
            self._szoveg("✅ A Telegram már be van állítva. Új botot is beköthetsz, vagy kikapcsolhatod.",
                         fg=COLORS['ok'], pady=(0, 8))
        self._szoveg("1.  Telepítsd a Telegramot a telefonodra, ha még nincs meg.\n"
                     "2.  Nyisd meg a @BotFather-t (gomb lent), és írd neki:  /newbot\n"
                     "3.  Adj nevet a botnak (pl. Arrabona Guard), majd egy felhasználónevet,\n"
                     "     aminek a végén „bot” van (pl. kovacs_guard_bot).\n"
                     "4.  A BotFather küld egy TOKENT, kb. így néz ki:\n"
                     "     123456789:AAH4kX...  -  ezt másold be ide:", pady=(0, 8))
        sor = tk.Frame(self.tart, bg=COLORS['panel'])
        sor.pack(anchor="w", pady=(0, 10))
        self._gomb(sor, "Telegram megnyitása (@BotFather)",
                   lambda: webbrowser.open("https://t.me/BotFather"))
        self.e_tok = tk.Entry(self.tart, font=("Consolas", 10), width=58)
        self.e_tok.pack(anchor="w", fill=tk.X, ipady=4)
        self.e_tok.bind("<Return>", lambda e: self.token_ellenorzes())
        self.allapot = self._szoveg("", fg=COLORS['text_soft'], pady=(6, 0))
        self._szoveg("A token csak ezen a gépen tárolódik, sehova nem küldjük el. "
                     "Ne oszd meg senkivel!", font=("Segoe UI", 8), fg=COLORS['text_soft'], pady=(8, 0))
        lent = tk.Frame(self.tart, bg=COLORS['panel'])
        lent.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        self.b_tovabb = self._gomb(lent, "Tovább ➜", self.token_ellenorzes, fo=True)
        self._gomb(lent, "Mégse", self.bezar)
        if beallitva():
            self._gomb(lent, "Telegram kikapcsolása", self.kikapcsol)
        self.e_tok.focus_set()

    def kikapcsol(self):
        import tkinter.messagebox as mb
        if mb.askyesno(APP_NAME, "Kikapcsolod a Telegram-értesítéseket?\n"
                                 "(A beállítás telegram.txt.bak néven megmarad.)", parent=self.w):
            kikapcsolas()
            log_line("[TELEGRAM] ertesitesek kikapcsolva (varazslo)")
            self.bezar()

    def token_ellenorzes(self):
        tok = re.sub(r"\s+", "", self.e_tok.get())
        if tok.lower().startswith("bot"):
            tok = tok[3:]
        if not _TOKEN_MINTA.match(tok):
            self.allapot.config(text="⚠ Ez nem tűnik tokennek. Pontosan a BotFather üzenetéből másold "
                                     "(szám, kettőspont, hosszú betűsor).", fg=COLORS['bad'])
            return
        self.allapot.config(text="Ellenőrzés...", fg=COLORS['text_soft'])
        self.b_tovabb.config(state=tk.DISABLED)

        def _hatter():
            try:
                r = _api(tok, "getMe")
            except Exception as e:
                r = {"ok": False, "description": "nincs internet? (%s)" % e}

            def _ui():
                try:
                    self.b_tovabb.config(state=tk.NORMAL)
                except Exception:
                    return
                if r.get("ok"):
                    self.tok = tok
                    self.bot_nev = (r.get("result") or {}).get("username") or ""
                    self.lap_start()
                elif r.get("error_code") == 401:
                    self.allapot.config(text="⚠ A Telegram szerint ez a token érvénytelen. "
                                             "Másold be újra a BotFather üzenetéből.", fg=COLORS['bad'])
                else:
                    self.allapot.config(text="⚠ Nem sikerült ellenőrizni: %s"
                                             % (r.get("description") or "ismeretlen hiba"), fg=COLORS['bad'])
            self._ui(_ui)
        threading.Thread(target=_hatter, daemon=True).start()

    # --- 2. lap: /start a botnak -> chat ID ---
    def lap_start(self):
        self._uj_lap("2 / 3  -  Összekapcsolás")
        self._szoveg("✅ A bot rendben: @%s" % self.bot_nev, fg=COLORS['ok'], pady=(0, 10))
        self._szoveg("Most nyisd meg a botodat a Telegramban (gomb lent), és nyomd meg a\n"
                     "START gombot (vagy írd neki:  /start ).\n\n"
                     "A Guard ebből ismeri fel, hogy a riasztásokat neked kell küldenie.", pady=(0, 10))
        sor = tk.Frame(self.tart, bg=COLORS['panel'])
        sor.pack(anchor="w", pady=(0, 12))
        self._gomb(sor, "Botom megnyitása (@%s)" % self.bot_nev,
                   lambda: webbrowser.open("https://t.me/%s" % self.bot_nev))
        self.allapot = self._szoveg("⏳ Várakozás az üzenetedre...", fg=COLORS['text_soft'])
        lent = tk.Frame(self.tart, bg=COLORS['panel'])
        lent.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        self._gomb(lent, "⬅ Vissza", self.lap_token)
        self._gomb(lent, "Mégse", self.bezar)
        self._fut = True
        threading.Thread(target=self._figyel, args=(self.tok, time.time()), daemon=True).start()

    def _figyel(self, tok, kezdet):
        try:
            _api(tok, "deleteWebhook")      # webhookkal a getUpdates nem mukodik
        except Exception:
            pass
        offset = 0
        hatar = kezdet + VARAKOZAS_MP
        while self._fut and time.time() < hatar and tok == self.tok:
            try:
                p = {"timeout": 10, "allowed_updates": _json.dumps(["message"])}
                if offset:
                    p["offset"] = offset
                r = _api(tok, "getUpdates", p, timeout=20)
            except Exception:
                time.sleep(3)
                continue
            if not r.get("ok"):
                if r.get("error_code") == 409:
                    time.sleep(3)          # egy masik getUpdates fut (pl. regi Guard-peldany)
                    continue
                time.sleep(3)
                continue
            for u in r.get("result") or []:
                offset = max(offset, int(u.get("update_id") or 0) + 1)
                m = u.get("message") or {}
                ch = m.get("chat") or {}
                if ch.get("type") != "private" or int(m.get("date") or 0) < kezdet - 5:
                    continue
                if not self._fut:
                    return
                self.offset = offset
                kitol = m.get("from") or {}
                nev = " ".join(x for x in (kitol.get("first_name"), kitol.get("last_name")) if x) or "?"
                if kitol.get("username"):
                    nev += " (@%s)" % kitol["username"]
                cid = str(ch.get("id"))
                self._ui(lambda c=cid, n=nev: self.lap_megerosites(c, n))
                return
        if self._fut and tok == self.tok:
            self._ui(lambda: self.allapot.config(
                text="⚠ 5 perc alatt nem jött üzenet. Nyomd meg a „Vissza”, majd a „Tovább” gombot, "
                     "és írj a botnak: /start", fg=COLORS['bad']))

    # --- 3. lap: megerosites + mentes ---
    def lap_megerosites(self, cid, nev):
        self._uj_lap("3 / 3  -  Megerősítés")
        self.cid = cid
        self._szoveg("Üzenet érkezett tőle:", pady=(0, 4))
        self._szoveg(nev, font=("Segoe UI", 13, "bold"), pady=(0, 10))
        self._szoveg("Te vagy az? Ha igen, a riasztások és a vezérlő gombok ebbe a chatbe érkeznek, "
                     "és csak innen fogad el parancsot a Guard.", pady=(0, 10))
        self.allapot = self._szoveg("", fg=COLORS['text_soft'])
        lent = tk.Frame(self.tart, bg=COLORS['panel'])
        lent.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        self.b_ment = self._gomb(lent, "Igen, ez én vagyok - mentés", self.mentes, fo=True)
        self._gomb(lent, "Nem, újra", self.lap_start)

    def mentes(self):
        tok, cid, offset = self.tok, self.cid, self.offset
        self.b_ment.config(state=tk.DISABLED)
        self.allapot.config(text="Mentés és próbaüzenet...", fg=COLORS['text_soft'])

        def _hatter():
            hiba = ""
            try:
                mentes(tok, cid)
            except Exception as e:
                hiba = "Nem sikerült menteni: %s" % e
            if not hiba:
                try:
                    if offset:      # a /start-ot mar feldolgoztuk, a fo figyelo ne kapja meg
                        _api(tok, "getUpdates", {"offset": offset, "timeout": 0})
                    r = _api(tok, "sendMessage", {
                        "chat_id": cid,
                        "text": "✅ Arrabona Guard összekapcsolva! (v%s)\n\nInnentől ide érkeznek a "
                                "riasztások. Parancsok: /help\nÁllapot: /status" % VERSION})
                    if not r.get("ok"):
                        hiba = "Mentve, de a próbaüzenet nem ment ki: %s" % r.get("description")
                except Exception as e:
                    hiba = "Mentve, de a próbaüzenet nem ment ki: %s" % e
            log_line("[TELEGRAM] varazslo: bot @%s osszekapcsolva%s" % (
                self.bot_nev, (" (" + hiba + ")") if hiba else ""))

            def _ui():
                if hiba.startswith("Nem sikerült menteni"):
                    self.allapot.config(text="⚠ " + hiba, fg=COLORS['bad'])
                    self.b_ment.config(state=tk.NORMAL)
                    return
                self.lap_kesz(hiba)
            self._ui(_ui)
        threading.Thread(target=_hatter, daemon=True).start()

    def lap_kesz(self, figyelmeztetes=""):
        self._uj_lap("Kész!")
        self._szoveg("✅ A Telegram-értesítések be vannak kapcsolva.", font=("Segoe UI", 12, "bold"),
                     fg=COLORS['ok'], pady=(0, 10))
        if figyelmeztetes:
            self._szoveg("⚠ " + figyelmeztetes, fg=COLORS['warn'], pady=(0, 10))
        self._szoveg("Küldtünk egy próbaüzenetet a botodtól. Hasznos parancsok:\n\n"
                     "  /status  - állapot\n  /help  - minden parancs\n"
                     "  /guardverzio  - verzió és frissítés\n\n"
                     "A riasztások alatt gombokkal dönthetsz (blokkolás, leállítás, karantén).")
        lent = tk.Frame(self.tart, bg=COLORS['panel'])
        lent.pack(side=tk.BOTTOM, fill=tk.X, pady=(10, 0))
        self._gomb(lent, "Bezárás", self.bezar, fo=True)
