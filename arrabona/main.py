# -*- coding: utf-8 -*-
"""Arrabona Guard - Belepesi pont: main()."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import datetime
import os
import queue
import sys
import threading
import time
from .common import (
    APP_NAME,
    VERSION,
    ensure_appdata,
    log_line,
)
from .watchdog import (heartbeat_read, quit_flag_clear)
from .core import (GuardCore)
from .ui import (GuardApp)
from .instance import (acquire_single_instance)

def _regi_peldany_le():
    """[v2.12.1] Frissites utan bennragadt regi peldany (Arrabona Guard.exe.old) leallitasa.
    Korabbi verziok frissiteskor nem leptek ki teljesen (a talcan maradtak)."""
    try:
        import psutil
        from .common import INSTALL_EXE
        regi = os.path.normcase(os.path.normpath(INSTALL_EXE + ".old"))
        sajat = {os.getpid(), os.getppid()}
        n = 0
        # [v2.12.3] elobb 20 mp-et hagyunk, hogy maga lepjen ki (a rendes kilepeskor
        # a sajat ideiglenes mappajat is kitakaritja); csak ami utana is fut, azt allitjuk le
        hatar = time.time() + 20.0
        while True:
            maradt = []
            for p in psutil.process_iter(["pid", "exe"]):
                try:
                    if p.info["pid"] in sajat or not p.info["exe"]:
                        continue
                    if os.path.normcase(os.path.normpath(p.info["exe"])) == regi:
                        maradt.append(p)
                except Exception:
                    pass
            if not maradt:
                break
            if time.time() >= hatar:
                for p in maradt:
                    try:
                        p.kill()
                        n += 1
                    except Exception:
                        pass
                break
            time.sleep(1.0)
        if n:
            log_line("Regi (frissites elotti) peldany leallitva: %d folyamat" % n)
    except Exception as e:
        log_line("Regi peldany ellenorzesi hiba: %s" % e)


def main():
    # --- Arrabona Guard single-instance: masodik peldany csendben kilep ---
    if not acquire_single_instance():
        try:
            _env_apdata = os.environ.get("APPDATA", "")
            _lg = os.path.join(_env_apdata, "ArrabonaGuard", "mutex_dupla_naplo.txt")
            with open(_lg, "a", encoding="utf-8", errors="ignore") as _f:
                _f.write("[%s] Masodik peldany kilepett (mar fut masik Arrabona Guard)\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        except Exception:
            pass
        return
    ensure_appdata()
    common.hiba_hookok_be()   # [v2.18.1] kezeletlen hibak -> hiba_naplo.txt
    threading.Thread(target=_regi_peldany_le, daemon=True).start()
    # [v1.9.5] elindultunk -> a korabbi szandekos kilepes jelzese torolheto
    quit_flag_clear()
    orkutya_inditas = "--watchdog" in sys.argv
    utolso_eletjel = heartbeat_read()

    ui_queue = queue.Queue()
    core = GuardCore(ui_queue)
    app = GuardApp(core)
    app.q = ui_queue

    worker = threading.Thread(target=core.run, daemon=True)
    worker.start()

    app.add_log("%s v%s elindult." % (APP_NAME, VERSION), "success")
    app.add_log("Minden port figyelve, belső (LAN) IP-k kihagyva — "
                "nincs több hamis riasztás a routertől.", "info")
    if not core.admin:
        app.add_log("⚠ Nem rendszergazdaként fut — a tűzfalnaplózás "
                    "nem kapcsolható be. A feketelista viszont működik!", "warning")
    if orkutya_inditas:
        # [v1.9.5] az orkutya inditott: a Guard nem futott (osszeomlott vagy
        # leallitottak). Jelezzuk, es a tálcára rejtve indulunk (pl. jatek kozben
        # ne ugorjon fel ablak).
        if utolso_eletjel > 0:
            mikor = time.strftime("%Y-%m-%d %H:%M", time.localtime(utolso_eletjel))
        else:
            mikor = "ismeretlen"
        msg = ("[ORKUTYA] Az Arrabona Guard NEM FUTOTT (leallt vagy leallitottak) - "
               "az orkutya ujrainditotta. Utolso eletjel: %s" % mikor)
        log_line(msg)
        try:
            core.alert("127.0.0.1", msg, always=True)
        except Exception:
            pass
        try:
            app.root.after(700, app.hide_window)
        except Exception:
            pass

    app.run()
