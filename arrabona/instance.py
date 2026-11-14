# -*- coding: utf-8 -*-
"""Arrabona Guard - Egypeldanyos futas (mutex) es biztonsagos ujrainditas."""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import ctypes
import os
import time
from .common import (APPDATA_DIR)

# ------------------------- Main -------------------------

# --- [v1.9.1] Single-instance mutex + biztonsagos ujrainditas ---
# Korabbi hiba: temavaltas / frissites utan az UJ peldany meg foglaltnak
# latta a mutexet (a regi meg nem lepett ki), ezert csendben kilepett,
# es utana egyaltalan nem futott vedelem. Most:
#  1) a regi peldany ujrainditas elott ELENGEDI a mutexet,
#  2) es letesz egy restart.flag-et; ha az uj peldany friss flag-et lat,
#     max. ~20 mp-ig ujraprobalja a mutexet, mielott feladna.
_INSTANCE_MUTEX = None
_MUTEX_NAME = "Global\\ArrabonaGuardSingleInstance"
RESTART_FLAG = os.path.join(APPDATA_DIR, "restart.flag")


_K32 = None


def _k32():
    """Egyetlen, tipusosan beallitott kernel32 objektum (64 bites handle-ok miatt)."""
    global _K32
    if _K32 is None:
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.CreateMutexW.restype = ctypes.c_void_p
        k.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_bool, ctypes.c_wchar_p]
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle.restype = ctypes.c_bool
        _K32 = k
    return _K32


def mark_restart():
    """Ujrainditas jelzese az uj peldanynak (restart.flag idobelyeggel)."""
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
        with open(RESTART_FLAG, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except Exception:
        pass


def _restart_pending():
    try:
        return (time.time() - os.path.getmtime(RESTART_FLAG)) < 60.0
    except OSError:
        return False


def release_single_instance():
    """A mutex elengedese, hogy az ujrainditott peldany megkaphassa."""
    global _INSTANCE_MUTEX
    if _INSTANCE_MUTEX:
        try:
            _k32().CloseHandle(_INSTANCE_MUTEX)
        except Exception:
            pass
        _INSTANCE_MUTEX = None


def acquire_single_instance():
    """True, ha mi vagyunk az egyetlen peldany. Ujrainditasnal var a regire."""
    global _INSTANCE_MUTEX
    k32 = _k32()
    probak = 40 if _restart_pending() else 1   # 40 x 0.5 mp = 20 mp
    for i in range(probak):
        h = k32.CreateMutexW(None, False, _MUTEX_NAME)
        err = ctypes.get_last_error()
        if h and err != 183:  # 183 = ERROR_ALREADY_EXISTS
            _INSTANCE_MUTEX = h
            try:
                if os.path.exists(RESTART_FLAG):
                    os.remove(RESTART_FLAG)
            except OSError:
                pass
            return True
        if h:
            k32.CloseHandle(h)
        if i + 1 < probak:
            time.sleep(0.5)
    return False
