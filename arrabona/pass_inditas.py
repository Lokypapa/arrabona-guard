# -*- coding: utf-8 -*-
"""[v2.19.0] Arrabona Pass (jelszokezelo) inditasa a Guardbol.

A Pass kulon program es kulon folyamat: a Guard csak elinditja, a jelszavak
soha nem kerulnek a Guard memoriajaba.
"""
import os
import shutil
import subprocess
import sys

from .common import APPDATA_DIR, app_dir

PASS_EXE = "Arrabona Pass.exe"
PASS_PY = "arrabona_pass.py"
UTVONAL_FILE = os.path.join(APPDATA_DIR, "pass_utvonal.txt")


def _jeloltek():
    out = []
    try:
        with open(UTVONAL_FILE, "r", encoding="utf-8") as f:
            out.append(f.read().strip())
    except Exception:
        pass
    for env in ("ProgramFiles", "ProgramFiles(x86)"):
        b = os.environ.get(env)
        if b:
            out.append(os.path.join(b, "Arrabona Pass", PASS_EXE))
    la = os.environ.get("LOCALAPPDATA")
    if la:
        out.append(os.path.join(la, "Programs", "Arrabona Pass", PASS_EXE))
    here = app_dir()
    for base in (here, os.path.dirname(here)):
        out.append(os.path.join(base, "Arrabona Pass", PASS_EXE))
        out.append(os.path.join(base, "arrabona-pass", "dist", "Arrabona Pass", PASS_EXE))
        out.append(os.path.join(base, "arrabona-pass", PASS_PY))
    return out


def keres():
    """Visszaadja az Arrabona Pass utvonalat (exe vagy .py), vagy None-t."""
    for p in _jeloltek():
        if p and os.path.isfile(p):
            return p
    return None


def mentes(path):
    try:
        os.makedirs(APPDATA_DIR, exist_ok=True)
        with open(UTVONAL_FILE, "w", encoding="utf-8") as f:
            f.write(path)
    except OSError:
        pass


def _pythonw():
    if not getattr(sys, "frozen", False) and sys.executable:
        cand = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if os.path.isfile(cand):
            return cand
    for name in ("pythonw", "pyw"):
        w = shutil.which(name)
        if w:
            return w
    return None


def indit(path):
    """Elinditja a Passt. Hiba eseten kivetelt dob (magyar szoveggel)."""
    low = path.lower()
    if low.endswith(".exe"):
        # explorer.exe-n keresztul: a Pass NEM orokli a Guard rendszergazdai jogat
        try:
            subprocess.Popen(["explorer.exe", path])
        except OSError:
            os.startfile(path)
        return
    if low.endswith(".py"):
        pw = _pythonw()
        if not pw:
            raise RuntimeError("Nem találom a pythonw.exe-t az arrabona_pass.py indításához.")
        subprocess.Popen([pw, path], cwd=os.path.dirname(path))
        return
    raise RuntimeError("Ez nem az Arrabona Pass (exe vagy .py kell).")
