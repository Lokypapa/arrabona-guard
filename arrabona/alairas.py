# -*- coding: utf-8 -*-
"""Arrabona Guard - Digitalis alairas (Authenticode) ellenorzes. [v2.4.0]

Get-AuthenticodeSignature: a beagyazott ES a katalogusos (Windows-rendszerfajlok)
alairast is ismeri. Egy PowerShell-hivas tobb fajlt is ellenoriz (kotegelve),
az eredmeny fajlonkent gyorsitotarazva (ut + modositas ideje + meret), igy
ugyanazt a fajlt csak akkor nezi ujra, ha megvaltozott.

allapot:
  "ok"             - ervenyes alairas (kiado: pl. "Valve Corp.")
  "nincs"          - ALAIRATLAN
  "megbizhatatlan" - alairt, de a tanusitvany nem megbizhato / visszavont / sajat keszitesu
  "rossz"          - ERVENYTELEN: a fajlt az alairas UTAN modositottak (HashMismatch)
  "nem_alairhato"  - olyan tipus, ami nem irhato ala (.bat, .cmd, .lnk...)
  "hianyzik"       - a fajl nem letezik
  "hiba"           - nem sikerult ellenorizni
"""
from . import common  # elobb toltodik be: csendes subprocess.run, alapkonyvtarak
import base64
import json as _json
import os
import re
import subprocess
import threading
import time
from .common import (log_line)

_CACHE = {}
_LOCK = threading.Lock()
_TTL = 6 * 3600
_KOTEG = 40
_NEM_ALAIRHATO = (".bat", ".cmd", ".lnk", ".url", ".txt", ".reg", ".hta", ".pif")
_CN = re.compile(r'(?:^|,\s*)CN=("([^"]+)"|[^,]+)')
_O = re.compile(r'(?:^|,\s*)O=("([^"]+)"|[^,]+)')

_PS = ("$ErrorActionPreference='SilentlyContinue';"
       "[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
       "$l=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'))|ConvertFrom-Json;"
       "$o=@();foreach($p in @($l)){$s=Get-AuthenticodeSignature -LiteralPath $p;"
       "$c='';if($s -and $s.SignerCertificate){$c=$s.SignerCertificate.Subject};"
       "$o+=[pscustomobject]@{p=$p;s=[string]$s.Status;t=[string]$s.SignatureType;c=$c;"
       "m=[string]$s.StatusMessage}};"
       "ConvertTo-Json -InputObject @($o) -Compress")


def _kiado(subject):
    for rx in (_CN, _O):
        m = rx.search(subject or "")
        if m:
            return (m.group(2) or m.group(1)).strip().strip('"')
    return ""


def _kulcs(p):
    try:
        s = os.stat(p)
        return (os.path.normcase(os.path.abspath(p)), int(s.st_mtime), s.st_size)
    except OSError:
        return None


def _besorol(status, tipus, subject, msg):
    st = (status or "").strip()
    info = {"status": st, "kiado": _kiado(subject), "katalogus": tipus.lower() == "catalog",
            "uzenet": (msg or "")[:200]}
    if st == "Valid":
        info["allapot"] = "ok"
    elif st == "NotSigned":
        info["allapot"] = "nincs"
    elif st == "HashMismatch":
        info["allapot"] = "rossz"
    elif st in ("NotTrusted", "UnknownError", "Incompatible"):
        info["allapot"] = "megbizhatatlan"
    elif st == "NotSupportedFileFormat":
        info["allapot"] = "nem_alairhato"
    else:
        info["allapot"] = "hiba"
    return info


def sig_check(paths):
    """{ut: info} tobb fajlra egyszerre (gyorsitotarral)."""
    eredm, kell = {}, []
    most = time.time()
    for p in dict.fromkeys(x for x in (paths or []) if x):
        if not os.path.isfile(p):
            eredm[p] = {"allapot": "hianyzik", "kiado": "", "status": "", "katalogus": False, "uzenet": ""}
            continue
        if p.lower().endswith(_NEM_ALAIRHATO):
            eredm[p] = {"allapot": "nem_alairhato", "kiado": "", "status": "", "katalogus": False, "uzenet": ""}
            continue
        k = _kulcs(p)
        with _LOCK:
            hit = _CACHE.get(k)
        if hit and most - hit[1] < _TTL:
            eredm[p] = hit[0]
        else:
            kell.append(p)
    for i in range(0, len(kell), _KOTEG):
        resz = kell[i:i + _KOTEG]
        b64 = base64.b64encode(_json.dumps(resz).encode("utf-8")).decode("ascii")
        adat = []
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS % b64],
                               capture_output=True, timeout=30 + 3 * len(resz))
            txt = (r.stdout or b"").decode("utf-8", errors="ignore").strip()
            j = txt.find("[")
            adat = _json.loads(txt[j:]) if j >= 0 else []
            if isinstance(adat, dict):
                adat = [adat]
        except Exception as e:
            log_line("[ALAIRAS] ellenorzesi hiba: %s" % e)
        kapott = {}
        for d in adat or []:
            try:
                kapott[os.path.normcase(d.get("p") or "")] = _besorol(d.get("s"), d.get("t") or "",
                                                                       d.get("c") or "", d.get("m") or "")
            except Exception:
                pass
        for p in resz:
            info = kapott.get(os.path.normcase(p))
            if info is None:
                info = {"allapot": "hiba", "kiado": "", "status": "", "katalogus": False, "uzenet": ""}
            else:
                with _LOCK:
                    if len(_CACHE) > 3000:
                        _CACHE.clear()
                    _CACHE[_kulcs(p)] = (info, time.time())
            eredm[p] = info
    return eredm


def sig_one(path):
    return sig_check([path]).get(path) if path else None


def sig_szoveg(info, ekezet=True):
    """Rovid szoveg a feluletre (ekezet=True) vagy a riasztasba (ASCII)."""
    if not info:
        return "?" if ekezet else "?"
    a, k = info.get("allapot"), info.get("kiado") or "?"
    if ekezet:
        return {"ok": "✔ %s%s" % (k, " (katalógus)" if info.get("katalogus") else ""),
                "nincs": "⚠ ALÁÍRATLAN",
                "megbizhatatlan": "⚠ nem megbízható tanúsítvány (%s)" % k,
                "rossz": "⛔ ÉRVÉNYTELEN — módosított fájl!",
                "nem_alairhato": "— (nem aláírható típus)",
                "hianyzik": "— (a fájl nem létezik)"}.get(a, "? (nem ellenőrizhető)")
    return {"ok": "ervenyes (%s)" % k,
            "nincs": "ALAIRATLAN",
            "megbizhatatlan": "NEM MEGBIZHATO tanusitvany (%s, %s)" % (k, info.get("status")),
            "rossz": "ERVENYTELEN ALAIRAS - a fajlt alairas utan MODOSITOTTAK!",
            "nem_alairhato": "nem alairhato tipus",
            "hianyzik": "a fajl nem letezik"}.get(a, "nem ellenorizheto")


def sig_veszely(info):
    """0 = rendben / nem dontheto el, 1 = alairatlan / nem megbizhato, 2 = ervenytelen (modositott)."""
    a = (info or {}).get("allapot")
    return 2 if a == "rossz" else (1 if a in ("nincs", "megbizhatatlan") else 0)
