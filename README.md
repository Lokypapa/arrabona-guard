# Arrabona Guard

Ingyenes, nyílt forrású **PC-védelmi program Windowsra**. Figyeli, ha a gépedet támadják. Riaszt, blokkol, és a telefonodra is szól Telegramon.

> ⚠ A Windows Defender mellé készült, nem helyette. A Defendert hagyd bekapcsolva: a Guard azzal együttműködik.

## Mit csinál?

- **Tűzfal és támadások:** valós időben figyeli a tűzfalnaplót (port-szkennelés, brute-force, SYN-flood), és automatikusan blokkol. Közösségi feketelistákat (Spamhaus, FireHOL) és ország szerinti blokkot is használ.
- **Belépésfigyelés:** jelez sikertelen és sikeres hálózati vagy RDP-belépésnél, új fióknál, rendszergazda-csoportba vételnél és eseménynapló-törlésnél.
- **Windows Defender:** állapotkártya, kártevő-riasztások, gyors és teljes vizsgálat egy gombbal.
- **Zsarolóvírus-csapda:** csalifájlokat helyez el. Ha valami hozzányúl, a programot megállítja.
- **Folyamatfigyelés:** álcázott rendszerfolyamatok, makróvírusok, kódolt PowerShell, gyanús helyről induló programok.
- **Infostealer-csapda:** észreveszi, ha egy program a böngészőben tárolt jelszavakat vagy sütiket olvassa.
- **További figyelés:** indítópult, ütemezett feladatok, hosts-fájl, DNS és proxy, böngésző-bővítmények, USB-eszközök, LAN-eszközök, ARP-mérgezés, router UPnP-portok, adatkiszivárgás, vágólap (kriptocím-csere), letöltések, elavult programok (winget).
- **Javítás és karantén:** egy kattintással karanténba tesz és visszaállít.
- **Játék mód:** teljes képernyős játék alatt nem dob fel ablakot.
- **Telegram:** riasztások gombokkal (blokkolás, leállítás, karantén) és távoli parancsok (`/help`).

## Letöltés és telepítés

1. Nyisd meg a **[Releases](https://github.com/Lokypapa/arrabona-guard/releases/latest)** oldalt, és töltsd le az `ArrabonaGuard_Setup_X.Y.Z.exe` fájlt.
2. Futtasd. Rendszergazdai jogot kér, mert a tűzfalhoz és az eseménynaplókhoz csak így fér hozzá.
3. Hagyd bejelölve az **automatikus indítást**. Így minden bejelentkezéskor elindul, UAC-ablak nélkül.

**Rendszerkövetelmény:** Windows 10 vagy 11, 64 bites.

### „A Windows megvédte a számítógépet” üzenet

A program nincs fizetős tanúsítvánnyal aláírva, ezért a SmartScreen első indításkor figyelmeztet. Kattints a **További információ → Futtatás mégis** gombra. Ha bizonytalan vagy, ellenőrizd a letöltött fájlt:

```powershell
Get-FileHash .\ArrabonaGuard_Setup_X.Y.Z.exe -Algorithm SHA256
```

Az eredménynek egyeznie kell a kiadás `SHA256SUMS.txt` fájljában szereplő értékkel.

## Telegram-értesítések

Első indításkor a Guard felajánlja a beállítást. Később a **📱 Telegram** gombbal vagy a tálca-menüből is elérhető. Minden felhasználó a **saját, ingyenes botját** használja, a varázsló végigvezet rajta:

1. Írj a [@BotFather](https://t.me/BotFather)-nek: `/newbot`, majd másold be a kapott tokent.
2. Írj a saját botodnak: `/start`. A Guard ebből felismeri a chatedet.
3. Megerősítés után a Guard küld egy próbaüzenetet, és kész.

A token csak a te gépeden tárolódik (`%APPDATA%\ArrabonaGuard\telegram.txt`). A Guard csak a saját chatedből fogad el parancsot.

## Frissítések

A Guard 6 óránként megnézi, van-e új kiadás. Ha van, sávot mutat az ablakban, és Telegramon is szól, gombbal. Magától **soha nem telepít**: csak ha te kéred (gomb, tálca-menü vagy `/guardfrissit`).

Frissítéskor letölti a telepítőt, és a **SHA-256 ellenőrzőösszeggel ellenőrzi**. Ha nem egyezik, nem telepít. Ha egyezik, csendben telepít, majd újraindul.

- Kézi keresés: tálca → **Frissítés keresése**, vagy Telegramon `/guardverzio`
- Kikapcsolás: `%APPDATA%\ArrabonaGuard\guard_frissites.txt` → `KERESES KI`

## Adatvédelem: mit küld a program, és hova?

A Guard **semmilyen adatot nem küld a készítőnek**. Kapcsolatot csak ezekkel tart:

| Cél | Miért |
|---|---|
| Telegram (a **te** botod) | riasztások, ha beállítod |
| api.github.com | új verzió keresése |
| Spamhaus, FireHOL, GitHub (sapics), db-ip.com | feketelisták, ország-adatbázis letöltése |
| ip-api.com | a **támadó** IP-címének országa (tartalék) |
| api.ipify.org | a saját nyilvános IP-címed (hogy azt ne blokkolja ki) |
| api.pwnedpasswords.com | kiszivárgott jelszó ellenőrzése: csak a hash első 5 karaktere megy ki (k-anonimitás) |
| VirusTotal | csak ha megadsz saját API-kulcsot; a fájlnak csak a hash-e megy ki |

A naplók és beállítások helye: `%APPDATA%\ArrabonaGuard`.

## Eltávolítás

Gépház → Alkalmazások → **Arrabona Guard** → Eltávolítás. Ez törli az ütemezett feladatokat, az automatikus indítást és a Guard tűzfal-szabályait. A beállítások és naplók (`%APPDATA%\ArrabonaGuard`) megmaradnak, ezeket kézzel törölheted.

## Fordítás forráskódból (fejlesztőknek)

Kell hozzá: **Python 3.11+** és **[Inno Setup 6](https://jrsoftware.org/isdl.php)**.

```bat
build\build.bat
```

Eredmény: `release\ArrabonaGuard_Setup_<verzió>.exe` és `release\SHA256SUMS.txt`. Új kiadásnál emeld meg a `VERSION` értékét az `arrabona/common.py`-ban, majd a GitHubon hozz létre egy Release-t `v<verzió>` taggel, és **mindkét fájlt** csatold hozzá.

Futtatás fordítás nélkül, rendszergazdai parancssorból:

```bat
pip install -r requirements.txt
python arrabona_guard.py
```

## Licenc

[MIT](LICENSE). Szabadon használható és módosítható, de garancia nélkül.
