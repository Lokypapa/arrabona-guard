# -*- coding: utf-8 -*-
# ============================================================
#  Arrabona Guard v2.18.1  —  G DATA-stílusú Dashboard UI
#
#  v2.18.1: AUTOMATIKUS INDÍTÁS ütemezett feladattal ("ArrabonaGuard AutoStart"): a pipa már ezt
#           kapcsolja (rendszergazdai jog UAC nélkül, akkuról is, időkorlát nélkül); a régi Run-kulcs
#           (amit a Windows az admin-exe-nél csendben kihagyott) csak tartalék admin jog nélkül.
#           HIBANAPLÓ: kezeletlen hibák (felület, háttérszálak) -> hiba_naplo.txt (csak helyben).
#           NÉVJEGY ablak: verzió, GitHub, frissítés keresése, kiadások, hiba bejelentése, hibanapló.
#
#  v2.18.0: NYILVÁNOS KIADÁS - bárki letöltheti (github.com/Lokypapa/arrabona-guard)
#           (arrabona/updater.py): ÖNFRISSÍTÉS GitHub Release-ből - 6 óránként keres, sáv az
#           ablakban + Telegram-gomb; a telepítőt SHA-256-tal ellenőrzi (SHA256SUMS.txt), ha nem
#           egyezik, NEM telepít; csendes telepítés, utána automatikus újraindulás.
#           Tálca: "Frissítés keresése". Telegram: /guardverzio, /guardfrissit; guard_frissites.txt
#           (arrabona/telegram_setup.py): TELEGRAM-VARÁZSLÓ - első indításkor felajánlja; saját bot
#           (@BotFather token), a chat ID-t a /start üzenetből olvassa ki, megerősítés, próbaüzenet.
#           "📱 Telegram" gomb + tálca-menü. A telepített exe helye már nem fix (INSTALL_EXE).
#           Build: build\build.bat (PyInstaller + Inno Setup + SHA256SUMS.txt)
#
#  v2.17.1: ütemezett feladatok - hamis riasztás javítva: a TaskCache XML nélküli (árva) bejegyzései
#           (régi beépített Windows-feladatok frissítés után) nem "REJTETT" feladatok; rejtettnek csak az
#           SD nélküli (Tarrask) számít. rundll32 url.dll,FileProtocolHandler https://... (weboldal
#           megnyitása, pl. RoboForm) nem gyanús.
#
#  v2.17.0 (arrabona/utemezett.py): ÜTEMEZETT FELADATOK TELJES ÁTNÉZÉSE - nem csak az új (4698), hanem
#           MINDEN meglévő feladat 30 percenként (+ 4698 után azonnal): kódolt / rejtett / letöltő
#           PowerShell, mshta / rundll32 / regsvr32 / certutil trükkök, szkript Temp / AppData / Public
#           mappából, aláíratlan / érvénytelen aláírású program, \Microsoft\ alá ÁLCÁZOTT feladat,
#           COM-ELTÉRÍTÉS (HKCU), REJTETT feladat (Tarrask: SD nélkül a TaskCache-ben). Új / MÓDOSULT
#           gyanús feladat -> riasztás + gombok: Letiltás / + program karanténba / Megbízható.
#           Javítás ablak: új "Ütemezett feladatok" fül. Telegram: /feladatok [most],
#           /feladattiltas <szám>, /feladatengedely <szám>; utemezett.txt (KIVETEL)
#           Elavult programok kártya: "Első lekérdezés: 18:29 (még 2 perc)" az "indulás…" helyett
#
#  v2.16.0 (arrabona/frissites.py): ELAVULT PROGRAMOK - a winget hetente lekérdezi, mi frissíthető;
#           a biztonsági szempontból kiemeltek (böngésző, 7-Zip/WinRAR, Discord, Java, PDF-olvasó,
#           távoli elérés...) jelölve. Telegram-gombok: Kiemeltek / Mind frissítése (csak kérésre).
#           Telegram: /frissitesek [most], /frissit <szám|kiemelt|mind>; frissites.txt (NAPOK, KIHAGY)
#           (arrabona/upnp.py): ROUTER NYITOTT PORTJAI (UPnP) - 5 percenként lekérdezi a routertől
#           (SSDP + WANIPConnection), új port -> riasztás: melyik gép / PROGRAM nyitotta, aláírás,
#           veszélyes portok (RDP, SMB, SSH, VNC, adatbázis) kiemelve; gomb: Port bezárása
#           (+ program leállítása) / Megbízható. Telegram: /upnp, /upnpzar <szám>; upnp.txt
#           (arrabona/kiszivargas.py): ADATKISZIVÁRGÁS-FIGYELÉS - TCP EStats: programonként pontosan
#           mért feltöltés (IPv4 + IPv6, csak internetes cél). Aláíratlan program 30 MB / 5 perc,
#           aláírt 1500 MB / 10 perc + saját rekordja 3x-a, rossz hírű cél 5 MB -> riasztás;
#           NAGYON GYANÚS esetben felfüggeszti (Leállítás / Folytatás / Karantén / Cél IP blokk /
#           Megbízható). Telegram: /kiszivargas; kiszivargas.txt (ISMERETLEN_MB, ALAIRT_MB, AKCIO, KIVETEL)
#
#  v2.15.3: felület: az Események panel nem szűkül össze betöltés után (elhelyezési sorrend),
#           a kártyák szövege a kártya szélességéhez tördelődik, egyforma széles oszlopok
#
#  v2.15.2: letöltés-figyelés: menet közben hozzáadott mappa meglévő fájljai nem "új letöltések"
#           (nincs riasztás-áradat); forráskód-ZIP (pl. GitHub Download ZIP) .js / .bat fájljai és
#           a .url parancsikonok nem riasztanak
#
#  v2.15.1: letöltés-figyelés: a böngészőkben beállított letöltési mappákat is figyeli
#           (Chrome / Edge / Brave / Vivaldi / Opera / Firefox), a figyelt mappák a naplóba
#           kerülnek; Firefox: a letöltés közbeni üres fájlt nem vizsgálja
#
#  v2.15.0 (arrabona/letoltes.py): LETÖLTÉSEK AUTOMATIKUS VIZSGÁLATA - minden új futtatható /
#           tömörített / makrós / lemezkép fájl a Letöltések mappában: forrásoldal (Zone.Identifier),
#           aláírás, dupla kiterjesztés, .js/.vbs/.hta/.lnk, JELSZAVAS ZIP exe-vel, felfújt exe,
#           Defender + VirusTotal. Telegram: /letoltes; letoltes.txt (MAPPA, DEFENDER, VT)
#           (arrabona/ui_extra.py): KERESHETŐ NAPLÓ (szöveg / modul / időszak, export; Telegram
#           /naplo [szó]), BEÁLLÍTÁSOK MENTÉSE / VISSZAÁLLÍTÁSA (ZIP, biztonsági mentéssel)
#
#  v2.14.0 (arrabona/vagolap.py): VÁGÓLAP-VÉDELEM ("clipper" ellen) - ha a másolt kriptotárca-cím
#           (BTC, ETH/BSC, LTC, DOGE, TRX, XMR, BCH, SOL) vagy IBAN 3 mp-en belül másik címre
#           cserélődik egy háttérprogram által: az eredetit visszaállítja, a cserélőt megállítja,
#           riaszt. A vágólap tartalmát nem menti / nem küldi el. Telegram: /vagolap; vagolap.txt
#           + "Megbízható" gomb nem némíthat el Windows-programot (PowerShell, cmd...)
#
#  v2.13.1: folyamatfigyelés: a rejtett PowerShell (enyhe jel) nem riaszt, ha egy aláírt,
#           Program Files-ba telepített program indította (pl. Kerish Doctor) - csak napló
#
#  v2.13.0 (arrabona/lopas.py): INFOSTEALER-CSAPDA - a böngészők jelszó-, süti- és
#           kártyaadat-fájljait (Chrome, Edge, Brave, Opera, Vivaldi, Yandex, Firefox) a Windows
#           olvasás-naplózásával (SACL + 4663) figyeli: PONTOSAN látja, melyik program olvasta.
#           Csalik a nem telepített programok helyén (Yandex, Opera GX, Exodus, Electrum,
#           FileZilla) - aki ezeket olvassa, szinte biztosan adatlopó. Ismeretlen olvasó:
#           megállítja (te döntesz). Telegram: /lopas; infolopas.txt (AKCIO, CSALIK, VALODI, KIVETEL)
#
#  v2.12.3: frissítés után az új példány saját ideiglenes mappát kap (PyInstaller _PYI_* /
#           PYINSTALLER_RESET_ENVIRONMENT) - eddig a régiét használta, ami a régi kilépésekor
#           törlődött ("base_library.zip" / "No module named expat"); a bennragadt régi
#           példány 20 mp türelmi idő után áll le
#
#  v2.12.2: folyamatfigyelés javítás - névütközés a kimenő-kapcsolat modullal (_proc_info /
#           _proc_cache): "'tuple' object has no attribute 'get'" hiba, a modul nem riasztott
#
#  v2.12.1: eseménynapló-ékezetek javítva (wevtutil /uni:true + dec_ki: "Súlyos" a "S?lyos" helyett);
#           folyamatfigyelés: ha a folyamat azonnal kilépett (pl. a Defender megölte), a 4688 is
#           kiértékeli; a 4688-naplózás már induláskor bekapcsol (nem 15 mp múlva)
#           FRISSÍTÉS: a régi példány most már tényleg kilép (eddig a tálcán maradt),
#           az új példány induláskor leállítja a bennragadt 'Arrabona Guard.exe.old'-ot
#
#  v2.12.0 (arrabona/folyamat.py): FOLYAMATFIGYELÉS - minden új folyamat indításkor:
#           álcázott rendszerfolyamat, árnyékmásolat-törlés, Defender/tűzfal kikapcsolása,
#           Office/PDF -> PowerShell (makróvírus), kódolt / rejtett / letöltő PowerShell,
#           certutil/bitsadmin/mshta/rundll32/regsvr32 trükkök, aláíratlan program Temp /
#           Letöltések / Lomtár mappából, dupla kiterjesztés. 4688-as eseménnyel a rövid
#           életű folyamatokat is látja. KRITIKUS esetben megállítja (te döntesz).
#           Telegram-gombok: Leállítás / Folytatás / Karantén / Megbízható;
#           /folyamat, /folyamatreset; folyamat.txt (AKCIO, SZINT, NAPLO, KIVETEL)
#
#  v2.11.0 (arrabona/extrak.py): KISZIVÁRGOTT JELSZÓ-ellenőrzés (HIBP, k-anonimitás),
#           VIRUSTOTAL (gyanús fájlok automatikusan; virustotal.txt KULCS=; /vt <út>),
#           WINDOWS UPDATE-figyelés (tiltás, házirend, utolsó frissítés, újraindítás;
#           /winupdate), BIZTONSÁGI PONTSZÁM 0-100 + tippek (/pontszam)
#
#  v2.10.0: TELEGRAM-GOMBOK a riasztások alatt (típus szerint): Végleges blokk /
#           Feloldás, Leállítás + teljes vizsgálat / Folytatás (zsarolóvírus),
#           Program leállítása, Hosts visszaállítása, Automatikus DNS, Proxy ki,
#           Teljes vizsgálat, Karanténba + leállítás (induló program), Rendben.
#           Megnyomás után a gombok eltűnnek, az eredmény az üzenet alá kerül.
#
#  v2.9.1: Tálca-menü: "Játék mód: AUTO — most aktív 🎮" almenü (AUTO / BE / KI, pipával)
#
#  v2.9.0: JÁTÉK MÓD (arrabona/jatek.py): teljes képernyős / keret nélküli
#          játék (vagy a jatek.txt-ben felsorolt program) alatt nincs hang és
#          felugró ablak (Telegram megy), az automatikus Defender-vizsgálatok és
#          a teljes LAN-keresés a játék végéig várnak. Utána összegzés +
#          elhalasztott vizsgálatok + zsarolóvírus-döntés ablak.
#          Gomb (AUTO/BE/KI), tálca-menü, Telegram: /jatek be|ki|auto
#
#  v2.8.0: DNS- ÉS PROXY-FIGYELÉS (arrabona/halozat.py): DNS adapterenként
#          (kézi + routertől kapott -> router-feltörés gyanú), NRPT-szabályok,
#          Windows proxy, PAC-szkript, WinHTTP, proxy környezeti változók,
#          Firefox proxy. DNS-besorolás: ismert / helyi / elfogadott / ISMERETLEN /
#          FEED-ben szereplő. Javítás ablak "Hálózat" fül: automatikus DNS,
#          proxy ki. Telegram: /dns, /dnsauto, /proxyki
#
#  v2.7.0: LAN-ESZKÖZ FIGYELÉS (arrabona/lan.py): ARP-tábla 30 mp-enként +
#          teljes hálózat-keresés (SendARP) 10 percenként; új MAC -> riasztás
#          (név, "véletlen MAC" jelzés). ARP-MÉRGEZÉS (MITM): a router MAC-címének
#          változása / másik eszköz a router MAC-jével -> riasztás.
#          lan.txt: FIGYELES, AKTIV. Telegram: /lan, /lannev <szám> <név>
#
#  v2.6.1: Bővítmények: a programok által a HIVATALOS boltból telepített
#          bővítmény (Malwarebytes, Adobe...) már nem "gyanús"; csak az idegen
#          címről / helyi fájlból telepített. A registry + profil duplikátum összevonva.
#
#  v2.6.0: BÖNGÉSZŐ-BŐVÍTMÉNYEK figyelése (arrabona/bongeszo.py): Chrome, Edge,
#          Brave, Vivaldi, Opera (minden profil) + Firefox; fejlesztői módban /
#          parancssorból betöltött, házirenddel KÉNYSZERÍTETT és registryből
#          telepített bővítmények is. Új bővítmény, ill. meglévő bővítmény
#          JOGOSULTSÁG-BŐVÜLÉSE -> riasztás a jogok magyarázatával.
#          Telegram: /bovitmenyek
#
#  v2.5.0: RANSOMWARE-CSAPDA (arrabona/csali.py): rejtett "!Arrabona_csali"
#          mappák csalifájlokkal (Dokumentumok, Asztal, Képek, Letöltések +
#          a többi belső lemez gyökere). Ha bármi hozzányúl: riasztás, és a
#          legtöbbet író folyamat MEGÁLLÍTVA (felfüggesztve) -> Leállítás /
#          Folytatás ablak (+ teljes vizsgálat). csali.txt: CSAPDA, AKCIO
#          (FELFUGGESZT / LEALLIT / RIASZT), MEGHAJTOK. Telegram: /csapda,
#          /leallit <PID>, /folytat <PID>
#
#  v2.4.0: DIGITÁLIS ALÁÍRÁS-ELLENŐRZÉS (arrabona/alairas.py): kiadó neve /
#          ALÁÍRATLAN / NEM MEGBÍZHATÓ / ÉRVÉNYTELEN (módosított fájl) a riasztásokban:
#          új indulóprogram, új szolgáltatás (7045) és ütemezett feladat (4698),
#          rossz IP-re kapcsolódó program, és ÚJ: PENDRIVE-RÓL INDULT PROGRAM.
#          Gyanús hely + aláíratlan = "NAGYON GYANÚS"; aláíratlan / érvénytelen
#          szolgáltatás-, feladat- és USB-program -> automatikus Defender-vizsgálat.
#          Javítás ablak: "Aláírás" oszlop. Telegram: /alairas <út>, /indulo kiadóval
#
#  v2.3.0: EGYKATTINTÁSOS JAVÍTÁS (arrabona/javitas.py + ui_javitas.py):
#          "Javítás / karantén" ablak: indulóprogram KARANTÉNBA (registry-érték
#          mentve + törölve, Indító mappa fájlja áthelyezve, Winlogon
#          alapértékre), kérésre a futó példány leállítása; visszaállítás a
#          Karantén fülön; hosts visszaállítása az előző / alapértelmezett
#          változatra (csere -> visszacsinálható, DataBasePath is, DNS-ürítés)
#          Telegram: /indulotiltas <szám> [kill], /karanten, /visszaallit <id>,
#                    /hostsvissza [alap]
#  v2.2.0: MEGSZAKÍTÁS gomb a folyamatpanelen (+ Telegram: /stopscan)
#          HOSTS-FÁJL figyelés (arrabona/hosts.py): minden változásra riaszt,
#            kiemelve a bank / Microsoft / vírusirtó / Guard-forrás címek
#            átirányítását vagy tiltását; a hosts HELYÉNEK (DataBasePath)
#            átállítását is; előző változat: hosts_elozo.txt (Telegram: /hosts)
#          INDÍTÓPULT figyelés (arrabona/startup.py): Run/RunOnce, Winlogon
#            Shell/Userinit, Indító mappák; új/módosult bejegyzés -> riasztás,
#            gyanús minták kiemelve, az új program fájlja automatikus
#            Defender-vizsgálatot kap (indulo.txt: AUTOSCAN BE/KI; Telegram: /indulo)
#          Mindkettő a Guard leállása alatti változást is jelzi indításkor.
#
#  v2.1.3: FOLYAMATPANEL a Defender-vizsgálatokhoz (lépések, mozgó sáv,
#          eltelt idő, eredmény); pendrive-nál a foglalt adatmennyiség is
#  v2.1.2: a Guard leállása / újraindulása alatt bedugott új pendrive is
#          vizsgálatot kap; egy pendrive = egy riasztás (USBSTOR + szülő összevonva)
#  v2.1.1: a gyors (UAS, "SCSIAdapter") pendrive-ok / SSD-k is tárolónak
#          számítanak -> "ÚJ USB-TÁROLÓ" + automatikus Defender-vizsgálat
#
#  Újdonságok a v2.1.0-ban (arrabona/usb.py):
#   - USB-FIGYELÉS: riasztás minden soha nem látott USB-eszközre;
#     külön kiemelve a BILLENTYŰZET (BadUSB) és a HÁLÓZATI ADAPTER
#   - Új pendrive / külső lemez: betűjel, név, méret + automatikus
#     Defender-vizsgálat (usb.txt: AUTOSCAN UJ / MIND / KI)
#   - Telegram: /usb
#
#  v2.0.0: MODULOKRA BONTVA - a kód az arrabona/ mappában van:
#   common, geoip, telegram, watchdog, feed, geo, honeypot, logon,
#   defender, outbound, core, ui, instance, main.
#   A működés változatlan (minden függvény bitre azonos az 1.9.6-tal).
#
#  Újdonságok a v1.9.6-ban:
#   - WINDOWS DEFENDER integráció: állapotkártya (valós idejű védelem,
#     definíciók, Memóriaintegritás, szabotázsvédelem, vizsgálatok)
#   - Riasztás: kártevő észlelve / kezelve / NEM eltávolítható,
#     védelem kikapcsolva, ÚJ KIVÉTEL hozzáadva (5007)
#   - Gyors vizsgálat gomb + Telegram: /defender /scan /scanfull /defupdate
#   - Javítás: a [BIZTONSAG] / [KIMENO] riasztások nem kerülnek
#     kétszer a naplóba (a napi riport duplán számolta őket)
#
#  Újdonságok a v1.9.5-ben:
#   - ŐRKUTYA: ütemezett feladat 2 percenként ellenőrzi, fut-e a
#     Guard; ha nem (és nem te léptél ki), újraindítja és Telegramon
#     szól. Ha valaki törli a feladatot, a Guard riaszt + visszaállítja.
#
#  Újdonságok a v1.9.4-ben:
#   - KIMENŐ védelem: a FEED rossz hálózatai felé a gép sem
#     kapcsolódhat (kimeno.txt: BE/KI)
#   - Melyik program próbált rossz IP-re kapcsolódni? A tűzfalnapló
#     kimenő eldobásaiból (PID) + nyitott kapcsolatok átnézése
#     30 mp-enként -> riasztás programnévvel és elérési úttal
#
#  Újdonságok a v1.9.3-ban:
#   - 4624: SIKERES hálózati/RDP belépés külső IP-ről -> azonnali
#     riasztás (feketelistás IP esetén végleges blokk is)
#   - 4720 új fiók, 4732 Administrators / Remote Desktop Users
#     csoportba vétel, 1102/104 eseménynapló törlése -> riasztás
#   - A szükséges Windows-naplózás automatikus bekapcsolása
#     (auditpol, GUID-dal - magyar Windowson is)
#   - Telegram /block <IP>: azonnali végleges blokk
#   - Tailscale: a teljes 100.64.0.0/10 tartomány belsőnek számít
#
#  Javítások a v1.9.2-ben:
#   - Perzisztencia (4698/7045): minden esemény külön riasztás
#   - Memória-takarítás 10 percenként a lejárt IP-bejegyzésekre
#   - 4625: feketelistás IP próbája azonnal riaszt + blokkol;
#     belső/saját forrás csak riaszt; halott kód kivezetve
#   - Rendszergazdai jog nélkül "Korlátozott védelem" (narancs)
#   - Országkód már az első riasztásban (helyi mmdb, szinkron)
#   - Honeypot: [CSALI] csak a ténylegesen nyitott csaliportokon;
#     a tűzfal-engedélyek nem halmozódnak indításonként
#   - Telegram /unblock: IP-ellenőrzés + csak aktív blokkra
#
#  Javítások a v1.9.1-ben:
#   - FEED: a FireHOL Level-1 privát/bogon tartományai (10/8,
#     192.168/16, 172.16/12, 100.64/10 Tailscale...) már NEM
#     kerülnek tűzfal-tiltásba -> a saját LAN nem zárja ki magát
#   - GEO: a szabályok nem duplikálódnak többé (időbélyeges nevek,
#     a régi felhalmozott szabályok egyszeri takarítása)
#   - SYN-flood: a tcpflags mezőt olvassa (eddig sosem jelzett)
#   - Már blokkolt IP csomagjai csendben számolódnak: nincs
#     percenkénti riasztás / Telegram-áradat, nincs önmaga általi
#     eszkaláció; blokklista körönként egyszer olvasva
#   - Témaváltás / frissítés után az új példány nem lép ki csendben
#     (mutex elengedése + restart.flag várakozás)
#
#  Újdonságok a v1.9-ben:
#   - single-instance (CreateMutexW): második példány csendben kilép
#   - nincs több dupla riasztás a párhuzamos példányokból
#   - PRIVÁT IP-K CSENDEN: a 192.168.*, 10.*, 172.16-31.*,
#     169.254.* stb. belső hálózati címek NEM adnak riasztást
#   - WHITELIST: %APPDATA%\ArrabonaGuard\whitelist.txt — ide írt
#     IP-ket szintén figyelmen kívül hagyja
#   - GEOIP: riasztásnál országkód, pl. "[RU]", "[DE]";
#     LAN címeknél "[LAN]" — online lekérdezés (ip-api.com),
#     gyorsítótárazva, internet nélkül egyszerűen nincs kód
#   - NAPLÓTAKARÍTÁS: 10 MB felett induláskor a régi rész törlődik
#   - AZ ÖSSZES PORT FIGYELVE: a tűzfal minden eldobott csomagját
#     látja (SSH, RDP, SMB, WoW, MySQL... mind) — a panel felirata
#     is ezt tükrözi immár
#  v1.7: zöld márka + dinamikus "védett" cím
#  v1.6: G DATA-stílusú dashboard layout
#  UI frissítés: görgethető tartalom (egérgörgő), az alsó
#  gombsor fixen az ablak alján — nem kell széthúzni az ablakot
# ============================================================
#  Ez a fajl csak az indito; a kod az arrabona/ csomagban van.

from arrabona.main import main

if __name__ == "__main__":
    main()
