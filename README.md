# clipsync

Deelt je klembord automatisch tussen je computers op hetzelfde lokale netwerk:
**tekst, afbeeldingen en bestanden/mappen**.
Eén Python-bestand, werkt op Windows en Linux. Extra packages zijn alleen nodig voor het (optionele) tray-icoon.

## Installatie

**Linux** (Python 3 zit er al op):

```bash
sudo apt install xclip python3-pystray gir1.2-ayatanaappindicator3-0.1
python3 clipsync.py --install
```

**Windows**: installeer Python 3 van python.org (vink "Add to PATH" aan), kopieer `clipsync.py` naar een vaste plek, en:

```bat
pip install pystray pillow
python clipsync.py --install
```

`pystray` (en op Linux de AppIndicator-bibliotheek) is alleen nodig voor het tray-icoon. Zonder die pakketten werkt clipsync gewoon, maar dan zonder icoon.

`--install` vraagt om een wachtwoord (gebruik op elk apparaat **hetzelfde**) en zorgt dat clipsync start zodra je inlogt. Start het daarna één keer handmatig of log opnieuw in.

Windows vraagt bij de eerste start om netwerktoegang via de firewall: sta dit toe voor **privénetwerken**. Je netwerk moet in Windows als "Privé" ingesteld staan.

## Gebruik

Kopieer op het ene apparaat, plak op het andere:

- **Tekst**: zoals je gewend bent.
- **Afbeeldingen**: screenshots, "Afbeelding kopiëren" in de browser, enz. Ze worden als PNG verstuurd.
- **Bestanden en mappen**: kopieer ze in Verkenner/Bestanden (Ctrl+C) en plak ze op het andere apparaat in een map (Ctrl+V).
  Ze worden direct bij het kopiëren al verstuurd en tijdelijk opgeslagen in
  `~/.cache/clipsync/files` (Linux) of `%LOCALAPPDATA%\clipsync\files` (Windows). Daar worden ze na 24 uur opgeruimd.
  Standaard is het maximum 500 MB per keer. Dat pas je aan met `max_files_mb` in `config.json`.

### Tray-icoon

Het klembord-icoon in de systeembalk laat zien dat clipsync draait:
**groen** als er een ander apparaat is gevonden, **grijs** als het nog zoekt.
Het menu toont met welke apparaten je verbonden bent en wat er als laatste is gedeeld.
Ook kun je er het logbestand openen of clipsync afsluiten.

Onder **Recent gekopieerd** staan de laatste 5 dingen die op je klembord stonden: tekst, afbeeldingen en bestanden, ook die van je andere apparaten.
Klik je op een item, dan staat het weer op je klembord en wordt het ook naar je andere apparaten gestuurd.
De geschiedenis staat alleen in het geheugen. Na een herstart begint hij dus leeg, en er komt niets op schijf te staan.

| Commando | Wat |
|---|---|
| `clipsync.py` | Draaien in de voorgrond (met log in de terminal) |
| `clipsync.py --setup` | Wachtwoord wijzigen |
| `clipsync.py --install` / `--uninstall` | Autostart aan/uit |
| `clipsync.py -v` | Extra logging |
| `clipsync.py --no-tray` | Zonder tray-icoon draaien |

Log en config staan in `~/.config/clipsync/` (Linux) of `%APPDATA%\clipsync\` (Windows).

## Hoe het werkt

- Elk apparaat roept elke 3 s via UDP-broadcast "ik ben er" op poort **45873**.
- Verandert je klembord, dan wordt de inhoud via TCP (zelfde poort) in versleutelde blokken van 1 MB naar alle gevonden apparaten gestuurd.
- Alles is versleuteld en geauthenticeerd met een sleutel die van je wachtwoord is afgeleid. Berichten met een ander wachtwoord of ouder dan 2 minuten worden genegeerd, dus de klokken moeten ongeveer gelijk lopen.
- Bevat het klembord meerdere soorten inhoud, dan gaat voorrang naar bestanden, dan tekst, dan afbeelding. Kopieer je bijvoorbeeld cellen in Excel, dan komt de tekst door.

## Problemen

- **Apparaten vinden elkaar niet**: controleer de firewall (poort 45873 TCP+UDP). Op Ubuntu met ufw: `sudo ufw allow from 192.168.1.0/24 to any port 45873`.
  Werkt broadcast niet op je netwerk, zet dan de IP-adressen van de andere apparaten in `config.json`: `"peers": ["192.168.1.30"]`.
- **Linux op Wayland**: xclip werkt via XWayland (GNOME/KDE). Heb je geen XWayland, installeer dan `wl-clipboard`.
- **Bestanden plakken lukt niet in je bestandsbeheerder**: onder GNOME, Cinnamon, MATE en XFCE gebruikt clipsync het GNOME-formaat, elders `text/uri-list`. Laat het weten als jouw bestandsbeheerder iets anders verwacht.
