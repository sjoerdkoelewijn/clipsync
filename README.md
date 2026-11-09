# clipsync

Automatically shares your clipboard between your computers on the same local network:
**text, images and files/folders**.
A single Python file that works on Windows and Linux. Extra packages are only needed for the (optional) tray icon.

## Disclaimer

> [!WARNING]
> clipsync is a hobby project I built for my own use. You're free to use and modify it, but it hasn't been extensively tested. It also hasn't been reviewed by a security expert. If you use it, you do so at your own risk. It may contain bugs or lack features, and I can't guarantee that it works correctly or that your data is safe. See also [Security](#security) and the [license](LICENSE).

## Installation

**Linux** (Python 3 is usually already installed):

```bash
sudo apt install xclip python3-pystray gir1.2-ayatanaappindicator3-0.1
python3 clipsync.py --install
```

**Windows**: install Python 3 from python.org (tick "Add to PATH"), put `clipsync.py` in a permanent location, and run:

```bat
pip install pystray pillow
python clipsync.py --install
```

`pystray` (and on Linux the AppIndicator library) is only needed for the tray icon. Without those packages clipsync still works, just without an icon.

`--install` asks for a password (use the **same** one on every device) and makes clipsync start when you log in. After that, start it once manually or log out and back in.

On first start, Windows asks for network access through the firewall: allow it for **private networks**. Your network must be set to "Private" in Windows.

## Usage

Copy on one device, paste on the other:

- **Text**: as you're used to.
- **Images**: screenshots, "Copy image" in your browser, etc. They are sent as PNG.
- **Files and folders**: copy them in Explorer/Files (Ctrl+C) and paste them into a folder on the other device (Ctrl+V).
  They are sent as soon as you copy them and stored temporarily in
  `~/.cache/clipsync/files` (Linux) or `%LOCALAPPDATA%\clipsync\files` (Windows), where they are cleaned up after 24 hours.
  By default the maximum is 500 MB per copy. You can change this with `max_files_mb` in `config.json`.

### Tray icon

The clipboard icon in the system tray shows that clipsync is running:
**green** when another device has been found, **grey** while it's still searching.
The menu shows which devices you're connected to and what was shared last.
You can also open the log file or quit clipsync from it.

**Recently copied** lists the last 5 things that were on your clipboard: text, images and files, including those from your other devices.
Click an item to put it back on your clipboard; it's also sent to your other devices.
The history is kept in memory only, so it starts empty after a restart and nothing is written to disk.

| Command | What it does |
|---|---|
| `clipsync.py` | Run in the foreground (with the log in the terminal) |
| `clipsync.py --setup` | Change the password |
| `clipsync.py --install` / `--uninstall` | Turn autostart on/off |
| `clipsync.py -v` | Extra logging |
| `clipsync.py --no-tray` | Run without a tray icon |

The log and config live in `~/.config/clipsync/` (Linux) or `%APPDATA%\clipsync\` (Windows).

### Settings (`config.json`)

| Setting | Default | What it does |
|---|---|---|
| `password` | – | Shared password, set with `--setup` |
| `port` | `45873` | Port for TCP and UDP (1024–65535). Must be the same on all devices |
| `peers` | `[]` | Fixed addresses if broadcast doesn't work, e.g. `["192.168.1.30"]` or `["192.168.1.30:45900"]` |
| `max_files_mb` | `500` | Maximum total size of files per copy |

Restart clipsync after changing `config.json`.

## How it works

- Every 3 seconds, each device announces "I'm here" via UDP broadcast (on port **45873** by default).
- When your clipboard changes, the content is sent over TCP (same port) in encrypted 1 MB blocks to all devices that were found.
- Everything is encrypted and authenticated with a key derived from your password. Messages with a different password or older than 2 minutes are ignored, so the devices' clocks need to be roughly in sync.
- If the clipboard holds several kinds of content, files take priority, then text, then images. If you copy cells in Excel, for example, the text comes through.

## Security

- clipsync is meant for a **trusted home network**. Don't expose the port to the internet.
- Everything clipsync sends over the network is encrypted. The key is derived from the password with `scrypt`. A stream cipher based on `SHAKE256` (SHA-3) then encrypts the data, and `HMAC-SHA256` checks that it hasn't been tampered with.
  The building blocks are standard and come from the Python standard library. I put the combination together myself, and it has **not been independently reviewed**.
- Known limitations:
  - There is no *forward secrecy*: anyone who records traffic and later learns the password can still read that old traffic.
  - Someone on the same network can replay a captured message within 2 minutes.
  - The password is stored readably in `config.json`. Only your user account can read that file.
- Security depends on your password. Choose a long password you don't use anywhere else.
- Received files are stored unencrypted in the cache folder until they are cleaned up after 24 hours.

## Troubleshooting

- **"Port is in use"**: is clipsync already running (check the system tray)? If not, another program is using that port. Choose another port with `port` in `config.json`, on all devices.
- **Devices can't find each other**: check that all devices use the same password and the same port. Also check the firewall (port 45873 TCP+UDP, or your own port). On Ubuntu with ufw: `sudo ufw allow from 192.168.1.0/24 to any port 45873`.
  If broadcast doesn't work on your network, put the IP addresses of the other devices in `config.json`: `"peers": ["192.168.1.30"]`.
- **Linux on Wayland**: xclip works via XWayland (GNOME/KDE). If you don't have XWayland, install `wl-clipboard`.
- **Pasting files doesn't work in your file manager**: on GNOME, Cinnamon, MATE and XFCE clipsync uses the GNOME format, elsewhere `text/uri-list`. Please open an issue if your file manager expects something else.
