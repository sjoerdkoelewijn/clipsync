#!/usr/bin/env python3
"""
clipsync - deel je klembord tussen computers op je lokale netwerk.

Ondersteunt tekst, afbeeldingen en bestanden/mappen.

- Alleen Python standaardbibliotheek, werkt op Windows en Linux.
- Optioneel tray-icoon via pystray (zonder pystray draait het gewoon zonder icoon).
- Apparaten vinden elkaar automatisch via UDP-broadcast.
- Alles wat over het netwerk gaat is versleuteld en geauthenticeerd met een
  gedeeld wachtwoord (scrypt -> SHAKE256-stroomcijfer + HMAC-SHA256).

Gebruik:
    python clipsync.py              # draaien (vraagt de eerste keer om een wachtwoord)
    python clipsync.py --setup      # wachtwoord (opnieuw) instellen
    python clipsync.py --install    # automatisch starten bij inloggen
    python clipsync.py --uninstall  # autostart weer verwijderen
"""

import argparse
import getpass
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import uuid
import zlib

DEFAULT_PORT = 45873           # standaardpoort; aan te passen met "port" in config.json
PORT = int(os.environ.get("CLIPSYNC_PORT", DEFAULT_PORT))  # UDP (ontdekken) en TCP (klembord)
BEACON_INTERVAL = 3            # seconden tussen "ik ben er"-berichten
PEER_TIMEOUT = 15              # peer vergeten als hij zo lang niets heeft laten horen
POLL_INTERVAL = 0.5            # hoe vaak het lokale klembord gecontroleerd wordt
MAX_AGE = 120                  # berichten ouder dan dit (seconden) worden geweigerd
MAX_INLINE = 50 * 1024 * 1024  # max grootte tekst/afbeelding
DEFAULT_MAX_FILES_MB = 500     # max totale grootte van gekopieerde bestanden
KEEP_FILES_HOURS = 24          # ontvangen bestanden worden daarna opgeruimd
HISTORY_SIZE = 5               # aantal recente klembord-items in het tray-menu
CHUNK = 1024 * 1024            # grootte van versleutelde blokken

IS_WINDOWS = sys.platform == "win32"
APP = "clipsync"


# --------------------------------------------------------------------------- #
# Paden & config
# --------------------------------------------------------------------------- #

def config_dir():
    if IS_WINDOWS:
        base = os.environ.get("APPDATA", os.path.expanduser("~"))
    else:
        base = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    path = os.path.join(base, APP)
    os.makedirs(path, exist_ok=True)
    return path


def files_dir():
    """Waar ontvangen bestanden terechtkomen (wordt automatisch opgeruimd)."""
    if IS_WINDOWS:
        base = os.environ.get("LOCALAPPDATA", config_dir())
    else:
        base = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    path = os.path.join(base, APP, "files")
    os.makedirs(path, exist_ok=True)
    return path


CONFIG_FILE = os.path.join(config_dir(), "config.json")
LOG_FILE = os.path.join(config_dir(), "clipsync.log")


def load_config():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None


def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    if not IS_WINDOWS:
        os.chmod(CONFIG_FILE, 0o600)


def setup():
    print("Kies een wachtwoord. Gebruik op ALLE apparaten exact hetzelfde wachtwoord.")
    while True:
        pw = getpass.getpass("Wachtwoord: ")
        if len(pw) < 8:
            print("Minimaal 8 tekens graag.")
            continue
        if getpass.getpass("Nogmaals: ") != pw:
            print("Komt niet overeen, probeer opnieuw.")
            continue
        break
    cfg = load_config() or {}
    cfg["password"] = pw
    cfg.setdefault("peers", [])  # optioneel: vaste IP-adressen als broadcast niet werkt
    cfg.setdefault("max_files_mb", DEFAULT_MAX_FILES_MB)
    cfg.setdefault("port", DEFAULT_PORT)  # moet op alle apparaten gelijk zijn
    save_config(cfg)
    print(f"Opgeslagen in {CONFIG_FILE}")
    return cfg


# --------------------------------------------------------------------------- #
# Crypto (alleen stdlib)
# --------------------------------------------------------------------------- #

def xor(a: bytes, b: bytes) -> bytes:
    n = len(a)
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(n, "big")


class Crypto:
    def __init__(self, password):
        master = hashlib.scrypt(password.encode(), salt=b"clipsync-v1",
                                n=2 ** 14, r=8, p=1, dklen=64)
        self.enc_key, self.mac_key = master[:32], master[32:]

    def crypt(self, nonce, idx, data):
        ks = hashlib.shake_256(self.enc_key + nonce + struct.pack(">Q", idx)).digest(len(data))
        return xor(data, ks)

    def tag(self, nonce, idx, last, ct):
        return hmac.digest(self.mac_key, nonce + struct.pack(">QB", idx, last) + ct, "sha256")

    # Losse berichten (UDP)
    def seal(self, obj) -> bytes:
        nonce = os.urandom(16)
        ct = self.crypt(nonce, 0, json.dumps({**obj, "t": time.time()}).encode())
        return nonce + ct + self.tag(nonce, 0, 1, ct)

    def open(self, blob):
        if len(blob) < 48:
            return None
        nonce, ct, tag = blob[:16], blob[16:-32], blob[-32:]
        if not hmac.compare_digest(tag, self.tag(nonce, 0, 1, ct)):
            return None
        obj = json.loads(self.crypt(nonce, 0, ct))
        if abs(time.time() - obj["t"]) > MAX_AGE:
            return None
        return obj


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(min(n - len(buf), CHUNK))
        if not chunk:
            raise ConnectionError("verbinding gesloten")
        buf += chunk
    return bytes(buf)


class FrameWriter:
    """Versleutelde stroom: header-blok gevolgd door data-blokken van max CHUNK."""

    def __init__(self, sock, crypto):
        self.sock, self.crypto = sock, crypto
        self.nonce = os.urandom(16)
        self.idx = 0
        self.buf = bytearray()
        sock.sendall(self.nonce)

    def _send(self, data, last):
        ct = self.crypto.crypt(self.nonce, self.idx, bytes(data))
        tag = self.crypto.tag(self.nonce, self.idx, last, ct)
        self.sock.sendall(struct.pack(">IB", len(ct), last) + ct + tag)
        self.idx += 1

    def header(self, obj):
        self._send(json.dumps({**obj, "t": time.time()}).encode(), 0)

    def write(self, data):
        self.buf += data
        while len(self.buf) >= CHUNK:
            self._send(self.buf[:CHUNK], 0)
            del self.buf[:CHUNK]

    def close(self):
        self._send(self.buf, 1)
        self.buf = bytearray()


class FrameReader:
    def __init__(self, sock, crypto):
        self.sock, self.crypto = sock, crypto
        self.nonce = recv_exact(sock, 16)
        self.idx = 0
        self.buf = bytearray()
        self.done = False

    def _next(self):
        length, last = struct.unpack(">IB", recv_exact(self.sock, 5))
        if length > 16 * CHUNK:
            raise ValueError("blok te groot")
        ct = recv_exact(self.sock, length)
        tag = recv_exact(self.sock, 32)
        if not hmac.compare_digest(tag, self.crypto.tag(self.nonce, self.idx, last, ct)):
            raise ValueError("ongeldige handtekening (ander wachtwoord?)")
        pt = self.crypto.crypt(self.nonce, self.idx, ct)
        self.idx += 1
        return pt, last

    def header(self):
        pt, last = self._next()
        if last:
            raise ValueError("leeg bericht")
        h = json.loads(pt)
        if abs(time.time() - h["t"]) > MAX_AGE:
            raise ValueError("bericht te oud (lopen de klokken gelijk?)")
        return h

    def _fill(self):
        pt, last = self._next()
        self.buf += pt
        self.done = bool(last)

    def read(self, n):
        while len(self.buf) < n and not self.done:
            self._fill()
        if len(self.buf) < n:
            raise ValueError("bericht afgebroken")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_all(self, limit):
        while not self.done:
            self._fill()
            if len(self.buf) > limit:
                raise ValueError("bericht te groot")
        out, self.buf = bytes(self.buf), bytearray()
        return out

    def finish(self):
        if self.read_all(0):
            raise ValueError("onverwachte extra data")


# --------------------------------------------------------------------------- #
# Klembord-inhoud
# --------------------------------------------------------------------------- #

class Clip:
    """kind: 'text' (str), 'image' (PNG-bytes) of 'files' (lijst met paden)."""

    def __init__(self, kind, data):
        self.kind, self.data = kind, data

    def sig(self):
        if self.kind == "text":
            return ("text", hashlib.sha256(self.data.encode("utf-8", "replace")).digest())
        if self.kind == "image":
            return ("image", hashlib.sha256(self.data).digest())
        items = []
        for p in self.data:
            try:
                st = os.stat(p)
                items.append((p, st.st_size, st.st_mtime))
            except OSError:
                items.append((p,))
        return ("files", tuple(items))

    def available(self):
        """Bestanden kunnen inmiddels verwijderd zijn (bv. opgeruimde cache)."""
        return self.kind != "files" or all(os.path.exists(p) for p in self.data)

    def label(self, width=45):
        """Korte omschrijving voor in een menu."""
        if self.kind == "text":
            t = " ".join(self.data.split()) or "(lege tekst)"
            return t if len(t) <= width else t[:width - 1] + "…"
        if self.kind == "image":
            if self.data[:8] == b"\x89PNG\r\n\x1a\n" and len(self.data) >= 24:
                w, h = struct.unpack(">II", self.data[16:24])
                return f"Afbeelding {w}×{h}"
            return "Afbeelding"
        name = os.path.basename(os.path.normpath(self.data[0])) or self.data[0]
        kind = "Map" if os.path.isdir(self.data[0]) else "Bestand"
        more = f" (+{len(self.data) - 1})" if len(self.data) > 1 else ""
        return f"{kind}: {name}{more}"

    def describe(self):
        if self.kind == "text":
            return f"tekst, {len(self.data)} tekens"
        if self.kind == "image":
            return f"afbeelding, {max(1, len(self.data) // 1024)} KB"
        return f"{len(self.data)} bestand(en)/map(pen)"


def make_png(width, height, color_type, raw):
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + chunk(b"IEND", b""))


def dib_to_png(dib):
    """Zet een Windows CF_DIB (24/32 bit) om naar PNG."""
    size, w, h, _planes, bpp, comp, _img, _x, _y, clr_used, _ = struct.unpack_from("<IiiHHIIiiII", dib)
    if bpp not in (24, 32) or comp not in (0, 3) or w <= 0 or h == 0:
        return None
    offset = size + (12 if comp == 3 and size == 40 else 0) + clr_used * 4
    stride = ((w * bpp + 31) // 32) * 4
    top_down, h = h < 0, abs(h)
    px = dib[offset:offset + stride * h]
    if len(px) < stride * h:
        return None
    rows = [px[y * stride:(y + 1) * stride] for y in range(h)]
    if not top_down:
        rows.reverse()
    raw = bytearray()
    if bpp == 32:
        # Veel programma's laten het alfakanaal op 0 staan: dan is het ondoorzichtig.
        alpha_used = any(r[3:w * 4:4].count(0) != w for r in rows)
        for r in rows:
            r = r[:w * 4]
            o = bytearray(r)
            o[0::4], o[2::4] = r[2::4], r[0::4]
            if not alpha_used:
                o[3::4] = b"\xff" * w
            raw += b"\x00" + o
        return make_png(w, h, 6, raw)
    for r in rows:
        r = r[:w * 3]
        o = bytearray(r)
        o[0::3], o[2::3] = r[2::3], r[0::3]
        raw += b"\x00" + o
    return make_png(w, h, 2, raw)


# --------------------------------------------------------------------------- #
# Klembord: Linux
# --------------------------------------------------------------------------- #

class LinuxClipboard:
    TEXT_TARGETS = ("UTF8_STRING", "text/plain;charset=utf-8", "text/plain", "STRING", "TEXT")
    FILE_TARGETS = ("x-special/gnome-copied-files", "text/uri-list")

    def __init__(self):
        # Onder GNOME/KDE-Wayland werkt xclip via XWayland prima en zonder
        # knipperende vensters; wl-clipboard is de terugval voor pure Wayland.
        if os.environ.get("DISPLAY") and shutil.which("xclip"):
            self.tool = "xclip"
        elif os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
            self.tool = "wl"
        else:
            raise SystemExit("Geen klembord-tool gevonden. Installeer xclip "
                             "(sudo apt install xclip) of wl-clipboard.")
        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
        # Nautilus en verwanten plakken alleen bestanden uit dit formaat
        self.gnome_files = any(d in desktop for d in
                               ("gnome", "unity", "cinnamon", "mate", "budgie", "pantheon", "xfce"))

    def _run_get(self, target):
        if self.tool == "xclip":
            cmd = ["xclip", "-selection", "clipboard", "-o", "-t", target]
        elif target == "TARGETS":
            cmd = ["wl-paste", "--list-types"]
        else:
            cmd = ["wl-paste", "--no-newline", "--type", target]
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=5)
        except subprocess.TimeoutExpired:
            return None
        return r.stdout if r.returncode == 0 else None

    def changed(self):
        return True  # X11 heeft geen goedkope wijzigingsteller; read() + sig() vergelijkt

    def read(self):
        out = self._run_get("TARGETS")
        if not out:
            return None
        targets = out.decode(errors="replace").split()
        for t in self.FILE_TARGETS:
            if t in targets:
                paths = self._parse_uris(self._run_get(t) or b"")
                if paths:
                    return Clip("files", paths)
        for t in self.TEXT_TARGETS:
            if t in targets:
                data = self._run_get(t)
                if data is not None:
                    return Clip("text", data.decode("utf-8", errors="replace"))
        if "image/png" in targets:
            data = self._run_get("image/png")
            if data:
                return Clip("image", data)
        return None

    @staticmethod
    def _parse_uris(data):
        paths = []
        for line in data.decode(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("file://"):
                path = urllib.parse.unquote(urllib.parse.urlparse(line).path)
                if os.path.exists(path):
                    paths.append(path)
        return paths

    def write(self, clip):
        if clip.kind == "text":
            target = "UTF8_STRING" if self.tool == "xclip" else "text/plain;charset=utf-8"
            data = clip.data.encode("utf-8")
        elif clip.kind == "image":
            target, data = "image/png", clip.data
        else:
            uris = ["file://" + urllib.parse.quote(p) for p in clip.data]
            if self.gnome_files:
                target, data = "x-special/gnome-copied-files", ("copy\n" + "\n".join(uris)).encode()
            else:
                target, data = "text/uri-list", ("\r\n".join(uris) + "\r\n").encode()
        if self.tool == "xclip":
            cmd = ["xclip", "-selection", "clipboard", "-i", "-t", target]
        else:
            cmd = ["wl-copy", "--type", target]
        # xclip/wl-copy blijven op de achtergrond draaien als eigenaar van het
        # klembord, dus niet wachten op stdout.
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(data, timeout=10)


# --------------------------------------------------------------------------- #
# Klembord: Windows
# --------------------------------------------------------------------------- #

class WindowsClipboard:
    CF_DIB = 8
    CF_UNICODETEXT = 13
    CF_HDROP = 15
    GMEM_MOVEABLE = 0x0002

    def __init__(self):
        import ctypes
        from ctypes import wintypes as wt
        self.ct, self.wt = ctypes, wt
        self.u32 = ctypes.WinDLL("user32", use_last_error=True)
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.sh32 = ctypes.WinDLL("shell32")
        u, k = self.u32, self.k32
        u.OpenClipboard.argtypes = [wt.HWND]
        u.IsClipboardFormatAvailable.argtypes = [wt.UINT]
        u.GetClipboardData.argtypes = [wt.UINT]
        u.GetClipboardData.restype = wt.HANDLE
        u.SetClipboardData.argtypes = [wt.UINT, wt.HANDLE]
        u.SetClipboardData.restype = wt.HANDLE
        u.RegisterClipboardFormatW.argtypes = [wt.LPCWSTR]
        u.RegisterClipboardFormatW.restype = wt.UINT
        u.GetClipboardSequenceNumber.restype = wt.DWORD
        k.GlobalAlloc.argtypes = [wt.UINT, ctypes.c_size_t]
        k.GlobalAlloc.restype = wt.HGLOBAL
        k.GlobalFree.argtypes = [wt.HGLOBAL]
        k.GlobalLock.argtypes = [wt.HGLOBAL]
        k.GlobalLock.restype = wt.LPVOID
        k.GlobalUnlock.argtypes = [wt.HGLOBAL]
        k.GlobalSize.argtypes = [wt.HGLOBAL]
        k.GlobalSize.restype = ctypes.c_size_t
        self.sh32.DragQueryFileW.argtypes = [wt.HANDLE, wt.UINT, wt.LPWSTR, wt.UINT]
        self.sh32.DragQueryFileW.restype = wt.UINT
        self.cf_png = u.RegisterClipboardFormatW("PNG")
        self.cf_effect = u.RegisterClipboardFormatW("Preferred DropEffect")
        self.seq = None
        self.gdip = None

    def _open(self):
        for _ in range(20):  # een ander programma kan het klembord even vasthouden
            if self.u32.OpenClipboard(None):
                return True
            time.sleep(0.05)
        return False

    def changed(self):
        seq = self.u32.GetClipboardSequenceNumber()
        if seq == self.seq:
            return False
        self.seq = seq
        return True

    def _get_bytes(self, fmt):
        h = self.u32.GetClipboardData(fmt)
        if not h:
            return None
        p = self.k32.GlobalLock(h)
        if not p:
            return None
        try:
            return self.ct.string_at(p, self.k32.GlobalSize(h))
        finally:
            self.k32.GlobalUnlock(h)

    def read(self):
        avail = self.u32.IsClipboardFormatAvailable
        if not self._open():
            self.seq = None  # volgende keer opnieuw proberen
            return None
        try:
            if avail(self.CF_HDROP):
                h = self.u32.GetClipboardData(self.CF_HDROP)
                if h:
                    paths = []
                    for i in range(self.sh32.DragQueryFileW(h, 0xFFFFFFFF, None, 0)):
                        n = self.sh32.DragQueryFileW(h, i, None, 0)
                        buf = self.ct.create_unicode_buffer(n + 1)
                        self.sh32.DragQueryFileW(h, i, buf, n + 1)
                        paths.append(buf.value)
                    if paths:
                        return Clip("files", paths)
            if avail(self.CF_UNICODETEXT):
                data = self._get_bytes(self.CF_UNICODETEXT)
                if data is not None:
                    text = data.decode("utf-16-le", errors="replace").split("\x00", 1)[0]
                    return Clip("text", text)
            if avail(self.cf_png):
                data = self._get_bytes(self.cf_png)
                if data:
                    end = data.rfind(b"IEND")  # GlobalSize kan naar boven afronden
                    return Clip("image", data[:end + 8] if end > 0 else data)
            if avail(self.CF_DIB):
                data = self._get_bytes(self.CF_DIB)
                png = dib_to_png(data) if data else None
                if png:
                    return Clip("image", png)
            return None
        finally:
            self.u32.CloseClipboard()

    def write(self, clip):
        if clip.kind == "text":
            formats = [(self.CF_UNICODETEXT, clip.data.encode("utf-16-le") + b"\x00\x00")]
        elif clip.kind == "image":
            formats = [(self.cf_png, clip.data)]
            try:
                formats.append((self.CF_DIB, self._png_to_dib(clip.data)))
            except Exception as e:
                logging.warning("PNG naar DIB omzetten mislukt (alleen PNG gezet): %s", e)
        else:
            # DROPFILES-struct + dubbel-null-afgesloten lijst met paden
            files = "".join(p + "\x00" for p in clip.data) + "\x00"
            drop = struct.pack("<IiiII", 20, 0, 0, 0, 1) + files.encode("utf-16-le")
            formats = [(self.CF_HDROP, drop), (self.cf_effect, struct.pack("<I", 1))]

        if not self._open():
            raise OSError("Kan klembord niet openen")
        try:
            self.u32.EmptyClipboard()
            for fmt, data in formats:
                h = self.k32.GlobalAlloc(self.GMEM_MOVEABLE, len(data))
                p = self.k32.GlobalLock(h)
                self.ct.memmove(p, data, len(data))
                self.k32.GlobalUnlock(h)
                if not self.u32.SetClipboardData(fmt, h):
                    self.k32.GlobalFree(h)
        finally:
            self.u32.CloseClipboard()

    def _png_to_dib(self, png):
        """Decodeer PNG met GDI+ (ingebouwd in Windows) naar een 32-bit CF_DIB."""
        ct, wt = self.ct, self.wt
        g = ct.WinDLL("gdiplus")
        if self.gdip is None:
            class StartupInput(ct.Structure):
                _fields_ = [("GdiplusVersion", ct.c_uint32), ("DebugEventCallback", ct.c_void_p),
                            ("SuppressBackgroundThread", wt.BOOL), ("SuppressExternalCodecs", wt.BOOL)]
            token = ct.c_size_t()
            g.GdiplusStartup.argtypes = [ct.POINTER(ct.c_size_t), ct.POINTER(StartupInput), ct.c_void_p]
            if g.GdiplusStartup(ct.byref(token), ct.byref(StartupInput(1, None, False, False)), None):
                raise OSError("GdiplusStartup mislukt")
            self.gdip = token

        class Rect(ct.Structure):
            _fields_ = [("X", ct.c_int), ("Y", ct.c_int), ("Width", ct.c_int), ("Height", ct.c_int)]

        class BitmapData(ct.Structure):
            _fields_ = [("Width", ct.c_uint), ("Height", ct.c_uint), ("Stride", ct.c_int),
                        ("PixelFormat", ct.c_int), ("Scan0", ct.c_void_p), ("Reserved", ct.c_size_t)]

        shl = ct.WinDLL("shlwapi")
        shl.SHCreateMemStream.argtypes = [ct.c_char_p, ct.c_uint]
        shl.SHCreateMemStream.restype = ct.c_void_p
        g.GdipCreateBitmapFromStream.argtypes = [ct.c_void_p, ct.POINTER(ct.c_void_p)]
        g.GdipGetImageWidth.argtypes = [ct.c_void_p, ct.POINTER(ct.c_uint)]
        g.GdipGetImageHeight.argtypes = [ct.c_void_p, ct.POINTER(ct.c_uint)]
        g.GdipBitmapLockBits.argtypes = [ct.c_void_p, ct.POINTER(Rect), ct.c_uint, ct.c_int,
                                         ct.POINTER(BitmapData)]
        g.GdipBitmapUnlockBits.argtypes = [ct.c_void_p, ct.POINTER(BitmapData)]
        g.GdipDisposeImage.argtypes = [ct.c_void_p]
        g.GdipCreateBitmapFromScan0.argtypes = [ct.c_int, ct.c_int, ct.c_int, ct.c_int,
                                                ct.c_void_p, ct.POINTER(ct.c_void_p)]
        g.GdipGetImageGraphicsContext.argtypes = [ct.c_void_p, ct.POINTER(ct.c_void_p)]
        g.GdipGraphicsClear.argtypes = [ct.c_void_p, ct.c_uint32]
        g.GdipDrawImageRectI.argtypes = [ct.c_void_p, ct.c_void_p, ct.c_int, ct.c_int,
                                         ct.c_int, ct.c_int]
        g.GdipDeleteGraphics.argtypes = [ct.c_void_p]

        stream = shl.SHCreateMemStream(png, len(png))
        if not stream:
            raise OSError("SHCreateMemStream mislukt")
        src, bmp = ct.c_void_p(), ct.c_void_p()
        try:
            st = g.GdipCreateBitmapFromStream(stream, ct.byref(src))
            if st:
                raise OSError(f"GDI+ kan afbeelding niet lezen (status {st})")
            w, h = ct.c_uint(), ct.c_uint()
            g.GdipGetImageWidth(src, ct.byref(w))
            g.GdipGetImageHeight(src, ct.byref(h))
            w, h = w.value, h.value
            # CF_DIB-lezers (Paint e.d.) negeren het alfakanaal, waardoor
            # transparante delen zwart worden. Daarom op wit tekenen.
            st = g.GdipCreateBitmapFromScan0(w, h, 0, 0x26200A, None, ct.byref(bmp))
            if st:
                raise OSError(f"GDI+ CreateBitmap mislukt (status {st})")
            gr = ct.c_void_p()
            st = g.GdipGetImageGraphicsContext(bmp, ct.byref(gr))
            if st:
                raise OSError(f"GDI+ Graphics mislukt (status {st})")
            try:
                g.GdipGraphicsClear(gr, 0xFFFFFFFF)
                st = g.GdipDrawImageRectI(gr, src, 0, 0, w, h)
            finally:
                g.GdipDeleteGraphics(gr)
            if st:
                raise OSError(f"GDI+ DrawImage mislukt (status {st})")
            bd = BitmapData()
            st = g.GdipBitmapLockBits(bmp, ct.byref(Rect(0, 0, w, h)), 1, 0x26200A, ct.byref(bd))
            if st:
                raise OSError(f"GDI+ LockBits mislukt (status {st})")
            try:
                stride = bd.Stride
                raw = ct.string_at(bd.Scan0, stride * h)
            finally:
                g.GdipBitmapUnlockBits(bmp, ct.byref(bd))
            rows = [raw[y * stride:y * stride + w * 4] for y in range(h)]
            pixels = b"".join(reversed(rows))  # DIB is van onder naar boven
            header = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 32, 0, len(pixels), 2835, 2835, 0, 0)
            return header + pixels
        finally:
            for img in (bmp, src):
                if img:
                    g.GdipDisposeImage(img)
            vtbl = ct.cast(stream, ct.POINTER(ct.POINTER(ct.c_void_p)))[0]
            ct.WINFUNCTYPE(ct.c_ulong, ct.c_void_p)(vtbl[2])(stream)  # IStream::Release


# --------------------------------------------------------------------------- #
# Bestanden
# --------------------------------------------------------------------------- #

WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                *(f"LPT{i}" for i in range(1, 10))}


def safe_part(name):
    if IS_WINDOWS:
        name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name).rstrip(" .") or "_"
        if name.split(".")[0].upper() in WIN_RESERVED:
            name = "_" + name
    return name.replace("\x00", "_")


def safe_join(base, rel):
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        raise ValueError(f"ongeldig pad: {rel!r}")
    return os.path.join(base, *(safe_part(p) for p in parts))


def build_manifest(paths):
    """Geeft (entries, bronpaden, roots, totale grootte) terug."""
    entries, sources, roots, total = [], [], [], 0

    def add_file(rel, path):
        nonlocal total
        size = os.path.getsize(path)
        entries.append({"p": rel, "n": size})
        sources.append(path)
        total += size

    for path in paths:
        path = os.path.normpath(path)
        name = os.path.basename(path) or "bestand"
        roots.append(name)
        if os.path.isdir(path):
            parent = os.path.dirname(path)
            for dirpath, dirnames, filenames in os.walk(path):
                dirnames.sort()
                rel_dir = os.path.relpath(dirpath, parent).replace(os.sep, "/")
                entries.append({"p": rel_dir, "d": 1})
                sources.append(None)
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    if os.path.isfile(full):
                        add_file(f"{rel_dir}/{fn}", full)
        elif os.path.isfile(path):
            add_file(name, path)
    return entries, sources, roots, total


def cleanup_old_files():
    cutoff = time.time() - KEEP_FILES_HOURS * 3600
    base = files_dir()
    for name in os.listdir(base):
        path = os.path.join(base, name)
        try:
            if os.path.getmtime(path) < cutoff:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Netwerk & hoofdlogica
# --------------------------------------------------------------------------- #

def parse_peer(s):
    host, _, port = s.rpartition(":") if ":" in s else (s, "", "")
    return host, int(port) if port else PORT


class ClipSync:
    def __init__(self, cfg, clipboard=None):
        self.crypto = Crypto(cfg["password"])
        self.static_peers = [parse_peer(p) for p in cfg.get("peers", [])]
        self.max_files = int(cfg.get("max_files_mb", DEFAULT_MAX_FILES_MB)) * 1024 * 1024
        self.node_id = uuid.uuid4().hex[:12]
        self.name = socket.gethostname()
        self.clipboard = clipboard or (WindowsClipboard() if IS_WINDOWS else LinuxClipboard())
        self.peers = {}               # (ip, poort) -> (naam, laatst gezien)
        self.peer_lock = threading.Lock()
        self.clip_lock = threading.RLock()
        self.last_event = None        # tekst voor het tray-menu
        self.history = []             # recente Clips, nieuwste eerst
        self.history_version = 0
        self.clipboard.changed()
        current = self._safe_read()
        self.last_sig = current.sig() if current else None
        if current:
            self.remember(current)

    def remember(self, clip):
        sig = clip.sig()
        with self.clip_lock:
            self.history = [c for c in self.history if c.sig() != sig][:HISTORY_SIZE - 1]
            self.history.insert(0, clip)
            self.history_version += 1

    def restore(self, clip):
        """Zet een item uit de geschiedenis terug op het klembord.
        De poll-loop ziet de wijziging en stuurt het ook naar de andere apparaten."""
        try:
            with self.clip_lock:
                self.clipboard.write(clip)
            logging.info("Uit geschiedenis teruggezet: %s", clip.describe())
        except Exception as e:
            logging.warning("Terugzetten mislukt: %s", e)

    def _safe_read(self):
        try:
            return self.clipboard.read()
        except Exception as e:
            logging.debug("Klembord lezen mislukt: %s", e)
            return None

    # -- ontdekken ---------------------------------------------------------- #

    @staticmethod
    def _local_ips():
        """IPv4-adressen van deze pc, één per /24 (geen loopback/link-local)."""
        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        except OSError:
            return []
        ips, nets = [], set()
        for *_, (ip, _port) in infos:
            net = ip.rsplit(".", 1)[0]
            if ip.startswith(("127.", "169.254.")) or net in nets:
                continue
            nets.add(net)
            ips.append(ip)
        return ips

    def beacon_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Windows stuurt 255.255.255.255 maar via één adapter (soms die van
        # WSL/Hyper-V/VPN). Daarom per lokaal adres een eigen socket.
        per_ip = {}
        while True:
            msg = self.crypto.seal({"k": "hello", "s": self.node_id, "n": self.name, "p": PORT})
            senders = [s]
            if IS_WINDOWS:
                ips = self._local_ips()
                for ip in list(per_ip):
                    if ip not in ips:
                        per_ip.pop(ip).close()
                for ip in ips:
                    if ip not in per_ip:
                        try:
                            b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            b.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                            b.bind((ip, 0))
                            per_ip[ip] = b
                        except OSError:
                            continue
                if per_ip:
                    senders = list(per_ip.values())
            for sock in senders:
                try:
                    sock.sendto(msg, ("255.255.255.255", PORT))
                except OSError:
                    pass
            for target in self.static_peers:
                try:
                    s.sendto(msg, target)
                except OSError:
                    pass
            time.sleep(BEACON_INTERVAL)

    def discovery_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("", PORT))
        while True:
            data, (ip, _) = s.recvfrom(4096)
            try:
                msg = self.crypto.open(data)
            except Exception:
                msg = None
            if not msg or msg.get("k") != "hello" or msg.get("s") == self.node_id:
                continue
            key = (ip, int(msg.get("p", PORT)))
            with self.peer_lock:
                if key not in self.peers:
                    logging.info("Apparaat gevonden: %s (%s)", msg.get("n"), ip)
                self.peers[key] = (msg.get("n"), time.time())

    def active_peers(self):
        now = time.time()
        with self.peer_lock:
            for key, (name, seen) in list(self.peers.items()):
                if now - seen > PEER_TIMEOUT:
                    logging.info("Apparaat weg: %s (%s)", name, key[0])
                    del self.peers[key]
            return list(self.peers)

    def peer_names(self):
        self.active_peers()
        with self.peer_lock:
            return sorted({name or ip for (ip, _), (name, _) in self.peers.items()})

    def peer_name(self, ip):
        with self.peer_lock:
            return next((n for (i, _), (n, _) in self.peers.items() if i == ip), ip)

    def _event(self, text):
        self.last_event = f"{time.strftime('%H:%M')}  {text}"

    # -- ontvangen ---------------------------------------------------------- #

    def server_loop(self):
        while True:
            conn, addr = self.srv.accept()
            threading.Thread(target=self.handle_conn, args=(conn, addr), daemon=True).start()

    def handle_conn(self, conn, addr):
        with conn:
            try:
                conn.settimeout(30)
                reader = FrameReader(conn, self.crypto)
                h = reader.header()
                if h.get("s") == self.node_id:
                    return
                kind = h.get("type")
                if kind == "text":
                    clip = Clip("text", reader.read_all(MAX_INLINE).decode("utf-8"))
                elif kind == "image":
                    clip = Clip("image", reader.read_all(MAX_INLINE))
                elif kind == "files":
                    clip = self.receive_files(reader, h)
                else:
                    raise ValueError(f"onbekend type {kind!r}")
                self.apply(clip)
                logging.info("Ontvangen van %s: %s", addr[0], clip.describe())
                self._event(f"Ontvangen van {self.peer_name(addr[0])}: {clip.describe()}")
            except Exception as e:
                logging.warning("Ontvangen van %s mislukt: %s", addr[0], e)

    def receive_files(self, reader, h):
        entries = h["files"]
        if sum(e.get("n", 0) for e in entries) > self.max_files:
            raise ValueError("bestanden groter dan max_files_mb")
        cleanup_old_files()
        dest = os.path.join(files_dir(), time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6])
        os.makedirs(dest)
        try:
            for e in entries:
                path = safe_join(dest, e["p"])
                if e.get("d"):
                    os.makedirs(path, exist_ok=True)
                    continue
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "wb") as f:
                    remaining = int(e["n"])
                    while remaining:
                        chunk = reader.read(min(CHUNK, remaining))
                        f.write(chunk)
                        remaining -= len(chunk)
            reader.finish()
            return Clip("files", [safe_join(dest, r) for r in h["roots"]])
        except BaseException:
            shutil.rmtree(dest, ignore_errors=True)
            raise

    def apply(self, clip):
        with self.clip_lock:
            self.clipboard.write(clip)
            # Teruglezen wat er nu echt op het klembord staat, zodat we het niet
            # direct weer terugsturen.
            back = self._safe_read()
            self.last_sig = back.sig() if back else clip.sig()
            self.remember(back or clip)

    # -- versturen ---------------------------------------------------------- #

    def send(self, addr, clip, manifest):
        try:
            with socket.create_connection(addr, timeout=5) as s:
                s.settimeout(60)
                w = FrameWriter(s, self.crypto)
                base = {"k": "clip", "s": self.node_id, "type": clip.kind}
                if clip.kind == "text":
                    w.header(base)
                    w.write(clip.data.encode("utf-8"))
                elif clip.kind == "image":
                    w.header(base)
                    w.write(clip.data)
                else:
                    entries, sources, roots, _ = manifest
                    w.header({**base, "files": entries, "roots": roots})
                    for e, src in zip(entries, sources):
                        if src is not None:
                            self._stream_file(w, src, e["n"])
                w.close()
            logging.info("Verstuurd naar %s: %s", addr[0], clip.describe())
            self._event(f"Verstuurd naar {self.peer_name(addr[0])}: {clip.describe()}")
        except OSError as e:
            logging.warning("Versturen naar %s mislukt: %s", addr[0], e)

    @staticmethod
    def _stream_file(w, path, size):
        # Precies `size` bytes sturen, ook als het bestand intussen veranderd is.
        remaining = size
        try:
            with open(path, "rb") as f:
                while remaining:
                    chunk = f.read(min(CHUNK, remaining))
                    if not chunk:
                        break
                    w.write(chunk)
                    remaining -= len(chunk)
        except OSError as e:
            logging.warning("Kan %s niet lezen: %s", path, e)
        if remaining:
            w.write(b"\x00" * remaining)

    def broadcast(self, clip):
        manifest = None
        if clip.kind == "files":
            try:
                manifest = build_manifest(clip.data)
            except OSError as e:
                logging.warning("Bestanden lezen mislukt: %s", e)
                return
            if manifest[3] > self.max_files:
                logging.warning("Bestanden te groot (%d MB > max_files_mb), niet verstuurd",
                                manifest[3] // 2 ** 20)
                return
        else:
            size = len(clip.data.encode("utf-8") if clip.kind == "text" else clip.data)
            if size > MAX_INLINE:
                logging.warning("Klembord te groot (%d MB), niet verstuurd", size // 2 ** 20)
                return
        for addr in self.active_peers():
            threading.Thread(target=self.send, args=(addr, clip, manifest), daemon=True).start()

    def poll_loop(self):
        while True:
            time.sleep(POLL_INTERVAL)
            if not self.clipboard.changed():
                continue
            with self.clip_lock:
                clip = self._safe_read()
                if not clip:
                    continue
                sig = clip.sig()
                if sig == self.last_sig:
                    continue
                self.last_sig = sig
                self.remember(clip)
            self.broadcast(clip)

    def start(self):
        """Start alle achtergrondthreads. Faalt als clipsync al draait."""
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not IS_WINDOWS:
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.srv.bind(("", PORT))
        except OSError:
            raise SystemExit(f"Poort {PORT} is bezet: draait clipsync al? Zo niet, kies dan "
                             f"een andere poort met \"port\" in {CONFIG_FILE}.")
        self.srv.listen(5)
        logging.info("clipsync gestart op %s (poort %d)", self.name, PORT)
        for target in (self.discovery_loop, self.server_loop, self.beacon_loop, self.poll_loop):
            threading.Thread(target=target, daemon=True).start()


# --------------------------------------------------------------------------- #
# Tray-icoon (optioneel, via pystray)
# --------------------------------------------------------------------------- #

def tray_icon_image(connected):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (46, 158, 91, 255) if connected else (140, 140, 140, 255)
    d.rounded_rectangle((10, 8, 54, 60), radius=8, fill=color)                # klembord
    d.rounded_rectangle((22, 2, 42, 16), radius=4, fill=(60, 60, 60, 255))    # klem
    for y in (26, 36, 46):                                                    # "tekst"
        d.rectangle((18, y, 46, y + 4), fill=(255, 255, 255, 255))
    return img


def open_log():
    if IS_WINDOWS:
        os.startfile(LOG_FILE)
    else:
        subprocess.Popen(["xdg-open", LOG_FILE],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_tray(app):
    """Toont een tray-icoon. Geeft False terug als pystray niet beschikbaar is."""
    try:
        import pystray
        from PIL import Image  # noqa: F401
    except Exception as e:
        logging.info("Geen tray-icoon (%s). Installeer pystray om er een te krijgen.", e)
        return False

    def status_text(_item):
        names = app.peer_names()
        return f"Verbonden met: {', '.join(names)}" if names else "Zoeken naar apparaten…"

    def history_items():
        items = [pystray.MenuItem(c.label(), (lambda c: lambda _icon, _item: threading.Thread(
                     target=app.restore, args=(c,), daemon=True).start())(c))
                 for c in list(app.history) if c.available()]
        return items or [pystray.MenuItem("Nog leeg", None, enabled=False)]

    def quit_app(icon, _item):
        logging.info("clipsync afgesloten via tray-icoon")
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(f"clipsync op {app.name}", None, enabled=False),
        pystray.MenuItem(status_text, None, enabled=False),
        pystray.MenuItem(lambda _i: app.last_event or "Nog niets gedeeld", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Recent gekopieerd", pystray.Menu(history_items)),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Logbestand openen", lambda *_: open_log()),
        pystray.MenuItem("Afsluiten", quit_app),
    )
    icon = pystray.Icon(APP, tray_icon_image(False), "clipsync", menu)

    def refresh(icon):
        icon.visible = True
        state = None
        while True:
            names, event = tuple(app.peer_names()), app.last_event
            if (names, event, app.history_version) != state:
                if state is None or bool(names) != bool(state[0]):
                    icon.icon = tray_icon_image(bool(names))
                icon.title = "clipsync: " + (", ".join(names) if names else "geen apparaten")
                icon.update_menu()
                state = (names, event, app.history_version)
            time.sleep(2)

    ctrl_handler = None
    if IS_WINDOWS:
        # De berichtenlus van pystray blokkeert de hoofdthread, waardoor
        # Python Ctrl+C in de console nooit afhandelt. Daarom zelf opvangen.
        import ctypes

        @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
        def ctrl_handler(_event):
            logging.info("clipsync afgesloten (Ctrl+C)")
            icon.stop()
            return 1

        ctypes.windll.kernel32.SetConsoleCtrlHandler(ctrl_handler, True)
    try:
        icon.run(setup=lambda ic: threading.Thread(target=refresh, args=(ic,), daemon=True).start())
    finally:
        if ctrl_handler:
            ctypes.windll.kernel32.SetConsoleCtrlHandler(ctrl_handler, False)
    return True


# --------------------------------------------------------------------------- #
# Autostart
# --------------------------------------------------------------------------- #

def autostart_path():
    if IS_WINDOWS:
        startup = os.path.join(os.environ["APPDATA"],
                               r"Microsoft\Windows\Start Menu\Programs\Startup")
        return os.path.join(startup, "clipsync.vbs")
    return os.path.expanduser("~/.config/autostart/clipsync.desktop")


def install():
    script = os.path.abspath(__file__)
    path = autostart_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if IS_WINDOWS:
        pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
        if not os.path.exists(pythonw):
            pythonw = sys.executable
        # .vbs zodat er geen consolevenster verschijnt
        content = (f'CreateObject("WScript.Shell").Run '
                   f'"""{pythonw}"" ""{script}""", 0, False\r\n')
    else:
        content = ("[Desktop Entry]\nType=Application\nName=clipsync\n"
                   f'Exec="{sys.executable}" "{script}"\n'
                   "X-GNOME-Autostart-enabled=true\nNoDisplay=true\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Autostart geïnstalleerd: {path}")
    print("Start nu handmatig of log opnieuw in.")


def uninstall():
    path = autostart_path()
    if os.path.exists(path):
        os.remove(path)
        print(f"Verwijderd: {path}")
    else:
        print("Autostart was niet geïnstalleerd.")


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Synchroniseer je klembord over het lokale netwerk.")
    ap.add_argument("--setup", action="store_true", help="wachtwoord instellen")
    ap.add_argument("--install", action="store_true", help="automatisch starten bij inloggen")
    ap.add_argument("--uninstall", action="store_true", help="autostart verwijderen")
    ap.add_argument("-v", "--verbose", action="store_true", help="meer logging")
    ap.add_argument("--no-tray", action="store_true", help="geen tray-icoon tonen")
    args = ap.parse_args()

    if args.install:
        if not load_config():
            setup()
        return install()
    if args.uninstall:
        return uninstall()

    cfg = load_config()
    if args.setup or not cfg or not cfg.get("password"):
        if not sys.stdin or not sys.stdin.isatty():
            raise SystemExit("Nog geen wachtwoord ingesteld: draai eerst 'clipsync.py --setup'.")
        cfg = setup()
        if args.setup:
            return

    global PORT
    if "CLIPSYNC_PORT" not in os.environ:
        PORT = int(cfg.get("port", DEFAULT_PORT))
    if not 1024 <= PORT <= 65535:
        raise SystemExit(f"Ongeldige poort {PORT}: kies een getal tussen 1024 en 65535.")

    handlers = [logging.handlers.RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=1, encoding="utf-8")]
    if sys.stdout and sys.stdout.isatty():
        handlers.append(logging.StreamHandler())
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", handlers=handlers)
    app = ClipSync(cfg)
    app.start()
    if args.no_tray or not run_tray(app):
        while True:
            time.sleep(3600)


if __name__ == "__main__":
    main()
