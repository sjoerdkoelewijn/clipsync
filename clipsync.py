#!/usr/bin/env python3
"""
clipsync - share your clipboard between computers on your local network.

Supports text, images and files/folders.

- Python standard library only, works on Windows and Linux.
- Optional tray icon via pystray (without pystray it simply runs without an icon).
- Devices find each other automatically via UDP broadcast.
- Everything sent over the network is encrypted and authenticated with a
  shared password (scrypt -> SHAKE256 stream cipher + HMAC-SHA256).

Usage:
    python clipsync.py              # run (asks for a password the first time)
    python clipsync.py --setup      # set (or change) the password
    python clipsync.py --install    # start automatically at login
    python clipsync.py --uninstall  # remove autostart again
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

DEFAULT_PORT = 45873           # default port; change it with "port" in config.json
PORT = int(os.environ.get("CLIPSYNC_PORT", DEFAULT_PORT))  # UDP (discovery) and TCP (clipboard)
BEACON_INTERVAL = 3            # seconds between "I am here" messages
PEER_TIMEOUT = 15              # forget a peer after this long without hearing from it
POLL_INTERVAL = 0.5            # how often the local clipboard is checked
MAX_AGE = 120                  # messages older than this (seconds) are rejected
MAX_INLINE = 50 * 1024 * 1024  # max size of text/image
DEFAULT_MAX_FILES_MB = 500     # max total size of copied files
KEEP_FILES_HOURS = 24          # received files are cleaned up after this
HISTORY_SIZE = 5               # number of recent clipboard items in the tray menu
CHUNK = 1024 * 1024            # size of encrypted blocks

IS_WINDOWS = sys.platform == "win32"
APP = "clipsync"


# --------------------------------------------------------------------------- #
# Paths & config
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
    """Where received files are stored (cleaned up automatically)."""
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
    print("Choose a password. Use exactly the same password on ALL devices.")
    while True:
        pw = getpass.getpass("Password: ")
        if len(pw) < 8:
            print("Please use at least 8 characters.")
            continue
        if getpass.getpass("Repeat: ") != pw:
            print("Passwords do not match, try again.")
            continue
        break
    cfg = load_config() or {}
    cfg["password"] = pw
    cfg.setdefault("peers", [])  # optional: fixed IP addresses if broadcast doesn't work
    cfg.setdefault("max_files_mb", DEFAULT_MAX_FILES_MB)
    cfg.setdefault("port", DEFAULT_PORT)  # must be the same on all devices
    save_config(cfg)
    print(f"Saved to {CONFIG_FILE}")
    return cfg


# --------------------------------------------------------------------------- #
# Crypto (stdlib only)
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

    # Single messages (UDP)
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
            raise ConnectionError("connection closed")
        buf += chunk
    return bytes(buf)


class FrameWriter:
    """Encrypted stream: a header block followed by data blocks of at most CHUNK."""

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
            raise ValueError("block too large")
        ct = recv_exact(self.sock, length)
        tag = recv_exact(self.sock, 32)
        if not hmac.compare_digest(tag, self.crypto.tag(self.nonce, self.idx, last, ct)):
            raise ValueError("invalid signature (different password?)")
        pt = self.crypto.crypt(self.nonce, self.idx, ct)
        self.idx += 1
        return pt, last

    def header(self):
        pt, last = self._next()
        if last:
            raise ValueError("empty message")
        h = json.loads(pt)
        if abs(time.time() - h["t"]) > MAX_AGE:
            raise ValueError("message too old (are the clocks in sync?)")
        return h

    def _fill(self):
        pt, last = self._next()
        self.buf += pt
        self.done = bool(last)

    def read(self, n):
        while len(self.buf) < n and not self.done:
            self._fill()
        if len(self.buf) < n:
            raise ValueError("message truncated")
        out = bytes(self.buf[:n])
        del self.buf[:n]
        return out

    def read_all(self, limit):
        while not self.done:
            self._fill()
            if len(self.buf) > limit:
                raise ValueError("message too large")
        out, self.buf = bytes(self.buf), bytearray()
        return out

    def finish(self):
        if self.read_all(0):
            raise ValueError("unexpected extra data")


# --------------------------------------------------------------------------- #
# Clipboard content
# --------------------------------------------------------------------------- #

class Clip:
    """kind: 'text' (str), 'image' (PNG bytes) or 'files' (list of paths)."""

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
        """Files may have been deleted in the meantime (e.g. cleaned-up cache)."""
        return self.kind != "files" or all(os.path.exists(p) for p in self.data)

    def label(self, width=45):
        """Short description for a menu."""
        if self.kind == "text":
            t = " ".join(self.data.split()) or "(empty text)"
            return t if len(t) <= width else t[:width - 1] + "…"
        if self.kind == "image":
            if self.data[:8] == b"\x89PNG\r\n\x1a\n" and len(self.data) >= 24:
                w, h = struct.unpack(">II", self.data[16:24])
                return f"Image {w}×{h}"
            return "Image"
        name = os.path.basename(os.path.normpath(self.data[0])) or self.data[0]
        kind = "Folder" if os.path.isdir(self.data[0]) else "File"
        more = f" (+{len(self.data) - 1})" if len(self.data) > 1 else ""
        return f"{kind}: {name}{more}"

    def describe(self):
        if self.kind == "text":
            return f"text, {len(self.data)} characters"
        if self.kind == "image":
            return f"image, {max(1, len(self.data) // 1024)} KB"
        return f"{len(self.data)} file(s)/folder(s)"


def make_png(width, height, color_type, raw):
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, color_type, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(bytes(raw), 6))
            + chunk(b"IEND", b""))


def dib_to_png(dib):
    """Convert a Windows CF_DIB (24/32 bit) to PNG."""
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
        # Many programs leave the alpha channel at 0: treat that as opaque.
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
# Clipboard: Linux
# --------------------------------------------------------------------------- #

class LinuxClipboard:
    TEXT_TARGETS = ("UTF8_STRING", "text/plain;charset=utf-8", "text/plain", "STRING", "TEXT")
    FILE_TARGETS = ("x-special/gnome-copied-files", "text/uri-list")

    def __init__(self):
        # On GNOME/KDE Wayland, xclip works fine via XWayland without
        # flickering windows; wl-clipboard is the fallback for pure Wayland.
        if os.environ.get("DISPLAY") and shutil.which("xclip"):
            self.tool = "xclip"
        elif os.environ.get("WAYLAND_DISPLAY") and shutil.which("wl-paste"):
            self.tool = "wl"
        else:
            raise SystemExit("No clipboard tool found. Install xclip "
                             "(sudo apt install xclip) or wl-clipboard.")
        desktop = os.environ.get("XDG_CURRENT_DESKTOP", "").lower()
        # Nautilus and friends only paste files from this format
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
        return True  # X11 has no cheap change counter; read() + sig() compares

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
        # xclip/wl-copy keep running in the background as clipboard owner,
        # so don't wait for stdout.
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        p.communicate(data, timeout=10)


# --------------------------------------------------------------------------- #
# Clipboard: Windows
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
        for _ in range(20):  # another program may briefly hold the clipboard
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
            self.seq = None  # try again next time
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
                    end = data.rfind(b"IEND")  # GlobalSize may round up
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
                logging.warning("Converting PNG to DIB failed (only PNG set): %s", e)
        else:
            # DROPFILES struct + double-null-terminated list of paths
            files = "".join(p + "\x00" for p in clip.data) + "\x00"
            drop = struct.pack("<IiiII", 20, 0, 0, 0, 1) + files.encode("utf-16-le")
            formats = [(self.CF_HDROP, drop), (self.cf_effect, struct.pack("<I", 1))]

        if not self._open():
            raise OSError("Cannot open clipboard")
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
        """Decode PNG with GDI+ (built into Windows) into a 32-bit CF_DIB."""
        ct, wt = self.ct, self.wt
        g = ct.WinDLL("gdiplus")
        if self.gdip is None:
            class StartupInput(ct.Structure):
                _fields_ = [("GdiplusVersion", ct.c_uint32), ("DebugEventCallback", ct.c_void_p),
                            ("SuppressBackgroundThread", wt.BOOL), ("SuppressExternalCodecs", wt.BOOL)]
            token = ct.c_size_t()
            g.GdiplusStartup.argtypes = [ct.POINTER(ct.c_size_t), ct.POINTER(StartupInput), ct.c_void_p]
            if g.GdiplusStartup(ct.byref(token), ct.byref(StartupInput(1, None, False, False)), None):
                raise OSError("GdiplusStartup failed")
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
            raise OSError("SHCreateMemStream failed")
        src, bmp = ct.c_void_p(), ct.c_void_p()
        try:
            st = g.GdipCreateBitmapFromStream(stream, ct.byref(src))
            if st:
                raise OSError(f"GDI+ cannot read image (status {st})")
            w, h = ct.c_uint(), ct.c_uint()
            g.GdipGetImageWidth(src, ct.byref(w))
            g.GdipGetImageHeight(src, ct.byref(h))
            w, h = w.value, h.value
            # CF_DIB readers (Paint etc.) ignore the alpha channel, which turns
            # transparent areas black. So draw onto a white background.
            st = g.GdipCreateBitmapFromScan0(w, h, 0, 0x26200A, None, ct.byref(bmp))
            if st:
                raise OSError(f"GDI+ CreateBitmap failed (status {st})")
            gr = ct.c_void_p()
            st = g.GdipGetImageGraphicsContext(bmp, ct.byref(gr))
            if st:
                raise OSError(f"GDI+ Graphics failed (status {st})")
            try:
                g.GdipGraphicsClear(gr, 0xFFFFFFFF)
                st = g.GdipDrawImageRectI(gr, src, 0, 0, w, h)
            finally:
                g.GdipDeleteGraphics(gr)
            if st:
                raise OSError(f"GDI+ DrawImage failed (status {st})")
            bd = BitmapData()
            st = g.GdipBitmapLockBits(bmp, ct.byref(Rect(0, 0, w, h)), 1, 0x26200A, ct.byref(bd))
            if st:
                raise OSError(f"GDI+ LockBits failed (status {st})")
            try:
                stride = bd.Stride
                raw = ct.string_at(bd.Scan0, stride * h)
            finally:
                g.GdipBitmapUnlockBits(bmp, ct.byref(bd))
            rows = [raw[y * stride:y * stride + w * 4] for y in range(h)]
            pixels = b"".join(reversed(rows))  # DIB is stored bottom-up
            header = struct.pack("<IiiHHIIiiII", 40, w, h, 1, 32, 0, len(pixels), 2835, 2835, 0, 0)
            return header + pixels
        finally:
            for img in (bmp, src):
                if img:
                    g.GdipDisposeImage(img)
            vtbl = ct.cast(stream, ct.POINTER(ct.POINTER(ct.c_void_p)))[0]
            ct.WINFUNCTYPE(ct.c_ulong, ct.c_void_p)(vtbl[2])(stream)  # IStream::Release


# --------------------------------------------------------------------------- #
# Files
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
        raise ValueError(f"invalid path: {rel!r}")
    return os.path.join(base, *(safe_part(p) for p in parts))


def build_manifest(paths):
    """Returns (entries, source paths, roots, total size)."""
    entries, sources, roots, total = [], [], [], 0

    def add_file(rel, path):
        nonlocal total
        size = os.path.getsize(path)
        entries.append({"p": rel, "n": size})
        sources.append(path)
        total += size

    for path in paths:
        path = os.path.normpath(path)
        name = os.path.basename(path) or "file"
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
# Network & main logic
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
        self.peers = {}               # (ip, port) -> (name, last seen)
        self.peer_lock = threading.Lock()
        self.clip_lock = threading.RLock()
        self.last_event = None        # text for the tray menu
        self.history = []             # recent Clips, newest first
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
        """Put an item from the history back on the clipboard.
        The poll loop notices the change and also sends it to the other devices."""
        try:
            with self.clip_lock:
                self.clipboard.write(clip)
            logging.info("Restored from history: %s", clip.describe())
        except Exception as e:
            logging.warning("Restore failed: %s", e)

    def _safe_read(self):
        try:
            return self.clipboard.read()
        except Exception as e:
            logging.debug("Reading clipboard failed: %s", e)
            return None

    # -- discovery ---------------------------------------------------------- #

    @staticmethod
    def _local_ips():
        """IPv4 addresses of this PC, one per /24 (no loopback/link-local)."""
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
        # Windows sends 255.255.255.255 through only one adapter (sometimes the
        # WSL/Hyper-V/VPN one). So use a separate socket per local address.
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
                    logging.info("Device found: %s (%s)", msg.get("n"), ip)
                self.peers[key] = (msg.get("n"), time.time())

    def active_peers(self):
        now = time.time()
        with self.peer_lock:
            for key, (name, seen) in list(self.peers.items()):
                if now - seen > PEER_TIMEOUT:
                    logging.info("Device gone: %s (%s)", name, key[0])
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

    # -- receiving ---------------------------------------------------------- #

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
                    raise ValueError(f"unknown type {kind!r}")
                self.apply(clip)
                logging.info("Received from %s: %s", addr[0], clip.describe())
                self._event(f"Received from {self.peer_name(addr[0])}: {clip.describe()}")
            except Exception as e:
                logging.warning("Receiving from %s failed: %s", addr[0], e)

    def receive_files(self, reader, h):
        entries = h["files"]
        if sum(e.get("n", 0) for e in entries) > self.max_files:
            raise ValueError("files larger than max_files_mb")
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
            # Read back what is actually on the clipboard now, so we don't
            # immediately send it back.
            back = self._safe_read()
            self.last_sig = back.sig() if back else clip.sig()
            self.remember(back or clip)

    # -- sending ---------------------------------------------------------- #

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
            logging.info("Sent to %s: %s", addr[0], clip.describe())
            self._event(f"Sent to {self.peer_name(addr[0])}: {clip.describe()}")
        except OSError as e:
            logging.warning("Sending to %s failed: %s", addr[0], e)

    @staticmethod
    def _stream_file(w, path, size):
        # Send exactly `size` bytes, even if the file changed in the meantime.
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
            logging.warning("Cannot read %s: %s", path, e)
        if remaining:
            w.write(b"\x00" * remaining)

    def broadcast(self, clip):
        manifest = None
        if clip.kind == "files":
            try:
                manifest = build_manifest(clip.data)
            except OSError as e:
                logging.warning("Reading files failed: %s", e)
                return
            if manifest[3] > self.max_files:
                logging.warning("Files too large (%d MB > max_files_mb), not sent",
                                manifest[3] // 2 ** 20)
                return
        else:
            size = len(clip.data.encode("utf-8") if clip.kind == "text" else clip.data)
            if size > MAX_INLINE:
                logging.warning("Clipboard too large (%d MB), not sent", size // 2 ** 20)
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
        """Start all background threads. Fails if clipsync is already running."""
        self.srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if not IS_WINDOWS:
            self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.srv.bind(("", PORT))
        except OSError:
            raise SystemExit(f"Port {PORT} is in use: is clipsync already running? If not, choose "
                             f"another port with \"port\" in {CONFIG_FILE}.")
        self.srv.listen(5)
        logging.info("clipsync started on %s (port %d)", self.name, PORT)
        for target in (self.discovery_loop, self.server_loop, self.beacon_loop, self.poll_loop):
            threading.Thread(target=target, daemon=True).start()


# --------------------------------------------------------------------------- #
# Tray icon (optional, via pystray)
# --------------------------------------------------------------------------- #

def tray_icon_image(connected):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    color = (46, 158, 91, 255) if connected else (140, 140, 140, 255)
    d.rounded_rectangle((10, 8, 54, 60), radius=8, fill=color)                # clipboard
    d.rounded_rectangle((22, 2, 42, 16), radius=4, fill=(60, 60, 60, 255))    # clip
    for y in (26, 36, 46):                                                    # "text"
        d.rectangle((18, y, 46, y + 4), fill=(255, 255, 255, 255))
    return img


def open_log():
    if IS_WINDOWS:
        os.startfile(LOG_FILE)
    else:
        subprocess.Popen(["xdg-open", LOG_FILE],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_tray(app):
    """Shows a tray icon. Returns False if pystray is not available."""
    try:
        import pystray
        from PIL import Image  # noqa: F401
    except Exception as e:
        logging.info("No tray icon (%s). Install pystray to get one.", e)
        return False

    def status_text(_item):
        names = app.peer_names()
        return f"Connected to: {', '.join(names)}" if names else "Looking for devices…"

    def history_items():
        items = [pystray.MenuItem(c.label(), (lambda c: lambda _icon, _item: threading.Thread(
                     target=app.restore, args=(c,), daemon=True).start())(c))
                 for c in list(app.history) if c.available()]
        return items or [pystray.MenuItem("Empty", None, enabled=False)]

    def quit_app(icon, _item):
        logging.info("clipsync quit via tray icon")
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(f"clipsync on {app.name}", None, enabled=False),
        pystray.MenuItem(status_text, None, enabled=False),
        pystray.MenuItem(lambda _i: app.last_event or "Nothing shared yet", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Recently copied", pystray.Menu(history_items)),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Open log file", lambda *_: open_log()),
        pystray.MenuItem("Quit", quit_app),
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
                icon.title = "clipsync: " + (", ".join(names) if names else "no devices")
                icon.update_menu()
                state = (names, event, app.history_version)
            time.sleep(2)

    ctrl_handler = None
    if IS_WINDOWS:
        # pystray's message loop blocks the main thread, so Python never
        # handles Ctrl+C in the console. Catch it ourselves.
        import ctypes

        @ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_uint)
        def ctrl_handler(_event):
            logging.info("clipsync quit (Ctrl+C)")
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
        # .vbs so no console window appears
        content = (f'CreateObject("WScript.Shell").Run '
                   f'"""{pythonw}"" ""{script}""", 0, False\r\n')
    else:
        content = ("[Desktop Entry]\nType=Application\nName=clipsync\n"
                   f'Exec="{sys.executable}" "{script}"\n'
                   "X-GNOME-Autostart-enabled=true\nNoDisplay=true\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Autostart installed: {path}")
    print("Start it manually now, or log out and back in.")


def uninstall():
    path = autostart_path()
    if os.path.exists(path):
        os.remove(path)
        print(f"Removed: {path}")
    else:
        print("Autostart was not installed.")


# --------------------------------------------------------------------------- #

def main():
    ap = argparse.ArgumentParser(description="Sync your clipboard over the local network.")
    ap.add_argument("--setup", action="store_true", help="set the password")
    ap.add_argument("--install", action="store_true", help="start automatically at login")
    ap.add_argument("--uninstall", action="store_true", help="remove autostart")
    ap.add_argument("-v", "--verbose", action="store_true", help="more logging")
    ap.add_argument("--no-tray", action="store_true", help="don't show a tray icon")
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
            raise SystemExit("No password set yet: run 'clipsync.py --setup' first.")
        cfg = setup()
        if args.setup:
            return

    global PORT
    if "CLIPSYNC_PORT" not in os.environ:
        PORT = int(cfg.get("port", DEFAULT_PORT))
    if not 1024 <= PORT <= 65535:
        raise SystemExit(f"Invalid port {PORT}: choose a number between 1024 and 65535.")

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
