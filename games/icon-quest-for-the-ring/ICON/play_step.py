#!/usr/bin/env python3
"""
One-step ICON play helper: FOCUS dosbox → action → settle → SCREENSHOT → print path.

Rules (user):
  - delay/settle after every move
  - when in doubt, screenshot
  - make sure DOSBox is focused before shot / human-visible keys

Usage:
  ./play_step.py shot now
  ./play_step.py move right
  ./play_step.py move down --hold-ms 400 --settle 1.3
  ./play_step.py tap P
  ./play_step.py tap esc
  ./play_step.py seq right right down   # each with settle + shot
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

SOCK = os.environ.get("DOSBOX_CONTROL_SOCK", "/tmp/dosbox-control.sock")
SHOT_DIR = Path(os.environ.get("ICON_SHOT_DIR", "/tmp/icon_shots"))
SETTLE = float(os.environ.get("MOVE_SETTLE", "1.3"))
HOLD_MS = int(os.environ.get("MOVE_HOLD_MS", "400"))


def log(msg: str) -> None:
    print(f"[play_step] {msg}", file=sys.stderr, flush=True)


def find_wid() -> str:
    for args in (
        ["xdotool", "search", "--name", "ICON.EXE"],
        ["xdotool", "search", "--class", "dosbox-staging"],
        ["xdotool", "search", "--class", "dosbox"],
    ):
        r = subprocess.run(args, capture_output=True, text=True)
        ids = [x for x in r.stdout.split() if x.isdigit()]
        if ids:
            return ids[-1]
    # pid-based
    try:
        pid = Path("/tmp/dosbox-control.pid").read_text().strip()
        r = subprocess.run(
            ["xdotool", "search", "--pid", pid],
            capture_output=True,
            text=True,
        )
        ids = [x for x in r.stdout.split() if x.isdigit()]
        if ids:
            # pick largest window (geometry)
            best, best_a = ids[0], -1
            for w in ids:
                g = subprocess.run(
                    ["xdotool", "getwindowgeometry", w],
                    capture_output=True,
                    text=True,
                ).stdout
                # Geometry:  WxH
                area = 0
                for line in g.splitlines():
                    if "Geometry:" in line:
                        # Geometry: 1067x800
                        part = line.split("Geometry:")[-1].strip().split("+")[0]
                        if "x" in part:
                            a, b = part.split("x")
                            area = int(a) * int(b)
                if area > best_a:
                    best, best_a = w, area
            return best
    except Exception:
        pass
    return ""


def focus() -> str:
    wid = find_wid()
    if not wid:
        raise RuntimeError("DOSBox window not found")
    subprocess.run(
        ["xdotool", "windowmap", wid, "windowactivate", "--sync", wid],
        check=False,
        capture_output=True,
    )
    # raise + slight settle so compositor paints
    subprocess.run(["xdotool", "windowraise", wid], check=False, capture_output=True)
    time.sleep(0.2)
    name = subprocess.run(
        ["xdotool", "getwindowname", wid], capture_output=True, text=True
    ).stdout.strip()
    log(f"focus wid={wid} name={name!r}")
    return wid


def screenshot(tag: str) -> Path:
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    wid = focus()
    ts = time.strftime("%H%M%S")
    path = SHOT_DIR / f"{ts}_{tag}.png"
    # Prefer ImageMagick 7 magick; fall back to convert / gnome
    raw = SHOT_DIR / "_grab.xwd"
    r = subprocess.run(
        ["xwd", "-id", wid, "-out", str(raw)],
        capture_output=True,
        text=True,
    )
    ok = False
    if r.returncode == 0 and raw.is_file() and raw.stat().st_size > 1000:
        for conv in (
            ["magick", str(raw), str(path)],
            ["convert", str(raw), str(path)],
        ):
            c = subprocess.run(conv, capture_output=True, text=True)
            if c.returncode == 0 and path.is_file() and path.stat().st_size > 5000:
                ok = True
                break
    try:
        raw.unlink(missing_ok=True)
    except Exception:
        pass

    if not ok:
        # gnome active window after focus
        subprocess.run(
            ["gnome-screenshot", "-w", "-f", str(path)],
            capture_output=True,
        )

    sz = path.stat().st_size if path.is_file() else 0
    log(f"SHOT {path} ({sz} bytes)")
    if sz < 5000:
        log("WARNING: screenshot tiny — window may be unmapped/composited wrong")
    print(path)
    return path


class Sock:
    def __init__(self) -> None:
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.connect(SOCK)
        self._buf = b""
        self._line()  # greeting

    def _line(self) -> str:
        while b"\n" not in self._buf:
            chunk = self.s.recv(4096)
            if not chunk:
                raise ConnectionError("closed")
            self._buf += chunk
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", "replace")

    def cmd(self, line: str, timeout: float = 8.0) -> str:
        self.s.settimeout(timeout)
        self.s.sendall((line + "\n").encode())
        # simple single-line replies for keys
        data = self._buf
        self._buf = b""
        deadline = time.time() + timeout
        while True:
            text = data.decode("utf-8", "replace")
            if text.startswith("OK TEXT") or text.startswith("OK B800"):
                if "\nEND\n" in text or text.endswith("END\n"):
                    return text
            elif text.endswith("\n") and text:
                return text.strip()
            if time.time() > deadline:
                return text.strip() if text else "ERR timeout"
            try:
                data += self.s.recv(8192)
            except socket.timeout:
                return text.strip() if text else "ERR timeout"

    def close(self) -> None:
        try:
            self.cmd("QUIT", timeout=1)
        except Exception:
            pass
        self.s.close()


def move(key: str, hold_ms: int, settle: float) -> Path:
    focus()
    sk = Sock()
    try:
        log(f"MOVE {key} hold={hold_ms}ms settle={settle}s")
        sk.cmd(f"KEYDOWN {key}")
        time.sleep(hold_ms / 1000.0)
        sk.cmd(f"KEYUP {key}")
    finally:
        sk.close()
    time.sleep(settle)
    return screenshot(f"after_{key}")


def tap(key: str, settle: float) -> Path:
    focus()
    sk = Sock()
    try:
        log(f"TAP {key} settle={settle}s")
        sk.cmd(f"KEY {key}")
    finally:
        sk.close()
    time.sleep(settle)
    return screenshot(f"after_{key}")


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("shot")
    p.add_argument("tag", nargs="?", default="now")

    p = sub.add_parser("move")
    p.add_argument("key")
    p.add_argument("--hold-ms", type=int, default=HOLD_MS)
    p.add_argument("--settle", type=float, default=SETTLE)

    p = sub.add_parser("tap")
    p.add_argument("key")
    p.add_argument("--settle", type=float, default=SETTLE)

    p = sub.add_parser("seq")
    p.add_argument("keys", nargs="+")
    p.add_argument("--hold-ms", type=int, default=HOLD_MS)
    p.add_argument("--settle", type=float, default=SETTLE)

    p = sub.add_parser("focus")

    args = ap.parse_args()
    if args.cmd == "shot":
        screenshot(args.tag)
    elif args.cmd == "focus":
        focus()
    elif args.cmd == "move":
        move(args.key, args.hold_ms, args.settle)
    elif args.cmd == "tap":
        tap(args.key, args.settle)
    elif args.cmd == "seq":
        for k in args.keys:
            move(k, args.hold_ms, args.settle)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
