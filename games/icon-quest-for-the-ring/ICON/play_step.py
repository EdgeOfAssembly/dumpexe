#!/usr/bin/env python3
"""
One-step ICON play helper via control socket only — no xdotool.

  ./play_step.py shot now
  ./play_step.py move right
  ./play_step.py move down --hold-ms 1100 --settle 1.4
  ./play_step.py tap P
  ./play_step.py seq right right down
  ./play_step.py capture grouped
  ./play_step.py hostpause
  ./play_step.py hostunpause
  ./play_step.py overlay on
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time
from pathlib import Path

SOCK = os.environ.get("DOSBOX_CONTROL_SOCK", "/tmp/dosbox-control.sock")
SHOT_DIR = Path(os.environ.get("ICON_SHOT_DIR", "/tmp/icon_shots"))
SETTLE = float(os.environ.get("MOVE_SETTLE", "1.3"))
HOLD_MS = int(os.environ.get("MOVE_HOLD_MS", "1100"))
CAPTURE_DIR = Path(
    os.environ.get(
        "ICON_CAPTURE_DIR",
        str(Path(__file__).resolve().parent / "capture"),
    )
)


def log(msg: str) -> None:
    print(f"[play_step] {msg}", file=sys.stderr, flush=True)


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

    def cmd(self, line: str, timeout: float = 15.0) -> str:
        self.s.settimeout(timeout)
        self.s.sendall((line + "\n").encode())
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


def sock_cmd(line: str, timeout: float = 15.0) -> str:
    s = Sock()
    try:
        r = s.cmd(line, timeout=timeout)
        log(f"{line!r} -> {r[:120]}")
        return r
    finally:
        s.close()


def newest_capture_png(after_ts: float) -> Path | None:
    """Return newest PNG under capture dir newer than after_ts."""
    if not CAPTURE_DIR.is_dir():
        return None
    best: Path | None = None
    best_m = after_ts
    for p in CAPTURE_DIR.rglob("*.png"):
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if m > best_m:
            best_m = m
            best = p
    return best


def capture(mode: str = "grouped", wait_s: float = 0.8) -> Path | None:
    """Staging PNG via socket CAPTURE (includes host overlay if enabled)."""
    SHOT_DIR.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    sock_cmd(f"CAPTURE {mode}")
    time.sleep(wait_s)
    src = newest_capture_png(t0 - 0.05)
    if not src:
        log("WARNING: no new PNG in capture/ yet")
        return None
    ts = time.strftime("%H%M%S")
    dest = SHOT_DIR / f"{ts}_{mode}_{src.name}"
    try:
        dest.write_bytes(src.read_bytes())
    except OSError as e:
        log(f"copy fail: {e}")
        return src
    log(f"SHOT {dest} (from {src})")
    print(dest)
    return dest


def move(key: str, hold_ms: int, settle: float) -> None:
    s = Sock()
    try:
        log(f"MOVE {key} hold={hold_ms}ms settle={settle}s")
        s.cmd(f"KEYDOWN {key}")
        time.sleep(hold_ms / 1000.0)
        s.cmd(f"KEYUP {key}")
    finally:
        s.close()
    time.sleep(settle)
    capture("rendered")


def tap(key: str, settle: float) -> None:
    s = Sock()
    try:
        log(f"TAP {key} settle={settle}s")
        s.cmd(f"KEY {key}")
    finally:
        s.close()
    time.sleep(settle)
    capture("rendered")


def main() -> int:
    ap = argparse.ArgumentParser(description="ICON control-socket helper (no xdotool)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("shot", help="CAPTURE rendered PNG")
    p.add_argument("tag", nargs="?", default="now")
    p.add_argument("--mode", default="rendered", choices=["grouped", "rendered", "raw"])

    p = sub.add_parser("capture")
    p.add_argument("mode", nargs="?", default="grouped", choices=["grouped", "rendered", "raw"])

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

    p = sub.add_parser("cmd", help="raw socket command")
    p.add_argument("line", nargs=argparse.REMAINDER)

    sub.add_parser("status")
    sub.add_parser("hostpause")
    sub.add_parser("hostunpause")

    p = sub.add_parser("overlay")
    p.add_argument("arg", nargs="?", default="status")

    args = ap.parse_args()

    if args.cmd == "shot":
        capture(args.mode)
    elif args.cmd == "capture":
        capture(args.mode)
    elif args.cmd == "move":
        move(args.key, args.hold_ms, args.settle)
    elif args.cmd == "tap":
        tap(args.key, args.settle)
    elif args.cmd == "seq":
        for k in args.keys:
            move(k, args.hold_ms, args.settle)
    elif args.cmd == "cmd":
        line = " ".join(args.line).strip()
        if not line:
            return 2
        print(sock_cmd(line))
    elif args.cmd == "status":
        print(sock_cmd("STATUS"))
    elif args.cmd == "hostpause":
        print(sock_cmd("HOSTPAUSE"))
    elif args.cmd == "hostunpause":
        print(sock_cmd("HOSTUNPAUSE"))
    elif args.cmd == "overlay":
        print(sock_cmd(f"OVERLAY {args.arg}"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
