#!/usr/bin/env python3
"""
Live ICON agent over DOSBox Staging [controlsocket] UNIX socket.

No xdotool / no window focus. Keys use US/emulator layout (same as keypress -e).

Policy (Level A, matches STARTUP-PROMPTS.md + auto_icon.sh):
  1. N  — not IBM PC Jr (default was Y)
  2. Esc — skip title
  3. Esc — skip particle ani
  4. N  — no restart saved
  5. N  — basic game (or Y if --advanced)
  6. Space × N — story / "SPACE BAR to continue"
  7. N  — no joystick (default was Y)
  8. Down ×6 + P — pick up sword south of spawn
  9. Optional wander + Space attack; extra Space if yellow hurt attr (8Eh)

Usage:
  ./live_agent.py                  # start DOSBox, to-play + sword, leave running
  ./live_agent.py --attach         # existing /tmp/dosbox-control.sock
  ./live_agent.py --to-play-only
  ./live_agent.py --sword-only --attach
  ./live_agent.py --wander 20
  ./live_agent.py --quit

Env (same idea as auto_icon.sh):
  STORY_SPACES, SWORD_SOUTH_STEPS, YN_GAP, SPACE_GAP, ESC_GAP, MOVE_HOLD_MS, CYCLES
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

ICON_DIR = Path(__file__).resolve().parent
DEFAULT_SOCK = os.environ.get("DOSBOX_CONTROL_SOCK", "/tmp/dosbox-control.sock")
CONF = ICON_DIR / "dosbox-staging.conf"
AUTO_CONF = ICON_DIR / "dosbox-auto.conf"


def log(msg: str) -> None:
    print(f"[live_agent] {msg}", file=sys.stderr, flush=True)


class ControlClient:
    def __init__(self, path: str = DEFAULT_SOCK) -> None:
        self.path = path
        self.sock: Optional[socket.socket] = None
        self._buf = b""

    def connect(self, timeout: float = 45.0) -> None:
        deadline = time.time() + timeout
        last_err: Optional[BaseException] = None
        while time.time() < deadline:
            if not os.path.exists(self.path):
                time.sleep(0.15)
                continue
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                s.settimeout(5.0)
                s.connect(self.path)
                self.sock = s
                self._buf = b""
                greet = self._recv_line()
                log(f"connected: {greet.strip()}")
                return
            except OSError as e:
                last_err = e
                s.close()
                time.sleep(0.2)
        raise RuntimeError(f"connect({self.path}) failed: {last_err}")

    def close(self) -> None:
        if not self.sock:
            return
        try:
            self.cmd("QUIT", timeout=1.0)
        except Exception:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = None

    def _recv_some(self) -> bytes:
        assert self.sock
        chunk = self.sock.recv(8192)
        if not chunk:
            raise ConnectionError("socket closed")
        return chunk

    def _recv_line(self) -> str:
        while b"\n" not in self._buf:
            self._buf += self._recv_some()
        line, _, self._buf = self._buf.partition(b"\n")
        return line.decode("utf-8", errors="replace") + "\n"

    def _recv_reply(self, timeout: float = 10.0) -> str:
        assert self.sock
        self.sock.settimeout(timeout)
        # Use accumulated buffer first
        data = self._buf
        self._buf = b""
        deadline = time.time() + timeout
        while True:
            text = data.decode("utf-8", errors="replace")
            if text.startswith("OK TEXT") or text.startswith("OK B800"):
                if "\nEND\n" in text or text.endswith("END\n"):
                    return text
            elif text.endswith("\n") and text:
                # single-line OK/ERR (not multi-line body)
                if not (text.startswith("OK TEXT") or text.startswith("OK B800")):
                    return text
            remaining = deadline - time.time()
            if remaining <= 0:
                if text:
                    return text
                raise TimeoutError("reply timeout")
            self.sock.settimeout(max(0.1, remaining))
            try:
                data += self._recv_some()
            except socket.timeout as e:
                if text:
                    return text
                raise TimeoutError("reply timeout") from e

    def cmd(self, line: str, timeout: float = 10.0) -> str:
        assert self.sock
        self.sock.settimeout(timeout)
        self.sock.sendall((line.rstrip("\n") + "\n").encode("utf-8"))
        reply = self._recv_reply(timeout=timeout)
        if not reply.startswith("OK"):
            log(f"CMD fail: {line!r} -> {reply[:160]!r}")
        return reply

    def key(self, name: str) -> str:
        return self.cmd(f"KEY {name}")

    def keydown(self, name: str) -> str:
        return self.cmd(f"KEYDOWN {name}")

    def keyup(self, name: str) -> str:
        return self.cmd(f"KEYUP {name}")

    def text(self) -> str:
        return self.cmd("TEXT", timeout=5.0)

    def b800(self) -> str:
        return self.cmd("B800", timeout=5.0)

    def status(self) -> str:
        return self.cmd("STATUS")

    def dumpscreen(self) -> str:
        return self.cmd("DUMPSCREEN", timeout=5.0)

    def dumpmem(self) -> str:
        return self.cmd("DUMPMEM", timeout=5.0)


def text_body(reply: str) -> str:
    lines = reply.splitlines()
    body = []
    for i, ln in enumerate(lines):
        if i == 0 and ln.startswith("OK TEXT"):
            continue
        if ln.strip() == "END":
            break
        body.append(ln)
    return "\n".join(body)


def screen_has(reply: str, *needles: str) -> bool:
    body = text_body(reply).lower()
    return any(n.lower() in body for n in needles)


def count_attr(b800_reply: str, attr: int) -> int:
    """Count cells whose attribute byte equals attr (char,attr pairs)."""
    hexpart = ""
    for ln in b800_reply.splitlines():
        if ln.startswith("OK ") or ln.strip() == "END":
            continue
        hexpart += ln.strip()
    if len(hexpart) < 4:
        return 0
    try:
        data = bytes.fromhex(hexpart)
    except ValueError:
        return 0
    return sum(1 for i in range(1, len(data), 2) if data[i] == attr)


def start_dosbox(cycles: str) -> subprocess.Popen:
    log(f"starting dosbox in {ICON_DIR} cycles={cycles}")
    cmd = [
        "dosbox",
        "--conf",
        str(CONF),
        "--conf",
        str(AUTO_CONF),
        str(ICON_DIR),
        "-c",
        f"cycles fixed {cycles}",
        "-c",
        "ICON.EXE",
    ]
    log_f = open("/tmp/live_agent_dosbox.log", "w")
    proc = subprocess.Popen(
        cmd,
        cwd=str(ICON_DIR),
        stdout=log_f,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    Path("/tmp/live_agent_dosbox.pid").write_text(str(proc.pid) + "\n")
    log(f"dosbox pid={proc.pid} log=/tmp/live_agent_dosbox.log")
    return proc


class LiveAgent:
    def __init__(self, client: ControlClient, args: argparse.Namespace) -> None:
        self.c = client
        self.args = args
        self.yn_gap = float(os.environ.get("YN_GAP", args.yn_gap))
        self.space_gap = float(os.environ.get("SPACE_GAP", args.space_gap))
        self.esc_gap = float(os.environ.get("ESC_GAP", args.esc_gap))
        self.move_hold_ms = int(os.environ.get("MOVE_HOLD_MS", args.move_hold_ms))
        self.story_spaces = int(os.environ.get("STORY_SPACES", args.story_spaces))
        self.sword_south = int(os.environ.get("SWORD_SOUTH_STEPS", args.sword_south))

    def sleep(self, s: float) -> None:
        time.sleep(s)

    def yn(self, key: str, label: str) -> None:
        log(f"YN: {label} -> {key}")
        self.c.key(key)
        self.sleep(self.yn_gap)

    def spaces(self, n: int, label: str = "story") -> None:
        log(f"Space x{n} ({label})")
        for i in range(1, n + 1):
            self.c.key("space")
            self.sleep(self.space_gap)
            if i % 8 == 0:
                log(f"  … space {i}/{n}")

    def hold_key(self, name: str, hold_s: Optional[float] = None) -> None:
        """Hold a key (movement). Default uses MOVE_HOLD_MS."""
        if hold_s is None:
            hold_s = self.move_hold_ms / 1000.0
        self.c.keydown(name)
        self.sleep(hold_s)
        self.c.keyup(name)

    def move_south(self) -> None:
        # Prefer arrow down; keypad also works
        self.hold_key("down")

    def observe(self) -> str:
        return self.c.text()

    def log_screen_snippet(self, tag: str) -> None:
        try:
            body = text_body(self.observe())
            # non-empty lines, first few
            lines = [ln.rstrip() for ln in body.splitlines() if ln.strip()]
            preview = " | ".join(lines[:4])[:160]
            log(f"TEXT@{tag}: {preview or '(blank/mostly empty)'}")
        except Exception as e:
            log(f"TEXT@{tag} failed: {e}")

    def wait_for(
        self,
        *needles: str,
        timeout: float = 8.0,
        poll: float = 0.35,
        tag: str = "wait",
    ) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = self.observe()
                if screen_has(r, *needles):
                    log(f"{tag}: saw {needles[0]!r}")
                    return True
            except Exception:
                pass
            self.sleep(poll)
        log(f"{tag}: timeout waiting for {needles}")
        return False

    def phase_to_play(self) -> None:
        log("=== to-play (STARTUP-PROMPTS.md) ===")
        self.sleep(float(self.args.boot_wait))
        self.log_screen_snippet("boot")

        # 1) IBM PC Jr? default Y → N
        self.yn("n", "IBM PC Jr? (default Y)")

        # 2-3) title + ani — Esc only
        log("Esc #1: skip TITLE")
        self.c.key("esc")
        self.sleep(self.esc_gap)
        log("Esc #2: skip ANI")
        self.c.key("esc")
        self.sleep(self.esc_gap)
        self.log_screen_snippet("after_esc")

        # 4) restart saved? default N
        self.yn("n", "restart saved?")

        # 5) advanced?
        if self.args.advanced:
            self.yn("y", "advanced?")
        else:
            self.yn("n", "advanced?")

        # 6) story / SPACE BAR to continue
        self.spaces(self.story_spaces, "story / SPACE BAR to continue")
        self.sleep(1.0)
        self.log_screen_snippet("after_story")

        # 7) joystick? default Y → N for keyboard
        self.yn("n", "joystick? (default Y)")
        self.sleep(2.0)
        self.log_screen_snippet("overworld")

        if self.args.dump:
            log("DUMPSCREEN + DUMPMEM")
            self.c.dumpscreen()
            self.c.dumpmem()

        log("=== overworld reached (hopefully) ===")

    def phase_sword(self) -> None:
        log(f"=== sword: south x{self.sword_south} then P ===")
        self.sleep(1.2)
        for s in range(1, self.sword_south + 1):
            log(f"sword: step {s}/{self.sword_south} south")
            self.move_south()
            self.sleep(0.45)
            # P on last 3 steps (stand on / near object)
            if s >= self.sword_south - 2:
                log(f"sword: P after step {s}")
                self.c.key("P")
                self.sleep(0.5)
                self.c.key("P")
                self.sleep(0.4)
        # one extra south + standing P spam
        log("sword: +1 south + stand P")
        self.move_south()
        self.sleep(0.55)
        for _ in range(5):
            self.c.key("P")
            self.sleep(0.45)
        if self.args.dump:
            self.c.dumpscreen()
        self.log_screen_snippet("after_sword")
        log("=== sword sequence done ===")

    def is_hurt(self) -> bool:
        """Yellow/blink hurt triangle uses attr 8Eh (bat hit)."""
        try:
            r = self.c.b800()
            n = count_attr(r, 0x8E)
            if n > 0:
                log(f"hurt: attr 8Eh cells={n}")
            return n > 0
        except Exception as e:
            log(f"hurt check fail: {e}")
            return False

    def phase_wander(self, steps: int) -> None:
        log(f"=== wander {steps} steps + Space attack ===")
        dirs = ["down", "left", "right", "up", "down", "right", "down", "left"]
        for i in range(1, steps + 1):
            d = dirs[(i - 1) % len(dirs)]
            self.hold_key(d)
            self.sleep(0.15)
            # Attack often; extra if hurt
            if i % 2 == 0 or self.is_hurt():
                self.c.key("space")
                self.sleep(0.1)
                if self.is_hurt():
                    self.c.key("space")
                    self.c.key("space")
            if i % 5 == 0:
                self.log_screen_snippet(f"wander_{i}")
                if self.args.dump:
                    self.c.dumpscreen()
        log("=== wander done ===")

    def phase_quit(self) -> None:
        log("quit: Esc, Y quit, N save")
        self.c.key("esc")
        self.sleep(1.0)
        self.c.key("y")
        self.sleep(self.yn_gap)
        self.c.key("n")
        self.sleep(0.5)


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="ICON live agent via controlsocket")
    p.add_argument(
        "--attach",
        action="store_true",
        help="Do not start DOSBox; connect to existing socket",
    )
    p.add_argument("--sock", default=DEFAULT_SOCK)
    p.add_argument(
        "--to-play-only",
        action="store_true",
        help="Stop after overworld (no sword)",
    )
    p.add_argument(
        "--sword-only",
        action="store_true",
        help="Only sword phase (assume already in overworld)",
    )
    p.add_argument(
        "--wander-only",
        action="store_true",
        help="Only wander/attack (already in overworld; skips to-play + sword)",
    )
    p.add_argument(
        "--wander",
        type=int,
        default=0,
        metavar="N",
        help="Wander N steps after sword (or with --wander-only). 0=skip unless --wander-only (then 40)",
    )
    p.add_argument("--advanced", action="store_true", help="Answer advanced=Y")
    p.add_argument("--quit", action="store_true", help="Quit game dialogs at end")
    p.add_argument(
        "--dump",
        action="store_true",
        default=True,
        help="DUMPSCREEN/DUMPMEM at checkpoints (default on)",
    )
    p.add_argument("--no-dump", action="store_false", dest="dump")
    p.add_argument("--story-spaces", type=int, default=28)
    p.add_argument("--sword-south", type=int, default=6)
    p.add_argument("--yn-gap", type=float, default=0.9)
    p.add_argument("--space-gap", type=float, default=0.35)
    p.add_argument("--esc-gap", type=float, default=1.3)
    p.add_argument("--move-hold-ms", type=int, default=280)
    p.add_argument("--boot-wait", type=float, default=2.0)
    p.add_argument(
        "--cycles",
        default=os.environ.get("CYCLES", "100000"),
        help="DOSBox cycles fixed N when starting",
    )
    p.add_argument(
        "--kill-dosbox",
        action="store_true",
        help="If we started DOSBox, SIGTERM it at the end",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    proc: Optional[subprocess.Popen] = None

    if not args.attach:
        if not CONF.is_file():
            log(f"missing conf {CONF}")
            return 1
        # Clean stale sock only if nothing listening — DOSBox also does this
        proc = start_dosbox(args.cycles)
    else:
        log(f"attach mode: {args.sock}")

    client = ControlClient(args.sock)
    try:
        client.connect(timeout=60.0)
        st = client.status()
        log(st.strip())
        agent = LiveAgent(client, args)

        wander_n = args.wander
        if args.wander_only:
            if wander_n <= 0:
                wander_n = 40
            agent.phase_wander(wander_n)
        elif args.sword_only:
            agent.phase_sword()
            if wander_n > 0:
                agent.phase_wander(wander_n)
        else:
            agent.phase_to_play()
            if not args.to_play_only:
                agent.phase_sword()
            if wander_n > 0:
                agent.phase_wander(wander_n)

        if args.quit:
            agent.phase_quit()

        log("agent finished (DOSBox left running unless --kill-dosbox/--quit path)")
        return 0
    except Exception as e:
        log(f"FATAL: {e}")
        return 1
    finally:
        client.close()
        if proc is not None and args.kill_dosbox:
            log(f"SIGTERM dosbox pid={proc.pid}")
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                proc.kill()


if __name__ == "__main__":
    raise SystemExit(main())
