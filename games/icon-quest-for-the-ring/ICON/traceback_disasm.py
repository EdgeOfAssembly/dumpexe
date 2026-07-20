#!/usr/bin/env python3
"""Fetch TRACEBACK from DOSBox control socket and disassemble with Capstone.

  ./traceback_disasm.py
  ./traceback_disasm.py 128
  ./traceback_disasm.py --sock /tmp/dosbox-control.sock 64

Requires: pip install capstone  (or distro package)
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import sys


def recv_traceback(sock: socket.socket) -> str:
    buf = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
        text = buf.decode("utf-8", errors="replace")
        if "\nEND\n" in text or text.endswith("END\n"):
            return text
    return buf.decode("utf-8", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("count", nargs="?", type=int, default=0, help="last N insns (0=all)")
    ap.add_argument("--sock", default=os.environ.get("DOSBOX_CONTROL_SOCK", "/tmp/dosbox-control.sock"))
    ap.add_argument("--hex-only", action="store_true", help="print server hex only")
    args = ap.parse_args()

    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.connect(args.sock)
    except OSError as e:
        print(f"connect: {e}", file=sys.stderr)
        return 1

    # greet
    g = b""
    while b"\n" not in g:
        g += s.recv(256)

    cmd = "TRACEBACK" if args.count <= 0 else f"TRACEBACK {args.count}"
    s.sendall((cmd + "\n").encode())
    text = recv_traceback(s)
    try:
        s.sendall(b"QUIT\n")
    except OSError:
        pass
    s.close()

    print(text, end="" if text.endswith("\n") else "\n")
    if args.hex_only:
        return 0

    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_16
    except ImportError:
        print(
            "\n# Capstone not installed — hex dump above is enough for offline tools.\n"
            "# Install: pip install capstone",
            file=sys.stderr,
        )
        return 0

    md = Cs(CS_ARCH_X86, CS_MODE_16)
    md.detail = False
    line_re = re.compile(
        r"^(?P<idx>\d+)\s+CS=(?P<cs>[0-9A-Fa-f]+)\s+IP=(?P<ip>[0-9A-Fa-f]+)\s+BYTES=(?P<bytes>[0-9A-Fa-f ]+)"
    )
    print("--- Capstone (16-bit) ---")
    for line in text.splitlines():
        m = line_re.match(line.strip())
        if not m:
            continue
        cs = int(m.group("cs"), 16)
        ip = int(m.group("ip"), 16)
        raw = bytes(int(x, 16) for x in m.group("bytes").split())
        addr = ((cs << 4) + ip) & 0xFFFFF
        for insn in md.disasm(raw, addr):
            print(
                f"{m.group('idx'):>4} {cs:04X}:{ip:04X}  "
                f"{raw.hex(' '):<24}  {insn.mnemonic} {insn.op_str}".rstrip()
            )
            break
        else:
            print(f"{m.group('idx'):>4} {cs:04X}:{ip:04X}  {raw.hex(' ')}  <undecoded>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
