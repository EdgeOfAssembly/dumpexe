#!/usr/bin/env bash
# P0: NE -d/-a must not decode past the on-disk code segment.
# These checks do not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-ne-XXXXXX")"
trap 'rm -rf "$TD"' EXIT

pass=0
fail=0
check() {
  local name=$1
  shift
  if "$@"; then
    echo "PASS $name"
    pass=$((pass + 1))
  else
    echo "FAIL $name"
    fail=$((fail + 1))
  fi
}

python3 - "$TD" << 'PY'
import struct
import sys
from pathlib import Path

td = Path(sys.argv[1])

def build_ne(ip, segment):
    """Minimal NE that ne_parse accepts. Poison B0 EE follows cbseg."""
    poison = b"\xB0\xEE"
    blob = bytearray(0x100 + len(segment) + len(poison))
    blob[0:2] = b"MZ"
    struct.pack_into("<I", blob, 0x3C, 0x40)
    struct.pack_into("<H", blob, 0x40, 0x454E)
    struct.pack_into("<H", blob, 0x40 + 0x14, ip)
    struct.pack_into("<H", blob, 0x40 + 0x16, 1)
    struct.pack_into("<H", blob, 0x40 + 0x1C, 1)
    struct.pack_into("<H", blob, 0x40 + 0x1E, 0)
    struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
    struct.pack_into("<H", blob, 0x40 + 0x26, 0x48)
    struct.pack_into("<H", blob, 0x40 + 0x32, 4)
    blob[0x40 + 0x36] = 2
    struct.pack_into("<HHHH", blob, 0x80, 0x10, len(segment), 0, len(segment))
    blob[0x100:0x100 + len(segment)] = segment
    blob[0x100 + len(segment):] = poison
    return bytes(blob)

(td / "ip0.exe").write_bytes(build_ne(0, b"\xB0\x42"))
# IP 3 is EB FB (jmp short 0). The mov at IP 0 is reached only when the
# entry window is the whole segment from foff, not cbseg-ip bytes at entry.
(td / "ip3.exe").write_bytes(build_ne(3, b"\xB0\x11\xC3\xEB\xFB"))
PY

# mode, fixture, required substrings, forbidden substrings
run_case() {
  local mode=$1
  local file=$2
  shift 2
  local out="$TD/out.txt"
  local err="$TD/err.txt"
  "$BIN" "$mode" --no-asm-file "$file" >"$out" 2>"$err"
  grep -q 'New Executable' "$out"
  local need
  for need in "$@"; do
    case "$need" in
      '!'*)
        local ban="${need:1}"
        if grep -q -F -- "$ban" "$out"; then
          echo "banned text present: $ban" >&2
          return 1
        fi
        ;;
      *)
        if ! grep -q -F -- "$need" "$out"; then
          echo "missing text: $need" >&2
          return 1
        fi
        ;;
    esac
  done
}

check ip0_d run_case -d "$TD/ip0.exe" 'B042' '0x42' '!B0EE' '!0xee'
check ip0_a run_case -a "$TD/ip0.exe" 'B042' '0x42' 'decoded 2 bytes' '!B0EE' '!0xee' '!first '
# -d must show the prefix. -a would show B011 from ip 0 even if entry dropped it.
check ip3_d run_case -d "$TD/ip3.exe" 'B011' '0x11' '!B0EE' '!0xee'
check ip3_a run_case -a "$TD/ip3.exe" 'decoded 5 bytes' '!B0EE' '!0xee' '!first '

echo "---"
echo "p0_ne passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
