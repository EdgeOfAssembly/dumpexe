#!/usr/bin/env bash
# P0 sim contracts: far lcall, far ljmp, cbw (Capstone cwde), cwd (Capstone cdq).
# These checks do not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-sim-XXXXXX")"
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
import sys
from pathlib import Path
td = Path(sys.argv[1])

def place(name, prefix, at, tail):
    if len(prefix) > at:
        raise SystemExit(f"{name}: prefix overlaps tail")
    buf = bytearray(at + len(tail))
    buf[:len(prefix)] = prefix
    buf[at:at + len(tail)] = tail
    (td / name).write_bytes(buf)

place("lcall.com",
      bytes([0x9A, 0x10, 0x01, 0x00, 0x10, 0xB4, 0x4C, 0xCD, 0x21]),
      0x10, bytes([0xB0, 0x42, 0xCB]))
place("ljmp.com",
      bytes([0xEA, 0x10, 0x01, 0x00, 0x10, 0xB0, 0x11]),
      0x10, bytes([0xB0, 0x22, 0xCD, 0x20]))
(td / "cbw.com").write_bytes(bytes([0xB0, 0x80, 0x98, 0x8A, 0xD4, 0xCD, 0x20]))
(td / "cbwpos.com").write_bytes(bytes([0xB0, 0x7F, 0x98, 0xCD, 0x20]))
(td / "cwd.com").write_bytes(bytes([0xB8, 0x00, 0x80, 0x99, 0xCD, 0x20]))

lcall = (td / "lcall.com").read_bytes()
ljmp = (td / "ljmp.com").read_bytes()
assert lcall[9:0x10] == bytes(7)
assert lcall[0x10:0x13] == bytes([0xB0, 0x42, 0xCB])
assert ljmp[7:0x10] == bytes(9)
assert ljmp[0x10:0x13] == bytes([0xB0, 0x22, 0xCD, 0x20])
print("fixtures", td)
PY

check lcall bash -c "
  set -euo pipefail
  out='$TD/lcall.out'
  '$BIN' --simulate --trace --max-insns=20 --no-asm-file '$TD/lcall.com' >\"\$out\"
  grep -F -q '1000:0110' \"\$out\" || { echo 'missing 1000:0110'; cat \"\$out\"; exit 1; }
  grep -F -q '1000:0105' \"\$out\" || { echo 'missing 1000:0105'; cat \"\$out\"; exit 1; }
  if grep -F -q 'unsupported opcode' \"\$out\"; then
    echo 'saw unsupported opcode' >&2
    cat \"\$out\" >&2
    exit 1
  fi
  grep -F -q 'DOS terminate (AH=4Ch, AL=42h)' \"\$out\" || { echo 'missing DOS terminate'; cat \"\$out\"; exit 1; }
  grep -F -q 'AX=4C42' \"\$out\" || { echo 'missing AX=4C42'; cat \"\$out\"; exit 1; }
"

check ljmp bash -c "
  set -euo pipefail
  out='$TD/ljmp.out'
  '$BIN' --simulate --trace --max-insns=20 --no-asm-file '$TD/ljmp.com' >\"\$out\"
  grep -F -q '1000:0110' \"\$out\" || { echo 'missing 1000:0110'; cat \"\$out\"; exit 1; }
  if grep -F -q '1000:0105' \"\$out\"; then
    echo 'saw 1000:0105' >&2
    cat \"\$out\" >&2
    exit 1
  fi
  if grep -F -q '1000:1000' \"\$out\"; then
    echo 'saw 1000:1000' >&2
    cat \"\$out\" >&2
    exit 1
  fi
  if grep -F -q 'unsupported opcode' \"\$out\"; then
    echo 'saw unsupported opcode' >&2
    cat \"\$out\" >&2
    exit 1
  fi
  grep -F -q 'INT 20h terminate' \"\$out\" || { echo 'missing INT 20h terminate'; cat \"\$out\"; exit 1; }
  grep -F -q 'AX=0022' \"\$out\" || { echo 'missing AX=0022'; cat \"\$out\"; exit 1; }
"

check cbw bash -c "
  set -euo pipefail
  out='$TD/cbw.out'
  '$BIN' --simulate --trace --max-insns=20 --no-asm-file '$TD/cbw.com' >\"\$out\"
  grep -F -q 'AX=FF80' \"\$out\" || { echo 'missing AX=FF80'; cat \"\$out\"; exit 1; }
  grep -F -q 'DX=00FF' \"\$out\" || { echo 'missing DX=00FF'; cat \"\$out\"; exit 1; }
  grep -F -q 'INT 20h terminate' \"\$out\" || { echo 'missing INT 20h terminate'; cat \"\$out\"; exit 1; }
"

check cbwpos bash -c "
  set -euo pipefail
  out='$TD/cbwpos.out'
  '$BIN' --simulate --trace --max-insns=20 --no-asm-file '$TD/cbwpos.com' >\"\$out\"
  grep -F -q 'AX=007F' \"\$out\" || { echo 'missing AX=007F'; cat \"\$out\"; exit 1; }
"

check cwd bash -c "
  set -euo pipefail
  out='$TD/cwd.out'
  '$BIN' --simulate --trace --max-insns=20 --no-asm-file '$TD/cwd.com' >\"\$out\"
  grep -F -q 'AX=8000' \"\$out\" || { echo 'missing AX=8000'; cat \"\$out\"; exit 1; }
  grep -F -q 'DX=FFFF' \"\$out\" || { echo 'missing DX=FFFF'; cat \"\$out\"; exit 1; }
"

echo "---"
echo "p0_sim passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
