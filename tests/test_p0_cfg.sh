#!/usr/bin/env bash
# P0 CFG contracts: DOS noreturn interrupts.
# INT 20h and INT 27h always stop. INT 21h stops only for AH 00h, 4Ch, or 31h.
# These checks do not skip. Synthetic COM fixtures only. No --simulate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-cfg-XXXXXX")"
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
fixtures = {
    "int20": bytes([0xCD, 0x20, 0xB0, 0x42]),
    "int27": bytes([0xCD, 0x27, 0xB0, 0x42]),
    "ah4c": bytes([0xB4, 0x4C, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah00": bytes([0xB4, 0x00, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah31": bytes([0xB4, 0x31, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ax4c": bytes([0xB8, 0x00, 0x4C, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "nop4c": bytes([0xB4, 0x4C, 0x90, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah09": bytes([0xB4, 0x09, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "unk": bytes([0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "into": bytes([0xCE, 0xB0, 0x42, 0xC3]),
}
for name, blob in fixtures.items():
    (td / f"{name}.com").write_bytes(blob)
print("fixtures", td)
PY

# File byte 0 is IP 0100. -d prints only decoded CFG instructions.
dump() {
  local name=$1
  "$BIN" -d --no-asm-file "$TD/$name.com" >"$TD/$name.out" 2>"$TD/$name.err"
}

has_f() {
  local out=$1 needle=$2
  if ! grep -F -q -- "$needle" "$out"; then
    echo "missing '$needle'" >&2
    cat "$out" >&2
    return 1
  fi
}

has_re() {
  local out=$1 re=$2
  if ! grep -E -q -- "$re" "$out"; then
    echo "missing /$re/" >&2
    cat "$out" >&2
    return 1
  fi
}

lacks_f() {
  local out=$1 needle=$2
  if grep -F -q -- "$needle" "$out"; then
    echo "unexpected '$needle'" >&2
    cat "$out" >&2
    return 1
  fi
}

case_int20() {
  dump int20 || return 1
  local out="$TD/int20.out"
  has_f "$out" CD20 || return 1
  has_re "$out" '[[:space:]]int[[:space:]]' || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_int27() {
  dump int27 || return 1
  local out="$TD/int27.out"
  has_f "$out" CD27 || return 1
  has_re "$out" '[[:space:]]int[[:space:]]' || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah4c() {
  dump ah4c || return 1
  local out="$TD/ah4c.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah00() {
  dump ah00 || return 1
  local out="$TD/ah00.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah31() {
  dump ah31 || return 1
  local out="$TD/ah31.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ax4c() {
  dump ax4c || return 1
  local out="$TD/ax4c.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_nop4c() {
  dump nop4c || return 1
  local out="$TD/nop4c.out"
  has_f "$out" CD21 || return 1
  has_re "$out" '[[:space:]]nop[[:space:]]' || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah09() {
  dump ah09 || return 1
  local out="$TD/ah09.out"
  has_f "$out" 0x42 || return 1
  has_f "$out" B042 || return 1
}

case_unk() {
  dump unk || return 1
  local out="$TD/unk.out"
  has_f "$out" 0x42 || return 1
}

case_into() {
  dump into || return 1
  local out="$TD/into.out"
  has_f "$out" 0x42 || return 1
  has_re "$out" '[[:space:]]into[[:space:]]' || return 1
}

check int20 case_int20
check int27 case_int27
check ah4c case_ah4c
check ah00 case_ah00
check ah31 case_ah31
check ax4c case_ax4c
check nop4c case_nop4c
check ah09 case_ah09
check unk case_unk
check into case_into

echo "cfg tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
