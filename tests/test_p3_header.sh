#!/usr/bin/env bash
# P3: --uasm-header (strategy C). The verified listing carries the MZ header
# and file tail, uasm -bin rebuilds the whole EXE byte for byte, and the data
# and paragraph shift tests keep every segment reference.
# Missing assembler: exit 77 (skip).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=fixtures.sh
source "$ROOT/tests/fixtures.sh"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_p3_header (no uasm)"; exit 77; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p3-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0
fail=0
check() {
  local name=$1
  shift
  if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi
}
V="$BIN --uasm --uasm-verified --uasm-bin $UASM_BIN"

# Option rules.
check header_needs_verified bash -c "! '$BIN' --uasm --uasm-header '$ROOT/dumpexe' >/dev/null 2>&1"

FX06="$(fixture fx06 || true)"
if [[ -f "$FX06" ]]; then
  cp "$FX06" "$TD/fx06.exe"
  (cd "$TD" && $V --uasm-header -o fx06.asm fx06.exe >/dev/null 2>&1) || true
  check c_verified grep -q '^; VERIFIED identical' "$TD/fx06.asm"
  check c_strategy_line grep -q '^; strategy C: MZ header and file tail in the source' "$TD/fx06.asm"
  check c_header_label grep -q '^DXHDR' "$TD/fx06.asm"
  check c_reltab_label grep -q '^DXRELTAB' "$TD/fx06.asm"
  check c_rebuilds_exe bash -c "cd '$TD' && env -u UASM -u INCLUDE '$UASM_BIN' -bin -nologo -Fofx06.bin fx06.asm >/dev/null 2>&1 && cmp -s fx06.bin fx06.exe"
  check c_shift_mid grep -qE '^; shift mid: [1-9][0-9]* references checked, 0 broken' "$TD/fx06.asm"
  check c_shift_para grep -qE '^; shift paragraph: [1-9][0-9]* references checked, 0 broken' "$TD/fx06.asm"
  check c_shift_data grep -qE '^; shift data: ([1-9][0-9]* references checked, 0 broken|not run)' "$TD/fx06.asm"
  # Without --uasm-header the listing is the load image only (P2 output).
  (cd "$TD" && $V -o img.asm fx06.exe >/dev/null 2>&1) || true
  check image_only_no_header bash -c "! grep -q '^DXHDR' '$TD/img.asm'"
fi

# COM: --uasm-header has no header to carry; the listing stays image-only.
printf '\xb4\x4c\xcd\x21' > "$TD/t.com"
(cd "$TD" && $V --uasm-header -o t.asm t.com >/dev/null 2>&1) || true
check com_no_header bash -c "grep -q '^; VERIFIED identical' '$TD/t.asm' && ! grep -q '^DXHDR' '$TD/t.asm'"

echo "p3_header passed=$pass failed=$fail"
fixtures_exit "$fail"
