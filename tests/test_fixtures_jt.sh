#!/usr/bin/env bash
# Generic jump tables on the private fixtures (skip if absent; nothing from
# the fixtures is committed). Checks 4 fixtures (fx11, fx09, fx10, fx01);
# all are in the private dumpexe-fixtures repo. fx11 runs twice: without
# hints (generic rules only) and with its hints file fx12. Every listing must verify byte-identical; code coverage must not
# drop below the pre-jump-table baseline (bytes from --bytemap).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
# shellcheck source=fixtures.sh
source "$ROOT/tests/fixtures.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_fixtures_jt (no uasm)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-fjt-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
codebytes() { python3 -c 'import sys
s=0
for l in open(sys.argv[1]):
    p=l.split()
    if l[0]!="#" and len(p)>1 and p[1]=="code":
        a,b=p[0].split("-"); s+=int(b,16)-int(a,16)+1
print(s)' "$1"; }
# name  fixture-path  baseline-code-bytes (dumpexe 4df1398)
run() {
  local n=$1 rel=$2 base=$3 f
  f=$(fixture "$rel") || return 0
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" --bytemap="$n.bytemap" -o "$n.asm" "$f" >/dev/null 2>&1) || true
  check "${n}_verified" grep -q '^; VERIFIED identical' "$TD/$n.asm"
  local c; c=$(codebytes "$TD/$n.bytemap")
  echo "  $n code bytes: $c (baseline $base)"
  check "${n}_no_loss" test "$c" -ge "$base"
}
run fx11 fx11 4997   # no hints
run fx09 fx09 11612
run fx10 fx10 10018
run fx01 fx01 19514
fx11_table() { # $1 listing: print "words holes" of jt_037A0 up to func_038E0
  awk '/^jt_037A0:/{f=1;next} f&&/^func_038E0/{exit} f&&/table word/{n++} f&&/^    db 0h, 0h\t/{h++} END{print n+0, h+0}' "$1"; }
if [[ -s "$TD/fx11.asm" ]]; then
  # No hints: the dispatcher index is a zero-extended byte (lodsb; xor ah,ah;
  # shl), so the table can hold at most 256 slots; it runs to the code at
  # 38E0 (160 slots), the two 0000 holes are skipped, and every other slot
  # is a clean entry inside the span of the 32 handlers before the first
  # hole (n8 part 2, width-bounded index). Same result as with the hint.
  c=$(codebytes "$TD/fx11.bytemap"); echo "  fx11 (no hints) code bytes: $c"
  check fx11_nohint_bytes test "$c" -eq 17419
  check fx11_nohint_dispatch_160 test "$(fx11_table "$TD/fx11.asm")" = "158 2"
  check fx11_nohint_ends_at_038E0 bash -c "grep -A1 '; 038DE: table word' '$TD/fx11.asm' | grep -q '^; ----' "
  check fx11_nohint_rebuild grep -q '^; VERIFIED identical' "$TD/fx11.asm"
  check fx11_char_table_data grep -qE '^    db 0A0h, 0E1h.*; 01CCA:' "$TD/fx11.asm"
fi
# With the per-program hints file from the fixtures (table 37A0 A0 near).
if f=$(fixture fx11) && h=$(fixture fx12); then
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" --hints="$h" --bytemap=fx11h.bytemap -o fx11h.asm "$f" >/dev/null 2>&1) || true
  c=$(codebytes "$TD/fx11h.bytemap"); echo "  fx11 (hints) code bytes: $c"
  check fx11h_rebuild grep -q '^; VERIFIED identical' "$TD/fx11h.asm"
  check fx11h_bytes test "$c" -eq 17419
  # Byte opcode dispatcher: 160 slots at 37A0-38DF (158 entries, two 0000
  # holes at 37E0 and 38BC), ending at the code at 38E0.
  check fx11h_dispatch_160 test "$(fx11_table "$TD/fx11h.asm")" = "158 2"
  check fx11h_holes bash -c "grep -qE '^    db 0h, 0h.; 037E0:' '$TD/fx11h.asm' && grep -qE '^    db 0h, 0h.; 038BC:' '$TD/fx11h.asm'"
  check fx11h_ends_at_038E0 bash -c "grep -A1 '; 038DE: table word' '$TD/fx11h.asm' | grep -q '^; ----' "
  check fx11h_char_table_data grep -qE '^    db 0A0h, 0E1h.*; 01CCA:' "$TD/fx11h.asm"
fi
echo "---"
echo "passed=$pass failed=$fail"
fixtures_exit "$fail"
