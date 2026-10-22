#!/usr/bin/env bash
# Generic jump tables on the private fixtures (skip if absent; nothing from
# the fixtures is committed). Checks 4 fixtures (DRAGON, AR, KOL, ICON);
# all are in the private dumpexe-fixtures repo. DRAGON runs twice: without
# hints (generic rules only) and with the fixtures' DRAGON.hints. Every listing must verify byte-identical; code coverage must not
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
run dragon dragon-wars/DRAGON.COM 4997   # no hints
run ar alternate-reality-the-city/AR.EXE 11612
run kol knights-of-legend/KOL.EXE 10018
run icon icon-quest-for-the-ring/ICON/ICON.EXE 19514
dragon_table() { # $1 listing: print "words holes" of jt_037A0 up to func_038E0
  awk '/^jt_037A0:/{f=1;next} f&&/^func_038E0/{exit} f&&/table word/{n++} f&&/^    db 0h, 0h\t/{h++} END{print n+0, h+0}' "$1"; }
if [[ -s "$TD/dragon.asm" ]]; then
  # No hints: the generic rules keep a tentative slot after a hole only when
  # an explicit branch joins proven code; eight 37A0 handlers rejoin the
  # dispatcher by fall-through or a call, so the table is cut at the 37E0
  # hole (32 slots before it).
  c=$(codebytes "$TD/dragon.bytemap"); echo "  dragon (no hints) code bytes: $c"
  check dragon_nohint_bytes test "$c" -ge 8600 -a "$c" -le 8800
  check dragon_nohint_cut_at_hole bash -c "grep -A1 '; 037DE: table word' '$TD/dragon.asm' | grep -q '; 037E0:' && ! grep -q '; 037E2: table word' '$TD/dragon.asm'"
  check dragon_nohint_rebuild grep -q '^; VERIFIED identical' "$TD/dragon.asm"
  check dragon_char_table_data grep -qE '^    db 0A0h, 0E1h.*; 01CCA:' "$TD/dragon.asm"
fi
# With the per-program hints file from the fixtures (table 37A0 A0 near).
if f=$(fixture dragon-wars/DRAGON.COM) && h=$(fixture dragon-wars/DRAGON.hints); then
  (cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" --hints="$h" --bytemap=dragonh.bytemap -o dragonh.asm "$f" >/dev/null 2>&1) || true
  c=$(codebytes "$TD/dragonh.bytemap"); echo "  dragon (hints) code bytes: $c"
  check dragonh_rebuild grep -q '^; VERIFIED identical' "$TD/dragonh.asm"
  check dragonh_bytes test "$c" -eq 17419
  # Byte opcode dispatcher: 160 slots at 37A0-38DF (158 entries, two 0000
  # holes at 37E0 and 38BC), ending at the code at 38E0.
  check dragonh_dispatch_160 test "$(dragon_table "$TD/dragonh.asm")" = "158 2"
  check dragonh_holes bash -c "grep -qE '^    db 0h, 0h.; 037E0:' '$TD/dragonh.asm' && grep -qE '^    db 0h, 0h.; 038BC:' '$TD/dragonh.asm'"
  check dragonh_ends_at_038E0 bash -c "grep -A1 '; 038DE: table word' '$TD/dragonh.asm' | grep -q '^; ----' "
  check dragonh_char_table_data grep -qE '^    db 0A0h, 0E1h.*; 01CCA:' "$TD/dragonh.asm"
fi
echo "---"
echo "passed=$pass failed=$fail"
fixtures_exit "$fail"
