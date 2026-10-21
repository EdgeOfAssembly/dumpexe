#!/usr/bin/env bash
# Generic jump tables on the private fixtures (skip if absent; nothing from
# the fixtures is committed). DRAGON.COM is not in dumpexe-fixtures yet:
# point DUMPEXE_FIXTURES at a tree with games/dragon-wars/DRAGON.COM, or it
# skips. Every listing must verify byte-identical; code coverage must not
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
run dragon dragon-wars/DRAGON.COM 4997
run ar alternate-reality-the-city/AR.EXE 11612
run kol knights-of-legend/KOL.EXE 10018
run icon icon-quest-for-the-ring/ICON/ICON.EXE 19514
if [[ -s "$TD/dragon.asm" ]]; then
  check dragon_gain test "$(codebytes "$TD/dragon.bytemap")" -ge 17000
  # Byte opcode dispatcher: 160 slots at 37A0-38DF (158 entries, two 0000 holes),
  # ending at the code at 38E0.
  check dragon_dispatch_160 bash -c "awk '/^jt_037A0:/{f=1;next} f&&/^func_038E0/{exit} f&&/table word/{n++} f&&/^    db 0h, 0h\t/{h++} END{exit !(n==158 && h==2)}' '$TD/dragon.asm'"
  check dragon_ends_at_038E0 bash -c "grep -A1 '; 038DE: table word' '$TD/dragon.asm' | grep -q '^; ----' "
  check dragon_char_table_data grep -qE '^    db 0A0h, 0E1h.*; 01CCA:' "$TD/dragon.asm"
fi
echo "---"
echo "passed=$pass failed=$fail"
fixtures_exit "$fail"
