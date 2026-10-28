#!/usr/bin/env bash
# Unpack-on-disassemble on the private fixtures (skip if absent; nothing from
# the fixtures is committed). fx13 is PKLITE 1.50 small cmpr whose
# decompressor treats code 0xfe as an uncompressed area.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=fixtures.sh
source "$ROOT/tests/fixtures.sh"
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-unp-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
run() {
  local n=$1 f
  f=$(fixture "$n") || return 0
  cp "$f" "$TD/$n.exe"
  (cd "$TD" && "$BIN" -d -o "$n.asm" "$n.exe" >"$n.out" 2>&1) || true
  check "${n}_no_failure" bash -c "! grep -q 'unpack failed' '$TD/$n.out'"
  check "${n}_unpacked_mz" bash -c "head -c2 '$TD/${n}_UNPACKED.EXE' 2>/dev/null | grep -q MZ"
  check "${n}_listing" test -s "$TD/${n}_UNPACKED.asm"
}
run fx13
echo "test_unpack_fixtures: $pass passed, $fail failed"
fixtures_exit "$fail"
