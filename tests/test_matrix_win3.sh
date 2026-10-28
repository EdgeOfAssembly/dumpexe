#!/usr/bin/env bash
# Regression for static-wins 3 (post-terminator starts) on a toolchain-matrix
# sample: a huge-model C program with the floating-point emulator, named only
# by its SHA-256 (the binary is never committed). Point DUMPEXE_MATRIX at a
# directory holding the self-built matrix; skips when the sample is absent.
# A new start must not decode the bytes right before the table of
# `jmp word ptr cs:[bx+T]` in the emulator segment, and post-terminator
# starts run only after the jump tables have settled.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM_BIN="$(uasm_resolve)" || { echo "SKIP test_matrix_win3 (no uasm)"; exit 77; }
SHA=976e8579b1d9e4119fe3bf7e98cf11f186c55519a7ff098f38d00a1e6ca1f731
DIR="${DUMPEXE_MATRIX:-}"
[[ -n "$DIR" && -d "$DIR" ]] || { echo "SKIP test_matrix_win3 (DUMPEXE_MATRIX not set)"; exit 77; }
F=""
while IFS= read -r -d '' c; do
  if [[ "$(sha256sum "$c" | cut -d' ' -f1)" == "$SHA" ]]; then F=$c; break; fi
done < <(find "$DIR" -type f -size 26872c -print0 2>/dev/null)
[[ -n "$F" ]] || { echo "SKIP test_matrix_win3 (sample ${SHA:0:16} absent)"; exit 77; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-mw3-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }
cp "$F" "$TD/s.exe"
(cd "$TD" && "$BIN" --uasm --uasm-verified --uasm-bin "$UASM_BIN" -o s.asm s.exe >/dev/null 2>&1) || true
A="$TD/s.asm"
check verified grep -q '^; VERIFIED identical' "$A"
mb=$(sed -n 's/^; lines: mnemonic [0-9]* (\([0-9]*\) bytes).*/\1/p' "$A")
bt=$(sed -n 's/^; value references: \([0-9]*\) bounded jump table.*/\1/p' "$A")
gt=$(sed -n 's/^; jump tables: \([0-9]*\) generic table.*/\1/p' "$A")
echo "  mnemonic bytes ${mb:-?} (pre-win-3 14256), bounded tables ${bt:-?} (9), generic tables ${gt:-?} (7)"
check mnemonic_no_loss test "${mb:-0}" -ge 14256
check bounded_tables test "${bt:-0}" -ge 9
check generic_tables test "${gt:-0}" -ge 7
# The emulator dispatcher's table is resolved and the 31 bytes before it
# stay data (no instruction line at 050DD..050FB that the old code lacked).
check emu_table_resolved grep -q 'jmp word ptr cs:\[bx+(jt_050FC' "$A"
check no_start_before_table bash -c "! grep -vE '^    d[bwd] ' '$A' | grep -qE '; 050F[3-9A-B]:'"
echo "---"
echo "passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
