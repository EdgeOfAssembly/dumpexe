#!/usr/bin/env bash
# P0 Q10: --uasm-stats is enable-only and prints one stderr coverage line.
# Synthetic COM fixtures only. No --simulate. Does not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
[[ -x /usr/bin/uasm ]] || { echo "FAIL: /usr/bin/uasm not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-stats-XXXXXX")"
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

printf '\xC3' >"$TD/c3.com"
printf '\xCD\x03\xC3' >"$TD/cd03.com"

EXACT_C3='uasm-stats: image=1 decoded=1 (100.0%) text=1 (100.0%) db=0 (0.0%) labels_defined=1 labels_referenced=1'

stats_count() {
  local file=$1
  grep -c 'uasm-stats:' "$file" || true
}

case_requires_flag_first() {
  local rc=0
  "$BIN" --uasm-stats -o "$TD/nope.asm" "$TD/c3.com" >"$TD/req1.out" 2>"$TD/req1.err" || rc=$?
  [[ "$rc" -eq 1 ]] || { echo "exit $rc"; return 1; }
  [[ ! -e "$TD/nope.asm" && ! -e "$TD/c3.asm" ]] || { echo "wrote an asm file"; return 1; }
  grep -F -q -- '--uasm-stats requires --uasm' "$TD/req1.err" || {
    echo "stderr does not name both flags" >&2
    cat "$TD/req1.err" >&2
    return 1
  }
}

case_requires_file_first() {
  local rc=0
  "$BIN" "$TD/c3.com" --uasm-stats >"$TD/req2.out" 2>"$TD/req2.err" || rc=$?
  [[ "$rc" -eq 1 ]] || { echo "exit $rc"; return 1; }
  [[ ! -e "$TD/c3.asm" ]] || { echo "wrote c3.asm"; return 1; }
  grep -F -q -- '--uasm-stats requires --uasm' "$TD/req2.err" || {
    echo "stderr does not name both flags" >&2
    cat "$TD/req2.err" >&2
    return 1
  }
}

case_uasm_without_stats() {
  "$BIN" --uasm -o "$TD/plain.asm" "$TD/c3.com" >"$TD/plain.out" 2>"$TD/plain.err" || return 1
  [[ "$(stats_count "$TD/plain.err")" -eq 0 ]] || { echo "stats on stderr"; cat "$TD/plain.err"; return 1; }
  [[ "$(stats_count "$TD/plain.out")" -eq 0 ]] || { echo "stats on stdout"; return 1; }
  if grep -F -q 'uasm-stats:' "$TD/plain.asm"; then
    echo "stats in asm" >&2
    return 1
  fi
  return 0
}

case_order_uasm_first() {
  "$BIN" --uasm --uasm-stats -o "$TD/ord1.asm" "$TD/c3.com" >"$TD/ord1.out" 2>"$TD/ord1.err" || return 1
  [[ "$(stats_count "$TD/ord1.err")" -eq 1 ]] || { echo "stderr:"; cat "$TD/ord1.err"; return 1; }
  [[ "$(stats_count "$TD/ord1.out")" -eq 0 ]] || { echo "stdout has stats"; return 1; }
  grep -F -x -q -- "$EXACT_C3" "$TD/ord1.err" || { echo "bad line"; cat "$TD/ord1.err"; return 1; }
}

case_order_stats_first() {
  "$BIN" --uasm-stats --uasm -o "$TD/ord2.asm" "$TD/c3.com" >"$TD/ord2.out" 2>"$TD/ord2.err" || return 1
  [[ "$(stats_count "$TD/ord2.err")" -eq 1 ]] || { echo "stderr:"; cat "$TD/ord2.err"; return 1; }
  [[ "$(stats_count "$TD/ord2.out")" -eq 0 ]] || return 1
  grep -F -x -q -- "$EXACT_C3" "$TD/ord2.err" || { echo "bad line"; cat "$TD/ord2.err"; return 1; }
}

case_order_file_middle() {
  "$BIN" --uasm-stats "$TD/c3.com" --uasm -o "$TD/ord3.asm" >"$TD/ord3.out" 2>"$TD/ord3.err" || return 1
  [[ "$(stats_count "$TD/ord3.err")" -eq 1 ]] || { echo "stderr:"; cat "$TD/ord3.err"; return 1; }
  [[ "$(stats_count "$TD/ord3.out")" -eq 0 ]] || return 1
  grep -F -x -q -- "$EXACT_C3" "$TD/ord3.err" || { echo "bad line"; cat "$TD/ord3.err"; return 1; }
}

case_cd03() {
  "$BIN" "$TD/cd03.com" --uasm-stats --uasm -o "$TD/cd03.asm" >"$TD/cd03.out" 2>"$TD/cd03.err" || return 1
  [[ "$(stats_count "$TD/cd03.err")" -eq 1 ]] || { echo "stderr:"; cat "$TD/cd03.err"; return 1; }
  [[ "$(stats_count "$TD/cd03.out")" -eq 0 ]] || return 1
  grep -E -q -- '^uasm-stats: image=3 decoded=3 \(100\.0%\) text=1 \([0-9]+\.[0-9]%\) db=2 \([0-9]+\.[0-9]%\) labels_defined=[0-9]+ labels_referenced=[0-9]+$' "$TD/cd03.err" || {
    echo "cd03 line mismatch" >&2
    cat "$TD/cd03.err" >&2
    return 1
  }
}

case_stdout_dash() {
  [[ ! -e "$TD/c3.asm" ]] || { echo "c3.asm already exists"; return 1; }
  "$BIN" -o - --uasm-stats "$TD/c3.com" --uasm >"$TD/dash.out" 2>"$TD/dash.err" || return 1
  [[ ! -e "$TD/c3.asm" ]] || { echo "wrote c3.asm for -o -"; return 1; }
  [[ "$(stats_count "$TD/dash.err")" -eq 1 ]] || { echo "stderr:"; cat "$TD/dash.err"; return 1; }
  [[ "$(stats_count "$TD/dash.out")" -eq 0 ]] || { echo "stats leaked to stdout"; return 1; }
  grep -F -x -q -- "$EXACT_C3" "$TD/dash.err" || { echo "bad dash line"; cat "$TD/dash.err"; return 1; }
  grep -F -q -- 'ret' "$TD/dash.out" || { echo "stdout is not the asm"; cat "$TD/dash.out"; return 1; }
  grep -F -q -- 'end func_0100' "$TD/dash.out" || { echo "missing end"; cat "$TD/dash.out"; return 1; }
}

case_help() {
  "$BIN" -h >"$TD/h.txt"
  "$BIN" --help >"$TD/help.txt"
  "$BIN" >"$TD/none.txt"
  for f in "$TD/h.txt" "$TD/help.txt" "$TD/none.txt"; do
    grep -F -q -- '--uasm-stats' "$f" || { echo "missing flag in $f"; return 1; }
    if grep -F -q -- '--no-uasm-stats' "$f"; then
      echo "disable twin documented in $f" >&2
      return 1
    fi
  done
  if grep -F -q -- '\-\-no-uasm-stats' "$ROOT/dumpexe.1"; then
    echo "man page documents a disable twin" >&2
    return 1
  fi
  grep -F -q -- '\-\-uasm-stats' "$ROOT/dumpexe.1" || {
    echo "man page missing flag" >&2
    return 1
  }
}

check requires_flag_first case_requires_flag_first
check requires_file_first case_requires_file_first
check uasm_without_stats case_uasm_without_stats
check order_uasm_first case_order_uasm_first
check order_stats_first case_order_stats_first
check order_file_middle case_order_file_middle
check cd03 case_cd03
check stdout_dash case_stdout_dash
check help case_help

echo "stats tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
