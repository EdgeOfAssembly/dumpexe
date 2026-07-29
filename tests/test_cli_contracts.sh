#!/usr/bin/env bash
# Contract tests for dumpexe CLI (max-quality-testing)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
if [[ ! -x "$BIN" ]]; then
  BIN=$(command -v dumpexe || true)
fi
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

pass=0
fail=0
check() {
  local name=$1
  shift
  if "$@"; then
    echo "PASS $name"
    pass=$((pass+1))
  else
    echo "FAIL $name"
    fail=$((fail+1))
  fi
}

check help_exit0 bash -c "$BIN -h >/dev/null 2>&1"
check version_exit0 bash -c "$BIN -v >/dev/null 2>&1"
check version_string bash -c "$BIN -v 2>&1 | grep -qi dumpexe"
check help_mentions_cfg bash -c "$BIN -h 2>&1 | grep -qE -- '--cfg|cfg'"

# ICON.EXE if present
ICON="$ROOT/games/icon-quest-for-the-ring/ICON/ICON.EXE"
if [[ -f "$ICON" ]]; then
  check icon_header bash -c "$BIN '$ICON' 2>&1 | grep -q 'Program Entry Point'"
  # Pascal MT+ length-prefixed string recovered by --strings / -a
  check icon_pascal bash -c "$BIN --strings '$ICON' 2>&1 | grep -q 'Pascal MT+'"
  check icon_strings_section bash -c "$BIN --strings '$ICON' 2>&1 | grep -q '=== Strings'"
  check icon_mz bash -c "$BIN '$ICON' 2>&1 | grep -qE 'MZ|DOS File Size'"
else
  echo "SKIP icon tests (no ICON.EXE)"
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
