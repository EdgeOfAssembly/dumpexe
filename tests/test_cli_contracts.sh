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
check help_mentions_no_pascal_mt bash -c "$BIN -h 2>&1 | grep -q -- '--no-pascal-mt'"
# Sane defaults: only disable switch, not --pascal-mt enable
check help_no_enable_pascal_mt bash -c "! $BIN -h 2>&1 | grep -qE -- '--pascal-mt[^+]|--enable-pascal'"

# ICON.EXE if present
ICON="$ROOT/games/icon-quest-for-the-ring/ICON/ICON.EXE"
if [[ -f "$ICON" ]]; then
  check icon_header bash -c "$BIN '$ICON' 2>&1 | grep -q 'Program Entry Point'"
  # Default path auto-detects Pascal MT+ 3.1.1 (no flag required)
  check icon_pascal_mt_default bash -c "$BIN '$ICON' 2>&1 | grep -q '=== Pascal MT+'"
  check icon_pascal_mt_compiler bash -c "$BIN '$ICON' 2>&1 | grep -q 'Pascal MT+86'"
  check icon_pascal_mt_jump bash -c "$BIN '$ICON' 2>&1 | grep -q 'Jump table'"
  check icon_pascal_mt_inipc bash -c "$BIN '$ICON' 2>&1 | grep -qE 'inipc_|rtl_error|entry_e8'"
  # --no-pascal-mt suppresses the section
  check icon_no_pascal_mt bash -c "! $BIN --no-pascal-mt '$ICON' 2>&1 | grep -q '=== Pascal MT+'"
  # Pascal length-prefixed string recovered by --strings / -a
  check icon_pascal bash -c "$BIN --strings '$ICON' 2>&1 | grep -q 'Pascal MT+'"
  check icon_strings_section bash -c "$BIN --strings '$ICON' 2>&1 | grep -q '=== Strings'"
  check icon_mz bash -c "$BIN '$ICON' 2>&1 | grep -qE 'MZ|DOS File Size'"
  # --json machine-readable (opt-in)
  check help_mentions_json bash -c "$BIN -h 2>&1 | grep -q -- '--json'"
  check help_mentions_cfg_dot bash -c "$BIN -h 2>&1 | grep -q -- '--cfg-dot'"
  check icon_json bash -c "$BIN --json '$ICON' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"tool\"]==\"dumpexe\"; assert d[\"pascal_mt\"][\"detected\"] is True; assert len(d[\"pascal_mt\"][\"jump_table\"])==23; assert d[\"cfg\"][\"blocks\"]>0'"
  # --cfg-dot Graphviz
  check icon_cfg_dot bash -c "DOT=\$(mktemp /tmp/dumpexe-cfg-XXXXXX.dot) && $BIN --cfg-dot=\"\$DOT\" '$ICON' >/dev/null 2>&1 && grep -q 'digraph cfg' \"\$DOT\" && grep -q 'n0000' \"\$DOT\" && rm -f \"\$DOT\""
else
  echo "SKIP icon tests (no ICON.EXE)"
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
