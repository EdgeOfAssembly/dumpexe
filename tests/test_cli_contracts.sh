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
  # Multi-pass listing is -d (no --listing flag); default .asm write
  check help_no_listing_flag bash -c "! $BIN -h 2>&1 | grep -q -- '--listing'"
  check help_mentions_no_asm_file bash -c "$BIN -h 2>&1 | grep -q -- '--no-asm-file'"
  check bare_no_multipass bash -c "! $BIN '$ICON' 2>/dev/null | grep -q 'Multi-pass assembly listing'"
  # Work in temp dir so default ICON.asm does not dirty the game tree
  check icon_listing_multipass bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$ICON"'" "$TD/ICON.EXE"
    "'"$BIN"'" -d --no-asm-file "$TD/ICON.EXE" >"$TD/out.txt" 2>/dev/null
    grep -q "Multi-pass assembly listing" "$TD/out.txt"
    grep -qE "func_[0-9A-Fa-f]{4}:" "$TD/out.txt"
    grep -qE "call[[:space:]]+func_" "$TD/out.txt"
    grep -qE "jmp[[:space:]]+func_" "$TD/out.txt"
    grep -qE "INT |; INT" "$TD/out.txt"
    rm -rf "$TD"
  '
  check icon_asm_default_write bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$ICON"'" "$TD/ICON.EXE"
    "'"$BIN"'" -d "$TD/ICON.EXE" >/dev/null 2>"$TD/err.txt"
    test -f "$TD/ICON.asm"
    grep -qE "func_[0-9A-Fa-f]{4}:" "$TD/ICON.asm"
    rm -rf "$TD"
  '
  check icon_asm_no_file bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$ICON"'" "$TD/ICON.EXE"
    "'"$BIN"'" -d --no-asm-file "$TD/ICON.EXE" >/dev/null 2>/dev/null
    test ! -f "$TD/ICON.asm"
    rm -rf "$TD"
  '
  check icon_asm_output_override bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$ICON"'" "$TD/ICON.EXE"
    "'"$BIN"'" -d -o "$TD/out.asm" "$TD/ICON.EXE" >/dev/null 2>/dev/null
    test -f "$TD/out.asm"
    grep -qE "func_" "$TD/out.asm"
    rm -rf "$TD"
  '
else
  echo "SKIP icon tests (no ICON.EXE)"
fi

# CuteMouse fixture (JWASM/TASM + com2exe ground truth)
CTM="$ROOT/games/cutemouse/bin/ctmouse.exe"
if [[ -f "$CTM" ]]; then
  check ctm_toolchain bash -c "$BIN '$CTM' 2>&1 | grep -q 'COM-in-EXE'"
  check ctm_cutemouse bash -c "$BIN '$CTM' 2>&1 | grep -q 'CuteMouse'"
  check ctm_jwasm18 bash -c "$BIN '$CTM' 2>&1 | grep -qE 'JWASM 1\.8|JWASM 1\.80|Assembler:[[:space:]]+JWASM'"
  check ctm_jwasm18_version bash -c "$BIN '$CTM' 2>&1 | grep -q '1.80'"
  check ctm_json_jwasm bash -c "$BIN --json '$CTM' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d[\"toolchain\"]; assert t[\"detected\"] and t[\"jwasm_1_8\"] is True; assert \"1.80\" in t.get(\"assembler_version\",\"\") or \"1.8\" in t.get(\"assembler_version\",\"\")'"
  check ctm_no_pascal bash -c "! $BIN '$CTM' 2>&1 | grep -q '=== Pascal MT+'"
  check ctm_sym_start bash -c "$BIN -d --no-asm-file '$CTM' 2>/dev/null | grep -qE '^start:'"
  check help_no_toolchain bash -c "$BIN -h 2>&1 | grep -q -- '--no-toolchain'"
  check help_map bash -c "$BIN -h 2>&1 | grep -q -- '--map='"
  check help_model bash -c "$BIN -h 2>&1 | grep -q -- '--model='"
  # COM-in-EXE always tiny even if user passes --model=small
  check ctm_model_tiny_forced bash -c "
    TD=\$(mktemp -d /tmp/dumpexe-model-XXXXXX)
    cp -f '$CTM' \"\$TD/c.exe\"
    $BIN -d --model=small --no-asm-file -o \"\$TD/o.asm\" \"\$TD/c.exe\" >/dev/null 2>&1
    grep -q 'forced: .COM / COM-in-EXE' \"\$TD/o.asm\"
    grep -q '.model tiny' \"\$TD/o.asm\"
    rm -rf \"\$TD\"
  "
else
  echo "SKIP cutemouse tests"
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
