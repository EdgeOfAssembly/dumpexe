#!/usr/bin/env bash
# Contract tests for dumpexe CLI (max-quality-testing)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=fixtures.sh
source "$ROOT/tests/fixtures.sh"
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

# fx01 (Pascal MT+ 3.1.1 MZ) if present
FX01="$(fixture fx01 || true)"
if [[ -f "$FX01" ]]; then
  check fx01_header bash -c "$BIN --header-only '$FX01' 2>&1 | grep -q 'Program Entry Point'"
  # Default path auto-detects Pascal MT+ 3.1.1 (no flag required)
  check fx01_pascal_mt_default bash -c "$BIN --header-only '$FX01' 2>&1 | grep -q '=== Pascal MT+'"
  check fx01_pascal_mt_compiler bash -c "$BIN --header-only '$FX01' 2>&1 | grep -q 'Pascal MT+86'"
  check fx01_pascal_mt_jump bash -c "$BIN --header-only '$FX01' 2>&1 | grep -q 'Jump table'"
  check fx01_pascal_mt_inipc bash -c "$BIN --header-only '$FX01' 2>&1 | grep -qE 'inipc_|rtl_error|entry_e8'"
  # --no-pascal-mt suppresses the section
  check fx01_no_pascal_mt bash -c "! $BIN --header-only --no-pascal-mt '$FX01' 2>&1 | grep -q '=== Pascal MT+'"
  # Pascal length-prefixed string recovered by --strings / -a
  check fx01_pascal bash -c "$BIN --strings '$FX01' 2>&1 | grep -q 'Pascal MT+'"
  check fx01_strings_section bash -c "$BIN --strings '$FX01' 2>&1 | grep -q '=== Strings'"
  check fx01_mz bash -c "$BIN --header-only '$FX01' 2>&1 | grep -qE 'MZ|DOS File Size'"
  # --json machine-readable (opt-in)
  check help_mentions_json bash -c "$BIN -h 2>&1 | grep -q -- '--json'"
  check help_mentions_cfg_dot bash -c "$BIN -h 2>&1 | grep -q -- '--cfg-dot'"
  check fx01_json bash -c "$BIN --json '$FX01' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"tool\"]==\"dumpexe\"; assert d[\"pascal_mt\"][\"detected\"] is True; assert len(d[\"pascal_mt\"][\"jump_table\"])==23; assert d[\"cfg\"][\"blocks\"]>0'"
  # --cfg-dot Graphviz
  check fx01_cfg_dot bash -c "DOT=\$(mktemp /tmp/dumpexe-cfg-XXXXXX.dot) && $BIN --cfg-dot=\"\$DOT\" '$FX01' >/dev/null 2>&1 && grep -q 'digraph cfg' \"\$DOT\" && grep -q 'n0000' \"\$DOT\" && rm -f \"\$DOT\""
  # Multi-pass listing is -d (no --listing flag); default .asm write
  check help_no_listing_flag bash -c "! $BIN -h 2>&1 | grep -q -- '--listing'"
  check help_mentions_no_asm_file bash -c "$BIN -h 2>&1 | grep -q -- '--no-asm-file'"
  # A bare file gets the full -a analysis; --header-only turns it off.
  check bare_is_all bash -c "d=\$(mktemp -d) && cp '$FX01' \"\$d/fx01.exe\" && cd \"\$d\" && $BIN fx01.exe 2>/dev/null | grep -q 'Multi-pass assembly listing'; r=\$?; rm -rf \"\$d\"; exit \$r"
  check header_only_no_multipass bash -c "! $BIN --header-only '$FX01' 2>/dev/null | grep -q 'Multi-pass assembly listing'"
  check header_only_and_all_conflict bash -c "! $BIN --header-only -a '$FX01' >/dev/null 2>&1"
  check help_header_only bash -c "$BIN -h 2>&1 | grep -q -- '--header-only'"
  # Work in temp dir so default fx01.asm does not dirty the fixture tree
  check fx01_listing_multipass bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$FX01"'" "$TD/fx01.exe"
    "'"$BIN"'" -d --no-asm-file "$TD/fx01.exe" >"$TD/out.txt" 2>/dev/null
    grep -q "Multi-pass assembly listing" "$TD/out.txt"
    grep -qE "func_[0-9A-Fa-f]{4}:" "$TD/out.txt"
    grep -qE "call[[:space:]]+func_" "$TD/out.txt"
    grep -qE "jmp[[:space:]]+func_" "$TD/out.txt"
    grep -qE "INT |; INT" "$TD/out.txt"
    rm -rf "$TD"
  '
  check fx01_asm_default_write bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$FX01"'" "$TD/fx01.exe"
    "'"$BIN"'" -d "$TD/fx01.exe" >/dev/null 2>"$TD/err.txt"
    test -f "$TD/fx01.asm"
    grep -qE "func_[0-9A-Fa-f]{4}:" "$TD/fx01.asm"
    rm -rf "$TD"
  '
  check fx01_asm_no_file bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$FX01"'" "$TD/fx01.exe"
    "'"$BIN"'" -d --no-asm-file "$TD/fx01.exe" >/dev/null 2>/dev/null
    test ! -f "$TD/fx01.asm"
    rm -rf "$TD"
  '
  check fx01_asm_output_override bash -c '
    set -e
    TD=$(mktemp -d /tmp/dumpexe-list-XXXXXX)
    cp -f "'"$FX01"'" "$TD/fx01.exe"
    "'"$BIN"'" -d -o "$TD/out.asm" "$TD/fx01.exe" >/dev/null 2>/dev/null
    test -f "$TD/out.asm"
    grep -qE "func_" "$TD/out.asm"
    rm -rf "$TD"
  '
else
  echo "SKIP fx01 tests (fixture unavailable)"
fi

# fx02: CuteMouse (GPL; JWASM/TASM + com2exe ground truth)
CTM="$(fixture fx02 || true)"
if [[ -f "$CTM" ]]; then
  check ctm_toolchain bash -c "$BIN --header-only '$CTM' 2>&1 | grep -q 'COM-in-EXE'"
  check ctm_cutemouse bash -c "$BIN --header-only '$CTM' 2>&1 | grep -q 'CuteMouse'"
  check ctm_jwasm18 bash -c "$BIN --header-only '$CTM' 2>&1 | grep -qE 'JWASM 1\.8|JWASM 1\.80|Assembler:[[:space:]]+JWASM'"
  check ctm_jwasm18_version bash -c "$BIN --header-only '$CTM' 2>&1 | grep -q '1.80'"
  check ctm_json_jwasm bash -c "$BIN --json '$CTM' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d[\"toolchain\"]; assert t[\"detected\"] and t[\"jwasm_1_8\"] is True; assert \"1.80\" in t.get(\"assembler_version\",\"\") or \"1.8\" in t.get(\"assembler_version\",\"\")'"
  check ctm_no_pascal bash -c "! $BIN --header-only '$CTM' 2>&1 | grep -q '=== Pascal MT+'"
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
  echo "SKIP fx02 tests (fixture unavailable)"
fi

# fx03: Turbo Pascal 5.5
FX03="$(fixture fx03 || true)"
if [[ -f "$FX03" ]]; then
  check fx03_tp55 bash -c "$BIN --header-only '$FX03' 2>&1 | grep -q 'Turbo Pascal 5.5'"
  check fx03_no_jwasm bash -c "! $BIN --header-only '$FX03' 2>&1 | grep -q 'JWASM 1.8'"
  check fx03_tp_export bash -c "
    TD=\$(mktemp -d /tmp/dumpexe-tp-XXXXXX)
    cp -f '$FX03' "\$TD/c.exe"
    $BIN -d --no-asm-file -o "\$TD/o.asm" "\$TD/c.exe" >/dev/null 2>&1
    grep -q 'Turbo Pascal export' "\$TD/o.asm"
    grep -q '.MODEL LARGE' "\$TD/o.asm"
    grep -q 'PROC' "\$TD/o.asm"
    grep -q 'REPACK-V1' "\$TD/o.asm"
    rm -rf "\$TD"
  "
  check fx03_repack_identical bash -c "
    TD=\$(mktemp -d /tmp/dumpexe-repack-XXXXXX)
    cp -f '$FX03' "\$TD/fx03.exe"
    $BIN -d "\$TD/fx03.exe" >/dev/null 2>"\$TD/err"
    test -f "\$TD/fx03.repack.exe"
    cmp -s "\$TD/fx03.exe" "\$TD/fx03.repack.exe"
    grep -q 'IDENTICAL to input' "\$TD/err"
    rm -rf "\$TD"
  "
  check help_no_repack bash -c "$BIN -h 2>&1 | grep -q -- '--no-repack'"
else
  echo "SKIP fx03 tests (fixture unavailable)"
fi

# fx04: Windows 3.x NE
NE_EXE="$(fixture fx04 || true)"
if [[ -f "$NE_EXE" ]]; then
  check help_mentions_ne bash -c "$BIN -h 2>&1 | grep -q 'NE EXE'"
  check ne_header bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'New Executable (NE)'"
  check ne_windows bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'Target OS.*Windows'"
  check ne_module bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'Module name'"
  # module name pinned by hash (the fixture's own name is not spelled here)
  check ne_module_hash bash -c "$BIN --json '$NE_EXE' 2>/dev/null | python3 -c 'import sys,json,hashlib; d=json.load(sys.stdin); assert hashlib.sha256(d[\"module\"].encode()).hexdigest().startswith(\"8dce9e428d909dd5\")'"
  check ne_segments bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'Segment table (15'"
  check ne_imports bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'KERNEL'"
  check ne_resources bash -c "$BIN --header-only '$NE_EXE' 2>&1 | grep -q 'GROUP_CURSOR'"
  check ne_json bash -c "$BIN --json '$NE_EXE' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); assert d[\"format\"]==\"ne\"; assert d[\"module\"].isupper(); assert d[\"cseg\"]==15; assert d[\"exetyp\"]==2'"
  check ne_not_plain_mz bash -c "! $BIN --header-only '$NE_EXE' 2>&1 | grep -q 'Program Entry Point'"
else
  echo "SKIP fx04 NE tests (fixture unavailable)"
fi

# fx05: DOS extender / DPMI (Huffman extender; no bare DS false positive)
FX05="$(fixture fx05 || true)"
if [[ -f "$FX05" ]]; then
  check help_mentions_dos_extender bash -c "$BIN -h 2>&1 | grep -q -- '--no-dos-extender'"
  check help_mentions_bits bash -c "$BIN -h 2>&1 | grep -q -- '--bits='"
  check fx05_huffman bash -c "$BIN --header-only '$FX05' 2>&1 | grep -q 'Doug Huffman'"
  check fx05_bits32 bash -c "$BIN --header-only '$FX05' 2>&1 | grep -q '32-bit payload'"
  check fx05_nested_mz bash -c "$BIN --header-only '$FX05' 2>&1 | grep -q 'nested MZ'"
  check fx05_not_dos4g bash -c "! $BIN --header-only '$FX05' 2>&1 | grep -q 'DOS/4G'"
  check fx05_disasm32 bash -c "$BIN -d --no-asm-file '$FX05' 2>&1 | grep -q '32-bit disassembly'"
  check fx05_disasm_has_insn bash -c "$BIN -d --no-asm-file '$FX05' 2>&1 | grep -qE 'jmp|mov|call|push'"
  check fx05_no_extender_flag bash -c "! $BIN --header-only --no-dos-extender '$FX05' 2>&1 | grep -q 'DOS extender / DPMI'"
else
  echo "SKIP fx05 DOS extender tests (fixture unavailable)"
fi

S07="${DUMPEXE_SAMPLES:-$ROOT/tests/.samples}/s07.exe"   # a DOS/4G LE program
if [[ -f "$S07" ]]; then
  check s07_dos4g bash -c "$BIN --header-only '$S07' 2>&1 | grep -qE 'DOS/4G|DOS/32A|LE/LX'"
fi

echo "---"
echo "passed=$pass failed=$fail"
fixtures_exit "$fail"
