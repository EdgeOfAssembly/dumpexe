#!/usr/bin/env bash
# P7: NE relocations (chained), entry table, exports from the resident and
# non-resident names tables, KERNEL/USER/GDI ordinal names, header-based
# detection. Optional fixtures (Outpost, MCIAAP, DIB) come from
# DUMPEXE_NE_FIXTURES; their checks are skipped when it is unset.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p7-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }

WS="$ROOT/SOURCER/WINSMALL.EXE"
if [[ -f "$WS" ]]; then
  "$BIN" -d "$WS" > "$TD/ws.txt" 2>&1
  check ws_inittask grep -qE '^1:0000  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 0\]' "$TD/ws.txt"
  check ws_reloc_table grep -qE '^ +0  far +import +KERNEL\.91 \(InitTask\) +1:0001' "$TD/ws.txt"
  check ws_no_placeholder bash -c "! grep -qE 'lcall +0, 0xffff' '$TD/ws.txt'"
  # Header, not extension: the same bytes named .COM and .SYS are still NE.
  cp "$WS" "$TD/WINSMALL.COM"; cp "$WS" "$TD/WINSMALL.SYS"; cp "$WS" "$TD/noext"
  for f in WINSMALL.COM WINSMALL.SYS noext; do
    check "detect_$f" bash -c "'$BIN' '$TD/$f' | grep -q '^=== New Executable (NE)'"
  done
fi
SL="$ROOT/games/simlife-win3x/SIMLIFEW.EXE"
if [[ -f "$SL" ]]; then
  "$BIN" "$SL" > "$TD/sl.txt" 2>&1
  check sl_exports grep -qE '^ +1  MAINWNDPROC +nonresident +11:CC3A' "$TD/sl.txt"
fi

FX="${DUMPEXE_NE_FIXTURES:-}"
if [[ -n "$FX" && -d "$FX" ]]; then
  OP="$FX/c46f49eb21f9a789670358563cb2f2107d35737f04d94c26b76b877f684a9623.exe"
  if [[ -f "$OP" ]]; then
    "$BIN" -d "$OP" > "$TD/op.txt" 2>&1
    check outpost_inittask grep -qE '^1:2303  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 27\]' "$TD/op.txt"
    check outpost_reloc27 bash -c "awk '/Relocations segment 1 /{f=1} f&&/^ +27 /{print;exit}' '$TD/op.txt' | grep -qE 'far +import +KERNEL\.91 \(InitTask\) +1:2304'"
  fi
  for f in "$FX"/*.drv; do
    "$BIN" "$f" > "$TD/drv.txt" 2>&1
    if grep -q 'Module name (resident) *MCIAAP' "$TD/drv.txt"; then
      for e in '1  WEP' '2  DRIVERPROC' '3  AFFWNDPROC' '4  MCIDIALOGPROC'; do
        check "mciaap_${e##* }" grep -qE "^ +$e " "$TD/drv.txt"
      done
    fi
    if grep -q 'Module name (resident) *DIB' "$TD/drv.txt"; then
      for e in '1  BITBLT' '28  STRETCHDIBITS' '200  DO_POLYLINES'; do
        check "dib_${e##* }" grep -qE "^ +$e " "$TD/drv.txt"
      done
    fi
  done
else
  echo "SKIP fixture checks (DUMPEXE_NE_FIXTURES unset)"
fi
echo "p7_ne passed=$pass failed=$fail"
[[ $fail -eq 0 ]]
