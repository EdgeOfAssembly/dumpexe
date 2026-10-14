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
  check ws_inittask grep -qE '^ +0000  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 0\]' "$TD/ws.txt"
  check ws_labels_kept grep -qE '^func_[0-9A-F]{4}:' "$TD/ws.txt"
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

# Review R3: 65535 records sharing one 32K-site chain must stay cheap.
python3 - "$TD/chain.exe" <<'PY'
import struct, sys
seglen = 0xFFF0
seg = bytearray(seglen)
for i in range(0, seglen - 2, 2):
    struct.pack_into("<H", seg, i, i + 2)
struct.pack_into("<H", seg, seglen - 2, 0xFFFF)
n = 65535
rel = struct.pack("<H", n) + struct.pack("<BBHHH", 5, 0, 0, 1, 0) * n
blob = bytearray(0x100) + seg + rel
blob[0:2] = b"MZ"
struct.pack_into("<I", blob, 0x3C, 0x40)
struct.pack_into("<H", blob, 0x40, 0x454E)
struct.pack_into("<H", blob, 0x40 + 0x16, 1)
struct.pack_into("<H", blob, 0x40 + 0x1C, 1)
struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
struct.pack_into("<H", blob, 0x40 + 0x26, 0x48)
struct.pack_into("<H", blob, 0x40 + 0x32, 4)
blob[0x40 + 0x36] = 2
struct.pack_into("<HHHH", blob, 0x80, 0x10, seglen, 0x100, seglen)
open(sys.argv[1], "wb").write(blob)
PY
check chain_bounded bash -c "timeout 20 '$BIN' -d '$TD/chain.exe' >/dev/null 2>&1; test \$? -ne 124"

# Review R3 (fuzz class): 1024 segments sharing one window and one big
# relocation table. The table is parsed once and the listing is capped.
python3 - "$TD/shared.exe" <<'PY'
import struct, sys
nseg = 1024
seglen = 0x4000
seg = bytearray(seglen)
for i in range(0, seglen - 2, 2):
    struct.pack_into("<H", seg, i, i + 2)
struct.pack_into("<H", seg, seglen - 2, 0xFFFF)
n = 9000
rel = struct.pack("<H", n) + b"".join(struct.pack("<BBHHH", 3, 1, (i * 4) % seglen, 1, i % 900 + 1) for i in range(n))
segtab_off = 0x40
data_off = 0x40 + 0x40 + nseg * 8 + 0x40
data_off = (data_off + 15) & ~15
blob = bytearray(data_off) + seg + rel
blob[0:2] = b"MZ"
struct.pack_into("<I", blob, 0x3C, 0x40)
struct.pack_into("<H", blob, 0x40, 0x454E)
struct.pack_into("<H", blob, 0x40 + 0x16, 1)
struct.pack_into("<H", blob, 0x40 + 0x1C, nseg)
struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
struct.pack_into("<H", blob, 0x40 + 0x26, 0x40 + nseg * 8)
struct.pack_into("<H", blob, 0x40 + 0x32, 4)
blob[0x40 + 0x36] = 2
for k in range(nseg):
    struct.pack_into("<HHHH", blob, 0x80 + k * 8, data_off >> 4, seglen, 0x100, seglen)
open(sys.argv[1], "wb").write(blob)
PY
check shared_fast bash -c "timeout 10 '$BIN' -a --no-asm-file '$TD/shared.exe' >'$TD/shared.txt' 2>&1"
check shared_alias grep -q 'Relocations segment 2: same table as segment 1' "$TD/shared.txt"
check shared_capped test "$(stat -c %s "$TD/shared.txt")" -lt 50000000

# P7 round trip: per-segment --uasm, uasm -bin, bin2ne, byte-identical.
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
B2N="$ROOT/bin2ne"
roundtrip() { # $1 = NE file; prints IDENT or a reason
  local w; w=$(mktemp -d "$TD/rt-XXXXXX"); cp "$1" "$w/IN.EXE"
  (cd "$w" && "$BIN" --uasm --uasm-bin "$UASM_BIN" IN.EXE >/dev/null 2>err.txt) || { echo "dumpexe rc"; return; }
  grep -q 'NOT VERIFIED' "$w/err.txt" && { echo "not verified"; return; }
  for a in "$w"/IN_seg*.asm; do
    (cd "$w" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$(basename "${a%.asm}").bin" "$(basename "$a")" >/dev/null 2>&1) || { echo "uasm $a"; return; }
  done
  (cd "$w" && "$B2N" IN.nemap OUT.EXE) || { echo "bin2ne"; return; }
  cmp -s "$w/OUT.EXE" "$w/IN.EXE" && echo IDENT || echo DIFF
}
if UASM_BIN="$(uasm_resolve)" && [[ -x "$B2N" ]]; then
  check bin2ne_usage bash -c "'$B2N' | grep -q '^usage: bin2ne MAP OUT'"
  [[ -f "$WS" ]] && check rt_winsmall test "$(roundtrip "$WS")" = IDENT
  [[ -f "$SL" ]] && check rt_simlifew test "$(roundtrip "$SL")" = IDENT
  if [[ -f "$WS" ]]; then
    w=$(mktemp -d "$TD/sk-XXXXXX"); cp "$WS" "$w/IN.EXE"
    (cd "$w" && "$BIN" --uasm --uasm-bin "$UASM_BIN" IN.EXE >/dev/null 2>&1) || true
    check skel_has_no_code bash -c "! cmp -s '$w/IN.neskel' '$w/IN.EXE'"
    check seg1_mnemonic grep -qE '^; lines: mnemonic [1-9][0-9]* ' "$w/IN_seg1.asm"
    # S3: hostile offsets and a missing segment are errors, not silent output.
    for a in "$w"/IN_seg*.asm; do
      (cd "$w" && env -u UASM -u INCLUDE "$UASM_BIN" -bin -nologo -Fo"$(basename "${a%.asm}").bin" "$(basename "$a")" >/dev/null 2>&1) || true
    done
    check map_has_segs grep -qE '^segs( [0-9]+)+$' "$w/IN.nemap"
    sed -E 's/^seg ([0-9]+) [0-9]+ /seg \1 18446744073709551615 /' "$w/IN.nemap" > "$w/wrap.nemap"
    check bin2ne_off_wrap bash -c "cd '$w' && ! '$B2N' wrap.nemap W.EXE 2>err && grep -q 'past the skeleton end' err"
    grep -v '^seg ' "$w/IN.nemap" > "$w/miss.nemap"
    check bin2ne_missing_seg bash -c "cd '$w' && ! '$B2N' miss.nemap M.EXE 2>err && grep -q 'missing from the map' err"
    grep -v '^segs' "$w/IN.nemap" > "$w/old.nemap"
    check bin2ne_needs_segs bash -c "cd '$w' && ! '$B2N' old.nemap O.EXE 2>/dev/null"
  fi
  if [[ -n "${DUMPEXE_NE_FIXTURES:-}" && -d "$DUMPEXE_NE_FIXTURES" ]]; then
    for f in "$DUMPEXE_NE_FIXTURES"/*.exe "$DUMPEXE_NE_FIXTURES"/*.dll "$DUMPEXE_NE_FIXTURES"/*.drv; do
      [[ -f "$f" ]] && check "rt_$(basename "$f" | cut -c1-8)" test "$(roundtrip "$f")" = IDENT
    done
  fi
else
  echo "SKIP round trip (no uasm or bin2ne)"
fi

FX="${DUMPEXE_NE_FIXTURES:-}"
if [[ -n "$FX" && -d "$FX" ]]; then
  OP="$FX/c46f49eb21f9a789670358563cb2f2107d35737f04d94c26b76b877f684a9623.exe"
  if [[ -f "$OP" ]]; then
    "$BIN" -d "$OP" > "$TD/op.txt" 2>&1
    check outpost_inittask grep -qE '^ +2303  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 27\]' "$TD/op.txt"
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
