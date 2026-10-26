#!/usr/bin/env bash
# P7: NE relocations (chained), entry table, exports from the resident and
# non-resident names tables, KERNEL/USER/GDI ordinal names, header-based
# detection. Optional fixtures (a large NE program named by its SHA-256, and the MCIAAP and DIB drivers) come from
# DUMPEXE_NE_FIXTURES; their checks are skipped when it is unset.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=fixtures.sh
source "$ROOT/tests/fixtures.sh"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p7-XXXXXX")"
trap 'rm -rf "$TD"' EXIT
pass=0; fail=0
check() { local name=$1; shift; if "$@"; then echo "PASS $name"; pass=$((pass + 1)); else echo "FAIL $name"; fail=$((fail + 1)); fi; }

FX08="$(fixture fx08 || true)"
if [[ -n "$FX08" && -f "$FX08" ]]; then
  "$BIN" -d "$FX08" > "$TD/fx08.txt" 2>&1
  check fx08_inittask grep -qE '^ +0000  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 0\]' "$TD/fx08.txt"
  check fx08_labels_kept grep -qE '^func_[0-9A-F]{4}:' "$TD/fx08.txt"
  check fx08_reloc_table grep -qE '^ +0  far +import +KERNEL\.91 \(InitTask\) +1:0001' "$TD/fx08.txt"
  check fx08_no_placeholder bash -c "! grep -qE 'lcall +0, 0xffff' '$TD/fx08.txt'"
  # Header, not extension: the same bytes named .COM and .SYS are still NE.
  cp "$FX08" "$TD/fx08.COM"; cp "$FX08" "$TD/fx08.SYS"; cp "$FX08" "$TD/noext"
  for f in fx08.COM fx08.SYS noext; do
    check "detect_$f" bash -c "'$BIN' --header-only '$TD/$f' | grep -q '^=== New Executable (NE)'"
  done
fi
FX04="$(fixture fx04 || true)"
if [[ -f "$FX04" ]]; then
  "$BIN" --header-only "$FX04" > "$TD/fx04.txt" 2>&1
  check fx04_exports grep -qE '^ +1  MAINWNDPROC +nonresident +11:CC3A' "$TD/fx04.txt"
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
# S5: no line cap in -d; a module with > 20000 distinct records lists all of them.
python3 - "$TD/many.exe" <<'PY'
import struct, sys
nseg, seglen, nrec = 3, 0x8000, 8000
data_off = 0x400
recs_len = 2 + nrec * 8
size = data_off + nseg * (seglen + recs_len) + 0x200
blob = bytearray(size)
blob[0:2] = b"MZ"; struct.pack_into("<I", blob, 0x3C, 0x40)
blob[0x40:0x42] = b"NE"
struct.pack_into("<H", blob, 0x40 + 0x1C, nseg)
struct.pack_into("<H", blob, 0x40 + 0x22, 0x40)
struct.pack_into("<H", blob, 0x40 + 0x26, 0x40 + nseg * 8)
struct.pack_into("<H", blob, 0x40 + 0x32, 4)
blob[0x40 + 0x36] = 2
p = data_off
for k in range(nseg):
    struct.pack_into("<HHHH", blob, 0x80 + k * 8, p >> 4, seglen, 0x100, seglen)
    r = p + seglen
    struct.pack_into("<H", blob, r, nrec)
    for i in range(nrec):
        # additive internal fixup, one site each
        struct.pack_into("<BBHBBH", blob, r + 2 + i * 8, 3, 4, i * 4, 1, 0, i)
    p = (r + recs_len + 15) & ~15
open(sys.argv[1], "wb").write(blob[:p + 0x10])
PY
"$BIN" -d --no-asm-file "$TD/many.exe" > "$TD/many.txt" 2>&1 || true
check relocs_no_cap bash -c "! grep -q 'output cap' '$TD/many.txt' && grep -q 'Relocations segment 3 (8000 records)' '$TD/many.txt' && grep -qE '^ *7999 ' '$TD/many.txt'"

# S2: -a seeds exports and far-call relocation sites, not only offset 0.
python3 - "$TD/roots.exe" <<'PY'
import struct, sys
blob = bytearray(0x400)
blob[0:2] = b"MZ"; struct.pack_into("<I", blob, 0x3C, 0x40)
h = 0x40
blob[h:h+2] = b"NE"
seg_tab, res_tab, mod_tab, imp_tab, ent_tab = 0x40, 0x48, 0x58, 0x5A, 0x62
struct.pack_into("<H", blob, h + 0x04, ent_tab)      # entry table
struct.pack_into("<H", blob, h + 0x06, 6)            # entry table length
struct.pack_into("<H", blob, h + 0x1C, 1)            # segments
struct.pack_into("<H", blob, h + 0x1E, 1)            # module refs
struct.pack_into("<H", blob, h + 0x22, seg_tab)
struct.pack_into("<H", blob, h + 0x26, res_tab)
struct.pack_into("<H", blob, h + 0x28, mod_tab)
struct.pack_into("<H", blob, h + 0x2A, imp_tab)
struct.pack_into("<H", blob, h + 0x32, 4)            # shift 16
blob[h + 0x36] = 2
struct.pack_into("<HH", blob, h + 0x14, 0, 1)        # CS:IP = 1:0000
code = bytearray(0x40)
code[0x00] = 0xC3                                    # ret (entry)
code[0x10:0x16] = bytes([0x9A, 0xFF, 0xFF, 0, 0, 0xC3])  # reached by nothing: far call KERNEL.91
code[0x20:0x22] = bytes([0x90, 0xC3])                # export 1
seg_off = 0x200
blob[seg_off:seg_off + len(code)] = code
struct.pack_into("<HHHH", blob, h + seg_tab, seg_off >> 4, len(code), 0x0100, len(code))
blob[h + res_tab:h + res_tab + 6] = b"\x05ROOTS"
struct.pack_into("<H", blob, h + res_tab + 6, 0)
blob[h + res_tab + 8] = 0
struct.pack_into("<H", blob, h + mod_tab, 1)         # module 1 -> imported names +1
blob[h + imp_tab:h + imp_tab + 8] = b"\x00\x06KERNEL"
blob[h + ent_tab:h + ent_tab + 6] = bytes([1, 1, 3, 0x20, 0, 0])  # 1 fixed entry in seg 1 at 0020h
r = seg_off + len(code)
struct.pack_into("<H", blob, r, 1)
struct.pack_into("<BBHHH", blob, r + 2, 3, 1, 0x11, 1, 91)  # far, import ordinal, KERNEL.91
open(sys.argv[1], "wb").write(blob[:r + 16])
PY
"$BIN" -a --no-asm-file "$TD/roots.exe" > "$TD/roots.txt" 2>&1 || true
check s2_reloc_root grep -qE '^ +0010  9AFFFF0000 +call +far KERNEL\.91  ; InitTask' "$TD/roots.txt"
check s2_export_root grep -qE '^ +0020  90 ' "$TD/roots.txt"
# R7: built-in ordinal names match the module name without case.
python3 -c "import sys; d=bytearray(open(sys.argv[1],'rb').read()); i=d.find(b'\x06KERNEL'); d[i+1:i+7]=b'kernel'; open(sys.argv[2],'wb').write(d)" "$TD/roots.exe" "$TD/rootsl.exe"
"$BIN" -a --no-asm-file "$TD/rootsl.exe" > "$TD/rootsl.txt" 2>&1 || true
check r7_module_case grep -qE 'call +far kernel\.91  ; InitTask' "$TD/rootsl.txt"

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
  [[ -f "$FX08" ]] && check rt_fx08 test "$(roundtrip "$FX08")" = IDENT
  [[ -f "$FX04" ]] && check rt_fx04 test "$(roundtrip "$FX04")" = IDENT
  if [[ -f "$FX08" ]]; then
    w=$(mktemp -d "$TD/sk-XXXXXX"); cp "$FX08" "$w/IN.EXE"
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
    check ne_big_inittask grep -qE '^ +2303  9AFFFF0000 +call +far KERNEL\.91  ; InitTask \[reloc 27\]' "$TD/op.txt"
    "$BIN" -a --no-asm-file "$OP" > "$TD/op_a.txt" 2>&1
    check ne_big_a_sites test "$(grep -o '\[reloc [0-9]*\]' "$TD/op_a.txt" | wc -l)" -ge 10000
    check ne_big_a_no_omit bash -c "! grep -q 'more blocks omitted' '$TD/op_a.txt'"
    check ne_big_reloc27 bash -c "awk '/Relocations segment 1 /{f=1} f&&/^ +27 /{print;exit}' '$TD/op.txt' | grep -qE 'far +import +KERNEL\.91 \(InitTask\) +1:2304'"
  fi
  for f in "$FX"/*.drv; do
    "$BIN" --header-only "$f" > "$TD/drv.txt" 2>&1
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
fixtures_exit "$fail"
