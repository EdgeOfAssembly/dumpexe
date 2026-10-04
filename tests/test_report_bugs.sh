#!/usr/bin/env bash
# Regression tests for dumpexe 2.3 report/header bugs.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

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

TD="$(mktemp -d /tmp/dumpexe-bugs-XXXXXX)"
cleanup() {
  rm -rf "$TD"
  rm -f "$ROOT/games/cutemouse/bin/ctmouse.repack.exe" \
        "$ROOT/games/cutemouse/bin/ctmouse.asm"
}
trap cleanup EXIT

python3 - "$TD" << 'PY'
import struct, sys
from pathlib import Path

td = Path(sys.argv[1])

def mz_prefix(total, e_lfanew, header_paras=2, mem_extra=0, mem_max=0xFFFF,
              checksum=0, overlay=0, ip=0, cs=0):
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total > 0 and total % 512 == 0:
        final_len = 0
    hdr = bytearray(struct.pack(
        "<14H", 0x5A4D, final_len, num_blocks, 0, header_paras,
        mem_extra, mem_max, 0, 0x200, checksum, ip, cs, 0x1C, overlay))
    if len(hdr) < 0x40:
        hdr.extend(b"\x00" * (0x40 - len(hdr)))
    struct.pack_into("<I", hdr, 0x3C, e_lfanew)
    return bytes(hdr)

# Bug 3: NEEDLE\0\0 must not be treated as an LE/LX image.
img = b"\xb8\x00\x4c\xcd\x21" + b"\x90" * 11 + b"NEEDLE\x00\x00" + b"\x00" * 8
size = 32 + len(img)
h = struct.pack("<14H", 0x5A4D, size % 512, (size + 511) // 512, 0, 2, 0,
                0xFFFF, 0, 0x100, 0, 0, 0, 0x1C, 0) + b"\x00" * 4
(td / "le_fp.exe").write_bytes(h + img)

# Sane LE at e_lfanew (byte/word order 0, CPU 2, page size 4096).
le = bytearray(0x2C)
le[0:4] = b"LE\x00\x00"
struct.pack_into("<H", le, 8, 2)
struct.pack_into("<I", le, 0x28, 0x1000)
blob = bytes(le)
(td / "le_ok.exe").write_bytes(mz_prefix(0x40 + len(blob), 0x40) + blob)

# Bug 4: RTL year 1983,90 plus enough near frames to cross the TP threshold.
frames = b"\x55\x8b\xec" * 16
text = b"Runtime error " + b"Portions Copyright (c) 1983,90 Borland"
payload = frames + text
hdr = struct.pack("<14H", 0x5A4D, (32 + len(payload)) % 512, 1, 0, 2, 0,
                  0xFFFF, 0, 0x200, 0, 0, 0, 0x1C, 0)
hdr = hdr.ljust(32, b"\x00")
(td / "tp60.exe").write_bytes(hdr + payload)

# Bug 7: declared size (4*512) is larger than the 64-byte file. final_len is 0.
short_hdr = struct.pack("<14H", 0x5A4D, 0, 4, 0, 2, 0x10, 0x20, 0, 0x200,
                        0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "short.exe").write_bytes(short_hdr + b"\x90" * 32)

# Bug 7: e_cblp = 0xFFFF.
cblp_hdr = struct.pack("<14H", 0x5A4D, 0xFFFF, 1, 0, 2, 0, 0xFFFF, 0, 0x200,
                       0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "cblp.exe").write_bytes(cblp_hdr + b"\x90" * 32)

# Bug 8: NE magic at e_lfanew, segment table does not fit.
ne = bytearray(64)
ne[0:2] = b"NE"
struct.pack_into("<H", ne, 0x1C, 4)   # cseg
struct.pack_into("<H", ne, 0x22, 64)  # segtab immediately after the header
ne_blob = bytes(ne)
(td / "ne_trunc.exe").write_bytes(mz_prefix(0x40 + len(ne_blob), 0x40) + ne_blob)

# Real-enough NE: one segment entry and an empty resident-name table.
ne_ok = bytearray(64)
ne_ok[0:2] = b"NE"
struct.pack_into("<H", ne_ok, 0x1C, 1)
struct.pack_into("<H", ne_ok, 0x22, 64)
struct.pack_into("<H", ne_ok, 0x26, 72)  # restab -> terminating 0
ok_blob = bytes(ne_ok) + bytes(8) + b"\x00"
(td / "ne_ok.exe").write_bytes(mz_prefix(0x40 + len(ok_blob), 0x40) + ok_blob)

# Bug 9: normal MZ with known paragraph alloc, checksum, overlay, extra tail.
body = b"\x90" * 32
extra = b"\x00" * 10
total_decl = 32 + len(body)  # 64
mz = struct.pack("<14H", 0x5A4D, total_decl, 1, 0, 2, 14, 16, 0, 0x200,
                 0x1234, 0, 0, 0x1C, 7).ljust(32, b"\x00")
(td / "mz_json.exe").write_bytes(mz + body + extra)

# One relocation: header is 2 paragraphs, entry lives at off_reloc 0x1C.
# RelocEntry is offset then segment. File location = header + seg*16 + off.
reloc = struct.pack("<HH", 0x0002, 0x0001)
img = b"\x90" * 16
total = 32 + len(img)
one = struct.pack("<14H", 0x5A4D, total % 512, (total + 511) // 512, 1, 2,
                  0, 0xFFFF, 0, 0x200, 0, 0, 0, 0x1C, 0)
assert len(one) == 28
(td / "one_reloc.exe").write_bytes(one + reloc + img)

# COM (flat) for entry IP / file size. Too short to contain a PSP.
(td / "tiny.com").write_bytes(b"\xc3")

# Embedded PSP: INT 20h, empty command tail ending in CR, RET at file 0x100.
psp = bytearray(0x101)
psp[0] = 0xCD
psp[1] = 0x20
psp[0x80] = 0
psp[0x81] = 0x0D
psp[0x100] = 0xC3
(td / "psp.com").write_bytes(psp)

# Bare ",90" with a TP-sized RTL must not become 6.0 (no copyright context).
bare = (b"\x55\x8b\xec" * 16) + b"Runtime error " + (b"\x00" * 64) + b",90"
bare_hdr = struct.pack("<14H", 0x5A4D, (32 + len(bare)) % 512, 1, 0, 2, 0,
                       0xFFFF, 0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "tp_bare90.exe").write_bytes(bare_hdr + bare)

# ",90" counts when "Portions Copyright" is within 40 bytes before the comma.
near = (b"\x55\x8b\xec" * 16) + b"Runtime error Portions Copyright,90"
near_hdr = struct.pack("<14H", 0x5A4D, (32 + len(near)) % 512, 1, 0, 2, 0,
                       0xFFFF, 0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "tp_portions90.exe").write_bytes(near_hdr + near)

# PKLITE banner.
pk = b"PKLITE Copr. 1990 PKWARE"
pk_hdr = struct.pack("<14H", 0x5A4D, (32 + len(pk)) % 512, 1, 0, 2, 0, 0xFFFF,
                     0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "pklite.exe").write_bytes(pk_hdr + pk)

# Borland C++ literal banner (MZ).
bc = b"Borland C++"
bc_hdr = struct.pack("<14H", 0x5A4D, (32 + len(bc)) % 512, 1, 0, 2, 0, 0xFFFF,
                     0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "borland.exe").write_bytes(bc_hdr + bc)

# COM containing the Turbo C RTL banner.
(td / "turboc.com").write_bytes(b"\xc3Turbo-C - Copyright")
print("fixtures ok", td)
PY

# Bug 1: .sym load must not trip ASan stack-use-after-scope.
check asan_ctmouse bash -c "
  set -euo pipefail
  make -C '$ROOT' asan
  err=\$(mktemp)
  out=\$(mktemp)
  set +e
  '$ROOT/dumpexe-asan' -d --no-asm-file '$ROOT/games/cutemouse/bin/ctmouse.exe' >\"\$out\" 2>\"\$err\"
  rc=\$?
  set -e
  rm -f '$ROOT/games/cutemouse/bin/ctmouse.repack.exe' \
        '$ROOT/games/cutemouse/bin/ctmouse.asm'
  if grep -q AddressSanitizer \"\$err\" || grep -q stack-use-after-scope \"\$err\"; then
    echo 'sanitizer output:' >&2
    cat \"\$err\" >&2
    exit 1
  fi
  if [[ \$rc -ne 0 ]]; then
    echo \"asan exit \$rc\" >&2
    cat \"\$err\" >&2
    exit 1
  fi
  rm -f \"\$err\" \"\$out\"
"

check le_no_false_positive bash -c "
  set -euo pipefail
  '$BIN' '$TD/le_fp.exe' >'$TD/le_fp.out'
  ! grep -q 'LE/LX' '$TD/le_fp.out'
"

check le_sane_header bash -c "
  set -euo pipefail
  '$BIN' '$TD/le_ok.exe' >'$TD/le_ok.out'
  grep -q 'LE/LX' '$TD/le_ok.out'
"

check tp60_not_makecat bash -c "
  set -euo pipefail
  '$BIN' '$TD/tp60.exe' >'$TD/tp60.out'
  grep -q 'Turbo Pascal 6.0' '$TD/tp60.out'
  ! grep -q 'MAKECAT.BAT' '$TD/tp60.out'
  ! grep -q 'Turbo Pascal 5.5' '$TD/tp60.out'
"

check tp_bare90_stays_55 bash -c "
  set -euo pipefail
  '$BIN' '$TD/tp_bare90.exe' >'$TD/tp_bare.out'
  grep -q 'Turbo Pascal 5.5' '$TD/tp_bare.out'
  ! grep -q 'Turbo Pascal 6.0' '$TD/tp_bare.out'
  ! grep -q 'MAKECAT.BAT' '$TD/tp_bare.out'
"

check tp_portions90_is_60 bash -c "
  set -euo pipefail
  '$BIN' '$TD/tp_portions90.exe' >'$TD/tp_portions.out'
  grep -q 'Turbo Pascal 6.0' '$TD/tp_portions.out'
  ! grep -q 'MAKECAT.BAT' '$TD/tp_portions.out'
  ! grep -q 'Turbo Pascal 5.5' '$TD/tp_portions.out'
"

CAT="$ROOT/games/catacomb/bin/CATACOMB.EXE"
if [[ -f "$CAT" ]]; then
  check cat_still_55 bash -c "
    set -euo pipefail
    '$BIN' '$CAT' >'$TD/cat.out'
    grep -q 'Turbo Pascal 5.5' '$TD/cat.out'
    ! grep -q 'MAKECAT.BAT' '$TD/cat.out'
  "
fi

short_mz_clamp() {
  "$BIN" "$TD/short.exe" >"$TD/short.out" 2>"$TD/short.err"
  grep -q 'Warning:' "$TD/short.err"
  python3 - "$TD/short.out" "$TD/short.exe" << 'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(errors="replace")
fs = Path(sys.argv[2]).stat().st_size
li = None
for line in text.splitlines():
    if line.startswith("Load Image Size"):
        m = re.search(r"\(\s*([0-9]+)\.", line)
        if not m:
            raise SystemExit("no load-image decimal: " + line)
        li = int(m.group(1))
        break
if li is None:
    raise SystemExit("missing Load Image Size")
if li > fs:
    raise SystemExit(f"load image {li} > file {fs}")
if li != fs - 32:
    raise SystemExit(f"expected clamped load image {fs - 32}, got {li}")
PY
}
check short_mz_clamp short_mz_clamp

check cblp_warning bash -c "
  set -euo pipefail
  '$BIN' '$TD/cblp.exe' >'$TD/cblp.out' 2>'$TD/cblp.err'
  grep -q 'Warning:' '$TD/cblp.err'
  grep -q 'final_len' '$TD/cblp.err'
"

check alloc_paragraphs bash -c "
  set -euo pipefail
  '$BIN' '$TD/mz_json.exe' >'$TD/mz.out' 2>'$TD/mz.err'
  grep -q '000Eh paragraphs (224 bytes)' '$TD/mz.out'
  grep -q '0010h paragraphs (256 bytes)' '$TD/mz.out'
  '$BIN' '$TD/le_fp.exe' >'$TD/le_fp_units.out'
  grep -q 'paragraphs' '$TD/le_fp_units.out'
  grep -q 'all available' '$TD/le_fp_units.out'
"

check ne_trunc_falls_back bash -c "
  set -euo pipefail
  '$BIN' '$TD/ne_trunc.exe' >'$TD/ne_trunc.out' 2>'$TD/ne_trunc.err'
  grep -qE 'DOS File Size|Program Entry Point' '$TD/ne_trunc.out'
  grep -q 'Warning:' '$TD/ne_trunc.err'
  grep -q 'Segment table truncated' '$TD/ne_trunc.err'
"

check ne_ok_not_mz_only bash -c "
  set -euo pipefail
  '$BIN' '$TD/ne_ok.exe' >'$TD/ne_ok.out' 2>'$TD/ne_ok.err'
  grep -q 'New Executable (NE)' '$TD/ne_ok.out'
  ! grep -q 'DOS File Size' '$TD/ne_ok.out'
"

json_mz_22() {
  "$BIN" --json "$TD/mz_json.exe" >"$TD/mz.json"
  python3 - "$TD/mz.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["tool"] == "dumpexe", d.get("tool")
assert d["version"] == "2.3", d.get("version")
mz = d["mz"]
assert mz["extra_bytes"] == 10, mz.get("extra_bytes")
assert mz["min_alloc"] == 14, mz.get("min_alloc")
assert mz["max_alloc"] == 16, mz.get("max_alloc")
assert mz["checksum"] == 0x1234, mz.get("checksum")
assert mz["overlay_number"] == 7, mz.get("overlay_number")
assert "overlay" not in mz
assert mz["relocs"] == [], mz.get("relocs")
assert "relocs_truncated" not in mz
PY
}
check json_mz_22 json_mz_22

json_mz_relocs() {
  "$BIN" --json "$TD/one_reloc.exe" >"$TD/one_reloc.json"
  python3 - "$TD/one_reloc.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
mz = d["mz"]
assert mz["reloc_count"] == 1, mz.get("reloc_count")
assert isinstance(mz["relocs"], list)
assert len(mz["relocs"]) == mz["reloc_count"]
entry = mz["relocs"][0]
assert entry["segment"] == "0001", entry
assert entry["offset"] == "0002", entry
assert entry["file_offset"] == 32 + 1 * 16 + 2, entry
assert "relocs_truncated" not in mz
PY
}
check json_mz_relocs json_mz_relocs

json_com_entry() {
  "$BIN" --json "$TD/tiny.com" >"$TD/com.json"
  "$BIN" --json --psp "$TD/tiny.com" >"$TD/com_psp_flag.json"
  python3 - "$TD/com.json" "$TD/com_psp_flag.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["version"] == "2.3"
assert d["format"] == "com"
assert d["com"]["file_size"] == 1
assert d["com"]["entry_ip"] == "0100"
assert d["com"]["load_model"] == "org100", d["com"]
assert d["com"]["entry_file_offset"] == 0, d["com"]
forced = json.load(open(sys.argv[2]))
assert forced["com"]["load_model"] == "psp", forced["com"]
assert forced["com"]["entry_ip"] == "0100"
assert forced["com"]["entry_file_offset"] == 0x100, forced["com"]
PY
}
check json_com_entry json_com_entry

json_com_psp() {
  "$BIN" --json "$TD/psp.com" >"$TD/psp.json"
  "$BIN" --json --no-psp "$TD/psp.com" >"$TD/psp_nopsp.json"
  python3 - "$TD/psp.json" "$TD/psp_nopsp.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["com"]["load_model"] == "psp", d["com"]
assert d["com"]["entry_ip"] == "0100"
assert d["com"]["entry_file_offset"] == 0x100, d["com"]
plain = json.load(open(sys.argv[2]))
assert plain["com"]["load_model"] == "org100", plain["com"]
assert plain["com"]["entry_file_offset"] == 0, plain["com"]
assert plain["com"]["entry_ip"] == "0100"
PY
}
check json_com_psp json_com_psp

check version_capstone bash -c "
  set -euo pipefail
  '$BIN' -v >'$TD/ver.txt'
  grep -q 'dumpexe 2.3' '$TD/ver.txt'
  grep -Eq 'Capstone[[:space:]]+[0-9]+\\.[0-9]+' '$TD/ver.txt'
"

check pklite_fingerprint bash -c "
  set -euo pipefail
  '$BIN' '$TD/pklite.exe' >'$TD/pk.out'
  grep -q 'Packer:      PKLITE' '$TD/pk.out'
"

check borland_cpp_fingerprint bash -c "
  set -euo pipefail
  '$BIN' '$TD/borland.exe' >'$TD/borland.out'
  grep -q 'Compiler:    Borland C++' '$TD/borland.out'
"

check com_turboc_fingerprint bash -c "
  set -euo pipefail
  '$BIN' '$TD/turboc.com' >'$TD/turboc.out'
  grep -q 'Compiler:    Turbo C' '$TD/turboc.out'
"

ICON="$ROOT/games/icon-quest-for-the-ring/ICON/ICON.EXE"
if [[ -f "$ICON" ]]; then
  check icon_not_turbo_c bash -c "! '$BIN' '$ICON' | grep -q 'Turbo C'"
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
