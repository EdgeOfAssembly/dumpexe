#!/usr/bin/env bash
# Regression tests for dumpexe 2.9 report/header bugs.
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
export TD
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

def write_ne(name, align=0, sector=0, resource=None, module=b"", description=b""):
    """MZ stub plus one NE segment. align is the uint16 at NE offset 0x32."""
    seg = struct.pack("<4H", sector, 16, 0, 16)
    cursor = 64 + len(seg)
    rsrctab = 0
    res_bytes = b""
    if resource is not None:
        rsrctab = cursor
        ashift, roff, rlen = resource
        res_bytes = struct.pack("<H", ashift)
        res_bytes += struct.pack("<HHI", 0x800A, 1, 0)
        res_bytes += struct.pack("<6H", roff, rlen, 0, 0x8001, 0, 0)
        res_bytes += struct.pack("<H", 0)
        cursor += len(res_bytes)
    restab = cursor
    if module:
        resident = bytes([len(module)]) + module + struct.pack("<H", 0) + b"\x00"
    else:
        resident = b"\x00"
    cursor += len(resident)
    nrestab = 0
    nr = b""
    if description:
        nrestab = 0x40 + cursor
        nr = bytes([len(description)]) + description
    ne_img = bytearray(64)
    ne_img[0:2] = b"NE"
    struct.pack_into("<H", ne_img, 0x1C, 1)
    struct.pack_into("<H", ne_img, 0x22, 64)
    struct.pack_into("<H", ne_img, 0x24, rsrctab)
    struct.pack_into("<H", ne_img, 0x26, restab)
    struct.pack_into("<I", ne_img, 0x2C, nrestab)
    struct.pack_into("<H", ne_img, 0x32, align)
    blob = bytes(ne_img) + seg + res_bytes + resident + nr
    (td / name).write_bytes(mz_prefix(0x40 + len(blob), 0x40) + blob)

write_ne("ne_align9.exe", align=9, sector=1)
write_ne("ne_align70.exe", align=70, sector=1)
write_ne("ne_res70.exe", align=9, sector=1, resource=(70, 1, 1))
write_ne(
    "ne_json_quote.exe",
    align=9,
    sector=1,
    module=b'A"B',
    description=b'say "hi"' + bytes([0x5C, 0x0A]),
)

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

# PKLITE banner only. String starts at file 0x20. CS and IP stay 0.
pk = b"PKLITE Copr. 1990 PKWARE"
pk_hdr = struct.pack("<14H", 0x5A4D, (32 + len(pk)) % 512, 1, 0, 2, 0, 0xFFFF,
                     0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
pk_blob = pk_hdr + pk
assert pk_blob[0x20:0x26] == b"PKLITE"
(td / "pklite.exe").write_bytes(pk_blob)

def build_mz(image, crlc=0, paras=2, sp=0x200, ip=0, cs=0,
             lfarlc=0x1C, ovno=0, at_1c=b""):
    header_bytes = paras * 16
    if header_bytes < 0x1C + len(at_1c):
        raise SystemExit("header too small for marker")
    total = header_bytes + len(image)
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total % 512 == 0:
        final_len = 0
    hdr = bytearray(header_bytes)
    struct.pack_into(
        "<14H", hdr, 0,
        0x5A4D, final_len, num_blocks, crlc, paras,
        0, 0xFFFF, 0, sp, 0, ip, cs & 0xFFFF, lfarlc, ovno)
    hdr[0x1C:0x1C + len(at_1c)] = at_1c
    return bytes(hdr) + image

# Structural PKLITE 1.12: header longer than 32 bytes, second prologue at entry.
pklite_pat = bytes([0xB8, 0x3C, 0x28, 0xBA, 0xCF, 0x08, 0x05, 0x00, 0x00, 0x3B, 0x06])
(td / "pklite_112.exe").write_bytes(build_mz(
    pklite_pat + b"\x90" * 16,
    crlc=0, paras=4, sp=0x200, ip=0x100, cs=0xFFF0,
    lfarlc=0x1C, ovno=0, at_1c=struct.pack("<H", 0x310C)))

lz_stub = bytes([0x06, 0x0E, 0x1F, 0x8B]) + b"\x90" * 8
(td / "lz91.exe").write_bytes(build_mz(
    lz_stub, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ91"))
(td / "lz09.exe").write_bytes(build_mz(
    lz_stub, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ09"))
# LZ91 at 0x1C but the entry stub is not 06 0E 1F 8B.
(td / "lz91_nostub.exe").write_bytes(build_mz(
    b"\x90" * 8, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ91"))
# Same stub, but e_crlc != 0, so the header gate fails.
(td / "lz91_relocs.exe").write_bytes(build_mz(
    lz_stub, crlc=1, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ91"))
# N3: PUSH AX then 06 0E 1F 8B, plus an LHA banner in the compressed-looking body.
push_stub = bytes([0x50, 0x06, 0x0E, 0x1F, 0x8B]) + b" with LHA Version 2.05" + b"\x90" * 4
(td / "lz91_push.exe").write_bytes(build_mz(
    push_stub, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ91"))
(td / "lz09_push.exe").write_bytes(build_mz(
    push_stub, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"LZ09"))

# EXEPACK: IP 16, RB at EP-2, epilog inside [EP+200, EP+300). No English sentence.
ex_image = bytearray(16 + 220 + 7)
ex_image[14] = 0x52
ex_image[15] = 0x42
ex_image[16 + 220:16 + 220 + 7] = bytes([0xCD, 0x21, 0xB8, 0xFF, 0x4C, 0xCD, 0x21])
(td / "exepack.exe").write_bytes(build_mz(
    bytes(ex_image), crlc=0, paras=2, sp=0x80, ip=16, cs=0,
    lfarlc=0x1C, ovno=0))

# The English stub sentence with an IP that is neither 16 nor 18.
(td / "exepack_sentence.exe").write_bytes(build_mz(
    b"Packed file is corrupt", crlc=0, paras=2, sp=0x200, ip=9, cs=0,
    lfarlc=0x1C, ovno=0))

# Borland C++ literal banner (MZ).
bc = b"Borland C++"
bc_hdr = struct.pack("<14H", 0x5A4D, (32 + len(bc)) % 512, 1, 0, 2, 0, 0xFFFF,
                     0, 0x200, 0, 0, 0, 0x1C, 0).ljust(32, b"\x00")
(td / "borland.exe").write_bytes(bc_hdr + bc)

# COM containing the Turbo C RTL banner.
(td / "turboc.com").write_bytes(b"\xc3Turbo-C - Copyright")

# DIET marker only: four bytes at 0x1C, no Deark DIET stub.
(td / "diet4.exe").write_bytes(build_mz(
    b"\x90" * 16, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0, at_1c=b"DIET"))

# e_cparhdr == 2, Deark EXE stub at file offset 77 (codestart-32+77).
diet_sig = bytes([0x8E, 0xDB, 0x8E, 0xC0, 0x33, 0xF6, 0x33, 0xFF, 0xB9])
diet_image = b"\x90" * (77 - 32) + diet_sig + b"\x90" * 8
diet_exe = build_mz(diet_image, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0)
assert diet_exe[8:10] == struct.pack("<H", 2)
assert diet_exe[77:77 + len(diet_sig)] == diet_sig
(td / "diet_exe.exe").write_bytes(diet_exe)

# COM 1.00: BF plus the old stub at offset 17. Not an MZ.
diet_old = bytes([0xFD, 0xF3, 0xA5, 0xFC, 0x8B, 0xF7, 0xBF, 0x00])
diet_com = bytearray(40)
diet_com[0] = 0xBF
diet_com[17:25] = diet_old
(td / "diet_com.com").write_bytes(diet_com)

# Data 1.02: 9D 89 + dlz at the start. A leading BE without the stubs is not DIET.
diet_data = bytearray(16)
diet_data[0:2] = bytes([0x9D, 0x89])
diet_data[2:5] = b"dlz"
(td / "diet_data.bin").write_bytes(diet_data)
(td / "diet_be_only.com").write_bytes(bytes([0xBE]) + b"\x00" * 48)

# LHA sentence without a header window.
(td / "lharc_banner.exe").write_bytes(build_mz(
    b"Archive created with LHA Version 2.13" + b"\x90" * 16,
    crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))

def lha_window(method, level, hsize, fnlen=0):
    win = bytearray(22)
    win[0] = hsize & 0xFF
    win[1] = (hsize >> 8) & 0xFF
    win[2:7] = method
    win[20] = level
    win[21] = fnlen
    return bytes(win)

def lha_member(method, level, hsize, comp_size=4, pad_len=4):
    """Level 0/1 header with a real checksum and a packed size that fits."""
    raw = bytearray(2 + hsize + pad_len)
    raw[0] = hsize & 0xFF
    raw[2:7] = method
    struct.pack_into("<I", raw, 7, comp_size)
    raw[20] = level
    raw[1] = sum(raw[2:2 + hsize]) & 0xFF
    return bytes(raw)

# Level 0: checksummed -lh5- at the end of a short MZ image (SFX trailer).
lha_l0 = build_mz(lha_member(b"-lh5-", 0, 22),
                  crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0)
assert lha_l0[34:39] == b"-lh5-"
assert lha_l0[32 + 20] == 0
assert lha_l0[33] == sum(lha_l0[34:34 + 22]) & 0xFF
(td / "lha_l0.exe").write_bytes(lha_l0)

# Level 1: hsize 25, fnlen 0. 22+0+5 <= 2+25. Checksummed, still in the trailer.
(td / "lha_l1.exe").write_bytes(build_mz(
    lha_member(b"-lh0-", 1, 25),
    crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))

# Same checksummed header buried in the middle of a long image.
lha_mid_member = lha_member(b"-lh5-", 0, 22)
(td / "lha_mid.exe").write_bytes(build_mz(
    b"\x90" * 200 + lha_mid_member + b"\x90" * 200,
    crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))

# Bare -lh5- and a possible-but-unknown -the- with an otherwise valid window.
(td / "lha_bare.exe").write_bytes(build_mz(
    b"-lh5-" + b"\x00" * 32, crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))
(td / "lha_the.exe").write_bytes(build_mz(
    lha_window(b"-the-", 0, 22) + b"\x90" * 8,
    crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))
# SWG method is not LHarc even with a level-0 size check.
(td / "lha_swg.exe").write_bytes(build_mz(
    lha_window(b"-sw0-", 0, 22) + b"\x90" * 8,
    crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0))

# Tiny real MZ (ret). Not a packer.
tiny = build_mz(b"\xc3", crlc=0, paras=2, ip=0, cs=0, lfarlc=0x1C, ovno=0)
(td / "tiny_mz.exe").write_bytes(tiny)
# L11-J: 32-byte header and a 32-byte load image. --max-image=31 refuses.
(td / "cap32.exe").write_bytes(build_mz(b"\xc3" + (b"\x00" * 31)))
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

make -C "$ROOT" asan

check ne_align9_sector512 bash -c "
  set -euo pipefail
  err=\$(mktemp)
  out=\$(mktemp)
  set +e
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    '$ROOT/dumpexe-asan' '$TD/ne_align9.exe' >\"\$out\" 2>\"\$err\"
  rc=\$?
  set -e
  if grep -q 'runtime error: shift' \"\$err\"; then
    echo 'shift ub:' >&2
    cat \"\$err\" >&2
    exit 1
  fi
  if [[ \$rc -ne 0 ]]; then
    echo \"asan exit \$rc\" >&2
    cat \"\$err\" >&2
    exit 1
  fi
  grep -q 'sector size 512' \"\$out\"
  grep -q '200h' \"\$out\"
  grep -q 'New Executable (NE)' \"\$out\"
  ! grep -q 'out of range' \"\$out\"
  rm -f \"\$err\" \"\$out\"
"

check ne_align70_out_of_range bash -c "
  set -euo pipefail
  err=\$(mktemp)
  out=\$(mktemp)
  set +e
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    '$ROOT/dumpexe-asan' '$TD/ne_align70.exe' >\"\$out\" 2>\"\$err\"
  rc=\$?
  set -e
  if grep -q 'runtime error: shift' \"\$err\"; then
    echo 'shift ub:' >&2
    cat \"\$err\" >&2
    exit 1
  fi
  if [[ \$rc -ne 0 ]]; then
    echo \"asan exit \$rc\" >&2
    cat \"\$err\" >&2
    exit 1
  fi
  grep -q 'Warning: NE sector alignment shift 70 is out of range' \"\$err\"
  grep -q 'out of range' \"\$out\"
  grep -q 'New Executable (NE)' \"\$out\"
  ! grep -q 'sector size' \"\$out\"
  rm -f \"\$err\" \"\$out\"
"

check ne_resource_align70_out_of_range bash -c "
  set -euo pipefail
  err=\$(mktemp)
  out=\$(mktemp)
  set +e
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    '$ROOT/dumpexe-asan' '$TD/ne_res70.exe' >\"\$out\" 2>\"\$err\"
  rc=\$?
  set -e
  if grep -q 'runtime error: shift' \"\$err\"; then
    echo 'shift ub:' >&2
    cat \"\$err\" >&2
    exit 1
  fi
  if [[ \$rc -ne 0 ]]; then
    echo \"asan exit \$rc\" >&2
    cat \"\$err\" >&2
    exit 1
  fi
  grep -q 'Warning: NE resource alignment shift 70 is out of range' \"\$err\"
  grep -q 'RCDATA' \"\$out\"
  grep -q 'off=0h' \"\$out\"
  grep -q 'len=0h' \"\$out\"
  grep -q 'New Executable (NE)' \"\$out\"
  rm -f \"\$err\" \"\$out\"
"

check ne_json_module_quote bash -c "
  set -euo pipefail
  err=\$(mktemp)
  out=\$(mktemp)
  set +e
  UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
    '$ROOT/dumpexe-asan' --json '$TD/ne_json_quote.exe' >\"\$out\" 2>\"\$err\"
  rc=\$?
  set -e
  if grep -q 'runtime error: shift' \"\$err\"; then
    echo 'shift ub:' >&2
    cat \"\$err\" >&2
    exit 1
  fi
  if [[ \$rc -ne 0 ]]; then
    echo \"asan exit \$rc\" >&2
    cat \"\$err\" >&2
    exit 1
  fi
  python3 - \"\$out\" '$TD/ne_json_quote.exe' << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d[\"module\"] == 'A\"B', d.get(\"module\")
assert '\"' in d[\"module\"]
desc = d[\"description\"]
assert desc == 'say \"hi\"' + chr(0x5C) + \"\\n\", repr(desc)
assert '\"' in desc and \"\\\\\" in desc and \"\\n\" in desc
assert d[\"file\"] == sys.argv[2], d.get(\"file\")
PY
  rm -f \"\$err\" \"\$out\"
"

json_mz_22() {
  "$BIN" --json "$TD/mz_json.exe" >"$TD/mz.json"
  python3 - "$TD/mz.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["tool"] == "dumpexe", d.get("tool")
assert d["version"] == "2.26", d.get("version")
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
assert d["version"] == "2.26"
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
  grep -q 'dumpexe 2.26' '$TD/ver.txt'
  grep -Eq 'Capstone[[:space:]]+[0-9]+\\.[0-9]+' '$TD/ver.txt'
"

# L11-J: over-cap MZ/COM with --json is one object. tiny.com is 1-byte C3, no PSP.
l11j_one_object() {
  python3 - "$1" "$2" "$3" "$4" << 'PY'
import json, sys
path, fmt, version, expect_file = sys.argv[1:]
raw = open(path, encoding="utf-8").read()
d = json.loads(raw)
assert set(d) == {"tool", "version", "file", "format", "error"}, sorted(d)
assert d["tool"] == "dumpexe", d["tool"]
assert d["version"] == version, d["version"]
assert d["format"] == fmt, d["format"]
assert d["error"] == "load image over cap", d["error"]
assert d["file"] == expect_file, d["file"]
PY
}

l11j_mz_json_over() {
  local out="$TD/l11j_mz_over.json" err="$TD/l11j_mz_over.err" rc=0 line n
  line='Error: load image is 32 bytes, over the 31 cap (use --max-image=N)'
  "$BIN" --json --max-image=31 "$TD/cap32.exe" >"$out" 2>"$err" || rc=$?
  [[ "$rc" -eq 1 ]] &&
    n=$(grep -F -c -- "$line" "$err") &&
    [[ "$n" -eq 1 ]] &&
    l11j_one_object "$out" mz 2.26 "$TD/cap32.exe"
}

l11j_mz_text_over() {
  local out="$TD/l11j_mz_text.out" err="$TD/l11j_mz_text.err" rc=0 line n
  line='Error: load image is 32 bytes, over the 31 cap (use --max-image=N)'
  "$BIN" --max-image=31 "$TD/cap32.exe" >"$out" 2>"$err" || rc=$?
  [[ "$rc" -eq 1 ]] &&
    [[ ! -s "$out" ]] &&
    n=$(grep -F -c -- "$line" "$err") &&
    [[ "$n" -eq 1 ]]
}

l11j_mz_json_ok() {
  local out="$TD/l11j_mz_ok.json" err="$TD/l11j_mz_ok.err" rc=0
  "$BIN" --json --max-image=32 "$TD/cap32.exe" >"$out" 2>"$err" || rc=$?
  [[ "$rc" -eq 0 ]] &&
    python3 - "$out" << 'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["format"] == "mz", d.get("format")
assert d["version"] == "2.26", d.get("version")
assert "error" not in d, d.get("error")
assert d["mz"]["load_image_size"] == 32, d["mz"]
PY
}

l11j_com_json_over() {
  local out="$TD/l11j_com_over.json" err="$TD/l11j_com_over.err" rc=0 line n
  line='Error: load image is 257 bytes, over the 256 cap (use --max-image=N)'
  "$BIN" --json --max-image=256 "$TD/tiny.com" >"$out" 2>"$err" || rc=$?
  [[ "$rc" -eq 1 ]] &&
    n=$(grep -F -c -- "$line" "$err") &&
    [[ "$n" -eq 1 ]] &&
    l11j_one_object "$out" com 2.26 "$TD/tiny.com"
}

l11j_com_json_ok() {
  local out="$TD/l11j_com_ok.json" err="$TD/l11j_com_ok.err" rc=0
  "$BIN" --json --max-image=257 "$TD/tiny.com" >"$out" 2>"$err" || rc=$?
  [[ "$rc" -eq 0 ]] &&
    python3 - "$out" << 'PY'
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["format"] == "com", d.get("format")
assert d["version"] == "2.26", d.get("version")
assert "error" not in d, d.get("error")
assert d["com"]["load_model"] == "org100", d["com"]
assert d["com"]["file_size"] == 1, d["com"]
PY
}

check l11j_mz_json_over l11j_mz_json_over
check l11j_mz_text_over l11j_mz_text_over
check l11j_mz_json_ok l11j_mz_json_ok
check l11j_com_json_over l11j_com_json_over
check l11j_com_json_ok l11j_com_json_ok

check pklite_fingerprint bash -c "
  set -euo pipefail
  '$BIN' '$TD/pklite.exe' >'$TD/pk.out'
  if grep -qx 'Packer:      PKLITE' '$TD/pk.out'; then
    echo 'banner-only MZ reported Packer PKLITE' >&2
    exit 1
  fi
"

check pklite_structural bash -c "
  set -euo pipefail
  '$BIN' '$TD/pklite_112.exe' >'$TD/pk112.out'
  grep -qx 'Packer:      PKLITE 1.12' '$TD/pk112.out'
"

check lzexe_091_and_090 bash -c "
  set -euo pipefail
  '$BIN' '$TD/lz91.exe' >'$TD/lz91.out'
  '$BIN' '$TD/lz09.exe' >'$TD/lz09.out'
  grep -qx 'Packer:      LZEXE 0.91' '$TD/lz91.out'
  grep -qx 'Packer:      LZEXE 0.90' '$TD/lz09.out'
"

check lzexe_gate_reject bash -c "
  set -euo pipefail
  '$BIN' '$TD/lz91_nostub.exe' >'$TD/lz91_nostub.out'
  '$BIN' '$TD/lz91_relocs.exe' >'$TD/lz91_relocs.out'
  if grep -q 'LZEXE' '$TD/lz91_nostub.out' || grep -q 'LZEXE' '$TD/lz91_relocs.out'; then
    echo 'LZEXE matched without every gate' >&2
    exit 1
  fi
"

check lzexe_push_ax bash -c "
  set -euo pipefail
  '$BIN' '$TD/lz91_push.exe' >'$TD/lz91_push.out'
  '$BIN' '$TD/lz09_push.exe' >'$TD/lz09_push.out'
  grep -qx 'Packer:      LZEXE 0.91' '$TD/lz91_push.out'
  grep -qx 'Packer:      LZEXE 0.90' '$TD/lz09_push.out'
  if grep -q 'LHarc' '$TD/lz91_push.out' || grep -q 'LHarc' '$TD/lz09_push.out'; then
    echo 'LZ91/LZ09 file reported LHarc' >&2
    exit 1
  fi
"

check json_high_byte python3 - "$BIN" "$TD" << 'PY'
import json, os, subprocess, sys
bin_path, td = sys.argv[1:]
# A real 0xFF byte in the name, not the UTF-8 encoding of U+00FF.
raw_name = os.path.join(os.fsencode(td), b"q\xff.com")
with open(raw_name, "wb") as fh:
    fh.write(b"\xc3")
proc = subprocess.run([os.fsencode(bin_path), b"--json", raw_name], capture_output=True)
if proc.returncode != 0:
    sys.stderr.buffer.write(proc.stderr)
    sys.exit(1)
text = proc.stdout.decode("utf-8")
if "\\u00ff" not in text:
    print("JSON did not escape 0xFF as \\\\u00ff")
    print(text[:500])
    sys.exit(1)
data = json.loads(text)
if "\u00ff" not in data["file"]:
    print("filename did not round-trip", repr(data.get("file")))
    sys.exit(1)
print("json utf-8 ok")
PY

check exepack_structural bash -c "
  set -euo pipefail
  '$BIN' '$TD/exepack.exe' >'$TD/exepack.out'
  grep -qx 'Packer:      Microsoft EXEPACK' '$TD/exepack.out'
  grep -q 'RB at file' '$TD/exepack.out'
  if grep -q 'Packed file is corrupt' '$TD/exepack.out'; then
    echo 'EXEPACK evidence used the English sentence' >&2
    exit 1
  fi
"

check exepack_sentence_not_enough bash -c "
  set -euo pipefail
  '$BIN' '$TD/exepack_sentence.exe' >'$TD/exepack_sentence.out'
  if grep -q 'EXEPACK' '$TD/exepack_sentence.out'; then
    echo 'English sentence alone reported EXEPACK' >&2
    exit 1
  fi
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

# Guest file I/O stays in the simulator. COMs are hand-built (no DOSBox, no TPC).
python3 - "$TD" << 'PY'
import sys
from pathlib import Path
td = Path(sys.argv[1])

def emit(name, hexbytes):
    (td / name).write_bytes(bytes.fromhex(hexbytes))

# FCB-create VICTIM.TXT (8.3). Must not truncate a host file of that name.
emit("victim.com",
     "ba1001b416cd21b44ccd2190909090900056494354494d2020545854"
     "00000000000000000000000000000000000000000000000000")
# FCB-create ../escap.txt (name "../escap" + ext "txt") and handle-open
# /etc/hostname, then print whatever a read returned.
emit("escape.com",
     "ba3001b416cd21ba550130c0b43dcd2189c3b94000ba6301b43fcd21ba63"
     "01b409cd21b44ccd21909090909090909090002e2e2f6573636170747874"
     "000000000000000000000000000000000000000000000000002f6574632f"
     "686f73746e616d6500000000000000000000000000000000000000000000"
     "000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000000024")
# Create NEWFILE.TXT, write MAPDATA!$, clobber the buffer, read it back, print.
emit("newfile.com",
     "ba8001b416cd21ba0002b41acd21ba8001b415cd21b05abf0002b90800f3"
     "aaba8001b421cd21ba0002b409cd21b44ccd219090909090909090909090"
     "909090909090909090909090909090909090909090909090909090909090"
     "909090909090909090909090909090909090909090909090909090909090"
     "9090909090909090004e455746494c452054585400000000000000000000"
     "000000000000000000000000000000000000000000000000000000000000"
     "000000000000000000000000000000000000000000000000000000000000"
     "000000000000000000000000000000000000000000000000000000000000"
     "000000000000000000000000000000004d41504441544121244141414141"
     "414141414141414141414141414141414141414141414141414141414141"
     "414141414141414141414141414141414141414141414141414141414141"
     "414141414141414141414141414141414141414141414141414141414141"
     "414141414141414141414141414141414141414141414141")
# FCB create + random-block read of 65535 records of 65535 bytes.
emit("huge.com",
     "ba2001b416cd21c7062e01ffffb9ffffba2001b427cd21b44ccd2190"
     "90909090004855474520202020444154000000000000000000000000"
     "0000000000000000000000000000000000000000")
# CX=1000, one rep movsb. --max-insns=10 must stop long before 1000 steps.
emit("rep.com", "b9e803f3a4c3")
# Create "A" and loop AH=40h CX=FFFFh. Guest storage must stay capped.
emit("grow.com",
     "ba200131c9b43ccd2189c3b440b9ffffba0000cd21ebf4"
     "9090909090909090904100")
PY

check sim_guest_victim bash -c "
  set -euo pipefail
  dir='$TD/simvic'
  mkdir -p \"\$dir\"
  printf 'HELLO' > \"\$dir/VICTIM.TXT\"
  cp '$TD/victim.com' \"\$dir/victim.com\"
  '$BIN' --simulate --max-insns=200 \"\$dir/victim.com\" >'$TD/vic.out'
  [[ \"\$(cat \"\$dir/VICTIM.TXT\")\" == HELLO ]]
  [[ ! -e \"\$dir/victim.txt\" ]]
  names=\$(find \"\$dir\" -type f -printf '%f\n' | sort)
  [[ \"\$names\" == $'VICTIM.TXT\nvictim.com' ]]
  grep -F \"FCB create 'VICTIM.TXT'\" '$TD/vic.out' >/dev/null
"

check sim_guest_escape bash -c "
  set -euo pipefail
  box='$TD/simesc'
  mkdir -p \"\$box/sub\"
  cp '$TD/escape.com' \"\$box/sub/escape.com\"
  '$BIN' --simulate --max-insns=400 \"\$box/sub/escape.com\" >'$TD/esc.out'
  [[ ! -e \"\$box/escap.txt\" ]]
  [[ ! -e \"\$box/sub/escap.txt\" ]]
  hn=\$(tr -d '\r\n' < /etc/hostname)
  [[ -n \"\$hn\" ]]
  if grep -a -F -q \"\$hn\" '$TD/esc.out'; then
    echo \"simulate stdout contains host name '\$hn'\" >&2
    exit 1
  fi
  grep -a -F \"FCB create '../escap.txt'\" '$TD/esc.out' >/dev/null
  grep -a -F \"handle open '/etc/hostname'\" '$TD/esc.out' >/dev/null
  grep -a -F '→ FAIL' '$TD/esc.out' >/dev/null
"

check sim_guest_newfile bash -c "
  set -euo pipefail
  dir='$TD/simnew'
  mkdir -p \"\$dir\"
  cp '$TD/newfile.com' \"\$dir/newfile.com\"
  '$BIN' --simulate --max-insns=400 \"\$dir/newfile.com\" >'$TD/new.out'
  [[ ! -e \"\$dir/NEWFILE.TXT\" ]]
  [[ ! -e \"\$dir/newfile.txt\" ]]
  names=\$(find \"\$dir\" -type f -printf '%f\n' | sort)
  [[ \"\$names\" == newfile.com ]]
  grep -F 'DOS: MAPDATA!' '$TD/new.out' >/dev/null
"

check sim_guest_huge bash -c "
  set -euo pipefail
  dir='$TD/simhuge'
  mkdir -p \"\$dir\"
  cp '$TD/huge.com' \"\$dir/huge.com\"
  # 512 MiB virtual cap: a multi-gigabyte FCB buffer cannot be allocated.
  bash -c 'ulimit -v 524288; timeout 8 \"\$1\" --simulate --max-insns=200 \"\$2\" >\"\$3\"' \
    bash '$BIN' \"\$dir/huge.com\" '$TD/huge.out'
  [[ ! -e \"\$dir/HUGE.DAT\" ]]
  [[ ! -e \"\$dir/huge.dat\" ]]
  grep -F 'FCB read' '$TD/huge.out' >/dev/null
  grep -F 'DOS terminate' '$TD/huge.out' >/dev/null
"

check sim_rep_budget bash -c "
  set -euo pipefail
  '$BIN' --simulate --sim-quiet --max-insns=10 '$TD/rep.com' >'$TD/rep.out' 2>'$TD/rep.err'
  grep -F 'max-insns reached' '$TD/rep.out' >/dev/null
  grep -E 'Instructions executed:[[:space:]]+10\$' '$TD/rep.out' >/dev/null
  python3 - '$TD/rep.out' << 'PY'
import re, sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
m = re.search(r'CX=([0-9A-Fa-f]{4})', text)
if not m:
    print('no CX')
    sys.exit(1)
cx = int(m.group(1), 16)
# 1000 iterations would leave CX=0. Stopping inside the REP leaves most of it.
if cx == 0 or cx < 0x300:
    print('rep ran too far, CX', hex(cx))
    sys.exit(1)
print('rep budget ok', hex(cx))
PY
"

check sim_guest_total_cap bash -c "
  set -euo pipefail
  dir='$TD/simgrow'
  mkdir -p \"\$dir\"
  cp '$TD/grow.com' \"\$dir/grow.com\"
  # 512 MiB virtual cap. Unbounded AH=40h growth would bad_alloc or be killed.
  set +e
  bash -c 'ulimit -v 524288; timeout 30 \"\$1\" --simulate --sim-quiet --loop-limit=0 --max-insns=4000 \"\$2\" >\"\$3\" 2>\"\$4\"' \
    bash '$BIN' \"\$dir/grow.com\" '$TD/grow.out' '$TD/grow.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  if grep -q 'bad_alloc' '$TD/grow.out' '$TD/grow.err'; then
    echo 'guest write threw bad_alloc' >&2
    exit 1
  fi
  grep -F 'AX=5' '$TD/grow.out' >/dev/null
  [[ ! -e \"\$dir/A\" ]]
"

SAMPLES="/tmp/project/fix-20261004/packer-samples"

check help_unpacked bash -c "
  set -euo pipefail
  '$BIN' -h >'$TD/help.txt'
  grep -q '_UNPACKED' '$TD/help.txt'
  if grep -E -q -- '--unpack|--no-unpack' '$TD/help.txt'; then
    echo 'help advertises an unpack switch' >&2
    exit 1
  fi
"

check tiny_mz_no_unpacked bash -c "
  set -euo pipefail
  '$BIN' -d '$TD/tiny_mz.exe' >'$TD/tiny_mz.out'
  [[ -s '$TD/tiny_mz.asm' ]]
  [[ ! -e '$TD/tiny_mz_UNPACKED.EXE' ]]
  [[ ! -e '$TD/tiny_mz_UNPACKED.COM' ]]
  [[ ! -e '$TD/tiny_mz_UNPACKED.asm' ]]
"

check exepack_synthetic_fails bash -c "
  set -euo pipefail
  set +e
  '$BIN' -d '$TD/exepack.exe' >'$TD/exepack_d.out' 2>'$TD/exepack_d.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  grep -q 'unpack failed (Microsoft EXEPACK)' '$TD/exepack_d.err'
  [[ ! -e '$TD/exepack_UNPACKED.EXE' ]]
  [[ ! -e '$TD/exepack_UNPACKED.COM' ]]
  [[ ! -e '$TD/exepack_UNPACKED.asm' ]]
"

check diet4_not_packer bash -c "
  set -euo pipefail
  set +e
  '$BIN' -d '$TD/diet4.exe' >'$TD/diet4.out' 2>'$TD/diet4.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  if grep -q 'Packer:      DIET' '$TD/diet4.out'; then
    echo 'DIET at 0x1C reported Packer DIET' >&2
    exit 1
  fi
  if grep -q 'unpack failed' '$TD/diet4.err'; then
    echo 'DIET at 0x1C tried to unpack' >&2
    exit 1
  fi
  [[ ! -e '$TD/diet4_UNPACKED.EXE' ]]
  [[ ! -e '$TD/diet4_UNPACKED.COM' ]]
  [[ ! -e '$TD/diet4_UNPACKED.asm' ]]
"

check diet_exe_structural bash -c "
  set -euo pipefail
  '$BIN' -d --no-repack '$TD/diet_exe.exe' >'$TD/diet_exe.out' 2>'$TD/diet_exe.err'
  grep -q 'DIET' '$TD/diet_exe.out'
"

check diet_com_and_data bash -c "
  set -euo pipefail
  '$BIN' '$TD/diet_com.com' >'$TD/diet_com.out'
  '$BIN' '$TD/diet_data.bin' >'$TD/diet_data.out'
  '$BIN' '$TD/diet_be_only.com' >'$TD/diet_be.out'
  grep -q 'Packer:      DIET' '$TD/diet_com.out'
  grep -q 'Packer:      DIET' '$TD/diet_data.out'
  if grep -q 'Packer:      DIET' '$TD/diet_be.out'; then
    echo 'bare BF/BE prefix reported DIET' >&2
    exit 1
  fi
"

check lharc_banner_not_packer bash -c "
  set -euo pipefail
  set +e
  '$BIN' -d '$TD/lharc_banner.exe' >'$TD/lharc.out' 2>'$TD/lharc.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  if grep -q 'Packer:      LHarc' '$TD/lharc.out'; then
    echo 'LHA sentence reported Packer LHarc' >&2
    exit 1
  fi
  if grep -q 'unpack failed' '$TD/lharc.err'; then
    echo 'LHA sentence tried to unpack' >&2
    exit 1
  fi
  [[ ! -e '$TD/lharc_banner_UNPACKED.EXE' ]]
  [[ ! -e '$TD/lharc_banner_UNPACKED.COM' ]]
"

check lha_header_structural bash -c "
  set -euo pipefail
  '$BIN' '$TD/lha_l0.exe' >'$TD/lha_l0.out'
  '$BIN' '$TD/lha_l1.exe' >'$TD/lha_l1.out'
  '$BIN' '$TD/lha_bare.exe' >'$TD/lha_bare.out'
  '$BIN' '$TD/lha_the.exe' >'$TD/lha_the.out'
  '$BIN' '$TD/lha_swg.exe' >'$TD/lha_swg.out'
  '$BIN' '$TD/lha_mid.exe' >'$TD/lha_mid.out'
  grep -q 'LHarc' '$TD/lha_l0.out'
  grep -q 'LHarc' '$TD/lha_l1.out'
  if grep -q 'LHarc' '$TD/lha_bare.out' || grep -q 'LHarc' '$TD/lha_the.out' \
      || grep -q 'LHarc' '$TD/lha_swg.out' || grep -q 'LHarc' '$TD/lha_mid.out'; then
    echo 'bare -lh5-, -the-, -sw0-, or a mid-file header reported LHarc' >&2
    exit 1
  fi
"

check json_no_unpack bash -c "
  set -euo pipefail
  '$BIN' --json -d '$TD/exepack.exe' >'$TD/exepack.json' 2>'$TD/exepack_json.err'
  if grep -q 'unpack failed' '$TD/exepack_json.err'; then
    echo 'json mode tried to unpack' >&2
    exit 1
  fi
  [[ ! -e '$TD/exepack_UNPACKED.EXE' ]]
"

# Missing packer-samples are a skip, not a suite failure. Byte compares still run
# when the files are present.
skip_or_check() {
  local name=$1
  local file=$2
  shift 2
  if [[ ! -f "$file" ]]; then
    echo "SKIP $name (no $file)"
    return 0
  fi
  check "$name" "$@"
}

skip_or_check probe_exepack2_no_unpack "$SAMPLES/exepack-2.exe" bash -c "
  set -euo pipefail
  [[ -f '$SAMPLES/exepack-2.exe' ]]
  cp '$SAMPLES/exepack-2.exe' '$TD/exepack-2.exe'
  '$BIN' -d '$TD/exepack-2.exe' >'$TD/exepack2.out'
  if grep -q '^Packer:' '$TD/exepack2.out'; then
    echo 'exepack-2 reported a packer' >&2
    exit 1
  fi
  [[ ! -e '$TD/exepack-2_UNPACKED.EXE' ]]
  [[ ! -e '$TD/exepack-2_UNPACKED.COM' ]]
  [[ ! -e '$TD/exepack-2_UNPACKED.asm' ]]
  [[ -s '$TD/exepack-2.asm' ]]
"

# Host oracle. Writes deark's in.*.exe to $3. Exported for bash -c checks.
oracle_deark() {
  if ! command -v deark >/dev/null 2>&1; then
    echo "SKIP deark oracle (deark not on PATH)"
    exit 0
  fi
  local mod="$1" src="$2" dst="$3"
  local work produced
  work=$(mktemp -d "$TD/deark-XXXXXX")
  cp "$src" "$work/in.exe"
  (cd "$work" && deark -m "$mod" in.exe >/dev/null)
  produced=$(find "$work" -maxdepth 1 -type f -name '*.exe' ! -name 'in.exe' | head -n 1)
  [[ -n "$produced" ]]
  cp "$produced" "$dst"
  rm -rf "$work"
}
export -f oracle_deark

skip_or_check probe_exepack1_deark "$SAMPLES/exepack-1.exe" bash -c "
  set -euo pipefail
  [[ -f '$SAMPLES/exepack-1.exe' ]]
  cp '$SAMPLES/exepack-1.exe' '$TD/exepack-1.exe'
  oracle_deark exepack '$TD/exepack-1.exe' '$TD/exepack-1.oracle'
  set +e
  '$BIN' -d '$TD/exepack-1.exe' >'$TD/exepack1.out' 2>'$TD/exepack1.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  [[ -s '$TD/exepack-1_UNPACKED.asm' ]]
  cmp -s '$TD/exepack-1.oracle' '$TD/exepack-1_UNPACKED.EXE'
"

skip_or_check probe_lz91_unlzexe "$SAMPLES/lz91.exe" bash -c "
  set -euo pipefail
  [[ -f '$SAMPLES/lz91.exe' ]]
  cp '$SAMPLES/lz91.exe' '$TD/lz91-probe.exe'
  cp '$SAMPLES/lz91.exe' '$TD/lz91-host.exe'
  (cd '$TD' && unlzexe lz91-host.exe >'$TD/unlzexe91.txt')
  [[ -s '$TD/lz91-host.ex' ]]
  set +e
  '$BIN' -d '$TD/lz91-probe.exe' >'$TD/lz91p.out' 2>'$TD/lz91p.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  [[ -s '$TD/lz91-probe_UNPACKED.asm' ]]
  cmp -s '$TD/lz91-host.ex' '$TD/lz91-probe_UNPACKED.EXE'
"

skip_or_check probe_lz09_deark "$SAMPLES/lz09.exe" bash -c "
  set -euo pipefail
  [[ -f '$SAMPLES/lz09.exe' ]]
  cp '$SAMPLES/lz09.exe' '$TD/lz09-probe.exe'
  cp '$SAMPLES/lz09.exe' '$TD/lz09-host.exe'
  set +e
  (cd '$TD' && unlzexe lz09-host.exe >'$TD/unlzexe09.txt' 2>&1)
  set -e
  # Host unlzexe does not write an unpacked image for this file.
  cmp -s '$SAMPLES/lz09.exe' '$TD/lz09-host.exe'
  oracle_deark lzexe '$TD/lz09-probe.exe' '$TD/lz09.oracle'
  set +e
  '$BIN' -d '$TD/lz09-probe.exe' >'$TD/lz09p.out' 2>'$TD/lz09p.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  [[ -s '$TD/lz09-probe_UNPACKED.asm' ]]
  cmp -s '$TD/lz09.oracle' '$TD/lz09-probe_UNPACKED.EXE'
"

skip_or_check probe_pklite_deark "$SAMPLES/pklite.exe" bash -c "
  set -euo pipefail
  [[ -f '$SAMPLES/pklite.exe' ]]
  cp '$SAMPLES/pklite.exe' '$TD/pklite-probe.exe'
  oracle_deark pklite '$TD/pklite-probe.exe' '$TD/pklite.oracle'
  set +e
  '$BIN' -d '$TD/pklite-probe.exe' >'$TD/pklitep.out' 2>'$TD/pklitep.err'
  rc=\$?
  set -e
  [[ \$rc -eq 0 ]]
  grep -q 'Packer:      PKLITE 1.12' '$TD/pklitep.out'
  [[ -s '$TD/pklite-probe_UNPACKED.asm' ]]
  cmp -s '$TD/pklite.oracle' '$TD/pklite-probe_UNPACKED.EXE'
"

skip_or_check unpack_no_asm_separator "$SAMPLES/exepack-1.exe" bash -c "
  set -euo pipefail
  rm -f '$TD/exepack-1_UNPACKED.EXE' '$TD/exepack-1_UNPACKED.asm' '$TD/exepack-1.asm'
  [[ -f '$TD/exepack-1.exe' ]]
  '$BIN' -d --no-asm-file '$TD/exepack-1.exe' >'$TD/exepack1_noasm.out' 2>'$TD/exepack1_noasm.err'
  [[ -s '$TD/exepack-1_UNPACKED.EXE' ]]
  [[ ! -e '$TD/exepack-1_UNPACKED.asm' ]]
  [[ ! -e '$TD/exepack-1.asm' ]]
  grep -q '^=== UNPACKED ===$' '$TD/exepack1_noasm.out'
"

skip_or_check unpack_o_names_packed_only "$SAMPLES/exepack-1.exe" bash -c "
  set -euo pipefail
  rm -f '$TD/exepack-1_UNPACKED.EXE' '$TD/exepack-1_UNPACKED.asm' '$TD/packed_only.asm'
  '$BIN' -d -o '$TD/packed_only.asm' '$TD/exepack-1.exe' >'$TD/exepack1_o.out'
  [[ -s '$TD/packed_only.asm' ]]
  [[ ! -e '$TD/exepack-1.asm' ]]
  [[ -s '$TD/exepack-1_UNPACKED.EXE' ]]
  [[ -s '$TD/exepack-1_UNPACKED.asm' ]]
"

skip_or_check unpack_keep_existing "$SAMPLES/exepack-1.exe" bash -c "
  set -euo pipefail
  python3 -c 'open(\"$TD/exepack-1_UNPACKED.EXE\",\"wb\").write(b\"KEEP\")'
  printf 'ASMKEEP\n' > '$TD/exepack-1_UNPACKED.asm'
  '$BIN' -d '$TD/exepack-1.exe' >'$TD/exepack1_keep.out' 2>'$TD/exepack1_keep.err'
  [[ \"\$(cat '$TD/exepack-1_UNPACKED.EXE')\" == KEEP ]]
  grep -q \"refuse to overwrite '$TD/exepack-1_UNPACKED.EXE'\" '$TD/exepack1_keep.err'
  grep -q \"refuse to overwrite '$TD/exepack-1_UNPACKED.asm'\" '$TD/exepack1_keep.err'
  [[ \"\$(cat '$TD/exepack-1_UNPACKED.asm')\" == ASMKEEP ]]
"

# DUMPEXE_SAMPLES, when set and non-empty, replaces /mnt/samples.
SAMPLE_ROOT="${DUMPEXE_SAMPLES:-/mnt/samples}"
BTECH="$SAMPLE_ROOT/BattleTech - The Crescent Hawks' Revenge (1990) (v1.00) (Infocom, Inc.) (360K) (Disk 1) [!]/INSTALL.EXE"
FIXIN="$SAMPLE_ROOT/Chamber of the Sci-Mutant Priestess (1990) (Data East USA, Inc.) (360K) (Disk 1) [cp] [!]/FIXIN.EXE"
GOLD="$SAMPLE_ROOT/Gold of the Aztecs, The (1991) (v1.0) (U.S. Gold, Inc.) (1.44M) (Disk 1) [!]/INSTALL.EXE"
ANOTHER="$SAMPLE_ROOT/Another World (1992) (Europe) (U.S. Gold Ltd.) (720K) (Disk A) [!]/ANOTHER.EXE"
LEMM="$SAMPLE_ROOT/Lemmings (1991-05-11) (Psygnosis Limited) (360K) (Disk 1) [cp] [!]/CGALEMMI.EXE"
WWF="$SAMPLE_ROOT/WWF Wrestlemania (1991) (Ocean Software Ltd.) (360K) (Disk 1) [!]/WWF.EXE"

if [[ -f "$BTECH" ]]; then
  cp "$BTECH" "$TD/btech.exe"
  check lzexe_btech_min_le_max bash -c "
    set -euo pipefail
    oracle_deark lzexe '$TD/btech.exe' '$TD/btech.oracle'
    '$BIN' -d --no-repack '$TD/btech.exe' >'$TD/btech.out' 2>'$TD/btech.err'
    python3 - '$TD/btech.oracle' '$TD/btech_UNPACKED.EXE' << 'PY'
import struct, sys
oracle = open(sys.argv[1], 'rb').read()
ours = open(sys.argv[2], 'rb').read()
omn, omx = struct.unpack_from('<HH', oracle, 10)
mn, mx = struct.unpack_from('<HH', ours, 10)
print('deark', hex(omn), hex(omx), 'len', len(oracle))
print('ours ', hex(mn), hex(mx), 'len', len(ours))
if mn > mx:
    sys.exit('unpacked minalloc > maxalloc')
# Deark 1.7.3 already had min<=max for this file, so the header words
# must stay what deark wrote. A different image length is not the wrap.
if omn <= omx and (mn, mx) != (omn, omx):
    sys.exit('min/max diverged from deark')
if omn <= omx and len(oracle) == len(ours) and oracle != ours:
    sys.exit('min<=max image differs from deark')
print('btech min<=max ok')
PY
  "
else
  echo "SKIP lzexe_btech_min_le_max (no $BTECH)"
fi

skip_or_check lzexe_fixin_minalloc "$FIXIN" bash -c "
  set -euo pipefail
  cp '$FIXIN' '$TD/fixin.exe'
  '$BIN' -d --no-repack '$TD/fixin.exe' >'$TD/fixin.out' 2>'$TD/fixin.err'
  [[ -s '$TD/fixin_UNPACKED.EXE' ]]
  python3 - '$TD/fixin_UNPACKED.EXE' << 'PY'
import struct, sys
b = open(sys.argv[1], 'rb').read()
mn, mx = struct.unpack_from('<HH', b, 10)
ss = struct.unpack_from('<h', b, 14)[0]
sp = struct.unpack_from('<H', b, 16)[0]
hdr = struct.unpack_from('<H', b, 8)[0] * 16
image_len = len(b) - hdr
stack_top = ss * 16 + sp
print('fixin minalloc', hex(mn), 'maxalloc', hex(mx),
      'stack', hex(stack_top), 'image', image_len)
if mn > mx:
    sys.exit('minalloc > maxalloc')
if stack_top > image_len:
    paras = (stack_top - image_len + 15) // 16
    if 0 < paras <= 65535 and mn < paras:
        sys.exit('minalloc %d below stack paragraphs %d' % (mn, paras))
PY
"

skip_or_check lzexe_gold_push_ax "$GOLD" bash -c "
  set -euo pipefail
  cp '$GOLD' '$TD/gold.exe'
  '$BIN' -d --no-repack '$TD/gold.exe' >'$TD/gold.out' 2>'$TD/gold.err'
  grep -q 'Packer:      LZEXE 0.91' '$TD/gold.out'
  if grep -q 'Packer:      LHarc' '$TD/gold.out'; then
    echo 'Gold reported LHarc' >&2
    exit 1
  fi
  [[ -s '$TD/gold_UNPACKED.EXE' ]]
  python3 - '$TD/gold_UNPACKED.EXE' << 'PY'
import sys
b = open(sys.argv[1], 'rb').read(2)
if b not in (b'MZ', b'ZM'):
    print('unpacked is not MZ', b)
    sys.exit(1)
print('gold mz ok')
PY
"

skip_or_check another_world_not_diet "$ANOTHER" bash -c "
  set -euo pipefail
  cp '$ANOTHER' '$TD/another.exe'
  '$BIN' -d --no-repack '$TD/another.exe' >'$TD/another.out' 2>'$TD/another.err'
  if grep -q 'Packer:      DIET' '$TD/another.out'; then
    echo 'Another World reported DIET' >&2
    exit 1
  fi
  if grep -q 'unpack failed' '$TD/another.err'; then
    echo 'Another World unpack failed' >&2
    exit 1
  fi
"

if [[ -f "$BTECH" ]]; then
  mkdir -p "$TD/oo" "$TD/na" "$TD/ro" "$TD/keep" "$TD/sy"
  cp "$BTECH" "$TD/oo/in.exe"
  cp "$BTECH" "$TD/na/in.exe"
  cp "$BTECH" "$TD/ro/in.exe"
  cp "$BTECH" "$TD/keep/in.exe"
  cp "$BTECH" "$TD/sy/in.exe"
else
  echo "SKIP unpack_stdout_only (no BattleTech INSTALL.EXE)"
  echo "SKIP unpack_no_asm_still_writes_image (no BattleTech INSTALL.EXE)"
  echo "SKIP unpack_write_error_not_failed (no BattleTech INSTALL.EXE)"
  echo "SKIP unpack_keep_exe_skips_asm (no BattleTech INSTALL.EXE)"
  echo "SKIP unpack_dangling_symlink (no BattleTech INSTALL.EXE)"
fi
if [[ -f "$TD/oo/in.exe" ]]; then
check unpack_stdout_only bash -c "
  set -euo pipefail
  '$BIN' -d -o - --no-repack '$TD/oo/in.exe' >'$TD/oo.out' 2>'$TD/oo.err'
  [[ ! -e '$TD/oo/in.asm' ]]
  [[ ! -e '$TD/oo/in_UNPACKED.EXE' ]]
  [[ ! -e '$TD/oo/in_UNPACKED.COM' ]]
  [[ ! -e '$TD/oo/in_UNPACKED.asm' ]]
  grep -q '^=== UNPACKED ===$' '$TD/oo.out'
  # Packed listing comes first.
  python3 - '$TD/oo.out' << 'PY'
import sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
a = text.find('=== Multi-pass assembly listing ===')
b = text.find('=== UNPACKED ===')
c = text.find('=== Multi-pass assembly listing ===', b if b >= 0 else 0)
if a < 0 or b < 0 or not (a < b):
    print('stdout order wrong', a, b)
    sys.exit(1)
if c < 0:
    print('unpacked listing missing')
    sys.exit(1)
print('stdout only ok')
PY
"

check unpack_no_asm_still_writes_image bash -c "
  set -euo pipefail
  '$BIN' -d --no-asm-file --no-repack '$TD/na/in.exe' >'$TD/na.out' 2>'$TD/na.err'
  [[ -s '$TD/na/in_UNPACKED.EXE' ]]
  [[ ! -e '$TD/na/in_UNPACKED.asm' ]]
  [[ ! -e '$TD/na/in.asm' ]]
  grep -q '^=== UNPACKED ===$' '$TD/na.out'
"

check unpack_write_error_not_failed bash -c "
  set -euo pipefail
  chmod a-w '$TD/ro'
  set +e
  '$BIN' -d --no-repack '$TD/ro/in.exe' >'$TD/ro.out' 2>'$TD/ro.err'
  rc=\$?
  set -e
  chmod u+w '$TD/ro'
  [[ \$rc -eq 0 ]]
  grep -F \"cannot write '$TD/ro/in_UNPACKED.EXE'\" '$TD/ro.err' >/dev/null
  if grep -q 'unpack failed' '$TD/ro.err'; then
    echo 'write error reported as unpack failed' >&2
    cat '$TD/ro.err' >&2
    exit 1
  fi
  grep -q '^=== UNPACKED ===$' '$TD/ro.out'
  [[ ! -e '$TD/ro/in_UNPACKED.EXE' ]]
"

check unpack_keep_exe_skips_asm bash -c "
  set -euo pipefail
  printf 'KEEP' > '$TD/keep/in_UNPACKED.EXE'
  '$BIN' -d --no-repack '$TD/keep/in.exe' >'$TD/keep.out' 2>'$TD/keep.err'
  [[ \"\$(cat '$TD/keep/in_UNPACKED.EXE')\" == KEEP ]]
  [[ ! -e '$TD/keep/in_UNPACKED.asm' ]]
  grep -q \"refuse to overwrite '$TD/keep/in_UNPACKED.EXE'\" '$TD/keep.err'
  grep -q 'kept' '$TD/keep.err'
  if grep -q 'func_' '$TD/keep/in_UNPACKED.asm' 2>/dev/null; then
    echo 'new asm was written for the kept exe' >&2
    exit 1
  fi
"

check unpack_dangling_symlink bash -c "
  set -euo pipefail
  ln -s '$TD/sy/missing-unpacked' '$TD/sy/in_UNPACKED.EXE'
  '$BIN' -d --no-repack '$TD/sy/in.exe' >'$TD/sy.out' 2>'$TD/sy.err'
  [[ ! -e '$TD/sy/missing-unpacked' ]]
  [[ -L '$TD/sy/in_UNPACKED.EXE' ]]
  [[ ! -e '$TD/sy/in_UNPACKED.asm' ]]
  grep -q \"refuse to overwrite '$TD/sy/in_UNPACKED.EXE'\" '$TD/sy.err'
"
fi

PKLITE_SRC=""
if [[ -f "$WWF" ]]; then
  PKLITE_SRC="$WWF"
elif [[ -f "$LEMM" ]]; then
  PKLITE_SRC="$LEMM"
fi
if [[ -n "$PKLITE_SRC" ]]; then
  check pklite_asan_no_leak bash -c "
    set -euo pipefail
    make -C '$ROOT' asan
    mkdir -p '$TD/pk'
    cp '$PKLITE_SRC' '$TD/pk/in.exe'
    set +e
    ASAN_OPTIONS=detect_leaks=1 \\
      '$ROOT/dumpexe-asan' -d --no-repack --no-asm-file '$TD/pk/in.exe' \\
      >'$TD/pk.out' 2>'$TD/pk.err'
    rc=\$?
    set -e
    if grep -q 'LeakSanitizer' '$TD/pk.err'; then
      echo 'PKLITE leaked' >&2
      cat '$TD/pk.err' >&2
      exit 1
    fi
    [[ \$rc -eq 0 ]]
    grep -q 'PKLITE' '$TD/pk.out'
    [[ -s '$TD/pk/in_UNPACKED.EXE' ]]
  "
else
  echo "SKIP pklite_asan_no_leak (no WWF or Lemmings sample)"
fi

echo "---"
echo "passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
