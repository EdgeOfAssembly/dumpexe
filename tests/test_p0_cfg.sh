#!/usr/bin/env bash
# P0 CFG contracts: DOS noreturn interrupts.
# INT 20h and INT 27h always stop. INT 21h stops only for AH 00h, 4Ch, or 31h.
# These checks do not skip. Synthetic COM fixtures only. No --simulate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-cfg-XXXXXX")"
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

python3 - "$TD" << 'PY'
import os
import struct
import sys
from pathlib import Path
td = Path(sys.argv[1])
fixtures = {
    "int20": bytes([0xCD, 0x20, 0xB0, 0x42]),
    "int27": bytes([0xCD, 0x27, 0xB0, 0x42]),
    "ah4c": bytes([0xB4, 0x4C, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah00": bytes([0xB4, 0x00, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah31": bytes([0xB4, 0x31, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ax4c": bytes([0xB8, 0x00, 0x4C, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "nop4c": bytes([0xB4, 0x4C, 0x90, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "ah09": bytes([0xB4, 0x09, 0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "unk": bytes([0xCD, 0x21, 0xB0, 0x42, 0xC3]),
    "into": bytes([0xCE, 0xB0, 0x42, 0xC3]),
}
for name, blob in fixtures.items():
    (td / f"{name}.com").write_bytes(blob)

def build_mz(image, paras=2, ip=0, cs=0, minalloc=0, signature=0x5A4D):
    header_bytes = paras * 16
    total = header_bytes + len(image)
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total % 512 == 0:
        final_len = 0
    hdr = bytearray(header_bytes)
    struct.pack_into("<14H", hdr, 0,
                     signature, final_len, num_blocks, 0, paras,
                     minalloc, 0xFFFF, 0, 0x200, 0, ip, cs & 0xFFFF, 0x1C, 0)
    return bytes(hdr) + bytes(image)

def write_sparse(path, size, prefix):
    fd = os.open(path, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o644)
    os.ftruncate(fd, size)
    os.pwrite(fd, prefix, 0)
    os.close(fd)

# X4: ZM is the little-endian word 0x4D5A (on disk 5A 4D), 32-byte header.
(td / "zm.exe").write_bytes(build_mz(bytes.fromhex("b44ccd21"), signature=0x4D5A))
(td / "one_m.bin").write_bytes(b"M")

# N7: delta == 0 still decodes image byte 0. CS=FFF0 IP=0100.
(td / "delta0.exe").write_bytes(build_mz(bytes.fromhex("b042c3"), ip=0x100, cs=0xFFF0))
# N7: delta < 0 (CS=FFFF IP=0 -> -16). Distinctive mov al,0EEh at linear 0.
(td / "before.exe").write_bytes(build_mz(bytes.fromhex("b0eec3"), ip=0, cs=0xFFFF))

# N5: near call whose next 8 bytes are mov ax,0 plus zeros (7 of 8 are 0).
# E8 08 00 ; B8 00 00 00 00 00 00 00 ; C3
(td / "callz.com").write_bytes(bytes.fromhex("e80800b800000000000000c3"))
# Straight line: mov ax,1 then four 00 bytes then nop. The nop stays.
(td / "nopgap.com").write_bytes(bytes.fromhex("b801000000000090c3"))
# ret then eight 00 bytes. The hole is not code.
(td / "retz.com").write_bytes(bytes.fromhex("c30000000000000000"))

# RG6: cmp at 0117 overlaps a speculative INT seed at site-8 (0118).
(td / "rg6.com").write_bytes(bytes.fromhex(
    "cd20" + ("00" * 14) +
    "0655b825038ed8833e900000750433c0cd20833e900001750633c0b401cd21c3"))
# RG6: call to 0105. The fall-through walk starts on nop. A later
# opcode 00 at 0104 must not swallow the ret leader.
(td / "zhole.com").write_bytes(bytes.fromhex("e802009000c3"))
# RG6-r: real opcode 00 at 0117 covers a speculative site-8 seed (0118).
(td / "rg6r.com").write_bytes(bytes.fromhex(
    "cd20" + ("00" * 14) +
    "0655b825038ed80006900090750433c0cd20833e900001750633c0b401cd21c3"))
# RG6-t: opcode 00 at 011C covers speculative site-8 (011F) over jmp target 0120.
(td / "rg6t.com").write_bytes(bytes.fromhex(
    "cd20" + ("00" * 21) +
    "90909090900093eb2ab8024233c933d2cd21c3061e5590ebf0b44ccd21c3"))
# N5-pfx: call 0106, nop, then 2E 00 C3. The prefix must not hide opcode 00.
(td / "n5_pfx.com").write_bytes(bytes.fromhex("e80300902e00c3"))
# P1: same bytes as zhole. A later real leader stops opcode 00.
(td / "real_leader_stop.com").write_bytes(bytes.fromhex("e802009000c3"))
# P1: the first instruction of a walk may cover an interior real leader.
(td / "first_insn_cover.com").write_bytes(bytes.fromhex("e80700eb0390909000060001c3c3"))
# P1: a second nearby seed does not promote. Both seeds fall outside the image.
(td / "second_nearby.com").write_bytes(bytes.fromhex("b401cd21b401cd21c3"))

# F6: 67-byte COM. X is linear 0x130 (file 0x30, byte C0). File 0x2F is 00.
# Fill is 90. INT 21h at file 0x38 is linear 0x138, so site-8 is X.
# nb1: one INT, X stays speculative, so the opcode-00 walk emits 012F 00C0.
# nb2: a second INT nearby-seeds X again and must not promote.
# nb3: nb2 plus EB F4 at file 0x3A (jmp 0130). That later enqueue promotes,
# so the opcode-00 walk stops and 012F is not a row.
# nb4: entry EB 2E (jmp 0130) plus both INTs. X is real before the walk.
def com67(entry, at_3a, second_int, ret_at_3c=False):
    blob = bytearray(b"\x90" * 0x43)
    blob[0:len(entry)] = entry
    blob[0x2F] = 0x00
    blob[0x30] = 0xC0
    blob[0x38:0x3A] = b"\xCD\x21"
    blob[0x3A:0x3A + len(at_3a)] = at_3a
    if ret_at_3c:
        blob[0x3C] = 0xC3
    if second_int:
        blob[0x40:0x43] = b"\xCD\x21\xC3"
    assert len(blob) == 0x43
    return bytes(blob)

(td / "nb1.com").write_bytes(com67(b"\xC3", b"\xC3", False))
(td / "nb2.com").write_bytes(com67(b"\xC3", b"\xC3", True))
(td / "nb3.com").write_bytes(com67(b"\xC3", b"\xEB\xF4", True, True))
(td / "nb4.com").write_bytes(com67(b"\xEB\x2E", b"\xC3", True))

# N-test RG4: CS=0100h IP=0, header 32 bytes, minalloc 0x10.
# INT 21h at linear 0x200 sits under the entry frame. Frame 0 must cover it.
rg4 = bytearray(0x1100)
rg4[0x1000:0x1005] = bytes.fromhex("b8004ccd21")
rg4[0x200:0x20C] = bytes.fromhex("b409ba0000cd21b8004ccd21")
(td / "rg4.exe").write_bytes(build_mz(rg4, ip=0, cs=0x0100, minalloc=0x10))

# L11: clamped load image 1114113 bytes (header 32 + image).
big_image = 1114113
big_total = 32 + big_image
big_prefix = build_mz(b"\xC3" + bytes(31))  # 32-byte header + 32 image bytes
# Rewrite page fields for the real length, then extend the file.
final_len = big_total % 512
num_blocks = (big_total + 511) // 512
if big_total % 512 == 0:
    final_len = 0
hdr = bytearray(big_prefix[:32])
struct.pack_into("<HH", hdr, 2, final_len, num_blocks)
write_sparse(str(td / "bigmz.exe"), big_total, bytes(hdr) + b"\xC3")
# 64-byte MZ: header 32 + 32 image bytes. Under the default cap.
(td / "smallmz.exe").write_bytes(build_mz(b"\xC3" + bytes(31)))
# COM whose disassembly image (file + PSP hole) is over the cap.
write_sparse(str(td / "big.com"), 1114113, b"\xC3")
print("fixtures", td)
PY

# File byte 0 is IP 0100. -d prints only decoded CFG instructions.
dump() {
  local name=$1
  "$BIN" -d --no-asm-file "$TD/$name.com" >"$TD/$name.out" 2>"$TD/$name.err"
}

has_f() {
  local out=$1 needle=$2
  if ! grep -F -q -- "$needle" "$out"; then
    echo "missing '$needle'" >&2
    cat "$out" >&2
    return 1
  fi
}

has_re() {
  local out=$1 re=$2
  if ! grep -E -q -- "$re" "$out"; then
    echo "missing /$re/" >&2
    cat "$out" >&2
    return 1
  fi
}

lacks_f() {
  local out=$1 needle=$2
  if grep -F -q -- "$needle" "$out"; then
    echo "unexpected '$needle'" >&2
    cat "$out" >&2
    return 1
  fi
}

case_int20() {
  dump int20 || return 1
  local out="$TD/int20.out"
  has_f "$out" CD20 || return 1
  has_re "$out" '[[:space:]]int[[:space:]]' || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_int27() {
  dump int27 || return 1
  local out="$TD/int27.out"
  has_f "$out" CD27 || return 1
  has_re "$out" '[[:space:]]int[[:space:]]' || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah4c() {
  dump ah4c || return 1
  local out="$TD/ah4c.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" B042 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah00() {
  dump ah00 || return 1
  local out="$TD/ah00.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah31() {
  dump ah31 || return 1
  local out="$TD/ah31.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ax4c() {
  dump ax4c || return 1
  local out="$TD/ax4c.out"
  has_f "$out" CD21 || return 1
  lacks_f "$out" 0x42 || return 1
}

case_nop4c() {
  dump nop4c || return 1
  local out="$TD/nop4c.out"
  has_f "$out" CD21 || return 1
  has_re "$out" '[[:space:]]nop[[:space:]]' || return 1
  lacks_f "$out" 0x42 || return 1
}

case_ah09() {
  dump ah09 || return 1
  local out="$TD/ah09.out"
  has_f "$out" 0x42 || return 1
  has_f "$out" B042 || return 1
}

case_unk() {
  dump unk || return 1
  local out="$TD/unk.out"
  has_f "$out" 0x42 || return 1
}

case_into() {
  dump into || return 1
  local out="$TD/into.out"
  has_f "$out" 0x42 || return 1
  has_re "$out" '[[:space:]]into[[:space:]]' || return 1
}

case_zm_magic() {
  "$BIN" --json --no-asm-file "$TD/zm.exe" >"$TD/zm.json" 2>"$TD/zm.err" || {
    echo "ZM json failed" >&2
    cat "$TD/zm.err" >&2
    return 1
  }
  has_f "$TD/zm.json" '"format": "mz"' || return 1
  lacks_f "$TD/zm.json" '"format": "com"' || return 1
  "$BIN" --json --no-asm-file "$TD/one_m.bin" >"$TD/one.json" 2>"$TD/one.err" || {
    echo "one-byte M failed" >&2
    cat "$TD/one.err" >&2
    return 1
  }
  has_f "$TD/one.json" '"format": "com"' || return 1
  lacks_f "$TD/one.json" '"format": "mz"' || return 1
}

case_before_image() {
  "$BIN" -d --no-asm-file --no-repack "$TD/before.exe" \
    >"$TD/before.out" 2>"$TD/before.err" || {
    echo "before-image disasm failed" >&2
    cat "$TD/before.err" >&2
    return 1
  }
  local n
  n=$(grep -c -F 'Warning: MZ entry is before the load image (in the PSP)' "$TD/before.err" || true)
  if [[ "$n" != "1" ]]; then
    echo "before-image warning count $n" >&2
    cat "$TD/before.err" >&2
    return 1
  fi
  lacks_f "$TD/before.out" B0EE || return 1
  "$BIN" --json --no-asm-file --no-repack "$TD/before.exe" \
    >"$TD/before.json" 2>"$TD/beforej.err" || return 1
  python3 - "$TD/before.json" << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
cfg = d.get("cfg")
if cfg is not None and cfg.get("blocks", 0) != 0:
    sys.exit("before-image seeded cfg blocks " + str(cfg.get("blocks")))
print("before-image cfg", cfg)
PY
}

case_delta0_entry() {
  "$BIN" -d --no-asm-file --no-repack "$TD/delta0.exe" \
    >"$TD/delta0.out" 2>"$TD/delta0.err" || {
    echo "delta0 disasm failed" >&2
    cat "$TD/delta0.err" >&2
    return 1
  }
  if grep -F -q 'Warning: MZ entry is before the load image (in the PSP)' "$TD/delta0.err"; then
    echo "delta0 warned" >&2
    cat "$TD/delta0.err" >&2
    return 1
  fi
  # com2exe listing is byte-exact db; the decoded entry is still linear 0.
  has_f "$TD/delta0.out" 'func_0000' || return 1
  has_f "$TD/delta0.out" 'mov al, 42h' || return 1
}

case_call_fallthrough_zeros() {
  dump callz || return 1
  local out="$TD/callz.out"
  has_f "$out" B80000 || return 1
  has_re "$out" '[[:space:]]mov[[:space:]]' || return 1
}

case_nop_after_four_zeros() {
  dump nopgap || return 1
  local out="$TD/nopgap.out"
  has_f "$out" 90 || return 1
  has_re "$out" '[[:space:]]nop[[:space:]]' || return 1
}

case_ret_zero_hole() {
  dump retz || return 1
  python3 - "$TD/retz.out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
for ip, hx, mnem in rows:
    if hx != "C3":
        sys.exit(f"decoded hole insn {ip} {hx} {mnem}")
print("ret hole", len(rows))
PY
}

# RG6: a real insn that covers a speculative INT-nearby seed stays decoded.
# Address 0118 must not be its own row. Do not search for 3E90.
case_rg6_intseed_cover() {
  dump rg6 || return 1
  local out="$TD/rg6.out"
  has_f "$out" 833E900001 || return 1
  has_f "$out" B401 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "0117" and r[1] == "833E900000"]
if not hit:
    sys.exit("no row 0117 833E900000:\n" + text)
bad = [r for r in rows if r[0].upper() == "0118"]
if bad:
    sys.exit("decoded row at 0118: " + " ".join(bad[0]) + "\n" + text)
print("rg6 intseed", len(rows))
PY
}

# RG6: a later opcode 00 must not swallow the ret leader.
case_rg6_zero_hole() {
  dump zhole || return 1
  local out="$TD/zhole.out"
  lacks_f "$out" 00C3 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "0105" and r[2].lower() == "ret"]
if not hit:
    sys.exit("no ret at 0105:\n" + text)
print("rg6 zero hole", " ".join(hit[0]))
PY
}

# RG6-r: a real opcode-00 add that covers a speculative INT-nearby seed
# stays one instruction, and the later mov ah,1 is still decoded.
case_rg6r() {
  dump rg6r || return 1
  local out="$TD/rg6r.out"
  has_f "$out" B401 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "0117" and r[1] == "00069000"]
if not hit:
    sys.exit("no row 0117 00069000:\n" + text)
print("rg6r", " ".join(hit[0]))
PY
}

# RG6-t: a speculative site-8 seed must not let opcode 00 swallow the
# jmp target. The target keeps its label and the INT 21h AH=42 note.
case_rg6t() {
  dump rg6t || return 1
  local out="$TD/rg6t.out"
  has_f "$out" func_0120 || return 1
  has_f "$out" LSEEK || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "0120" and r[1] == "B80242"]
if not hit:
    sys.exit("no row 0120 B80242:\n" + text)
print("rg6t", " ".join(hit[0]))
PY
}

# N5-pfx: opcode 00 after a CS prefix stops. ret at 0106 stays.
# A decoded row whose bytes are 2E00C3 swallowed that leader.
case_n5_pfx() {
  dump n5_pfx || return 1
  local out="$TD/n5_pfx.out"
  lacks_f "$out" 2E00C3 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
bad = [r for r in rows if r[1] == "2E00C3"]
if bad:
    sys.exit("decoded row bytes 2E00C3: " + " ".join(bad[0]) + "\n" + text)
hit = [r for r in rows if r[0].upper() == "0106" and r[2].lower() == "ret"]
if not hit:
    sys.exit("no ret at 0106:\n" + text)
print("n5 pfx", " ".join(hit[0]))
PY
}

# P1: a later opcode 00 must not swallow the ret leader. Same bytes as zhole.
case_real_leader_stop() {
  dump real_leader_stop || return 1
  local out="$TD/real_leader_stop.out"
  lacks_f "$out" 00C3 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
bad = [r for r in rows if r[1] == "00C3"]
if bad:
    sys.exit("decoded row bytes 00C3: " + " ".join(bad[0]) + "\n" + text)
hit = [r for r in rows if r[0].upper() == "0105" and r[2].lower() == "ret"]
if not hit:
    sys.exit("no ret at 0105:\n" + text)
print("real leader stop", " ".join(hit[0]))
PY
}

# P1: call target is claimed before the jmp target, so 0108 is not decoded.
# 010A stays 0001. The jmp prints 0x108 and not func_0108. ret stays at 010C.
case_first_insn_cover() {
  dump first_insn_cover || return 1
  local out="$TD/first_insn_cover.out"
  has_f "$out" 0x108 || return 1
  lacks_f "$out" func_0108 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "010A" and r[1] == "0001" and r[2].lower() == "add"]
if not hit:
    sys.exit("no row 010A 0001 add:\n" + text)
bad = [r for r in rows if r[0].upper() == "0108"]
if bad:
    sys.exit("decoded row at 0108: " + " ".join(bad[0]) + "\n" + text)
ret = [r for r in rows if r[0].upper() == "010C" and r[2].lower() == "ret"]
if not ret:
    sys.exit("no ret at 010C:\n" + text)
if "func_0108" in text:
    sys.exit("unexpected func_0108:\n" + text)
if "0x108" not in text:
    sys.exit("missing 0x108:\n" + text)
print("first insn cover", " ".join(hit[0]), " ".join(ret[0]))
PY
}

# P1: one func_0100, both INT 21h keep the AH=01 note, ret at 0108.
# A second nearby seed must not create func_0102.
case_second_nearby() {
  dump second_nearby || return 1
  local out="$TD/second_nearby.out"
  has_f "$out" func_0100 || return 1
  lacks_f "$out" func_0102 || return 1
  python3 - "$out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
cd = [r for r in rows if r[1] == "CD21"]
if len(cd) != 2:
    sys.exit("expected two CD21 rows, got %d:\n%s" % (len(cd), text))
ret = [r for r in rows if r[0].upper() == "0108" and r[2].lower() == "ret"]
if not ret:
    sys.exit("no ret at 0108:\n" + text)
notes = text.count("READ CHARACTER")
ah = text.count("ah, 1")
if notes < 2 and ah < 2:
    sys.exit("expected two AH=01 notes:\n" + text)
if "func_0100" not in text:
    sys.exit("missing func_0100:\n" + text)
if "func_0102" in text:
    sys.exit("unexpected func_0102:\n" + text)
print("second nearby", "cd", len(cd), "notes", notes, "ah", ah)
PY
}

# F6 nearby pins. -d listing only. A second nearby seed must not promote
# (nb1, nb2 keep row 012F 00C0). A later real enqueue must still promote
# (nb3, nb4 have no row at 012F).
dump_nb() {
  local name=$1
  "$BIN" -d --no-asm-file --no-repack "$TD/$name.com" >"$TD/$name.out" 2>"$TD/$name.err"
}

case_nb1() {
  dump_nb nb1 || return 1
  python3 - "$TD/nb1.out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "012F" and r[1] == "00C0"]
if not hit:
    sys.exit("no row 012F 00C0:\n" + text)
print("nb1", " ".join(hit[0]))
PY
}

case_nb2() {
  dump_nb nb2 || return 1
  python3 - "$TD/nb2.out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
hit = [r for r in rows if r[0].upper() == "012F" and r[1] == "00C0"]
if not hit:
    sys.exit("no row 012F 00C0 (second nearby seed promoted?):\n" + text)
print("nb2", " ".join(hit[0]))
PY
}

case_nb3() {
  dump_nb nb3 || return 1
  python3 - "$TD/nb3.out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
bad = [r for r in rows if r[0].upper() == "012F"]
if bad:
    sys.exit("row at 012F (later enqueue did not promote?): " + " ".join(bad[0]) + "\n" + text)
print("nb3 no 012F")
PY
}

case_nb4() {
  dump_nb nb4 || return 1
  python3 - "$TD/nb4.out" << 'PY'
import re, sys
text = open(sys.argv[1], errors="replace").read()
rows = re.findall(r"^\s+([0-9A-Fa-f]+)\s+([0-9A-F]+)\s+(\S+)", text, re.M)
if not rows:
    sys.exit("no decoded rows:\n" + text)
bad = [r for r in rows if r[0].upper() == "012F"]
if bad:
    sys.exit("row at 012F: " + " ".join(bad[0]) + "\n" + text)
print("nb4 no 012F")
PY
}

# Moved from test_p0_linear.sh. Same assertion. Does not need uasm.
case_rg4_int_below_frame() {
  "$BIN" --json --no-asm-file --no-repack "$TD/rg4.exe" \
    >"$TD/rg4.json" 2>"$TD/rg4.err" || {
    echo "rg4 json failed" >&2
    cat "$TD/rg4.err" >&2
    return 1
  }
  python3 - "$TD/rg4.json" << 'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))["cfg"]
if cfg["blocks"] < 5:
    sys.exit("blocks " + str(cfg["blocks"]))
print("rg4 int below frame", cfg["blocks"])
PY
}

case_max_image() {
  local err="$TD/big.err"
  if "$BIN" --no-asm-file --no-repack "$TD/bigmz.exe" >"$TD/big.out" 2>"$err"; then
    echo "oversize MZ exited 0" >&2
    return 1
  fi
  has_f "$err" 'Error: load image is 1114113 bytes, over the 1114112 cap (use --max-image=N)' || return 1
  "$BIN" --max-image=1114113 --no-asm-file --no-repack "$TD/bigmz.exe" \
    >"$TD/bigok.out" 2>"$TD/bigok.err" || {
    echo "raised cap failed" >&2
    cat "$TD/bigok.err" >&2
    return 1
  }
  if grep -F -q 'over the ' "$TD/bigok.err"; then
    echo "raised cap still refused" >&2
    cat "$TD/bigok.err" >&2
    return 1
  fi
  "$BIN" --no-asm-file --no-repack "$TD/smallmz.exe" \
    >"$TD/small.out" 2>"$TD/small.err" || {
    echo "small MZ failed" >&2
    cat "$TD/small.err" >&2
    return 1
  }
  if grep -F -q 'over the ' "$TD/small.err"; then
    echo "small MZ hit the cap" >&2
    return 1
  fi
  if "$BIN" --max-image 31 --no-asm-file --no-repack "$TD/smallmz.exe" \
      >"$TD/sp.out" 2>"$TD/sp.err"; then
    echo "space form did not cap" >&2
    return 1
  fi
  has_f "$TD/sp.err" 'Error: load image is 32 bytes, over the 31 cap (use --max-image=N)' || return 1
  if "$BIN" --no-asm-file "$TD/big.com" >"$TD/bigcom.out" 2>"$TD/bigcom.err"; then
    echo "oversize COM exited 0" >&2
    return 1
  fi
  has_f "$TD/bigcom.err" 'Error: load image is 1114369 bytes, over the 1114112 cap (use --max-image=N)' || return 1
  "$BIN" --max-image=0 "$TD/smallmz.exe" >"$TD/bad0.out" 2>"$TD/bad0.err" && return 1
  has_f "$TD/bad0.err" 'Error: Invalid --max-image value' || return 1
  "$BIN" --max-image= "$TD/smallmz.exe" >"$TD/bade.out" 2>"$TD/bade.err" && return 1
  has_f "$TD/bade.err" 'Error: Invalid --max-image value' || return 1
  "$BIN" --max-image=abc "$TD/smallmz.exe" >"$TD/bada.out" 2>"$TD/bada.err" && return 1
  has_f "$TD/bada.err" 'Error: Invalid --max-image value' || return 1
  "$BIN" --max-image 0 "$TD/smallmz.exe" >"$TD/badsp.out" 2>"$TD/badsp.err" && return 1
  has_f "$TD/badsp.err" 'Error: Invalid --max-image value' || return 1
}

check int20 case_int20
check int27 case_int27
check ah4c case_ah4c
check ah00 case_ah00
check ah31 case_ah31
check ax4c case_ax4c
check nop4c case_nop4c
check ah09 case_ah09
check unk case_unk
check into case_into
check zm_magic case_zm_magic
check before_image case_before_image
check delta0_entry case_delta0_entry
check call_fallthrough_zeros case_call_fallthrough_zeros
check nop_after_four_zeros case_nop_after_four_zeros
check ret_zero_hole case_ret_zero_hole
check rg6_intseed_cover case_rg6_intseed_cover
check rg6_zero_hole case_rg6_zero_hole
check rg6r case_rg6r
check rg6t case_rg6t
check n5_pfx case_n5_pfx
check real_leader_stop case_real_leader_stop
check first_insn_cover case_first_insn_cover
check second_nearby case_second_nearby
check nb1 case_nb1
check nb2 case_nb2
check nb3 case_nb3
check nb4 case_nb4
check rg4_int_below_frame case_rg4_int_below_frame
check max_image case_max_image

echo "cfg tests: $pass passed, $fail failed"
[[ "$fail" -eq 0 ]]
