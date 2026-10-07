#!/usr/bin/env bash
# dumpexe 2.13 bugfix contracts. These checks do not skip.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-v213-XXXXXX")"
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
import struct, sys
from pathlib import Path
td = Path(sys.argv[1])

def build_mz(image, crlc=0, paras=2, sp=0x200, ip=0, cs=0, lfarlc=0x1C, ovno=0):
    header_bytes = paras * 16
    total = header_bytes + len(image)
    final_len = total % 512
    num_blocks = (total + 511) // 512
    if total % 512 == 0:
        final_len = 0
    hdr = bytearray(header_bytes)
    struct.pack_into("<14H", hdr, 0,
                     0x5A4D, final_len, num_blocks, crlc, paras,
                     0, 0xFFFF, 0, sp, 0, ip, cs & 0xFFFF, lfarlc, ovno)
    return bytes(hdr) + image

def crc16_arc(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA001
            else:
                crc >>= 1
            crc &= 0xFFFF
    return crc

# M1: lcall 0:0006 inside an image whose file CS is 0.
same = bytes([0x9A, 0x06, 0x00, 0x00, 0x00, 0xC3, 0xC3])
(td / "far_same.exe").write_bytes(build_mz(same, ip=0, cs=0))
cross = bytes([0x9A, 0x06, 0x00, 0x34, 0x12, 0xC3, 0xC3])
(td / "far_cross.exe").write_bytes(build_mz(cross, ip=0, cs=0))

# M2: 65 distinct AH=3Ch creates. Names are AA, AB, ... at 0130h.
com = bytes([
    0x32, 0xFF,             # xor bh, bh
    0xB6, 0x41,             # mov dh, 'A'
    0xB2, 0x41,             # mov dl, 'A'
    0x88, 0x36, 0x30, 0x01, # mov [0130h], dh
    0x88, 0x16, 0x31, 0x01, # mov [0131h], dl
    0x52,                   # push dx
    0xBA, 0x30, 0x01,       # mov dx, 0130h
    0x33, 0xC9,             # xor cx, cx
    0xB4, 0x3C,             # mov ah, 3Ch
    0xCD, 0x21,             # int 21h
    0x5A,                   # pop dx
    0xFE, 0xC7,             # inc bh
    0x80, 0xFF, 0x41,       # cmp bh, 65
    0x73, 0x0D,             # jae done
    0xFE, 0xC2,             # inc dl
    0x80, 0xFA, 0x5B,       # cmp dl, 'Z'+1
    0x72, 0xDF,             # jb loop
    0xB2, 0x41,             # mov dl, 'A'
    0xFE, 0xC6,             # inc dh
    0xEB, 0xD9,             # jmp loop
    0xC3,                   # ret
    0x00, 0x00,
    0x41, 0x41, 0x00,       # "AA"
])
assert com[0x30:0x33] == b"AA\x00"
(td / "cap.com").write_bytes(com)

# O9: last-in-chain SYS, a chained header, and a COM that must stay COM.
last = bytearray(0x40)
struct.pack_into("<I", last, 0, 0xFFFFFFFF)
struct.pack_into("<H", last, 4, 0x8000)
struct.pack_into("<HH", last, 6, 0x20, 0x21)
last[0x20] = 0xC3
last[0x21] = 0xC3
(td / "last.sys").write_bytes(last)
sys = bytearray(0x40)
struct.pack_into("<I", sys, 0, 0x20)
struct.pack_into("<H", sys, 4, 0x8000)
struct.pack_into("<HH", sys, 6, 0x30, 0x31)
sys[10:18] = b"NUL     "
struct.pack_into("<I", sys, 0x20, 0xFFFFFFFF)
struct.pack_into("<H", sys, 0x24, 0x8000)
# Offsets are from this second header, so they must fit in the tail.
struct.pack_into("<HH", sys, 0x26, 0x10, 0x11)
sys[0x30] = 0xC3
sys[0x31] = 0xC3
(td / "chain.sys").write_bytes(sys)
(td / "plain.com").write_bytes(b"\xC3" + b"\x00" * 63)

# O10 / X2 / L2 use these.
(td / "tiny.com").write_bytes(b"\xC3")
bad = bytearray(32)
struct.pack_into("<14H", bad, 0, 0x5A4D, 0, 0, 0, 2, 0, 0xFFFF, 0, 0x200, 0, 0, 0, 0x1C, 0)
(td / "bad_mz.exe").write_bytes(bad)

# L3: CS 0x1000 IP 0 is linear 0x10000, inside a 65537-byte image.
image = bytearray(65537)
image[0] = 0xC3
image[65536] = 0xC3
(td / "past64.exe").write_bytes(build_mz(bytes(image), ip=0, cs=0x1000))

# Level-2 LHA appended after the declared MZ image (SFX trailer).
stub = build_mz(b"\xC3" + b"\x90" * 16, ip=0, cs=0)
hdr = bytearray(31 + 4)
hdr[0] = 31
hdr[2:7] = b"-lh5-"
struct.pack_into("<I", hdr, 7, 4)
struct.pack_into("<I", hdr, 11, 4)
hdr[19] = 0x20
hdr[20] = 2
hdr[23] = ord("M")
hdr[24] = 5
hdr[26] = 0
csum = crc16_arc(bytes(hdr[:31]))
hdr[27] = csum & 0xFF
hdr[28] = (csum >> 8) & 0xFF
(td / "lha_l2.exe").write_bytes(stub + bytes(hdr))

# Sentence plus NULs in the middle of a long image.
mid = bytearray(400)
mid[80:85] = b"-lh5-"
(td / "lha_text.exe").write_bytes(build_mz(bytes(mid), ip=0, cs=0))
print("fixtures", td)
PY

check far_default bash -c "
  set -euo pipefail
  '$BIN' --json '$TD/far_same.exe' >'$TD/far_same.json'
  python3 - '$TD/far_same.json' << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
edges = d['cfg']['edges']
hit = [e for e in edges if e.get('to') == '0006' and e.get('kind') == 'call']
if not hit:
    sys.exit('default base did not follow lcall 0:0006: ' + str(edges))
print('far default ok', len(edges))
PY
"

check far_base0 bash -c "
  set -euo pipefail
  '$BIN' --json --base=0 '$TD/far_same.exe' >'$TD/far_base0.json'
  python3 - '$TD/far_base0.json' << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
edges = d['cfg']['edges']
hit = [e for e in edges if e.get('to') == '0006' and e.get('kind') == 'call']
if not hit:
    sys.exit('base 0 did not follow lcall 0:0006')
print('far base0 ok')
PY
"

check far_cross bash -c "
  set -euo pipefail
  '$BIN' --json '$TD/far_cross.exe' >'$TD/far_cross.json'
  python3 - '$TD/far_cross.json' << 'PY'
import json, sys
d = json.load(open(sys.argv[1]))
edges = d['cfg']['edges']
hit = [e for e in edges if e.get('to') == '0006']
if hit:
    sys.exit('cross-segment lcall was followed: ' + str(hit))
print('far cross ok')
PY
"

check guest_file_cap bash -c "
  set -euo pipefail
  '$BIN' --max-insns=8000 '$TD/cap.com' >'$TD/cap.out' 2>'$TD/cap.err'
  python3 - '$TD/cap.out' << 'PY'
import sys
text = open(sys.argv[1], encoding='utf-8', errors='replace').read()
ok = text.count('\u2192 handle')
cap = text.count('guest file cap')
print('creates', ok, 'cap_fails', cap)
if ok != 64 or cap != 1:
    sys.exit(1)
PY
"

check sys_chain bash -c "
  set -euo pipefail
  '$BIN' --json '$TD/chain.sys' >'$TD/chain.json'
  '$BIN' --json '$TD/last.sys' >'$TD/last.json'
  '$BIN' --json '$TD/plain.com' >'$TD/plain.json'
  python3 - '$TD/chain.json' '$TD/last.json' '$TD/plain.json' << 'PY'
import json, sys
chain = json.load(open(sys.argv[1]))
last = json.load(open(sys.argv[2]))
plain = json.load(open(sys.argv[3]))
assert chain['format'] == 'sys', chain['format']
assert last['format'] == 'sys', last['format']
assert plain['format'] == 'com', plain['format']
print('sys chain ok')
PY
  set +e
  '$BIN' --uasm -o '$TD/chain.asm' '$TD/chain.sys' >'$TD/chain_u.out' 2>'$TD/chain_u.err'
  rc=\$?
  set -e
  [[ \$rc -eq 1 ]]
  grep -q 'implemented for MZ and COM' '$TD/chain_u.err'
  [[ ! -e '$TD/chain.asm' ]]
"

check max_insns_minus bash -c "
  set -euo pipefail
  set +e
  '$BIN' --max-insns=-1 '$TD/tiny.com' >'$TD/minus.out' 2>'$TD/minus.err'
  rc=\$?
  set -e
  [[ \$rc -eq 1 ]]
  grep -q 'Invalid --max-insns' '$TD/minus.err'
"

check json_n_edges bash -c "
  set -euo pipefail
  '$BIN' --json '$TD/far_same.exe' >'$TD/edges.json'
  python3 - '$TD/edges.json' << 'PY'
import json, sys
text = open(sys.argv[1]).read()
d = json.load(open(sys.argv[1]))
if text.count('\"edges\"') != 1:
    sys.exit('edges key count ' + str(text.count('\"edges\"')))
if '\"n_edges\"' not in text:
    sys.exit('missing n_edges')
assert isinstance(d['cfg']['edges'], list)
assert d['cfg']['n_edges'] == len(d['cfg']['edges']) or d['cfg']['edges_truncated']
tc = d['toolchain']
assert 'packer' in tc, tc
assert tc['packer'] == '' or isinstance(tc['packer'], str)
print('json edges ok', d['cfg']['n_edges'], 'packer', repr(tc['packer']))
PY
"

check json_rejected_mz bash -c "
  set -euo pipefail
  set +e
  '$BIN' --json '$TD/bad_mz.exe' >'$TD/bad.json' 2>'$TD/bad.err'
  rc=\$?
  set -e
  [[ \$rc -eq 1 ]]
  python3 - '$TD/bad.json' << 'PY'
import json, sys
text = open(sys.argv[1]).read()
d = json.load(open(sys.argv[1]))
assert d['error'] == 'rejected MZ header', d
assert d['format'] == 'mz'
keys = []
for line in text.splitlines():
    s = line.strip().rstrip(',')
    if s.startswith('\"') and '\":' in s:
        keys.append(s.split('\"', 2)[1])
if len(keys) != len(set(keys)):
    sys.exit('duplicate keys ' + str(keys))
print('rejected mz ok', keys)
PY
"

check entry_past_window bash -c "
  set -euo pipefail
  '$BIN' --uasm -o '$TD/past64.asm' '$TD/past64.exe' >'$TD/past64.out' 2>'$TD/past64.err'
  if grep -q 'entry is past the 64 KiB decode window' '$TD/past64.asm'; then
    echo 'in-image entry must not print the past-window note' >&2
    exit 1
  fi
  grep -q 'func_10000' '$TD/past64.asm'
  grep -q 'ret' '$TD/past64.asm'
  # Multi-segment listing still ends with a bare end.
  tail -n 5 '$TD/past64.asm' | grep -q '^end$'
  if grep -q 'func_FFFF' '$TD/past64.asm'; then
    echo 'func_FFFF still emitted' >&2
    exit 1
  fi
"

check named_o_quiet_stdout bash -c "
  set -euo pipefail
  '$BIN' -d -o '$TD/tiny.asm' '$TD/tiny.com' >'$TD/tiny_d.out' 2>'$TD/tiny_d.err'
  # The header report stays on stdout. The listing does not.
  if grep -q 'func_' '$TD/tiny_d.out'; then
    echo 'listing was also printed on stdout' >&2
    exit 1
  fi
  grep -q 'func_' '$TD/tiny.asm'
"

check lha_level2_trailer bash -c "
  set -euo pipefail
  '$BIN' '$TD/lha_l2.exe' >'$TD/lha_l2.out'
  '$BIN' '$TD/lha_text.exe' >'$TD/lha_text.out'
  grep -q 'Packer:      LHarc' '$TD/lha_l2.out'
  if grep -q 'Packer:      LHarc' '$TD/lha_text.out'; then
    echo 'mid-file -lh5- reported LHarc' >&2
    exit 1
  fi
"

check uasm_no_side_file bash -c "
  set -euo pipefail
  '$BIN' --uasm -o '$TD/lha_l2.asm' '$TD/lha_l2.exe' >'$TD/lha_u.out' 2>'$TD/lha_u.err'
  [[ ! -e '$TD/lha_l2_UNPACKED.EXE' ]]
  [[ ! -e '$TD/lha_l2_UNPACKED.COM' ]]
  [[ ! -e '$TD/lha_l2_UNPACKED.asm' ]]
  if grep -q 'unpack failed' '$TD/lha_u.err'; then
    echo '--uasm tried to unpack' >&2
    exit 1
  fi
"

echo "---"
echo "v213 passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
