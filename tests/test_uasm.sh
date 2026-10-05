#!/usr/bin/env bash
# dumpexe --uasm: UASM source assembles back to the load image (v2.10).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
if [[ ! -x "$BIN" ]]; then
  BIN=$(command -v dumpexe || true)
fi
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
[[ -x /usr/bin/uasm ]] || { echo "FAIL: /usr/bin/uasm is required"; exit 1; }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-uasm-XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

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

cmp_note() {
  local name=$1
  local a=$2
  local b=$3
  if cmp -s "$a" "$b"; then
    echo "cmp $name: identical (exit 0)"
    return 0
  fi
  echo "cmp $name: differ (exit 1)" >&2
  echo "  left  $a ($(wc -c < "$a") bytes)" >&2
  echo "  right $b ($(wc -c < "$b") bytes)" >&2
  return 1
}

python3 - "$tmp" << 'PY'
import struct, sys
from pathlib import Path
td = Path(sys.argv[1])

def mz(image: bytes) -> bytes:
    hdr = 32
    total = hdr + len(image)
    blocks = (total + 511) // 512
    final = total % 512
    # final_len 0 means a full last page; keep a non-zero remainder.
    if final == 0:
        final = 512
        blocks = total // 512
    h = bytearray(hdr)
    struct.pack_into("<H", h, 0, 0x5A4D)
    struct.pack_into("<H", h, 2, final if final != 512 else 0)
    struct.pack_into("<H", h, 4, blocks if final != 512 else total // 512)
    struct.pack_into("<H", h, 6, 0)       # relocs
    struct.pack_into("<H", h, 8, 2)       # header paragraphs
    struct.pack_into("<H", h, 10, 0)      # minalloc
    struct.pack_into("<H", h, 12, 0xFFFF) # maxalloc
    struct.pack_into("<H", h, 14, 0)      # ss
    struct.pack_into("<H", h, 16, 0)      # sp
    struct.pack_into("<H", h, 18, 0)      # checksum
    struct.pack_into("<H", h, 20, 0)      # ip
    struct.pack_into("<H", h, 22, 0)      # cs
    struct.pack_into("<H", h, 24, 0x1C)   # reloc table
    struct.pack_into("<H", h, 26, 0)      # overlay
    return bytes(h) + image

td.joinpath("tiny.com").write_bytes(bytes.fromhex("B8004CCD21"))
td.joinpath("wide.com").write_bytes(bytes.fromhex("B8004C6690"))
td.joinpath("wide.exe").write_bytes(mz(bytes.fromhex("B8004C6690")))
td.joinpath("wide.img").write_bytes(bytes.fromhex("B8004C6690"))
td.joinpath("small.exe").write_bytes(mz(bytes.fromhex("B8004CCD2190")))
big = bytearray(65540)
big[0:5] = bytes.fromhex("B8004CCD21")
big[65536] = 0x90
td.joinpath("big.exe").write_bytes(mz(bytes(big)))
td.joinpath("big.img").write_bytes(bytes(big))
td.joinpath("small.img").write_bytes(bytes.fromhex("B8004CCD2190"))
PY

# 1. COM round-trip. No address column. org 100h and a mov line.
"$BIN" --uasm -o "$tmp/com.asm" "$tmp/tiny.com" >"$tmp/com.out" 2>"$tmp/com.err"
check com_has_mov grep -q 'mov' "$tmp/com.asm"
check com_org grep -q 'org 100h' "$tmp/com.asm"
check com_no_addr bash -c "! grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' '$tmp/com.asm'"
check com_no_repack bash -c "! grep -q 'REPACK-V1' '$tmp/com.asm'"
/usr/bin/uasm -bin -nologo -Fo "$tmp/com.bin" "$tmp/com.asm" >"$tmp/com_uasm.out" 2>"$tmp/com_uasm.err"
check com_cmp cmp_note com "$tmp/com.bin" "$tmp/tiny.com"

# 2. Small MZ: uasm -mz payload equals the load image.
"$BIN" --uasm -o "$tmp/small.asm" "$tmp/small.exe" >"$tmp/small.out" 2>"$tmp/small.err"
/usr/bin/uasm -mz -nologo -Fo "$tmp/small.built.exe" "$tmp/small.asm" >"$tmp/small_uasm.out" 2>"$tmp/small_uasm.err"
python3 - "$tmp/small.built.exe" "$tmp/small.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"small e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
check small_cmp cmp_note small "$tmp/small.pay" "$tmp/small.img"

# 3. 65540-byte load image, at least two segment directives, full payload.
"$BIN" --uasm -o "$tmp/big.asm" "$tmp/big.exe" >"$tmp/big.out" 2>"$tmp/big.err"
check big_segments bash -c 'test "$(grep -c segment "$1")" -ge 2' _ "$tmp/big.asm"
/usr/bin/uasm -mz -nologo -Fo "$tmp/big.built.exe" "$tmp/big.asm" >"$tmp/big_uasm.out" 2>"$tmp/big_uasm.err"
python3 - "$tmp/big.built.exe" "$tmp/big.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"big e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
check big_cmp cmp_note big "$tmp/big.pay" "$tmp/big.img"

# 7. Stood-behind mov plus a 66h byte. .model before .386 keeps USE16.
"$BIN" --uasm -o "$tmp/wide.asm" "$tmp/wide.com" >"$tmp/wide.out" 2>"$tmp/wide.err"
check wide_mov grep -q 'mov' "$tmp/wide.asm"
check wide_no_addr bash -c "! grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' '$tmp/wide.asm'"
check wide_model_before_386 python3 - "$tmp/wide.asm" << 'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
model = next(i for i, line in enumerate(lines) if line.startswith(".model"))
cpu = next(i for i, line in enumerate(lines) if line.startswith(".386"))
sys.exit(0 if model < cpu else 1)
PY
/usr/bin/uasm -bin -nologo -Fo "$tmp/wide.bin" "$tmp/wide.asm" >"$tmp/wide_uasm.out" 2>"$tmp/wide_uasm.err"
check wide_cmp cmp_note wide "$tmp/wide.bin" "$tmp/wide.com"
"$BIN" --uasm -o "$tmp/wide_mz.asm" "$tmp/wide.exe" >"$tmp/wide_mz.out" 2>"$tmp/wide_mz.err"
/usr/bin/uasm -mz -nologo -Fo "$tmp/wide_mz.built.exe" "$tmp/wide_mz.asm" >"$tmp/wide_mz_uasm.out" 2>"$tmp/wide_mz_uasm.err"
python3 - "$tmp/wide_mz.built.exe" "$tmp/wide_mz.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"wide e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
check wide_mz_cmp cmp_note wide_mz "$tmp/wide_mz.pay" "$tmp/wide.img"

# 8. -d --uasm -o - is UASM on stdout, no address listing.
"$BIN" -d --uasm -o - "$tmp/tiny.com" >"$tmp/dash.out" 2>"$tmp/dash.err"
check dash_mov grep -q 'mov' "$tmp/dash.out"
check dash_org grep -q 'org 100h' "$tmp/dash.out"
check dash_no_addr bash -c "! grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' '$tmp/dash.out'"

# 4. -d without --uasm still prints an address column.
"$BIN" -d --no-asm-file "$tmp/tiny.com" >"$tmp/d.out" 2>"$tmp/d.err"
check d_addr grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' "$tmp/d.out"

# 5. --uasm --no-asm-file exits 1.
set +e
"$BIN" --uasm --no-asm-file >"$tmp/need.out" 2>"$tmp/need.err"
need_rc=$?
set -e
check uasm_needs_file test "$need_rc" -eq 1
check uasm_needs_msg grep -q 'dumpexe: --uasm needs an .asm file' "$tmp/need.err"

# 6. Help and version.
"$BIN" --help >"$tmp/help.txt"
check help_uasm grep -q -- '--uasm' "$tmp/help.txt"
check help_no_disable bash -c "! grep -q -- '--no-uasm' '$tmp/help.txt'"
"$BIN" -v >"$tmp/ver.txt"
check version_210 grep -q '2.10' "$tmp/ver.txt"

echo "uasm tests: $pass passed, $fail failed"
if [[ "$fail" -ne 0 ]]; then
  echo "---- com.asm head ----" >&2
  head -n 40 "$tmp/com.asm" >&2 || true
  echo "---- com uasm err ----" >&2
  cat "$tmp/com_uasm.err" >&2 || true
  echo "---- small.asm head ----" >&2
  head -n 40 "$tmp/small.asm" >&2 || true
  echo "---- small uasm err ----" >&2
  cat "$tmp/small_uasm.err" >&2 || true
  echo "---- big.asm head ----" >&2
  head -n 30 "$tmp/big.asm" >&2 || true
  echo "---- big uasm err ----" >&2
  cat "$tmp/big_uasm.err" >&2 || true
  exit 1
fi
