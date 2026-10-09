#!/usr/bin/env bash
# dumpexe --uasm: UASM source assembles back to the load image (v2.26).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
if [[ ! -x "$BIN" ]]; then
  BIN=$(command -v dumpexe || true)
fi
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM="$(uasm_resolve)" || { echo "SKIP uasm tests (no uasm)"; exit 77; }

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
# or ax, 000Ah / 0100h / FF80h / FF7Fh, then ret. Signed-byte forms must stay db.
td.joinpath("aximm.com").write_bytes(bytes.fromhex("0D0A000D00010D80FF0D7FFFC3"))
PY

# 1. COM round-trip. No address column. org 100h and a mov line.
"$BIN" --uasm -o "$tmp/com.asm" "$tmp/tiny.com" >"$tmp/com.out" 2>"$tmp/com.err"
check com_has_mov grep -q 'mov' "$tmp/com.asm"
check com_org grep -q 'org 100h' "$tmp/com.asm"
check com_no_addr bash -c "! grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' '$tmp/com.asm'"
check com_no_repack bash -c "! grep -q 'REPACK-V1' '$tmp/com.asm'"
check com_end grep -qx 'end func_0100' "$tmp/com.asm"
( cd "$tmp" && "$UASM" -bin -nologo -Fo com.bin com.asm >com_uasm.out 2>com_uasm.err )
check com_cmp cmp_note com "$tmp/com.bin" "$tmp/tiny.com"

# 2. Small MZ: uasm -mz payload equals the load image.
"$BIN" --uasm -o "$tmp/small.asm" "$tmp/small.exe" >"$tmp/small.out" 2>"$tmp/small.err"
( cd "$tmp" && "$UASM" -mz -nologo -Fo small.built.exe small.asm >small_uasm.out 2>small_uasm.err )
python3 - "$tmp/small.built.exe" "$tmp/small.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"small e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
check small_cmp cmp_note small "$tmp/small.pay" "$tmp/small.img"
( cd "$tmp" && "$UASM" -bin -nologo -Fo small.bin small.asm >small_bin.out 2>small_bin.err )
check small_bin_cmp cmp_note small_bin "$tmp/small.bin" "$tmp/small.img"

# 3. 65540-byte load image, at least two segment directives, full payload.
"$BIN" --uasm -o "$tmp/big.asm" "$tmp/big.exe" >"$tmp/big.out" 2>"$tmp/big.err"
check big_segments bash -c 'test "$(grep -c segment "$1")" -ge 2' _ "$tmp/big.asm"
( cd "$tmp" && "$UASM" -mz -nologo -Fo big.built.exe big.asm >big_uasm.out 2>big_uasm.err )
python3 - "$tmp/big.built.exe" "$tmp/big.pay" << 'PY'
import struct, sys
p = open(sys.argv[1], "rb").read()
cpar = struct.unpack_from("<H", p, 8)[0]
open(sys.argv[2], "wb").write(p[cpar * 16:])
print(f"big e_cparhdr={cpar} payload={len(p) - cpar * 16}")
PY
check big_cmp cmp_note big "$tmp/big.pay" "$tmp/big.img"
check big_bare_end bash -c 'tail -n 1 "$1" | grep -qx end' _ "$tmp/big.asm"
( cd "$tmp" && "$UASM" -bin -nologo -Fo big.bin big.asm >big_bin.out 2>big_bin.err )
check big_bin_cmp cmp_note big_bin "$tmp/big.bin" "$tmp/big.img"

# 7. Stood-behind mov plus a 66h byte that is not itself stood behind.
# The prefix stays db. It must not raise .386 (that would be data-as-code).
# .8086 stays above .model. A real .186/.286/.386, if one appears, stays below.
"$BIN" --uasm -o "$tmp/wide.asm" "$tmp/wide.com" >"$tmp/wide.out" 2>"$tmp/wide.err"
check wide_mov grep -q 'mov' "$tmp/wide.asm"
check wide_no_addr bash -c "! grep -E -q '^[[:space:]]*[0-9A-Fa-f]{4}[[:space:]]+[0-9A-Fa-f]{2}' '$tmp/wide.asm'"
check wide_model_before_386 python3 - "$tmp/wide.asm" << 'PY'
import sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
model = next(i for i, line in enumerate(lines) if line.startswith(".model"))
text = "\n".join(lines)
if ".386" in text or ".286" in text or ".186" in text:
    print("66h db raised the CPU directive")
    print(text)
    sys.exit(1)
cpu = next(i for i, line in enumerate(lines) if line.startswith(".8086"))
if cpu > model:
    print(".8086 followed .model")
    sys.exit(1)
if "066h" not in text or "090h" not in text:
    print("operand-size prefix was not emitted as db")
    print(text)
    sys.exit(1)
PY
( cd "$tmp" && "$UASM" -bin -nologo -Fo wide.bin wide.asm >wide_uasm.out 2>wide_uasm.err )
check wide_cmp cmp_note wide "$tmp/wide.bin" "$tmp/wide.com"
"$BIN" --uasm -o "$tmp/wide_mz.asm" "$tmp/wide.exe" >"$tmp/wide_mz.out" 2>"$tmp/wide_mz.err"
( cd "$tmp" && "$UASM" -mz -nologo -Fo wide_mz.built.exe wide_mz.asm >wide_mz_uasm.out 2>wide_mz_uasm.err )
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

# 9. Signed-byte AX imm16 stays db; wider immediates stay the mnemonic.
"$BIN" --uasm -o "$tmp/aximm.asm" "$tmp/aximm.com" >"$tmp/aximm.out" 2>"$tmp/aximm.err"
check aximm_db_000a grep -q 'db 00Dh, 00Ah, 000h' "$tmp/aximm.asm"
check aximm_db_ff80 grep -q 'db 00Dh, 080h, 0FFh' "$tmp/aximm.asm"
check aximm_keep_100 grep -E -q '^[[:space:]]*or ax, 100h[[:space:]]*$' "$tmp/aximm.asm"
check aximm_keep_ff7f grep -E -q '^[[:space:]]*or ax, 0FF7Fh[[:space:]]*$' "$tmp/aximm.asm"
check aximm_reject_0a bash -c "! grep -E -q '^[[:space:]]*or ax, 0Ah[[:space:]]*$' '$tmp/aximm.asm'"
check aximm_reject_ff80 bash -c "! grep -E -q '^[[:space:]]*or ax, 0FF80h[[:space:]]*$' '$tmp/aximm.asm'"
( cd "$tmp" && "$UASM" -bin -nologo -Fo aximm.bin aximm.asm >aximm_uasm.out 2>aximm_uasm.err )
check aximm_cmp cmp_note aximm "$tmp/aximm.bin" "$tmp/aximm.com"

# 6. Help and version.
"$BIN" --help >"$tmp/help.txt"
check help_uasm grep -q -- '--uasm' "$tmp/help.txt"
check help_no_disable bash -c "! grep -q -- '--no-uasm' '$tmp/help.txt'"
"$BIN" -v >"$tmp/ver.txt"
check version_226 grep -q '2.26' "$tmp/ver.txt"

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
  echo "---- aximm.asm ----" >&2
  cat "$tmp/aximm.asm" >&2 || true
  echo "---- aximm uasm err ----" >&2
  cat "$tmp/aximm_uasm.err" >&2 || true
  exit 1
fi
