#!/usr/bin/env bash
# P0 UASM spelling and bounded verify-by-assembly.
# Missing assembler: exit 77 (skip). make test-uasm fails instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
# shellcheck source=lib_uasm.sh
source "$ROOT/tests/lib_uasm.sh"
UASM="$(uasm_resolve)" || { echo "SKIP test_p0_uasm (no uasm)"; exit 77; }

TD="$(mktemp -d "${TMPDIR:-/tmp}/dumpexe-p0-uasm-XXXXXX")"
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

write_com() {
  local name=$1
  local hex=$2
  python3 -c 'import pathlib, sys; pathlib.Path(sys.argv[1]).write_bytes(bytes.fromhex(sys.argv[2]))' \
    "$TD/$name.com" "$hex"
}

emit_u() {
  local name=$1
  local hex=$2
  shift 2
  write_com "$name" "$hex" || return 1
  if ! "$BIN" "$@" --uasm -o "$TD/$name.asm" "$TD/$name.com" \
      >"$TD/$name.stdout" 2>"$TD/$name.stderr"; then
    echo "dumpexe --uasm failed for $name" >&2
    cat "$TD/$name.stderr" >&2 || true
    return 1
  fi
}

emit() {
  emit_u "$1" "$2"
}

emit_verify() {
  emit_u "$1" "$2" --uasm-verify --uasm-bin "$UASM"
}

disasm() {
  local name=$1
  if ! "$BIN" -d --no-asm-file "$TD/$name.com" \
      >"$TD/$name.d" 2>"$TD/$name.derr"; then
    echo "dumpexe -d failed for $name" >&2
    cat "$TD/$name.derr" >&2 || true
    return 1
  fi
}

round_bin() {
  local name=$1
  if ! (
    cd "$TD" || exit 1
    "$UASM" -bin -nologo -Fo "$name.bin" "$name.asm" \
      >"$name.uout" 2>"$name.uerr"
  ); then
    echo "uasm failed for $name" >&2
    cat "$TD/$name.uerr" >&2 || true
    echo "---- $name.asm ----" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
  if ! cmp -s "$TD/$name.bin" "$TD/$name.com"; then
    echo "cmp failed for $name" >&2
    echo "---- $name.asm ----" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
}

has() {
  local name=$1
  local needle=$2
  if ! grep -F -q -- "$needle" "$TD/$name.asm"; then
    echo "missing [$needle] in $name.asm" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
}

lacks() {
  local name=$1
  local needle=$2
  if grep -F -q -- "$needle" "$TD/$name.asm"; then
    echo "unexpected [$needle] in $name.asm" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
}

has_d() {
  local name=$1
  local needle=$2
  if ! grep -F -q -- "$needle" "$TD/$name.d"; then
    echo "missing [$needle] in $name -d" >&2
    cat "$TD/$name.d" >&2 || true
    return 1
  fi
}

# Mnemonic column only. Comment lines (the source path) do not count.
has_d_mnem() {
  local name=$1
  local mnem=$2
  python3 - "$TD/$name.d" "$mnem" << 'PY'
import sys
path, mnem = sys.argv[1], sys.argv[2]
for raw in open(path, encoding="utf-8", errors="replace"):
    if raw.lstrip().startswith(";"):
        continue
    if mnem in raw.split():
        sys.exit(0)
print("missing -d mnemonic", mnem, file=sys.stderr)
sys.stderr.write(open(path, encoding="utf-8", errors="replace").read())
sys.exit(1)
PY
}

lacks_d_mnem() {
  local name=$1
  local mnem=$2
  python3 - "$TD/$name.d" "$mnem" << 'PY'
import sys
path, mnem = sys.argv[1], sys.argv[2]
for raw in open(path, encoding="utf-8", errors="replace"):
    if raw.lstrip().startswith(";"):
        continue
    if mnem in raw.split():
        print("unexpected -d mnemonic", mnem, file=sys.stderr)
        sys.stderr.write(raw)
        sys.exit(1)
sys.exit(0)
PY
}

# Ban an instruction line equal to the text, or that text plus a suffix with no space
# only when the whole stripped line is exactly it. db/directives are ignored.
no_insn() {
  local name=$1
  local bad=$2
  python3 - "$TD/$name.asm" "$bad" << 'PY'
import sys
path, bad = sys.argv[1], sys.argv[2]
for raw in open(path, encoding="utf-8"):
    s = raw.strip()
    if not s or s.startswith(";") or s.startswith(".") or s.endswith(":"):
        continue
    if s.startswith("db ") or s.startswith("org ") or s.startswith("end"):
        continue
    if s == bad or s.startswith(bad + " ") or s.startswith(bad + "\t"):
        print("banned instruction:", s, file=sys.stderr)
        sys.exit(1)
sys.exit(0)
PY
}

exact_insn() {
  local name=$1
  local want=$2
  python3 - "$TD/$name.asm" "$want" << 'PY'
import sys
path, want = sys.argv[1], sys.argv[2]
hit = False
for raw in open(path, encoding="utf-8"):
    s = raw.strip()
    if s == want:
        hit = True
if not hit:
    print("missing instruction line:", want, file=sys.stderr)
    sys.exit(1)
PY
}

case_eb() {
  emit eb EB00C3 || return 1
  has eb "jmp short" || return 1
  has eb "ret" || return 1
  round_bin eb
}

case_e9() {
  emit e9 E90000C3 || return 1
  has e9 "jmp near ptr" || return 1
  round_bin e9
}

case_e8() {
  emit e8 E80000C3 || return 1
  has e8 "call near ptr" || return 1
  round_bin e8
}

case_je() {
  emit je 7400C3 || return 1
  has je "je short" || return 1
  round_bin je
}

case_cbw() {
  emit op98 98C3 || return 1
  exact_insn op98 "cbw" || return 1
  lacks op98 "cwde" || return 1
  disasm op98 || return 1
  has_d_mnem op98 "cbw" || return 1
  lacks_d_mnem op98 "cwde" || return 1
  round_bin op98
}

case_cwd() {
  emit op99 99C3 || return 1
  exact_insn op99 "cwd" || return 1
  lacks op99 "cdq" || return 1
  disasm op99 || return 1
  has_d_mnem op99 "cwd" || return 1
  lacks_d_mnem op99 "cdq" || return 1
  round_bin op99
}

case_op66() {
  emit op66 6698C3 || return 1
  disasm op66 || return 1
  has_d_mnem op66 "cwde" || return 1
  has op66 "066h" || return 1
  has op66 "098h" || return 1
  lacks op66 "cbw" || return 1
  lacks op66 ".386" || return 1
  round_bin op66
}

case_d42() {
  write_com d42 B042C3 || return 1
  disasm d42 || return 1
  has_d d42 "0x42"
}

case_imm() {
  emit imm B80100C3 || return 1
  has imm "mov ax, 1h" || return 1
  round_bin imm
}

case_mov89() {
  emit mov89 89D8C3 || return 1
  has mov89 "089h" || return 1
  has mov89 "0D8h" || return 1
  no_insn mov89 "mov ax, bx" || return 1
  round_bin mov89
}

case_mov8b() {
  emit mov8b 8BC3C3 || return 1
  has mov8b "08Bh" || return 1
  has mov8b "0C3h" || return 1
  no_insn mov8b "mov ax, bx" || return 1
  has mov8b "; NOT VERIFIED" || return 1
  round_bin mov8b
}

case_mov8b_verify() {
  emit_verify mov8bv 8BC3C3 || return 1
  exact_insn mov8bv "mov ax, bx" || return 1
  has mov8bv "; verified: uasm" || return 1
  round_bin mov8bv
}

case_int3() {
  emit cc CCC3 || return 1
  exact_insn cc "int 3" || return 1
  lacks cc "int3" || return 1
  round_bin cc
}

case_cd03() {
  emit cd03 CD03C3 || return 1
  has cd03 "0CDh" || return 1
  has cd03 "03h" || return 1
  no_insn cd03 "int 3" || return 1
  no_insn cd03 "int 3h" || return 1
  round_bin cd03
}

case_pushds() {
  emit pushds 1EC3 || return 1
  exact_insn pushds "push ds" || return 1
  round_bin pushds
}

case_aximm() {
  emit aximm 0580FFC3 || return 1
  has aximm "005h" || return 1
  has aximm "080h" || return 1
  has aximm "0FFh" || return 1
  no_insn aximm "add ax" || return 1
  round_bin aximm
}

case_movsb() {
  emit_verify movsb A4C3 || return 1
  exact_insn movsb "movsb" || return 1
  lacks movsb "byte ptr" || return 1
  round_bin movsb
}

case_repmovsb() {
  emit_verify rep F3A4C3 || return 1
  exact_insn rep "rep movsb" || return 1
  lacks rep "repne" || return 1
  round_bin rep
}

case_lds() {
  emit_verify lds C507C3 || return 1
  has lds "dword ptr" || return 1
  round_bin lds
}

case_xchg() {
  emit xchg 93C3 || return 1
  exact_insn xchg "xchg ax, bx" || return 1
  round_bin xchg
}

case_pusha() {
  emit_verify pusha 60C3 || return 1
  exact_insn pusha "pusha" || return 1
  python3 - "$TD/pusha.asm" << 'PY' || return 1
import sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
model = next(i for i, line in enumerate(lines) if line.startswith(".model"))
cpu = next(i for i, line in enumerate(lines) if line.startswith(".186"))
if cpu <= model:
    print(".186 does not follow .model", file=sys.stderr)
    sys.exit(1)
PY
  round_bin pusha
}

check eb00 case_eb
check e9 case_e9
check e8 case_e8
check je case_je
check cbw case_cbw
check cwd case_cwd
check op66 case_op66
check d42 case_d42
check imm1h case_imm
check mov89 case_mov89
check mov8b case_mov8b
check int3 case_int3
check cd03 case_cd03
check pushds case_pushds
check aximm_ff80 case_aximm
check movsb case_movsb
check rep_movsb case_repmovsb
check lds case_lds
check xchg case_xchg
check pusha case_pusha

labels_closed() {
  local name=$1
  python3 - "$TD/$name.asm" << 'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
defined = set()
for line in text.splitlines():
    s = line.strip()
    m = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):", s)
    if m:
        defined.add(m.group(1))
        continue
    m = re.match(r"([A-Za-z_][A-Za-z0-9_]*)\s+equ\b", s)
    if m:
        defined.add(m.group(1))
refs = set(re.findall(r"\b(?:func|loc)_[0-9A-Fa-f]+\b", text))
missing = sorted(r for r in refs if r not in defined)
if missing:
    sys.stderr.write("undefined " + " ".join(missing) + "\n")
    sys.stderr.write(text)
    sys.exit(1)
PY
}

case_source_name_not_label() {
  printf '\xc3' > "$TD/func_BEEF.com"
  if ! "$BIN" --uasm -o "$TD/func_BEEF.asm" "$TD/func_BEEF.com" \
      >"$TD/func_BEEF.out" 2>"$TD/func_BEEF.err"; then
    echo "source name func_BEEF.com was treated as a label" >&2
    cat "$TD/func_BEEF.err" >&2 || true
    return 1
  fi
  if grep -q 'undefined labels' "$TD/func_BEEF.err"; then
    echo "comment path counted as a reference" >&2
    cat "$TD/func_BEEF.err" >&2
    return 1
  fi
}

case_mid_insn_label() {
  emit mid E80100B8C3C3CD20 || return 1
  has mid "s0_base:" || return 1
  has mid "func_0104 equ s0_base+(0104h-100h)" || return 1
  has mid "call near ptr func_0104" || return 1
  labels_closed mid || return 1
  round_bin mid
}

case_ret0() {
  emit ret0 C20000 || return 1
  has ret0 "0C2h" || return 1
  no_insn ret0 "ret" || return 1
  round_bin ret0
}

case_retf0() {
  emit retf0 CA0000 || return 1
  has retf0 "0CAh" || return 1
  no_insn retf0 "retf" || return 1
  round_bin retf0
}

case_ret4() {
  emit ret4 C20400 || return 1
  exact_insn ret4 "ret 4h" || return 1
  round_bin ret4
}

case_x9_call() {
  emit x9call E80100B8C3C3 || return 1
  has x9call "func_0104 equ s0_base+(0104h-100h)" || return 1
  labels_closed x9call || return 1
  round_bin x9call
}

case_x9_psp() {
  emit x9psp E9FAFFC3 || return 1
  has x9psp "func_00FD equ s0_base+(00FDh-100h)" || return 1
  labels_closed x9psp || return 1
  round_bin x9psp
}

case_batch64() {
  python3 - "$TD/b64.com" << 'PY'
import pathlib
import sys
body = bytearray()
for modrm in range(0xC0, 0x100):
    body += bytes((0x8B, modrm))
pathlib.Path(sys.argv[1]).write_bytes(body)
PY
  local start end ms n
  start=$(date +%s%N)
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$UASM" -o "$TD/b64.asm" "$TD/b64.com" \
      >"$TD/b64.stdout" 2>"$TD/b64.stderr"; then
    echo "batch verify failed" >&2
    cat "$TD/b64.stderr" >&2 || true
    return 1
  fi
  end=$(date +%s%N)
  ms=$(( (end - start) / 1000000 ))
  if [[ "$ms" -ge 3000 ]]; then
    echo "batch verify took ${ms} ms" >&2
    return 1
  fi
  n=$(grep -c '^    mov ' "$TD/b64.asm" || true)
  if [[ "$n" -lt 64 ]]; then
    echo "promoted mov lines: $n (${ms} ms)" >&2
    cat "$TD/b64.asm" >&2 || true
    return 1
  fi
  has b64 "; verified: uasm" || return 1
  echo "batch64 ${ms} ms"
}

case_verify_missing() {
  write_com miss C3 || return 1
  local rc=0
  "$BIN" --uasm --uasm-verify --uasm-bin /no/such/uasm -o "$TD/miss.asm" "$TD/miss.com" \
    >"$TD/miss.stdout" 2>"$TD/miss.stderr" || rc=$?
  [[ "$rc" -ne 0 ]] || { echo "missing assembler exited 0"; return 1; }
  grep -F -q "assembler not found" "$TD/miss.stderr" || {
    cat "$TD/miss.stderr" >&2 || true
    return 1
  }
}

lacks_token() {
  local name=$1
  local tok=$2
  python3 - "$TD/$name.asm" "$tok" << 'PY'
import re
import sys
text = open(sys.argv[1], encoding="utf-8").read()
tok = sys.argv[2]
pat = re.compile(r"(?<![A-Za-z0-9_])" + re.escape(tok) + r"(?![A-Za-z0-9_])")
if pat.search(text):
    print("unexpected token", tok, file=sys.stderr)
    sys.exit(1)
PY
}

round_img() {
  local name=$1
  if ! (
    cd "$TD" || exit 1
    "$UASM" -bin -nologo -Fo "$name.bin" "$name.asm" \
      >"$name.uout" 2>"$name.uerr"
  ); then
    echo "uasm failed for $name" >&2
    cat "$TD/$name.uerr" >&2 || true
    echo "---- $name.asm ----" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
  if ! cmp -s "$TD/$name.bin" "$TD/$name.img"; then
    echo "load image cmp failed for $name" >&2
    echo "---- $name.asm ----" >&2
    cat "$TD/$name.asm" >&2 || true
    return 1
  fi
}

emit_mz() {
  local name=$1
  if ! "$BIN" --uasm -o "$TD/$name.asm" "$TD/$name.exe" \
      >"$TD/$name.stdout" 2>"$TD/$name.stderr"; then
    echo "dumpexe --uasm failed for $name" >&2
    cat "$TD/$name.stderr" >&2 || true
    return 1
  fi
}

python3 - "$TD" << 'PY'
import struct
import sys
from pathlib import Path

td = Path(sys.argv[1])

def mz(image, ip=0, cs=0, ss=0, sp=0x200):
    hdr = 0x20
    size = hdr + len(image)
    h = struct.pack(
        "<2s13H",
        b"MZ",
        size % 512,
        (size + 511) // 512,
        0,
        hdr // 16,
        0x10,
        0xFFFF,
        ss,
        sp,
        0,
        ip,
        cs,
        0x1C,
        0,
    )
    return h.ljust(hdr, b"\0") + bytes(image)

def put(img, at, hx):
    raw = bytes.fromhex(hx)
    img[at : at + len(raw)] = raw

com = bytearray(40720)
put(com, 0, "e9fd9e")
put(com, 40704, "e80100b8c3c3cd20")
(td / "rg5com.com").write_bytes(com)

mz_img = bytearray(49168)
put(mz_img, 0, "e9fdbf")
put(mz_img, 49152, "e80100b8c3c3b8004ccd21")
(td / "rg5mz.exe").write_bytes(mz(mz_img, ip=0, cs=0))
(td / "rg5mz.img").write_bytes(mz_img)

e2d = bytearray(0x10100)
put(e2d, 0xFFF0, "e82d00b8004ccd21")
put(e2d, 0x10010, "c3")
(td / "e2d.exe").write_bytes(mz(e2d, ip=0, cs=0x0FFF))
(td / "e2d.img").write_bytes(e2d)

e2e = bytearray(0x10100)
put(e2e, 0xFFF0, "e82e00eb0c")
put(e2e, 0x10010, "b8c3c3c3")
put(e2e, 0xFFFE, "eb10")
(td / "e2e.exe").write_bytes(mz(e2e, ip=0, cs=0x0FFF))
(td / "e2e.img").write_bytes(e2e)

e2f = bytearray(0x10100)
put(e2f, 0x8000, "e9fb7f")
put(e2f, 0xFFFE, "eb10")
put(e2f, 0x10010, "b8004ccd21")
(td / "e2f.exe").write_bytes(mz(e2f, ip=0, cs=0x0800))
(td / "e2f.img").write_bytes(e2f)

# N-C1: func_10030 is a sized near call in s1 (its own segment) and from s0.
# CS=0FFF puts frame FFF0 over both sites. INT 21 at 10010 seeds the s1 call
# (ip-16) without being the shared symbol.
nc1 = bytearray(0x10040)
nc1[0xFFF0:0xFFF4] = bytes.fromhex("e83d00c3")
nc1[0x10000:0x10004] = bytes.fromhex("e82d00c3")
nc1[0x10010:0x10012] = bytes.fromhex("cd21")
nc1[0x10030] = 0xC3
(td / "nc1.exe").write_bytes(mz(nc1, ip=0, cs=0x0FFF))
PY

case_rg5_com() {
  if ! "$BIN" --uasm -o "$TD/rg5com.asm" "$TD/rg5com.com" \
      >"$TD/rg5com.stdout" 2>"$TD/rg5com.stderr"; then
    echo "dumpexe failed rg5 com" >&2
    cat "$TD/rg5com.stderr" >&2 || true
    return 1
  fi
  lacks_token rg5com "A004h" || return 1
  has rg5com "0A004h" || return 1
  # round_bin compares uasm -bin to the .com of the same stem.
  round_bin rg5com
}

case_rg5_mz() {
  emit_mz rg5mz || return 1
  lacks_token rg5mz "C004h" || return 1
  has rg5mz "0C004h" || return 1
  round_img rg5mz
}

case_c1() {
  local name=$1
  emit_mz "$name" || return 1
  round_img "$name"
}

# Same symbol, two sized uses. Only the other segment becomes db.
case_nc1() {
  emit_mz nc1 || return 1
  python3 - "$TD/nc1.asm" << 'PY'
import sys
text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
marker = "s1 segment"
at = text.find(marker)
if at < 0:
    print("missing s1 segment")
    sys.exit(1)
s0 = text[:at]
s1 = text[at:]
end = s1.find("s2 segment")
if end >= 0:
    s1 = s1[:end]
sym = "call near ptr func_10030"
if sym in s0:
    print("s0 still has a sized branch to func_10030")
    sys.exit(1)
if s1.count(sym) != 1:
    print("s1 sized-branch count", s1.count(sym))
    sys.stderr.write(s1)
    sys.exit(1)
if "0E8h, 03Dh, 000h" not in s0:
    print("s0 cross-segment call was not db")
    sys.exit(1)
if "0E8h, 02Dh, 000h" in s1:
    print("s1 same-segment call was demoted to db")
    sys.exit(1)
print("nc1 ok")
PY
}

UASM_ABS="$(readlink -f "$UASM")"
cat > "$TD/uasm-count" << EOF
#!/bin/sh
printf '.\\n' >> '$TD/uasm-spawns'
exec '$UASM_ABS' "\$@"
EOF
chmod +x "$TD/uasm-count"

spawn_lines() {
  if [[ ! -f "$TD/uasm-spawns" ]]; then
    echo 0
    return 0
  fi
  wc -l < "$TD/uasm-spawns" | tr -d ' '
}

case_v1_partial() {
  printf '\xd6\x8b\xc3\xc3' > "$TD/poison.com"
  : > "$TD/uasm-spawns"
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$TD/uasm-count" \
      -o "$TD/poison.asm" "$TD/poison.com" \
      >"$TD/poison.stdout" 2>"$TD/poison.stderr"; then
    echo "poison verify failed" >&2
    cat "$TD/poison.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$TD/poison.asm"; then
    echo "mov ax, bx was not promoted" >&2
    cat "$TD/poison.asm" >&2 || true
    return 1
  fi
  no_insn poison "salc" || return 1
  if grep -F -q '; verified:' "$TD/poison.asm"; then
    echo "header still claims verified" >&2
    cat "$TD/poison.asm" >&2 || true
    return 1
  fi
  if ! grep -F -q 'assembler rejected' "$TD/poison.stderr"; then
    echo "stderr missing rejected count" >&2
    cat "$TD/poison.stderr" >&2 || true
    return 1
  fi
  local n
  n="$(spawn_lines)"
  if [[ "$n" -lt 1 || "$n" -gt 16 ]]; then
    echo "poison spawn count $n" >&2
    return 1
  fi
}

case_v1_one_spawn() {
  printf '\x8b\xc3\xc3' > "$TD/okv.com"
  : > "$TD/uasm-spawns"
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$TD/uasm-count" \
      -o "$TD/okv.asm" "$TD/okv.com" \
      >"$TD/okv.stdout" 2>"$TD/okv.stderr"; then
    echo "clean verify failed" >&2
    cat "$TD/okv.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$TD/okv.asm"; then
    echo "clean mov ax, bx missing" >&2
    cat "$TD/okv.asm" >&2 || true
    return 1
  fi
  has okv "; verified: uasm" || return 1
  local n
  n="$(spawn_lines)"
  if [[ "$n" -ne 1 ]]; then
    echo "clean spawn count $n" >&2
    return 1
  fi
}

case_v2_rel() {
  mkdir -p "$TD/v2cwd/rel"
  cp "$UASM_ABS" "$TD/v2cwd/rel/uasm"
  chmod +x "$TD/v2cwd/rel/uasm"
  printf '\x8b\xc3\xc3' > "$TD/v2cwd/ok.com"
  if ! (
    cd "$TD/v2cwd" || exit 1
    "$BIN" --uasm --uasm-verify --uasm-bin rel/uasm -o ok.asm ok.com \
      >ok.stdout 2>ok.stderr
  ); then
    echo "relative --uasm-bin failed" >&2
    cat "$TD/v2cwd/ok.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$TD/v2cwd/ok.asm"; then
    echo "relative bin did not promote mov ax, bx" >&2
    cat "$TD/v2cwd/ok.asm" >&2 || true
    cat "$TD/v2cwd/ok.stderr" >&2 || true
    return 1
  fi
}

case_v3_path_dir() {
  mkdir -p "$TD/d1/uasm" "$TD/d2"
  cp "$UASM_ABS" "$TD/d2/uasm"
  chmod +x "$TD/d2/uasm"
  printf '\x8b\xc3\xc3' > "$TD/v3.com"
  if ! env -u DUMPEXE_UASM PATH="$TD/d1:$TD/d2" \
      "$BIN" --uasm --uasm-verify -o "$TD/v3.asm" "$TD/v3.com" \
      >"$TD/v3.stdout" 2>"$TD/v3.stderr"; then
    echo "PATH directory uasm was not skipped" >&2
    cat "$TD/v3.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$TD/v3.asm"; then
    echo "PATH search did not promote mov ax, bx" >&2
    cat "$TD/v3.asm" >&2 || true
    cat "$TD/v3.stderr" >&2 || true
    return 1
  fi
}

scratch_dirs() {
  (
    shopt -s nullglob
    local d
    for d in /tmp/dumpexe-uasm-*; do
      printf '%s\n' "$d"
    done | sort
  )
}

case_v4_env() {
  printf 'nop\n' > "$TD/extra.asm"
  printf '\x8b\xc3\xc3' > "$TD/v4.com"
  local before after new
  before="$(scratch_dirs)"
  if ! UASM="$TD/extra.asm" "$BIN" --uasm --uasm-verify --uasm-bin "$UASM_ABS" \
      -o "$TD/v4.asm" "$TD/v4.com" \
      >"$TD/v4.stdout" 2>"$TD/v4.stderr"; then
    echo "v4 verify failed" >&2
    cat "$TD/v4.stderr" >&2 || true
    return 1
  fi
  after="$(scratch_dirs)"
  new="$(comm -13 <(printf '%s\n' "$before") <(printf '%s\n' "$after") || true)"
  # comm emits a blank line when both sides are empty.
  new="$(printf '%s\n' "$new" | sed '/^$/d' || true)"
  if [[ -n "$new" ]]; then
    echo "scratch dir leaked:" >&2
    printf '%s\n' "$new" >&2
    return 1
  fi
}

# N-I2: cwd ./uasm must not run for an empty or relative PATH component.
case_ni2_path() {
  local stub_dir="$TD/ni2cwd"
  local abs_bin="$TD/ni2abs"
  mkdir -p "$stub_dir" "$abs_bin"
  cp "$UASM_ABS" "$abs_bin/uasm"
  chmod +x "$abs_bin/uasm"
  cat > "$stub_dir/uasm" << EOF
#!/bin/sh
touch '$TD/ni2.marker'
exit 1
EOF
  chmod +x "$stub_dir/uasm"
  printf '\x8b\xc3\xc3' > "$stub_dir/mov.com"

  rm -f "$TD/ni2.marker"
  if ! (
    cd "$stub_dir" || exit 1
    env -u DUMPEXE_UASM PATH=":$abs_bin" \
      "$BIN" --uasm --uasm-verify -o mov-lead.asm mov.com \
      >mov-lead.stdout 2>mov-lead.stderr
  ); then
    echo "leading-colon PATH failed" >&2
    cat "$stub_dir/mov-lead.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$stub_dir/mov-lead.asm"; then
    echo "leading-colon PATH did not promote mov ax, bx" >&2
    cat "$stub_dir/mov-lead.asm" >&2 || true
    cat "$stub_dir/mov-lead.stderr" >&2 || true
    return 1
  fi
  if [[ -e "$TD/ni2.marker" ]]; then
    echo "leading-colon PATH ran ./uasm" >&2
    return 1
  fi

  rm -f "$TD/ni2.marker"
  local rc=0
  (
    cd "$stub_dir" || exit 1
    env -u DUMPEXE_UASM PATH="." \
      "$BIN" --uasm --uasm-verify -o mov-dot.asm mov.com \
      >mov-dot.stdout 2>mov-dot.stderr
  ) || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    echo "PATH=. exited 0" >&2
    cat "$stub_dir/mov-dot.stderr" >&2 || true
    return 1
  fi
  if [[ -e "$TD/ni2.marker" ]]; then
    echo "PATH=. ran ./uasm" >&2
    return 1
  fi
  if [[ -f "$stub_dir/mov-dot.asm" ]] &&
      grep -F -q '; verified:' "$stub_dir/mov-dot.asm"; then
    echo "PATH=. header claims verified" >&2
    cat "$stub_dir/mov-dot.asm" >&2 || true
    return 1
  fi
  if ! grep -F -q 'assembler not found' "$stub_dir/mov-dot.stderr"; then
    echo "PATH=. did not report a missing assembler" >&2
    cat "$stub_dir/mov-dot.stderr" >&2 || true
    return 1
  fi

  rm -f "$TD/ni2.marker"
  if ! (
    cd "$stub_dir" || exit 1
    env -u DUMPEXE_UASM PATH="$abs_bin:" \
      "$BIN" --uasm --uasm-verify -o mov-trail.asm mov.com \
      >mov-trail.stdout 2>mov-trail.stderr
  ); then
    echo "trailing-colon PATH failed" >&2
    cat "$stub_dir/mov-trail.stderr" >&2 || true
    return 1
  fi
  if [[ -e "$TD/ni2.marker" ]]; then
    echo "trailing colon ran ./uasm" >&2
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$stub_dir/mov-trail.asm"; then
    echo "trailing colon did not promote mov ax, bx" >&2
    cat "$stub_dir/mov-trail.asm" >&2 || true
    cat "$stub_dir/mov-trail.stderr" >&2 || true
    return 1
  fi
}

# V1b: out-of-image near calls are not offered, so one mov still verifies.
case_v1b_numeric() {
  python3 - "$TD/ncall.com" << 'PY'
import pathlib
import sys
body = bytearray()
for i in range(1200):
    off = i * 3
    ip = 0x100 + off
    target = 0xF000 + i
    disp = (target - (ip + 3)) & 0xFFFF
    body += bytes((0xE8, disp & 0xFF, (disp >> 8) & 0xFF))
body += bytes((0x8B, 0xC3))
pathlib.Path(sys.argv[1]).write_bytes(body)
PY
  : > "$TD/uasm-spawns"
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$TD/uasm-count" \
      -o "$TD/ncall.asm" "$TD/ncall.com" \
      >"$TD/ncall.stdout" 2>"$TD/ncall.stderr"; then
    echo "numeric call verify failed" >&2
    cat "$TD/ncall.stderr" >&2 || true
    return 1
  fi
  if ! grep -E -q '^[[:space:]]+mov ax, bx' "$TD/ncall.asm"; then
    echo "mov ax, bx stayed db" >&2
    cat "$TD/ncall.asm" >&2 || true
    return 1
  fi
  if grep -E -q '^[[:space:]]+call' "$TD/ncall.asm"; then
    echo "numeric call was promoted" >&2
    grep -E -n '^[[:space:]]+call' "$TD/ncall.asm" >&2 || true
    return 1
  fi
  local n
  n="$(spawn_lines)"
  if [[ "$n" -ne 1 ]]; then
    echo "numeric call spawn count $n" >&2
    cat "$TD/ncall.stderr" >&2 || true
    return 1
  fi
}

# V1b: the verify spawn passes UASM's error limit.
case_v1b_e100000() {
  cat > "$TD/uasm-argv" << EOF
#!/bin/sh
printf '%s\n' "\$*" >> '$TD/uasm-args'
exec '$UASM_ABS' "\$@"
EOF
  chmod +x "$TD/uasm-argv"
  printf '\x8b\xc3\xc3' > "$TD/e100.com"
  : > "$TD/uasm-args"
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$TD/uasm-argv" \
      -o "$TD/e100.asm" "$TD/e100.com" \
      >"$TD/e100.stdout" 2>"$TD/e100.stderr"; then
    echo "e100000 verify failed" >&2
    cat "$TD/e100.stderr" >&2 || true
    return 1
  fi
  if ! grep -F -q -- '-e100000' "$TD/uasm-args"; then
    echo "argv missing -e100000" >&2
    cat "$TD/uasm-args" >&2 || true
    return 1
  fi
  local n
  n="$(wc -l < "$TD/uasm-args" | tr -d ' ')"
  if [[ "$n" -ne 1 ]]; then
    echo "e100000 spawn count $n" >&2
    cat "$TD/uasm-args" >&2 || true
    return 1
  fi
  has e100 "; verified: uasm" || return 1
}

# V1b: 16 unnamed bisects of 40 memory movs leave a non-empty queue.
case_v1b_cap() {
  python3 - "$TD/vcap.com" << 'PY'
import pathlib
import sys
# 89 87 lo hi is mov [bx+disp16], ax. A 0Fh, 66h, or 67h byte is not a
# candidate, so skip displacement 15 (low byte 0Fh). Forty others stay.
body = bytearray()
disps = [i for i in range(0, 64) if i != 0x0F][:40]
for disp in disps:
    body += bytes((0x89, 0x87, disp & 0xFF, (disp >> 8) & 0xFF))
pathlib.Path(sys.argv[1]).write_bytes(body)
PY
  cat > "$TD/uasm-fail" << EOF
#!/bin/sh
printf '%s\n' "\$*" >> '$TD/vcap-args'
printf 'uasm: fatal\n' > line.err
exit 1
EOF
  chmod +x "$TD/uasm-fail"
  : > "$TD/vcap-args"
  if ! "$BIN" --uasm --uasm-verify --uasm-bin "$TD/uasm-fail" \
      -o "$TD/vcap.asm" "$TD/vcap.com" \
      >"$TD/vcap.stdout" 2>"$TD/vcap.stderr"; then
    echo "cap verify failed" >&2
    cat "$TD/vcap.stderr" >&2 || true
    return 1
  fi
  if ! grep -F -q 'unverified' "$TD/vcap.asm"; then
    echo "header missing unverified" >&2
    cat "$TD/vcap.asm" >&2 || true
    cat "$TD/vcap.stderr" >&2 || true
    return 1
  fi
  if ! grep -F -q 'assembler rejected 7 candidates, unverified 33' \
      "$TD/vcap.asm"; then
    echo "header counts were not rejected 7, unverified 33" >&2
    cat "$TD/vcap.asm" >&2 || true
    return 1
  fi
  if grep -F -q '; verified:' "$TD/vcap.asm"; then
    echo "cap header claims verified" >&2
    cat "$TD/vcap.asm" >&2 || true
    return 1
  fi
  if ! grep -F -q 'assembler rejected' "$TD/vcap.stderr"; then
    echo "stderr missing assembler rejected" >&2
    cat "$TD/vcap.stderr" >&2 || true
    return 1
  fi
  if ! grep -F -q 'assembler rejected 7 candidates, unverified 33' \
      "$TD/vcap.stderr"; then
    echo "stderr counts were not rejected 7, unverified 33" >&2
    cat "$TD/vcap.stderr" >&2 || true
    return 1
  fi
  if ! grep -F -q -- '-e100000' "$TD/vcap-args"; then
    echo "cap argv missing -e100000" >&2
    cat "$TD/vcap-args" >&2 || true
    return 1
  fi
}

check mov8b_verify case_mov8b_verify
check rg5_com case_rg5_com
check rg5_mz case_rg5_mz
check c1_e2d case_c1 e2d
check c1_e2e case_c1 e2e
check c1_e2f case_c1 e2f
check nc1_same_seg case_nc1
check v1_partial case_v1_partial
check v1_one_spawn case_v1_one_spawn
check v2_rel_bin case_v2_rel
check v3_path_dir case_v3_path_dir
check v4_env case_v4_env
check ni2_path case_ni2_path
check v1b_numeric case_v1b_numeric
check v1b_e100000 case_v1b_e100000
check v1b_cap case_v1b_cap
check source_name_not_label case_source_name_not_label
check mid_insn_label case_mid_insn_label
check ret0 case_ret0
check retf0 case_retf0
check ret4 case_ret4
check x9_call case_x9_call
check x9_psp case_x9_psp
check batch64 case_batch64
check verify_missing case_verify_missing

echo "---"
echo "p0_uasm passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
