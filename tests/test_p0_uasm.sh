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

check mov8b_verify case_mov8b_verify
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
