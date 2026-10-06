#!/usr/bin/env bash
# P0 UASM spelling and bounded verify-by-assembly.
# These checks do not skip. A missing /usr/bin/uasm is a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DUMPEXE_BIN:-$ROOT/dumpexe}"
[[ -x "$BIN" ]] || { echo "FAIL: dumpexe binary not found"; exit 1; }
[[ -x /usr/bin/uasm ]] || { echo "FAIL: /usr/bin/uasm missing"; exit 1; }

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

emit() {
  local name=$1
  local hex=$2
  write_com "$name" "$hex" || return 1
  if ! "$BIN" --uasm -o "$TD/$name.asm" "$TD/$name.com" \
      >"$TD/$name.stdout" 2>"$TD/$name.stderr"; then
    echo "dumpexe --uasm failed for $name" >&2
    cat "$TD/$name.stderr" >&2 || true
    return 1
  fi
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
  if ! /usr/bin/uasm -bin -nologo -Fo "$TD/$name.bin" "$TD/$name.asm" \
      >"$TD/$name.uout" 2>"$TD/$name.uerr"; then
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
  exact_insn mov8b "mov ax, bx" || return 1
  round_bin mov8b
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
  emit movsb A4C3 || return 1
  exact_insn movsb "movsb" || return 1
  lacks movsb "byte ptr" || return 1
  round_bin movsb
}

case_repmovsb() {
  emit rep F3A4C3 || return 1
  exact_insn rep "rep movsb" || return 1
  lacks rep "repne" || return 1
  round_bin rep
}

case_lds() {
  emit lds C507C3 || return 1
  has lds "dword ptr" || return 1
  round_bin lds
}

case_xchg() {
  emit xchg 93C3 || return 1
  exact_insn xchg "xchg ax, bx" || return 1
  round_bin xchg
}

case_pusha() {
  emit pusha 60C3 || return 1
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

echo "---"
echo "p0_uasm passed=$pass failed=$fail"
[[ "$fail" -eq 0 ]]
