# Shared fixture lookup for dumpexe tests. Source from a bash suite.
#
# The binary fixtures (formerly games/) live in a PRIVATE repository,
# EdgeOfAssembly/dumpexe-fixtures, and are not part of this repo.
# Lookup order:
#   1. DUMPEXE_FIXTURES=<dir>   (dir holding games/, or the games dir itself)
#   2. ./games                  (local, untracked copy in the checkout)
#   3. tests/.fixtures/dumpexe-fixtures (gitignored cache; cloned on first
#      use when git can reach the private repo; DUMPEXE_FIXTURES_NO_CLONE=1
#      disables the clone)
# Every file a test uses is checked against tests/fixtures.sha256.
#
#   fixture REL         prints the absolute path of games/REL, or returns 1
#                       when it is unavailable or its checksum does not match
#   fixtures_available  returns 0 when a fixture tree was found
#   fixtures_exit F     end of suite: exit 1 when F>0, 77 (skip) when any
#                       fixture was unavailable, else 0

_FIX_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_FIX_REPO="${DUMPEXE_FIXTURES_REPO:-https://github.com/EdgeOfAssembly/dumpexe-fixtures.git}"
_FIX_SUMS="$_FIX_ROOT/tests/fixtures.sha256"
# fixture() usually runs in $(...), so the "missing" flag lives in a file.
_FIX_FLAG="$(mktemp "${TMPDIR:-/tmp}/dumpexe-fix-XXXXXX")"
_FIX_DIR=""

_fixtures_find() {
    [[ -n "$_FIX_DIR" ]] && return 0
    local d
    if [[ -n "${DUMPEXE_FIXTURES+x}" ]]; then
        d="$DUMPEXE_FIXTURES"
        if [[ -d "$d/games" ]]; then _FIX_DIR="$d/games"; return 0; fi
        # A dir that is the games tree itself (has any of our folders).
        if [[ -n "$d" && -d "$d" ]] && [[ -n "$(cut -c67- "$_FIX_SUMS" | cut -d/ -f1 | sort -u | while read -r s; do [[ -e "$d/$s" ]] && echo y && break; done)" ]]; then
            _FIX_DIR="$d"; return 0
        fi
        return 1   # explicit setting wins; no fallback
    fi
    if [[ -d "$_FIX_ROOT/games" ]]; then _FIX_DIR="$_FIX_ROOT/games"; return 0; fi
    local cache="$_FIX_ROOT/tests/.fixtures/dumpexe-fixtures"
    if [[ ! -d "$cache/games" && "${DUMPEXE_FIXTURES_NO_CLONE:-0}" != 1 ]]; then
        mkdir -p "$_FIX_ROOT/tests/.fixtures"
        if GIT_TERMINAL_PROMPT=0 git ls-remote "$_FIX_REPO" HEAD >/dev/null 2>&1; then
            rm -rf "$cache.tmp"
            GIT_TERMINAL_PROMPT=0 git clone -q --depth 1 "$_FIX_REPO" "$cache.tmp" >/dev/null 2>&1 \
                && mv "$cache.tmp" "$cache" || rm -rf "$cache.tmp"
        fi
    fi
    if [[ -d "$cache/games" ]]; then _FIX_DIR="$cache/games"; return 0; fi
    return 1
}

fixtures_available() { _fixtures_find; }

fixture() {
    local rel=$1 want got
    if ! _fixtures_find; then
        echo 1 >"$_FIX_FLAG"; echo "SKIP fixture $rel (fixtures unavailable)" >&2; return 1
    fi
    if [[ ! -f "$_FIX_DIR/$rel" ]]; then
        echo 1 >"$_FIX_FLAG"; echo "SKIP fixture $rel (not found)" >&2; return 1
    fi
    want=$(awk -v p="games/$rel" '{ f=substr($0, 67) } f==p { print $1 }' "$_FIX_SUMS")
    if [[ -z "$want" ]]; then
        echo "fixture $rel has no entry in tests/fixtures.sha256" >&2; echo 1 >"$_FIX_FLAG"; return 1
    fi
    got=$(sha256sum "$_FIX_DIR/$rel" | cut -d' ' -f1)
    if [[ "$got" != "$want" ]]; then
        echo "FAIL fixture $rel checksum mismatch" >&2; echo 1 >"$_FIX_FLAG"; return 1
    fi
    printf '%s\n' "$_FIX_DIR/$rel"
}

fixtures_exit() {
    local f=${1:-0}
    local missing=0
    [[ -s "$_FIX_FLAG" ]] && missing=1
    rm -f "$_FIX_FLAG"
    if (( f > 0 )); then exit 1; fi
    if (( missing )); then echo "SKIP (some fixtures unavailable; non-fixture checks passed)"; exit 77; fi
    exit 0
}

# Resolve once in the suite shell so $(fixture ...) subshells inherit it.
_fixtures_find || true
