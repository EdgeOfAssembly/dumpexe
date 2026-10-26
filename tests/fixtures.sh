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
#   fixture ID          prints the absolute path of the fixture with the generic
#                       id ID (fxNN), or returns 1 when it is unavailable.
#                       tests/fixtures.sha256 maps each id to the file's SHA-256
#                       and the first 16 hex digits of the SHA-256 of its path
#                       under games/ (picks one copy when the tree holds the same
#                       bytes twice, so sidecar .sym/.map files are found). No
#                       private path or title is part of this repository.
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
        # Otherwise the dir is taken as the games tree itself.
        if [[ -n "$d" && -d "$d" ]]; then _FIX_DIR="$d"; return 0; fi
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

_FIX_INDEX=""
# sha256 index of the fixture tree, built once in the suite shell.
_fixtures_index() {
    [[ -n "$_FIX_INDEX" && -s "$_FIX_INDEX" ]] && return 0
    _fixtures_find || return 1
    _FIX_INDEX="${_FIX_FLAG}.idx"
    find "$_FIX_DIR" -type f -size -64M -print0 2>/dev/null \
        | xargs -0 -r sha256sum >"$_FIX_INDEX" 2>/dev/null || true
    [[ -s "$_FIX_INDEX" ]]
}

fixture() {
    local id=$1 want wantp got c rel
    want=$(awk -v i="$id" '$2==i { print $1 }' "$_FIX_SUMS")
    wantp=$(awk -v i="$id" '$2==i { print $3 }' "$_FIX_SUMS")
    if [[ -z "$want" ]]; then
        echo "fixture $id has no entry in tests/fixtures.sha256" >&2; echo 1 >"$_FIX_FLAG"; return 1
    fi
    if ! _fixtures_index; then
        echo 1 >"$_FIX_FLAG"; echo "SKIP fixture $id (fixtures unavailable)" >&2; return 1
    fi
    got=""
    while IFS= read -r c; do
        [[ -z "$got" ]] && got=$c
        rel=${c#"$_FIX_DIR"/}
        if [[ -n "$wantp" && "$(printf '%s' "$rel" | sha256sum | cut -c1-16)" == "$wantp" ]]; then
            got=$c; break
        fi
    done < <(awk -v h="$want" '$1==h { sub(/^[0-9a-f]+  /, ""); print }' "$_FIX_INDEX")
    if [[ -z "$got" || ! -f "$got" ]]; then
        echo 1 >"$_FIX_FLAG"; echo "SKIP fixture $id (not found)" >&2; return 1
    fi
    printf '%s\n' "$got"
}

fixtures_exit() {
    local f=${1:-0}
    local missing=0
    [[ -s "$_FIX_FLAG" ]] && missing=1
    rm -f "$_FIX_FLAG" "${_FIX_FLAG}.idx"
    if (( f > 0 )); then exit 1; fi
    if (( missing )); then echo "SKIP (some fixtures unavailable; non-fixture checks passed)"; exit 77; fi
    exit 0
}

# Resolve once in the suite shell so $(fixture ...) subshells inherit it.
_fixtures_index || true
