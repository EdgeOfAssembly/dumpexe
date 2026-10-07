# Shared UASM lookup for dumpexe tests.
# Source from a bash suite. Does not skip by itself.
# UASM=/path overrides. Otherwise the first uasm on PATH.
# Prints the path and returns 0, or returns 1 when no assembler is found.

uasm_resolve() {
    if [[ -n "${UASM:-}" ]]; then
        if [[ -x "$UASM" ]]; then
            printf '%s\n' "$UASM"
            return 0
        fi
        echo "UASM is set but not executable: $UASM" >&2
        return 1
    fi
    local found
    found=$(command -v uasm 2>/dev/null || true)
    if [[ -n "$found" && -x "$found" ]]; then
        printf '%s\n' "$found"
        return 0
    fi
    return 1
}
