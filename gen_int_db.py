#!/usr/bin/env python3
"""
gen_int_db.py - Generate int_db.h from Ralph Brown's Interrupt List (RBIL)

Reads interrupts/INTERRUP.* files and produces a sorted constexpr C++ array
of IntEntry structs for use at compile time.

Regenerate with: python3 gen_int_db.py
"""

import re
import glob
import os
import sys

INTERRUP_GLOB = os.path.join(os.path.dirname(__file__), "interrupts", "INTERRUP.*")
OUTPUT_FILE   = os.path.join(os.path.dirname(__file__), "int_db.h")

# Regex for separator lines: --------X-IIAASSLLL---
SEP_RE = re.compile(r'^--------')

# Regex for the INT header line inside a block
INT_LINE_RE = re.compile(
    r'^INT\s+([0-9A-Fa-f]{1,3})'  # interrupt number (hex, 1-3 hex digits)
    r'(?:/([0-9A-Fa-f]{1,4}))?'   # optional /XXXX subfunction (AX or AH)
    r'\s*-\s*(.+)$'               # description (after first ' - ')
)

# Regex for AH/AL/AX inside a block
AH_RE = re.compile(r'^\s+AH\s*=\s*([0-9A-Fa-f]{1,2})h', re.IGNORECASE)
AL_RE = re.compile(r'^\s+AL\s*=\s*([0-9A-Fa-f]{1,2})h', re.IGNORECASE)
AX_RE = re.compile(r'^\s+AX\s*=\s*([0-9A-Fa-f]{3,4})h', re.IGNORECASE)


def escape_cpp_string(s: str) -> str:
    """Escape a string for use in a C++ string literal."""
    # Escape backslashes and double quotes
    s = s.replace('\\', '\\\\').replace('"', '\\"')
    # Escape '?' to prevent trigraph interpretation (e.g. ??> = ^)
    s = s.replace('?', '\\?')
    return s


def parse_description(int_line: str) -> str:
    """
    Extract the human-readable description from an INT header line.
    The INT line looks like:
        INT 10 - VIDEO - SET VIDEO MODE
        INT 21 - DOS 2+ - CREATE NEW FILE
        INT 03 C - CPU-generated - BREAKPOINT
    We want everything after the first ' - '.
    """
    # Strip any category letter between INT XX and the first ' - '
    # e.g. "INT 10 C - VIDEO - ..." -> strip " C" prefix
    # Find first ' - ' and take everything after it
    idx = int_line.find(' - ')
    if idx == -1:
        return int_line.strip()
    return int_line[idx + 3:].strip()


def files_in_order():
    """Return INTERRUP.* files in alphabetical order (A-R, plus .1ST, .PRI)."""
    files = glob.glob(INTERRUP_GLOB)
    files.sort()
    return files


def parse_rbil():
    """
    Parse all RBIL files and return a list of (int_num, ah, al, desc) tuples.
    ah/al are 0xFF when not specified (wildcard).
    Entries are de-duplicated: first occurrence wins.
    """
    seen = set()    # (int_num, ah, al) keys to deduplicate
    entries = []

    for filepath in files_in_order():
        try:
            # RBIL files are Latin-1 encoded
            with open(filepath, encoding='latin-1', errors='replace') as fh:
                lines = fh.readlines()
        except OSError as e:
            print(f"Warning: cannot read {filepath}: {e}", file=sys.stderr)
            continue

        i = 0
        n = len(lines)
        while i < n:
            line = lines[i].rstrip('\r\n')

            # A separator line starts a new block
            if SEP_RE.match(line):
                i += 1
                # Collect block lines until the next separator
                block = []
                while i < n and not SEP_RE.match(lines[i].rstrip('\r\n')):
                    block.append(lines[i].rstrip('\r\n'))
                    i += 1

                if not block:
                    continue

                # The first line of the block must start with 'INT '
                first = block[0]
                if not first.upper().startswith('INT '):
                    continue

                # Parse interrupt number from first token
                tokens = first.split()
                if len(tokens) < 2:
                    continue
                int_str = tokens[1]
                if int_str.endswith('h') or int_str.endswith('H'):
                    int_str = int_str[:-1]
                try:
                    int_num = int(int_str, 16)
                except ValueError:
                    continue
                if int_num > 0xFF:
                    continue

                # Extract description: everything after first ' - '
                desc = parse_description(first)
                if not desc or desc == '???':
                    continue

                # Scan the next few lines for AH/AL/AX specifiers (up to 10 lines)
                ah = 0xFF
                al = 0xFF
                for bline in block[1:11]:
                    m = AX_RE.match(bline)
                    if m:
                        ax_val = int(m.group(1), 16)
                        ah = (ax_val >> 8) & 0xFF
                        al = ax_val & 0xFF
                        break
                    m = AH_RE.match(bline)
                    if m:
                        ah = int(m.group(1), 16)
                        continue
                    m = AL_RE.match(bline)
                    if m:
                        al = int(m.group(1), 16)
                        continue
                    # Stop scanning at a blank line
                    if bline.strip() == '':
                        break

                key = (int_num, ah, al)
                if key not in seen:
                    seen.add(key)
                    entries.append((int_num, ah, al, desc))
            else:
                i += 1

    # Sort by (int_num, ah, al) — 0xFF sorts after all specific values
    entries.sort(key=lambda e: (e[0], e[1], e[2]))
    return entries


def generate_header(entries):
    n = len(entries)
    lines = []
    lines.append("// int_db.h - AUTO-GENERATED from Ralph Brown's Interrupt List")
    lines.append("// DO NOT EDIT MANUALLY - regenerate with: python3 gen_int_db.py")
    lines.append("#ifndef INT_DB_H")
    lines.append("#define INT_DB_H")
    lines.append("")
    lines.append("#include <cstdint>")
    lines.append("#include <string_view>")
    lines.append("#include <array>")
    lines.append("")
    lines.append("/// One entry in the interrupt annotation database.")
    lines.append("/// ah == 0xFF means 'any AH value' (wildcard).")
    lines.append("/// al == 0xFF means 'any AL value' (wildcard).")
    lines.append("struct IntEntry {")
    lines.append("    uint8_t          int_num;")
    lines.append("    uint8_t          ah;")
    lines.append("    uint8_t          al;")
    lines.append("    std::string_view desc;")
    lines.append("};")
    lines.append("")
    lines.append(f"/// {n} entries sorted by (int_num, ah, al) for binary search.")
    lines.append(f"static constexpr std::array<IntEntry, {n}> INT_DB = {{{{")

    for int_num, ah, al, desc in entries:
        safe = escape_cpp_string(desc)
        lines.append(
            f"    {{0x{int_num:02X}, 0x{ah:02X}, 0x{al:02X}, \"{safe}\"}},"
        )

    lines.append("}};")
    lines.append("")
    lines.append("#endif // INT_DB_H")
    lines.append("")
    return "\n".join(lines)


def main():
    print("Parsing RBIL files...", file=sys.stderr)
    entries = parse_rbil()
    print(f"  Found {len(entries)} unique entries.", file=sys.stderr)

    if not entries:
        print("Error: no entries parsed — check that interrupts/INTERRUP.* files exist.",
              file=sys.stderr)
        sys.exit(1)

    header = generate_header(entries)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as fh:
        fh.write(header)
    print(f"  Written to {OUTPUT_FILE}", file=sys.stderr)


if __name__ == '__main__':
    main()
