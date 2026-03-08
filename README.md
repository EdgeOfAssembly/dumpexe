# dumpexe

**16-bit MS-DOS Binary Analyzer & Single-Pass Disassembler**

A comprehensive command-line utility for analyzing MS-DOS 16-bit binary files: MZ EXE executables, plain `.COM` programs, and device driver (`.SYS`) files. Provides TDUMP-style header analysis, relocation table display, hex dumps with zero-compression, x86-16 disassembly using Capstone, and DOS load simulation with register tracking.

## Features

- **MZ EXE Analysis**: Full header decode, relocation table, entry point, memory requirements
- **COM File Analysis**: Flat-binary analysis with automatic PSP heuristic detection
- **Device Driver Analysis**: DOS `.SYS` driver header decode (character and block devices)
- **Relocation Table**: Shows all relocation entries with file locations and linear offsets
- **Hex+ASCII Dumps**: Canonical `hexdump -C` format with zero-compression (repeated lines shown as `*`)
- **x86-16 Disassembly**: Static code analysis from entry point to EOF using Capstone
- **DOS Load Simulation**: Dynamic analysis simulating DOS loading with register state tracking
- **Cross-Platform**: Analyze DOS binaries on Linux/Unix systems

## Building

### Prerequisites

**Compiler:** GCC 14 or later is required (needed for complete C++23 `std::format` support).

**Capstone** is a **mandatory** build dependency.

```bash
sudo apt-get update
sudo apt-get install -y build-essential libcapstone-dev
```

### Compile

```bash
make
```

> The build will fail with a clear error if `libcapstone-dev` is not installed.

## Usage

### Basic Syntax

```bash
dumpexe [options] <file>
```

### Options

- `-h, --help` — Show help message
- `-v, --version` — Show version information
- `-r, --relocation` — Show relocation table with padding *(MZ EXE only)*
- `-x, --hexdump` — Show hex+ASCII dump from entry point to EOF
- `-d, --disassemble` — Show x86-16 disassembly from entry point to EOF
- `-a, --all` — Show all sections (relocation + hexdump + disassembly)
- `-n, --no-int-annotations` — Suppress INT annotation comments in disassembly
- `--simulate` — Enable DOS load simulation with register tracking
- `--base=XXXX` — Set load base segment (hex, default: `1000h`)
- `--psp` — Force `.COM` to be treated as having an embedded PSP (entry at file offset `0100h`)
- `--no-psp` — Force `.COM` to be treated as having no embedded PSP (entry at file offset `0000h`)

### Format Detection

File format is detected automatically from content:

| Format | Signature | Detection rule |
|--------|-----------|----------------|
| MZ EXE | `MZ` | First two bytes are `4Dh 5Ah` |
| `.SYS`  | `FFFFFFFF` | First four bytes are `FFh FFh FFh FFh` |
| `.COM`  | *(any)* | Fallback — all other DOS binaries |

### .COM PSP Auto-Detection

A `.COM` file on disk normally starts directly with its code (no PSP embedded). Occasionally a
file is a raw memory snapshot that includes the 256-byte PSP at the beginning. `dumpexe` uses a
two-point heuristic:

1. First two bytes are `CD 20` (INT 20h — the canonical PSP start instruction).
2. The command-tail at offset `0x80` is plausible: length ≤ `0x7E` and the byte at `0x81+len` is `0x0D` (CR).

Use `--psp` or `--no-psp` to override detection when the heuristic guesses wrong.

### Examples

> **Note**: You need to supply your own DOS binary files for testing.

**Show header information only (any format):**
```bash
./dumpexe <your_file>
```

**Show everything (complete analysis):**
```bash
./dumpexe -a <your_file.exe>
```

**Disassemble a .COM file:**
```bash
./dumpexe -d <your_file.com>
```

**Force no-PSP treatment for a .COM file:**
```bash
./dumpexe --no-psp -d <your_file.com>
```

**Simulate DOS loading at a specific base segment:**
```bash
./dumpexe --simulate --base=2000 <your_file.exe>
```

**Show relocation table (MZ EXE):**
```bash
./dumpexe -r <your_file.exe>
```

**Combine options:**
```bash
./dumpexe -d --simulate <your_file.exe> | less
```

## Example Files

The `examples/` directory contains pre-generated output examples demonstrating various dumpexe features.

### Obtaining Test Files

To test dumpexe, you need to provide your own binary files. Good sources include:

- **DOS games and utilities** from abandonware sites (check licensing)
- **Your own DOS programs** compiled with tools like Borland/Turbo C, MASM, or TASM
- **Open source DOS software** with available binaries

### Recommended Test Cases

For comprehensive testing, consider using files that demonstrate:

- **Packed executables**: Files compressed with EXEPACK or similar packers
  - Typically have no or few relocation entries
  - Smaller file size

- **Unpacked executables**: Standard MZ format files
  - Contains relocation table entries
  - Larger file size
  - Better for disassembly analysis

- **Plain .COM files**: Small utilities, games, TSR (Terminate-and-Stay-Resident) programs

The `examples/README.md` file provides additional guidance on working with DOS binary files.

## Output Format

### Static Header Information

Shows comprehensive header analysis:
- **MZ EXE**: DOS File Size, Load Image Size, Relocation Table, Memory Requirements, Entry Point, SS:SP / CS:IP
- **COM**: File Size, Load Model (PSP present or not), Entry Point File Offset, CS:IP / SS:SP
- **SYS**: Driver type (char/block), entry points, device name or unit count

### Relocation Table (`-r`, MZ EXE only)

Formatted table with:
- Entry number
- Segment:Offset pair
- File location in hex
- Linear offset within image

### Hex+ASCII Dump (`-x`)

Canonical format matching `hexdump -C`:
- 8-digit hex addresses (lowercase)
- 16 bytes per line with space after 8th byte
- ASCII panel with `|` delimiters
- Zero-compression: repeated lines shown as `*`

### Disassembly (`-d`)

Static code analysis:
- File offset for each instruction
- Raw instruction bytes (up to 8 bytes)
- x86-16 mnemonic and operands
- INT annotation comments (INT 21h, INT 10h, etc.) from RBIL database

### Simulation (`--simulate`)

Dynamic execution trace:
- Initial CPU register state (CS:IP, SS:SP, DS, ES, FLAGS, etc.)
- Relocation fixup table showing segment adjustments *(MZ EXE only)*
- Register tracing (first ~20 instructions with register changes)

## Static vs Dynamic Analysis

**Static Analysis** (`-d`): Disassembles all code without execution. Shows complete instruction stream. Good for understanding program structure and finding code paths.

**Dynamic Analysis** (`--simulate`): Simulates DOS loading and execution from entry point. Shows register state changes. Good for understanding program initialization and verifying relocation correctness.

**Combined** (`-d --simulate`): Shows both full disassembly and dynamic trace for complete analysis.

## Technical Details

### MZ EXE Format
- Signature: `MZ` (0x5A4D little-endian)
- 28-byte minimum header
- Header sizes in paragraphs (16-byte units)
- File size: `((num_blocks-1) × 512) + final_len`
- Entry point: `header_size + (CS × 16) + IP`

### COM Format
- Flat binary image; DOS loads it at memory offset `0x100` within the load segment
- All segment registers (CS, DS, ES, SS) equal the load segment at startup
- SP initialised to `0xFFFE` (top of 64 KB segment minus two bytes)
- A typical `.COM` file on disk starts with the code/data that maps to memory offset `0x100`

### SYS Device Driver Format
- Starts with `0xFFFFFFFF` (next-driver pointer = end of chain)
- Followed by 16-bit attribute word, strategy/interrupt offsets, and device name or unit count

### Register State Representation
Uses packed unions and bitfields for authentic x86 register access:
- AX/BX/CX/DX with hi/lo byte access (AH/AL, etc.)
- Segment registers: CS, DS, ES, SS
- Pointers: IP, SP, BP, SI, DI
- FLAGS with individual bit access (CF, ZF, SF, OF, etc.)

## Installation

```bash
sudo make install
```

Installs to `/usr/local/bin/dumpexe` by default. Use `PREFIX` to change:

```bash
sudo make install PREFIX=/usr
```

## Manual Page

```bash
man dumpexe
```

## License

Dual license:
- **GPLv2** for open source use
- **Commercial** license available - contact author

## Author

EdgeOfAssembly <haxbox2000@gmail.com>

## Credits

Part of the RetroCodeMess project for analyzing retro computing and DOS executable formats.

Built with [Capstone](http://www.capstone-engine.org/) disassembly framework.
