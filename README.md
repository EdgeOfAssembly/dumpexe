# dumpexe

**16-bit MS-DOS Binary Analyzer & Multi-Pass Listing**

A comprehensive command-line utility for analyzing MS-DOS 16-bit binary files: MZ EXE executables, plain `.COM` programs, and device driver (`.SYS`) files. Provides TDUMP-style header analysis, relocation tables, hex dumps, Capstone x86-16 disassembly, multi-pass listings, toolchain fingerprints (Pascal MT+, JWASM 1.8, COM-in-EXE), Graphviz CFG, JSON reports, and DOS load simulation.

## Features

- **MZ EXE / COM / SYS**: Header decode, relocations, entry, memory requirements
- **Multi-pass listing** (`-d` and `-a`): `func_*` labels, INT notes, call/jmp rewrite; default write `<stem>.asm`
- **UASM source** (`--uasm`, enable-only): no address column. COM round-trips with `uasm -bin`. An EXE load image round-trips with `uasm -mz`, which writes a 32-byte MZ header (0 relocations, CS:IP and SS:SP 0:0) plus warnings A4205/A4204 and then the payload only. `e_cparhdr * 16` is that header size, not the load image. Prefer `uasm -bin` and `bin2exe --header` to restore the original header. A multi-segment listing ends with a bare `end`. Past 64 KiB is decoded when reached through the entry, near wrap, or a decoded relocation-pinned far call. `--uasm` does not spawn an assembler (header `; NOT VERIFIED`). `--uasm-verify` (enable-only, requires `--uasm`) assembles distinct candidate lines with `--uasm-bin`, else `$DUMPEXE_UASM`, else `uasm` on `PATH`. A clean batch is one assemble and the header says `; verified: uasm … at PATH`. A line the assembler rejects is dropped, the rest are assembled again, and the header says `; NOT VERIFIED (assembler rejected N candidates)`. `--uasm` does not write `_UNPACKED` files unless `-d` or `-a` is also set.
- **Unpack** on `-d` and `-a` for Microsoft EXEPACK, LZEXE 0.91, LZEXE 0.90, PKLITE, DIET, and LHarc. Writes `<stem>_UNPACKED.EXE` (or `.COM` when the image is not MZ) and `<stem>_UNPACKED.asm`. An existing `.asm`, `.repack.exe`, or `_UNPACKED` output is kept. `-o -` writes none of those files. `--json` and `--no-toolchain` skip unpack. There is no `--unpack` switch.
- **Packer detect** is structural. DIET follows Deark `identify_diet_fmt` (EXE bytes `8E DB 8E C0 33 F6 33 FF` at `codestart-32+{77,72,52,55}`, plus the COM and data patterns). `DIET` at file `0x1C` is not enough. LHarc follows `de_identify_lha`, then requires a level-0/1 header checksum or a level-2 CRC, a packed size that fits, and a header in the SFX trailer (at the end of the MZ image, not a sentence in the middle). LZEXE 0.91/0.90 suppresses LHarc.
- **Toolchain detect** (default on): Pascal MT+ 3.1.1; JWASM 1.80 / COM-in-EXE / CuteMouse
- **JWASM export**: When JWASM is detected, `-d` emits JWASM-oriented assemblable layout (`.model`; **.COM / COM-in-EXE always tiny**)
- **CFG / Graphviz**: `--cfg`, `--cfg-dot=FILE`
- **JSON**: `--json` machine-readable report
- **Symbol maps**: auto `<stem>.sym`/`.map` or `--map=FILE`
- **Era tools**: versioned assemblers under `bin/jwasm/` (see `docs/TOOLCHAIN-SUPPORT.md`)
- **bin2exe**: sibling program in this repo (`make` builds it, `make install` installs it). Wraps a `uasm -bin` flat image. The default header runs that image as a COM program. `--header ORIGINAL.EXE` copies that MZ header unchanged, which is how a `--uasm` round trip keeps relocations and SS:SP. dumpexe does not run bin2exe.
- **Cross-Platform**: Analyze DOS binaries on Linux/Unix

## Adding a new compiler/assembler

See **[docs/TOOLCHAIN-SUPPORT.md](docs/TOOLCHAIN-SUPPORT.md)** — ground-truth workflow:

binary + sources → pin tool version → rebuild proof → fingerprint in dumpexe → tests + commit.

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

That builds `dumpexe` and `bin2exe`. `make test` runs both suites. `make install` installs both programs and their man pages.

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
- `-d, --disassemble` — Multi-pass listing from the entry point; also writes `<stem>.asm` and, for a structural packer, `<stem>_UNPACKED.EXE` or `.COM` plus `<stem>_UNPACKED.asm`
- `-a, --all` — Show all sections (relocation + hexdump + disassembly + strings) and unpack the same packers as `-d`
- `-o, --output PATH` — Packed listing path. `-` means stdout only: no `.asm`, no `_UNPACKED.EXE`, no `_UNPACKED.asm`
- `-n, --no-int-annotations` — Suppress INT annotation comments in disassembly
- `--simulate` — In-memory DOS sandbox. Guest data files start empty. Guest I/O does not open host files. A write to handle 1 or 2 returns CF=1 and AX=6
- `--no-toolchain` — Disable toolchain and packer detection (default on). Also skips unpack
- `--json` — JSON report on stdout. Does not unpack
- `--cfg-max=N` — CFG full-dump block cap (default 500). The `-d` listing cap is `max(N, 2000)`
- `--no-repack` — Do not write `<stem>.repack.exe` (auto-repack stays on otherwise)
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

**Show default summary (header + entry-point preview, any format):**
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

Packed files are programs to analyze, not only fixtures. `-d` and `-a` name the packer and, when the unpacker accepts the image, write the unpacked program beside the input.

- **Packed executables**: EXEPACK, LZEXE 0.90/0.91, PKLITE, DIET, or LHarc
  - Detection is structural. `DIET` at offset `0x1C`, or a sentence that mentions LHA, is not a packer
  - `-d` writes `<stem>.asm` plus `<stem>_UNPACKED.EXE` or `.COM` and `<stem>_UNPACKED.asm` when unpack succeeds
  - An output that already exists is left unchanged

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

### Disassembly (`-d`, also `-a`)

Static code analysis:
- File offset for each instruction
- Raw instruction bytes (up to 8 bytes)
- x86-16 mnemonic and operands
- INT annotation comments (INT 21h, INT 10h, etc.) from RBIL database
- Default `<stem>.asm` next to the input. An existing file is kept unless `-o` names it
- Structural EXEPACK, LZEXE 0.90/0.91, PKLITE, DIET, and LHarc also produce `<stem>_UNPACKED.EXE` or `<stem>_UNPACKED.COM` and `<stem>_UNPACKED.asm`. An existing unpacked file is kept

### Simulation (`--simulate`)

In-memory sandbox. Guest data files start empty, and guest I/O does not open host files. A write to DOS handle 1 (stdout) or handle 2 (stderr) fails with CF=1 and AX=6.

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
- File size: `num_blocks × 512` when `final_len == 0` (last page full); otherwise `((num_blocks-1) × 512) + final_len`
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
