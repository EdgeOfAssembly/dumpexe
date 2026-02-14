# dumpexe

**16-bit MS-DOS MZ EXE Analyzer & Single-Pass Disassembler**

A comprehensive command-line utility for analyzing MS-DOS MZ format executable files, providing TDUMP-style header analysis, relocation table display, hex dumps with zero-compression, x86-16 disassembly using Capstone, and DOS load simulation with register tracking.

## Features

- **Static Header Analysis**: Displays comprehensive EXE header information in TDUMP style
- **Relocation Table**: Shows all relocation entries with file locations and linear offsets
- **Hex+ASCII Dumps**: Canonical `hexdump -C` format with zero-compression (repeated lines shown as `*`)
- **x86-16 Disassembly**: Static code analysis from entry point to EOF using Capstone
- **DOS Load Simulation**: Dynamic analysis simulating DOS loading with register state tracking
- **Cross-Platform**: Analyze DOS EXEs on Linux/Unix systems

## Building

### Prerequisites

```bash
sudo apt-get update
sudo apt-get install -y build-essential libcapstone-dev
```

### Compile

```bash
make
```

The Makefile automatically detects Capstone availability. If Capstone is not installed, the tool builds without disassembly support (all other features remain functional).

To build without Capstone intentionally:
```bash
make dumpexe-nocap
```

## Usage

### Basic Syntax

```bash
dumpexe [options] <exe_file>
```

### Options

- `-h, --help` - Show help message
- `-v, --version` - Show version information
- `-r, --relocation` - Show relocation table with padding
- `-x, --hexdump` - Show hex+ASCII dump from entry point to EOF
- `-d, --disassemble` - Show x86-16 disassembly (requires Capstone)
- `-a, --all` - Show all sections (relocation + hexdump + disassembly)
- `--simulate` - Enable DOS load simulation with register tracking
- `--base=XXXX` - Set load base segment (hex, default: 1000h)

### Examples

**Show header information only:**
```bash
./dumpexe examples/AR_unpacked.exe
```

**Show everything (complete analysis):**
```bash
./dumpexe -a examples/AR_unpacked.exe
```

**Disassemble code:**
```bash
./dumpexe -d examples/AR_unpacked.exe
```

**Simulate DOS loading at a specific base segment:**
```bash
./dumpexe --simulate --base=2000 examples/AR_unpacked.exe
```

**Show relocation table:**
```bash
./dumpexe -r examples/AR_unpacked.exe
```

**Combine options:**
```bash
./dumpexe -d --simulate examples/AR_unpacked.exe | less
```

## Example Files

The `examples/` directory contains:

- **AR.EXE** - Microprose's "Airborne Ranger" (1988), packed with Microsoft EXEPACK
  - MD5: `e87a8ff54161ef5fd138cbdf3ea4dae0`
  - Size: 72KB (73,237 bytes)
  
- **AR_unpacked.exe** - Unpacked version of Airborne Ranger
  - MD5: `d654710b1203d606c7dd80600d71dd38`
  - Size: 162KB (165,136 bytes)
  - Contains 152 relocation entries

These files demonstrate the difference between packed and unpacked executables.

## Output Format

### Static Header Information

Shows comprehensive MZ header analysis:
- DOS File Size, Load Image Size
- Relocation Table entry count and address
- Header Size, Memory Requirements
- Entry Point locations (file offset and image offset)
- Initial register values (SS:SP, CS:IP)

### Relocation Table (`-r`)

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

### Simulation (`--simulate`)

Dynamic execution trace:
- Initial CPU register state (CS:IP, SS:SP, DS, ES, FLAGS, etc.)
- Relocation fixup table showing segment adjustments
- Register tracing (first ~20 instructions with register changes)

## Static vs Dynamic Analysis

**Static Analysis** (`-d`): Disassembles all code without execution. Shows complete instruction stream. Good for understanding program structure and finding code paths.

**Dynamic Analysis** (`--simulate`): Simulates DOS loading and execution from entry point. Shows register state changes. Good for understanding program initialization and verifying relocation correctness.

**Combined** (`-d --simulate`): Shows both full disassembly and dynamic trace for complete analysis.

## Technical Details

### MZ EXE Format
- Signature: 'MZ' (0x5A4D little-endian)
- 28-byte minimum header
- Header sizes in paragraphs (16-byte units)
- File size: `((num_blocks-1) × 512) + final_len`
- Entry point: `header_size + (CS × 16) + IP`

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
