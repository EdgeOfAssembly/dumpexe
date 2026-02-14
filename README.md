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

> **Note**: You need to supply your own MZ EXE file for testing. See the "Example Files" section below for guidance on obtaining test files.

**Show header information only:**
```bash
./dumpexe <your_file.exe>
```

**Show everything (complete analysis):**
```bash
./dumpexe -a <your_file.exe>
```

**Disassemble code:**
```bash
./dumpexe -d <your_file.exe>
```

**Simulate DOS loading at a specific base segment:**
```bash
./dumpexe --simulate --base=2000 <your_file.exe>
```

**Show relocation table:**
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

To test dumpexe, you need to provide your own MZ EXE files. Good sources include:

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

The `examples/README.md` file provides additional guidance on working with MZ EXE files.

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
