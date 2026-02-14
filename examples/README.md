# Examples Directory

This directory contains pre-generated output examples for the dumpexe utility.

## Working with MZ EXE Files

The dumpexe utility analyzes MS-DOS MZ format executable files. To use dumpexe, you need to provide your own EXE files for testing and analysis.

### Where to Obtain MZ EXE Files

1. **DOS Games and Utilities**: Many classic DOS games and utilities are available from abandonware sites. Always check licensing before use.

2. **Compile Your Own**: Create test executables using DOS development tools:
   - Borland/Turbo C/C++
   - Microsoft C/C++
   - MASM (Microsoft Macro Assembler)
   - TASM (Turbo Assembler)
   - NASM with DOS targeting

3. **Open Source DOS Software**: Look for DOS projects with available binaries on GitHub or SourceForge.

### Recommended Test File Characteristics

For comprehensive testing of dumpexe features, consider using files that demonstrate:

#### Packed Executables
- **Characteristics**: Compressed with EXEPACK or similar packers
- **Features to observe**:
  - Few or no relocation entries
  - Smaller file size
  - Entry point typically late in file
- **Example characteristics** (like AR.EXE):
  - Size: ~72 KB
  - No relocation entries
  - Entry point at high file offset

#### Unpacked Executables
- **Characteristics**: Standard MZ format without compression
- **Features to observe**:
  - Multiple relocation table entries
  - Larger file size
  - Better for disassembly analysis
- **Example characteristics** (like AR_unpacked.exe):
  - Size: ~160 KB
  - 150+ relocation entries
  - Entry point near beginning of file

## Pre-Generated Output Examples

This directory contains pre-generated output files demonstrating various dumpexe options:

- **output_version.txt** - Version information (`-v`)
- **output_help.txt** - Help message (`-h`)
- **output_AR_static.txt** - Static header analysis example (packed executable)
- **output_AR_unpacked_static.txt** - Static header analysis example (unpacked executable)
- **output_relocation.txt** - Relocation table display example (`-r`)

These files show typical output from dumpexe when analyzing MZ EXE files.

## Using Dumpexe with Your Files

Once you have obtained an MZ EXE file, you can analyze it with dumpexe:

```bash
# Basic header info
./dumpexe <your_file.exe>

# Complete analysis
./dumpexe -a <your_file.exe> > full_analysis.txt

# Just disassembly
./dumpexe -d <your_file.exe> > disassembly.txt

# Simulation with custom base
./dumpexe --simulate --base=2000 <your_file.exe> > simulation.txt
```

## Verifying MZ EXE Files

To verify you have a valid MZ EXE file, check:

```bash
# Check for MZ signature (first two bytes should be 'MZ')
hexdump -C <your_file.exe> | head -n 1

# Expected output should start with:
# 00000000  4d 5a ...
#            ^  ^--- 'Z' (0x5A)
#            +------ 'M' (0x4D)
```

## Understanding MZ EXE Format

MZ EXE files are the standard executable format for MS-DOS. They typically exhibit these characteristics:

- **MZ signature**: 'MZ' (0x5A4D) at file offset 0
- **Real mode 16-bit x86 code**: Native DOS instruction set
- **Segment-based memory model**: 64KB segments with segment:offset addressing
- **Relocation table**: Segment addresses adjusted during load
- **Optional compression**: EXEPACK or similar packers reduce file size

Understanding these characteristics helps in analyzing and debugging DOS executables with dumpexe.
