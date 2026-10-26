# Examples Directory

This directory contains pre-generated output examples for the dumpexe utility.

## Working with MZ EXE Files

The dumpexe utility analyzes MS-DOS MZ format executable files. To use dumpexe, you need to provide your own EXE files for testing and analysis.

### Where to Obtain MZ EXE Files

1. **DOS Utilities**: Use programs you have the right to use and analyze.

2. **Compile Your Own**: Create test executables using DOS development tools:
   - Borland/Turbo C/C++
   - Microsoft C/C++
   - MASM (Microsoft Macro Assembler)
   - TASM (Turbo Assembler)
   - NASM with DOS targeting

3. **Open Source DOS Software**: Look for DOS projects with available binaries on GitHub or SourceForge.

## Pre-Generated Output Examples (dumpexe 2.45.0)

- **output_version.txt** - Version information (`-v`)
- **output_help.txt** - Help message (`-h`)
- **output_header_com_in_exe.txt** - Header report (`--header-only`) of
  CuteMouse 2.1 beta4 `ctmouse.exe` (FreeDOS, GPL), a COM program wrapped as
  MZ, with the JWASM 1.80 toolchain fingerprint
- **output_relocation.txt** - Relocation table (`-r`) of a 96-byte synthetic
  MZ with three segment fixups

## Using Dumpexe with Your Files

Once you have obtained an MZ EXE file, you can analyze it with dumpexe:

```bash
# Complete analysis (the default, same as -a)
./dumpexe <your_file.exe> > full_analysis.txt

# Basic header info
./dumpexe --header-only <your_file.exe>

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
