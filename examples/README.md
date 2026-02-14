# Examples Directory

This directory contains test files and output examples for the dumpexe utility.

## Test Files

### AR.EXE
- **Description**: Microprose's "Airborne Ranger" (1988 PC DOS game)
- **Status**: Packed with Microsoft EXEPACK
- **MD5**: `e87a8ff54161ef5fd138cbdf3ea4dae0`
- **Size**: 73,237 bytes (72 KB)
- **Features**:
  - No relocation entries (packed format)
  - Entry point at file offset 0x11BB0
  - Demonstrates packed executable analysis

### AR_unpacked.exe
- **Description**: Unpacked version of Airborne Ranger
- **MD5**: `d654710b1203d606c7dd80600d71dd38`
- **Size**: 165,136 bytes (162 KB)
- **Features**:
  - 152 relocation entries
  - Entry point at file offset 0x00420
  - Demonstrates unpacked executable analysis with relocations

## Output Examples

Pre-generated output files demonstrating various dumpexe options:

- **output_version.txt** - Version information (`-v`)
- **output_help.txt** - Help message (`-h`)
- **output_AR_static.txt** - Static header analysis of AR.EXE
- **output_AR_unpacked_static.txt** - Static header analysis of unpacked version
- **output_relocation.txt** - Relocation table display (`-r`)

## Generating Your Own Examples

```bash
# Basic header info
./dumpexe examples/AR.EXE

# Complete analysis
./dumpexe -a examples/AR_unpacked.exe > full_analysis.txt

# Just disassembly
./dumpexe -d examples/AR_unpacked.exe > disassembly.txt

# Simulation with custom base
./dumpexe --simulate --base=2000 examples/AR_unpacked.exe > simulation.txt
```

## Verifying File Integrity

```bash
cd examples/
md5sum AR.EXE AR_unpacked.exe
```

Expected output:
```
e87a8ff54161ef5fd138cbdf3ea4dae0  AR.EXE
d654710b1203d606c7dd80600d71dd38  AR_unpacked.exe
```

## About Airborne Ranger

Airborne Ranger is a tactical action game developed and published by Microprose in 1988. The game features behind-enemy-lines missions where players control an Army Ranger. The executable demonstrates typical characteristics of late-1980s DOS games:
- Real mode 16-bit x86 code
- Segment-based memory model
- Relocation-based loading for memory flexibility
- EXEPACK compression for distribution size reduction
