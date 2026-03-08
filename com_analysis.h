// com_analysis.h - MS-DOS .COM file analysis functions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Provides PSP heuristic detection and full analysis output for MS-DOS .COM
// (plain binary) files.  Follows the same conventions as sys_analysis.h:
// all helpers are static inline, use formatting.h for TDUMP-style output,
// and accept the shared Options struct.
//
// PSP detection background
// ------------------------
// DOS loads a .COM file by:
//   1. Allocating a memory segment, building a 256-byte PSP at offset 0x000.
//   2. Copying the .COM *file* to offset 0x100 inside that segment.
//   3. Setting CS = DS = ES = SS = load segment, SP = 0xFFFE, IP = 0x100.
//   4. Jumping to CS:0100h.
//
// Therefore a typical .COM file on disk starts with the code/data that
// will sit at memory offset 0x100 — it does NOT include the PSP.  However,
// some .COM files are saved as raw memory snapshots that begin with the PSP
// (making the code start at file offset 0x100 rather than 0x000).
//
// detect_psp() uses two quick sanity checks to distinguish these cases:
//   • Check 1 – INT 20h marker: file[0x00]==0xCD && file[0x01]==0x20.
//     The first two bytes of every real PSP are the INT 20h instruction.
//   • Check 2 – Command-tail plausibility: len = file[0x80], len <= 0x7E,
//     and file[0x81 + len] == 0x0D (CR terminator).
// Both checks must pass before we declare a PSP present.  If the file is
// shorter than 256 bytes it cannot contain a PSP.

#ifndef COM_ANALYSIS_H
#define COM_ANALYSIS_H

#include <iostream>
#include <format>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>

#include "com.h"
#include "formatting.h"
#include "options.h"
#include "disasm.h"
#include "registers.h"
#include "analysis.h"   // trace_comment(), reg_get(), reg_set(), reg_fmt()

//=============================================================================
// PSP Heuristic Detection
//=============================================================================

/// Detect whether a .COM file begins with an embedded Program Segment Prefix.
///
/// Returns true only when BOTH of the following hold:
///   1. The first two bytes are 0xCD 0x20 (INT 20h — the canonical PSP start).
///   2. The command-tail at offset 0x80 is plausible: length byte <= 0x7E
///      and the byte at 0x81 + length equals 0x0D (carriage return).
///
/// If either check fails the function returns false (no PSP embedded).
/// A file shorter than COM_PSP_SIZE (256 bytes) automatically returns false.
///
/// @param data Full file contents as a byte vector.
/// @return true if an embedded PSP is detected, false otherwise.
static inline bool detect_psp(const std::vector<uint8_t>& data) {
    // A full PSP is 256 bytes; a shorter file cannot contain one.
    if (data.size() < COM_PSP_SIZE) return false;

    // Check 1: PSP always begins with INT 20h (0xCD 0x20).
    if (data[COM_PSP_INT20_OFFSET]     != 0xCD) return false;
    if (data[COM_PSP_INT20_OFFSET + 1] != 0x20) return false;

    // Check 2: Command-tail structure at offset 0x80.
    //   • data[0x80] is the length of the command tail (0 to 0x7E).
    //   • The character at data[0x81 + length] must be 0x0D (CR).
    uint8_t tail_len = data[COM_PSP_CMD_TAIL_OFFSET];
    if (tail_len > COM_PSP_CMD_TAIL_MAX_LEN) return false;

    // Ensure the CR byte is still within the buffer.
    size_t cr_offset = static_cast<size_t>(COM_PSP_CMD_TAIL_OFFSET) + 1 + tail_len;
    if (cr_offset >= data.size()) return false;
    if (data[cr_offset] != COM_PSP_CMD_TAIL_CR) return false;

    return true;
}

//=============================================================================
// COM Header / Info Printing
//=============================================================================

/// Print .COM file summary information in TDUMP style.
///
/// @param opts         Parsed CLI options (filename for display).
/// @param fileSize     Total file size in bytes.
/// @param has_psp      Whether an embedded PSP was detected (or forced).
/// @param entry_offset File offset of the entry point (0x000 or 0x100).
static inline void print_com_info(const Options& opts,
                                  int64_t fileSize,
                                  bool has_psp,
                                  size_t entry_offset) {
    std::cout << "Display of File " << opts.filename << "\n\n";

    std::cout << std::format("{:<50}{}\n", "File Format", ".COM (flat binary, 16-bit MS-DOS)");
    print_field("File Size", static_cast<uint32_t>(fileSize), 5);

    if (has_psp) {
        std::cout << std::format("{:<50}{}\n", "Load Model",
                                 "PSP embedded in file (entry at file offset 0100h)");
    } else {
        std::cout << std::format("{:<50}{}\n", "Load Model",
                                 "No PSP in file (code starts at file offset 0000h)");
    }

    print_field("Entry Point File Offset", static_cast<uint32_t>(entry_offset), 4);

    // In memory, CS:IP = load_segment:0100h for all .COM programs.
    std::cout << std::format("\n{:<50}{:04X}:{:04X}\n",
                             "Program Entry Point (CS:IP)",
                             opts.loadBase, COM_ENTRY_IP);

    // Stack: DOS sets SP to 0xFFFE, pointing to segment top minus two bytes.
    std::cout << std::format("{:<50}{:04X}:{:04X}\n",
                             "Initial Stack (SS:SP)",
                             opts.loadBase, uint16_t{0xFFFE});

    // DS, ES, SS all equal the load segment at startup.
    std::cout << std::format("{:<50}{:04X}h\n", "DS = ES = SS = CS", opts.loadBase);
}

//=============================================================================
// COM Simulation
//=============================================================================

/// Simulate DOS loading a .COM file and show initial register state plus a
/// best-effort Capstone register trace of the first ~20 instructions.
///
/// @param opts         Parsed CLI options.
/// @param data         Full file contents.
/// @param entry_offset File byte offset where code begins (0x000 or 0x100).
static inline void run_com_simulation(const Options& opts,
                                      const std::vector<uint8_t>& data,
                                      size_t entry_offset) {
    std::cout << "\n========================================\n";
    std::cout << "=== DOS LOAD SIMULATION (.COM) ===\n";
    std::cout << "========================================\n";
    std::cout << "Note: Best-effort; .COM PSP setup is simplified.\n";
    std::cout << "Load Base Segment: " << hex_format(opts.loadBase, 4) << "\n\n";

    // DOS sets all segment registers to the load segment for .COM programs.
    CS = opts.loadBase;
    DS = opts.loadBase;
    ES = opts.loadBase;
    SS = opts.loadBase;
    IP = COM_ENTRY_IP;          // Always 0x0100 in memory
    SP = 0xFFFE;                // Stack grows down from top of segment
    AX = 0; BX = 0; CX = 0; DX = 0;
    SI = 0; DI = 0; BP = 0;
    FLAGS = 0x0002;

    std::cout << "Initial Register State:\n";
    std::cout << "  CS:IP = " << hex_format(CS, 4) << ":" << hex_format(IP, 4) << "\n";
    std::cout << "  SS:SP = " << hex_format(SS, 4) << ":" << hex_format(SP, 4) << "\n";
    std::cout << "  DS    = " << hex_format(DS, 4) << "\n";
    std::cout << "  ES    = " << hex_format(ES, 4) << "\n";
    std::cout << "  FLAGS = " << hex_format(FLAGS, 4) << "\n\n";

    if (entry_offset >= data.size()) {
        std::cout << "Register tracing skipped: entry offset ("
                  << entry_offset << ") is beyond file size ("
                  << data.size() << ").\n";
        return;
    }

    std::cout << "=== Register Tracing ===\n";
    std::cout << "Note: Best-effort trace for common instructions.\n\n";

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone disassembler\n";
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t codeSize = std::min((size_t)128, data.size() - entry_offset);
    const uint8_t* code = data.data() + entry_offset;
    // Linear address = CS*16 + IP
    uint32_t entryLinear = static_cast<uint32_t>(CS) * 16u + IP;

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(handle, code, codeSize, entryLinear, 20, &insn);

    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
            std::cout << std::format("{:04x}: {}", insn[i].address & 0xFFFF,
                                     insn[i].mnemonic);
            if (insn[i].op_str[0]) std::cout << " " << insn[i].op_str;

            std::string comment = trace_comment(handle, &insn[i], opts.noIntAnnot);
            if (!comment.empty()) std::cout << "  " << comment;

            std::cout << "\n";
        }
        cs_free(insn, count);
    }
    cs_close(&handle);
}

//=============================================================================
// Main COM Analysis Entry Point
//=============================================================================

/// Analyze a .COM file and print its information.
///
/// Detection order for the entry point:
///   1. --psp flag  → force PSP present, entry file offset = 0x100.
///   2. --no-psp flag → force no PSP,    entry file offset = 0x000.
///   3. Otherwise  → use detect_psp() heuristic.
///
/// @param opts     Parsed CLI options.
/// @param data     Full file contents as a byte vector.
/// @param fileSize Actual file size in bytes.
static inline void analyze_com(const Options& opts,
                                const std::vector<uint8_t>& data,
                                int64_t fileSize) {
    // Resolve PSP presence using flags or heuristic.
    bool has_psp = false;
    if (opts.comForcePsp) {
        has_psp = true;
    } else if (opts.comForceNoPsp) {
        has_psp = false;
    } else {
        has_psp = detect_psp(data);
    }

    // Entry point file offset: 0x100 when the PSP is part of the file,
    // 0x000 otherwise (file content goes to memory starting at 0x100).
    size_t entry_offset = has_psp ? COM_PSP_SIZE : 0;

    print_com_info(opts, fileSize, has_psp, entry_offset);

    // Hex dump from entry point to EOF (same behaviour as EXE path).
    if (opts.showHexdump || opts.showAll) {
        if (entry_offset < data.size()) {
            size_t dump_size = data.size() - entry_offset;
            print_hex_dump(data, entry_offset, dump_size,
                           "=== Hex+ASCII Dump (from entry point to EOF) ===");
        }
    } else if (!opts.showReloc && !opts.showDisasm) {
        // Default: show a 64-byte preview when no section flag is given.
        if (entry_offset < data.size()) {
            size_t preview = std::min((size_t)64, data.size() - entry_offset);
            print_hex_dump(data, entry_offset, preview,
                           "Code at Entry Point (first 64 bytes):");
        }
    }

    // Disassembly from entry point.
    if (opts.showDisasm || opts.showAll) {
        disassemble(data, entry_offset,
                    opts.loadBase, COM_ENTRY_IP, opts);
    }

    if (opts.simulate) {
        run_com_simulation(opts, data, entry_offset);
    }
}

#endif // COM_ANALYSIS_H
