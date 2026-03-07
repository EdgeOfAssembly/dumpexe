// analysis.h - EXE analysis and dump helper functions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Contains all logic extracted from main(): file loading, header validation,
// size calculations, header printing, relocation dumping, hex dumping, and
// DOS load simulation. All functions are static inline.

#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <algorithm>

#include "exe.h"
#include "format.h"
#include "options.h"
#include "registers.h"
#include "disasm.h"

//=============================================================================
// Computed size/offset bundle passed between helpers
//=============================================================================

/// All derived sizes and offsets calculated from the MZ header
struct ExeSizes {
    size_t  headerSizeBytes;          ///< Header size in bytes (header_size * 16)
    size_t  entryPointFileOffset;     ///< Absolute file offset of the entry point
    size_t  entryPointImageOffset;    ///< Image-relative offset of the entry point
    int64_t loadImageSize;            ///< Declared load-image size in bytes
    int64_t extraBytes;               ///< Bytes beyond declared size (overlay/debug)
    int64_t dosFileSize;              ///< Actual file size on disk
};

//=============================================================================
// File loading
//=============================================================================

/// Read an entire EXE file into a byte vector after basic size validation.
/// Returns an empty vector on error (error message already printed to stderr).
/// @param filename Path to the EXE file
/// @param dosFileSize Receives the actual file size in bytes
static inline std::vector<uint8_t> read_exe_file(const std::string& filename, int64_t& dosFileSize) {
    try {
        dosFileSize = static_cast<int64_t>(std::filesystem::file_size(filename));
    } catch (...) {
        std::cerr << "Error: Cannot get file size of '" << filename << "'\n";
        return {};
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file '" << filename << "'\n";
        return {};
    }

    std::vector<uint8_t> data(static_cast<size_t>(dosFileSize));
    file.read(reinterpret_cast<char*>(data.data()), dosFileSize);
    return data;
}

//=============================================================================
// Header validation
//=============================================================================

/// Validate MZ header fields.  Returns true on success; prints to stderr and
/// returns false on the first failing check.
/// @param header The already-read MZ header
/// @param dosFileSize Actual file size in bytes
static inline bool validate_header(const MZHeader& header, int64_t dosFileSize) {
    if (header.signature != 0x5A4D) {   // 'MZ'
        std::cerr << "Error: Not a valid MZ EXE file\n";
        return false;
    }
    if (header.num_blocks == 0) {
        std::cerr << "Error: Invalid header (zero pages)\n";
        return false;
    }

    int64_t headerSizeBytes64 = static_cast<int64_t>(header.header_size) * 16LL;
    if (headerSizeBytes64 <= 0 || headerSizeBytes64 > dosFileSize) {
        std::cerr << "Error: Invalid header size field\n";
        return false;
    }

    int64_t csBytes               = static_cast<int64_t>(header.cs) * 16LL;
    int64_t entryPointImageOffset = csBytes + static_cast<int64_t>(header.ip);
    int64_t entryPointFileOffset  = headerSizeBytes64 + entryPointImageOffset;

    if (csBytes < 0 || entryPointImageOffset < 0 || entryPointFileOffset < 0 ||
        entryPointFileOffset > dosFileSize) {
        std::cerr << "Error: Invalid CS:IP or entry point outside file\n";
        return false;
    }

    return true;
}

//=============================================================================
// Size calculation
//=============================================================================

/// Compute all derived sizes and offsets from a validated MZ header.
/// @param header Validated MZ header
/// @param dosFileSize Actual file size in bytes
/// @return Fully populated ExeSizes bundle
static inline ExeSizes calculate_sizes(const MZHeader& header, int64_t dosFileSize) {
    ExeSizes s;
    s.dosFileSize = dosFileSize;

    int64_t headerSizeBytes64      = static_cast<int64_t>(header.header_size) * 16LL;
    int64_t csBytes                = static_cast<int64_t>(header.cs) * 16LL;
    int64_t entryPointImageOffset64 = csBytes + static_cast<int64_t>(header.ip);
    int64_t loadImageSize64        = ((header.num_blocks - 1) * 512 + header.final_len)
                                     - headerSizeBytes64;
    int64_t entryPointFileOffset64 = headerSizeBytes64 + entryPointImageOffset64;

    s.headerSizeBytes         = static_cast<size_t>(headerSizeBytes64);
    s.entryPointFileOffset    = static_cast<size_t>(entryPointFileOffset64);
    s.entryPointImageOffset   = static_cast<size_t>(entryPointImageOffset64);
    s.loadImageSize           = loadImageSize64;
    s.extraBytes              = dosFileSize - loadImageSize64 - headerSizeBytes64;
    return s;
}

//=============================================================================
// Header printing
//=============================================================================

/// Print EXE header fields in TDUMP style.
/// @param opts Parsed command-line options (filename used for display)
/// @param header Validated MZ header
/// @param s     Computed size bundle
static inline void print_header_info(const Options& opts, const MZHeader& header, const ExeSizes& s) {
    std::cout << "Display of File " << opts.filename << "\n\n";

    print_field("DOS File Size",                 static_cast<uint32_t>(s.dosFileSize),           5);
    print_field("Load Image Size",               static_cast<uint32_t>(s.loadImageSize),         5);
    print_field("Relocation Table entry count",  header.num_reloc,                               4);
    print_field("Relocation Table address",      header.off_reloc,                               4);
    print_field("Header Size",                   static_cast<uint32_t>(s.headerSizeBytes),       4);
    print_field("Minimum Extra Memory",          header.mem_extra,                               4);

    if (header.mem_max == 0xFFFF) {
        std::cout << std::left << std::setw(50) << "Maximum Memory Requirement"
                  << std::right << std::setw(5) << "FFFFh"
                  << "  ( 65535. paragraphs = 1048560 bytes, all available )\n";
    } else {
        print_field("Maximum Memory Requirement", header.mem_max * 16,                           4);
    }

    print_field("File load checksum",            header.checksum,                                4);
    print_field("Overlay Number",                header.overlay_index,                           4);
    print_field("Entry Point File Offset",       static_cast<uint32_t>(s.entryPointFileOffset),  5);
    print_field("Entry Point Image Offset",      static_cast<uint32_t>(s.entryPointImageOffset), 5);

    std::cout << "\n";
    print_seg_off("Initial Stack Segment  (SS:SP)", static_cast<uint16_t>(header.ss), header.sp);
    print_seg_off("Program Entry Point    (CS:IP)", static_cast<uint16_t>(header.cs), header.ip);

    if (s.extraBytes > 0) {
        std::cout << "\nNote: File contains " << std::dec << s.extraBytes
                  << " extra bytes beyond declared size (overlay/debug data?)\n";
    }
}

//=============================================================================
// Relocation table dump
//=============================================================================

/// Dump the relocation table (and any surrounding padding) to stdout.
/// Also populates the relocs vector used later by run_simulation().
/// @param opts            Parsed CLI options — only called when showReloc/showAll is set
/// @param header          Validated MZ header
/// @param fileData        Full file contents
/// @param s               Computed size bundle
/// @param relocs          Output: populated with relocation entries on success
static inline void dump_relocations(const Options& opts,
                                    const MZHeader& header,
                                    const std::vector<uint8_t>& fileData,
                                    const ExeSizes& s,
                                    std::vector<RelocEntry>& relocs) {
    if (!opts.showReloc && !opts.showAll) return;

    size_t relocStart     = header.off_reloc;
    size_t relocEntrySize = sizeof(RelocEntry);
    size_t relocTableBytes = static_cast<size_t>(header.num_reloc) * relocEntrySize;
    size_t relocEnd       = relocStart + relocTableBytes;

    // Padding after fixed header, before relocation area
    if (relocStart > sizeof(MZHeader)) {
        size_t padSize = relocStart - sizeof(MZHeader);
        if (padSize > 0) {
            print_hex_dump(fileData, sizeof(MZHeader), padSize, "Padding:");
        }
    }

    if (header.num_reloc > 0) {
        if (relocStart <= fileData.size() &&
            relocTableBytes <= fileData.size() - relocStart) {
            relocs.resize(header.num_reloc);
            std::memcpy(relocs.data(), fileData.data() + relocStart, relocTableBytes);

            std::cout << "\n=== Relocation Table (" << std::dec << header.num_reloc << " entries) ===\n";
            std::cout << "Entry  Segment:Offset  File Location (Hex)  Linear Offset\n";
            std::cout << "-----  --------------  -------------------  -------------\n";

            for (size_t i = 0; i < relocs.size(); ++i) {
                uint32_t fileLoc = static_cast<uint32_t>(s.headerSizeBytes)
                                   + (relocs[i].segment * 16u) + relocs[i].offset;
                uint32_t linear  = (relocs[i].segment * 16u) + relocs[i].offset;

                std::cout << std::right << std::setw(5) << std::dec << i << "  "
                          << std::hex << std::uppercase << std::setfill('0')
                          << std::setw(4) << relocs[i].segment << ":"
                          << std::setw(4) << relocs[i].offset << "        "
                          << std::setw(8) << fileLoc << "h          "
                          << std::setw(6) << linear  << "h\n";
            }
        } else {
            std::cerr << "\n[Warning] Relocation table extends beyond file end. Skipped.\n";
        }
    }

    // Padding between end of reloc area and start of load image
    if (relocEnd < s.headerSizeBytes) {
        size_t padSize = s.headerSizeBytes - relocEnd;
        if (padSize > 0) {
            print_hex_dump(fileData, relocEnd, padSize, "Padding:");
        }
    }
}

//=============================================================================
// Hex dump
//=============================================================================

/// Dump binary content from the entry point (or a 64-byte preview) to stdout.
/// @param opts     Parsed CLI options
/// @param fileData Full file contents
/// @param s        Computed size bundle
static inline void dump_hex(const Options& opts,
                             const std::vector<uint8_t>& fileData,
                             const ExeSizes& s) {
    if (opts.showHexdump || opts.showAll) {
        if (s.entryPointFileOffset < fileData.size()) {
            size_t dumpSize = fileData.size() - s.entryPointFileOffset;
            print_hex_dump(fileData, s.entryPointFileOffset, dumpSize,
                           "=== Hex+ASCII Dump (from entry point to EOF) ===");
        }
    } else {
        if (!opts.showReloc && !opts.showDisasm) {
            if (s.entryPointFileOffset < fileData.size()) {
                size_t dumpSize = std::min((size_t)64, fileData.size() - s.entryPointFileOffset);
                print_hex_dump(fileData, s.entryPointFileOffset, dumpSize,
                               "Code at Entry Point (first 64 bytes):");
            }
        }
    }
}

//=============================================================================
// DOS load simulation
//=============================================================================

/// Run a DOS load simulation, printing register state and relocation fixups,
/// followed by a Capstone-powered register-trace of the first ~20 instructions.
/// @param opts     Parsed CLI options (loadBase, simulate flag)
/// @param header   Validated MZ header
/// @param fileData Full file contents
/// @param relocs   Relocation entries (may be empty)
/// @param s        Computed size bundle
static inline void run_simulation(const Options& opts,
                                  const MZHeader& header,
                                  const std::vector<uint8_t>& fileData,
                                  const std::vector<RelocEntry>& relocs,
                                  const ExeSizes& s) {
    if (!opts.simulate) return;

    std::cout << "\n========================================\n";
    std::cout << "=== DOS LOAD SIMULATION ===\n";
    std::cout << "========================================\n";
    std::cout << "Load Base Segment: " << hex_format(opts.loadBase, 4) << "\n\n";

    CS = opts.loadBase + static_cast<uint16_t>(header.cs);
    IP = header.ip;
    SS = opts.loadBase + static_cast<uint16_t>(header.ss);
    SP = header.sp;
    DS = opts.loadBase;
    ES = opts.loadBase;
    AX = 0; BX = 0; CX = 0; DX = 0;
    SI = 0; DI = 0; BP = 0;
    FLAGS = 0x0002;

    std::cout << "Initial Register State:\n";
    std::cout << "  CS:IP = " << hex_format(CS, 4) << ":" << hex_format(IP, 4) << "\n";
    std::cout << "  SS:SP = " << hex_format(SS, 4) << ":" << hex_format(SP, 4) << "\n";
    std::cout << "  DS    = " << hex_format(DS, 4) << "\n";
    std::cout << "  ES    = " << hex_format(ES, 4) << "\n";
    std::cout << "  FLAGS = " << hex_format(FLAGS, 4) << "\n\n";

    if (!relocs.empty()) {
        std::cout << "=== Relocation Fixups ===\n";
        std::cout << "Entry  Image Offset  Original Seg  Relocated Seg  Change\n";
        std::cout << "-----  ------------  ------------  -------------  ------\n";

        for (size_t i = 0; i < relocs.size(); i++) {
            uint32_t fileLocation = static_cast<uint32_t>(s.headerSizeBytes)
                                    + (relocs[i].segment * 16u) + relocs[i].offset;
            uint32_t imageOffset  = (relocs[i].segment * 16u) + relocs[i].offset;

            uint16_t originalSeg = 0;
            if (fileLocation + 1 < fileData.size()) {
                originalSeg = fileData[fileLocation] | (fileData[fileLocation + 1] << 8);
            }

            uint16_t relocatedSeg = originalSeg + opts.loadBase;

            std::cout << std::right << std::setw(5) << std::dec << i << "  "
                      << std::hex << std::uppercase << std::setfill('0')
                      << std::setw(6) << imageOffset << "h      "
                      << std::setw(4) << originalSeg << "h          "
                      << std::setw(4) << relocatedSeg << "h         +"
                      << std::setw(4) << opts.loadBase << "h\n";
        }
    }

    std::cout << "\n=== Register Tracing ===\n";
    std::cout << "Note: Best-effort trace for common instructions.\n\n";

    // Guard against entry point beyond file size
    if (s.entryPointFileOffset >= fileData.size()) {
        std::cout << "Register tracing skipped: entry point file offset ("
                  << s.entryPointFileOffset
                  << ") is beyond file size (" << fileData.size()
                  << ").\n";
    } else {
        csh handle;
        cs_insn *insn;

        // Calculate entry linear address for disassembly
        uint32_t entryLinear = (CS * 16) + IP;

        if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) == CS_ERR_OK) {
            size_t codeSize = std::min((size_t)128, fileData.size() - s.entryPointFileOffset);
            const uint8_t* code = fileData.data() + s.entryPointFileOffset;

            size_t count = cs_disasm(handle, code, codeSize, entryLinear, 20, &insn);

            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                    std::string mnem = insn[i].mnemonic;
                    std::string ops  = insn[i].op_str;

                    std::cout << std::hex << std::setw(4) << std::setfill('0')
                              << (insn[i].address & 0xFFFF) << ": "
                              << std::setw(8) << std::left << mnem << " " << ops;

                    if (mnem == "xor" && ops.find("ax,ax") != std::string::npos) {
                        AX = 0;
                        std::cout << "  ; AX = 0000h";
                    } else if (mnem == "xor" && ops.find("bx,bx") != std::string::npos) {
                        BX = 0;
                        std::cout << "  ; BX = 0000h";
                    } else if (mnem == "push") {
                        SP -= 2;
                        std::cout << "  ; SP = " << hex_format(SP, 4);
                    } else if (mnem == "pop") {
                        SP += 2;
                        std::cout << "  ; SP = " << hex_format(SP, 4);
                    } else if (mnem == "int") {
                        std::cout << "  ; interrupt";
                    }

                    std::cout << "\n";
                }
                cs_free(insn, count);
            }
            cs_close(&handle);
        }
    }
}

#endif // ANALYSIS_H
