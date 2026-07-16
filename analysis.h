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
#include <format>
#include <vector>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <cctype>

#include "exe.h"
#include "formatting.h"
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
    int64_t entryPointImageOffset;    ///< Image-relative offset of the entry point (may be negative)
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

    if (dosFileSize < static_cast<int64_t>(sizeof(MZHeader))) {
        std::cerr << "Error: File '" << filename << "' is too small to contain a valid MZ header\n";
        return {};
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Cannot open file '" << filename << "'\n";
        return {};
    }

    const std::size_t bufferSize = static_cast<std::size_t>(dosFileSize);
    std::vector<uint8_t> data(bufferSize);
    file.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(bufferSize));
    if (!file || file.gcount() != static_cast<std::streamsize>(bufferSize)) {
        std::cerr << "Error: Failed to read full contents of '" << filename << "'\n";
        return {};
    }
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
    if (header.signature != MZ_SIGNATURE) {   // 'MZ'
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

    // cs is a signed relative offset — negative values are valid (e.g. cs=0xFFF0
    // combined with a matching ip can yield a non-negative entryPointFileOffset).
    // Only the final file offset needs to be within bounds.
    if (entryPointFileOffset < 0 || entryPointFileOffset > dosFileSize) {
        std::cerr << "Error: Invalid CS:IP or entry point outside file\n";
        return false;
    }

    return true;
}

//=============================================================================
// Size calculation
//=============================================================================

/// Declared EXE size on disk from MZ page fields.
/// final_len == 0 means the last 512-byte page is full (classic MZ rule).
static inline int64_t mz_declared_file_size(const MZHeader& header) {
    if (header.final_len == 0)
        return static_cast<int64_t>(header.num_blocks) * 512LL;
    return (static_cast<int64_t>(header.num_blocks) - 1LL) * 512LL
           + static_cast<int64_t>(header.final_len);
}

/// Compute all derived sizes and offsets from a validated MZ header.
/// @param header Validated MZ header
/// @param dosFileSize Actual file size in bytes
/// @return Fully populated ExeSizes bundle
static inline ExeSizes calculate_sizes(const MZHeader& header, int64_t dosFileSize) {
    ExeSizes s;
    s.dosFileSize = dosFileSize;

    int64_t headerSizeBytes64       = static_cast<int64_t>(header.header_size) * 16LL;
    int64_t csBytes                 = static_cast<int64_t>(header.cs) * 16LL;
    int64_t entryPointImageOffset64 = csBytes + static_cast<int64_t>(header.ip);
    int64_t declaredFileSize64      = mz_declared_file_size(header);
    int64_t loadImageSize64         = declaredFileSize64 - headerSizeBytes64;
    int64_t entryPointFileOffset64  = headerSizeBytes64 + entryPointImageOffset64;

    if (loadImageSize64 < 0)
        loadImageSize64 = 0;

    s.headerSizeBytes         = static_cast<size_t>(headerSizeBytes64);
    s.entryPointFileOffset    = static_cast<size_t>(entryPointFileOffset64);
    s.entryPointImageOffset   = entryPointImageOffset64;
    s.loadImageSize           = loadImageSize64;
    s.extraBytes              = dosFileSize - declaredFileSize64;
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
        std::cout << std::format("{:<50}{:>5}  ( 65535. paragraphs = 1048560 bytes, all available )\n",
                                 "Maximum Memory Requirement", "FFFFh");
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
        std::cout << std::format("\nNote: File contains {} extra bytes beyond declared size (overlay/debug data?)\n",
                                 s.extraBytes);
    }
}

//=============================================================================
// Relocation table dump
//=============================================================================

/// Load relocation entries into @p relocs (always; needed by --simulate).
/// Returns true if a table was present and loaded (or num_reloc == 0).
static inline bool load_relocations(const MZHeader& header,
                                    const std::vector<uint8_t>& fileData,
                                    std::vector<RelocEntry>& relocs) {
    relocs.clear();
    if (header.num_reloc == 0)
        return true;

    const size_t relocStart      = header.off_reloc;
    const size_t relocTableBytes = static_cast<size_t>(header.num_reloc) * sizeof(RelocEntry);

    if (relocStart > fileData.size() ||
        relocTableBytes > fileData.size() - relocStart) {
        std::cerr << "\n[Warning] Relocation table extends beyond file end. Skipped.\n";
        return false;
    }

    relocs.resize(header.num_reloc);
    std::memcpy(relocs.data(), fileData.data() + relocStart, relocTableBytes);
    return true;
}

/// Dump the relocation table (and any surrounding padding) to stdout.
/// Always loads reloc entries into @p relocs for later use by run_simulation().
/// @param opts            Parsed CLI options
/// @param header          Validated MZ header
/// @param fileData        Full file contents
/// @param s               Computed size bundle
/// @param relocs          Output: populated with relocation entries on success
static inline void dump_relocations(const Options& opts,
                                    const MZHeader& header,
                                    const std::vector<uint8_t>& fileData,
                                    const ExeSizes& s,
                                    std::vector<RelocEntry>& relocs) {
    // Always load — simulation needs fixups even without -r/--all.
    load_relocations(header, fileData, relocs);

    if (!opts.showReloc && !opts.showAll)
        return;

    const size_t relocStart      = header.off_reloc;
    const size_t relocTableBytes = static_cast<size_t>(header.num_reloc) * sizeof(RelocEntry);
    const size_t relocEnd        = relocStart + relocTableBytes;

    // Padding after fixed header, before relocation area (only if table is after header)
    if (header.num_reloc > 0 && relocStart > sizeof(MZHeader)) {
        size_t padSize = relocStart - sizeof(MZHeader);
        if (padSize > 0) {
            print_hex_dump(fileData, sizeof(MZHeader), padSize, "Padding:");
        }
    }

    if (header.num_reloc > 0) {
        if (!relocs.empty()) {
            std::cout << std::format("\n=== Relocation Table ({} entries) ===\n", header.num_reloc);
            std::cout << "Entry  Segment:Offset  File Location (Hex)  Linear Offset\n";
            std::cout << "-----  --------------  -------------------  -------------\n";

            for (size_t i = 0; i < relocs.size(); ++i) {
                const auto& r = relocs[i];
                uint32_t fileLoc = static_cast<uint32_t>(s.headerSizeBytes)
                                   + (r.segment * 16u) + r.offset;
                uint32_t linear  = (r.segment * 16u) + r.offset;

                std::cout << std::format("{:05}  {:04X}:{:04X}        {:08X}h          {:06X}h\n",
                                         i, r.segment, r.offset, fileLoc, linear);
            }
        }
    }

    // Reserved/padding between end of header structures and start of load image.
    // Never treat the fixed 28-byte MZ header itself as padding (e.g. off_reloc=0,
    // num_reloc=0 would otherwise dump from file offset 0).
    size_t padStart = sizeof(MZHeader);
    if (header.num_reloc > 0 && relocEnd > padStart)
        padStart = relocEnd;
    if (padStart < s.headerSizeBytes) {
        size_t padSize = s.headerSizeBytes - padStart;
        if (padSize > 0) {
            print_hex_dump(fileData, padStart, padSize, "Padding:");
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
// Register helpers — read/write the global CPU state from registers.h
//=============================================================================

/// Read the current value of a named 8/16-bit register from global state.
/// Returns false when the name is not a recognised register.
static inline bool reg_get(const std::string& n, uint16_t& out) {
    if      (n=="ax"){out=AX;return true;} else if (n=="bx"){out=BX;return true;}
    else if (n=="cx"){out=CX;return true;} else if (n=="dx"){out=DX;return true;}
    else if (n=="si"){out=SI;return true;} else if (n=="di"){out=DI;return true;}
    else if (n=="sp"){out=SP;return true;} else if (n=="bp"){out=BP;return true;}
    else if (n=="cs"){out=CS;return true;} else if (n=="ds"){out=DS;return true;}
    else if (n=="es"){out=ES;return true;} else if (n=="ss"){out=SS;return true;}
    else if (n=="ah"){out=AH;return true;} else if (n=="al"){out=AL;return true;}
    else if (n=="bh"){out=BH;return true;} else if (n=="bl"){out=BL;return true;}
    else if (n=="ch"){out=CH;return true;} else if (n=="cl"){out=CL;return true;}
    else if (n=="dh"){out=DH;return true;} else if (n=="dl"){out=DL;return true;}
    return false;
}

/// Write a value to a named 8/16-bit register in global state.
static inline void reg_set(const std::string& n, uint16_t val) {
    if      (n=="ax") AX=val;          else if (n=="bx") BX=val;
    else if (n=="cx") CX=val;          else if (n=="dx") DX=val;
    else if (n=="si") SI=val;          else if (n=="di") DI=val;
    else if (n=="sp") SP=val;          else if (n=="bp") BP=val;
    else if (n=="cs") CS=val;          else if (n=="ds") DS=val;
    else if (n=="es") ES=val;          else if (n=="ss") SS=val;
    else if (n=="ah") AH=uint8_t(val); else if (n=="al") AL=uint8_t(val);
    else if (n=="bh") BH=uint8_t(val); else if (n=="bl") BL=uint8_t(val);
    else if (n=="ch") CH=uint8_t(val); else if (n=="cl") CL=uint8_t(val);
    else if (n=="dh") DH=uint8_t(val); else if (n=="dl") DL=uint8_t(val);
}

/// Format a value as "0xNNNN" (4 digits) or "0xNN" for byte registers.
static inline std::string reg_fmt(const std::string& n, uint16_t val) {
    bool isByte = (n.size()==2 && (n[1]=='h'||n[1]=='l') &&
                   (n[0]=='a'||n[0]=='b'||n[0]=='c'||n[0]=='d'));
    return std::format("0x{:0{}x}", val, isByte ? 2 : 4);
}

//=============================================================================
// Capstone-powered register trace
//=============================================================================

/// Build a "; reg = value" comment using Capstone's structured operand detail.
/// Updates the global CPU registers (AX, BX, … SP, DS, …) as a side-effect.
/// Requires CS_OPT_DETAIL to have been enabled on the handle.
static inline std::string trace_comment(csh handle, const cs_insn* insn,
                                         bool no_int_annot = false) {
    if (!insn->detail) return "";

    const cs_x86& x86  = insn->detail->x86;
    const std::string  mnem = insn->mnemonic;

    // Resolve a Capstone register ID → lowercase name string
    auto rname = [&](x86_reg r) -> std::string {
        const char* n = cs_reg_name(handle, r);
        return n ? std::string(n) : "";
    };

    // Instructions whose first operand is a destination register
    if (x86.op_count >= 2 && x86.operands[0].type == X86_OP_REG) {
        std::string dst = rname(x86.operands[0].reg);
        uint16_t cur = 0;
        bool curKnown = reg_get(dst, cur);

        if (mnem == "mov") {
            // mov reg, imm  or  mov reg, reg  →  update dst, show ; dst = val
            uint16_t val = 0; bool known = false;
            if (x86.operands[1].type == X86_OP_IMM) {
                val = static_cast<uint16_t>(x86.operands[1].imm);
                known = true;
            } else if (x86.operands[1].type == X86_OP_REG) {
                known = reg_get(rname(x86.operands[1].reg), val);
            }
            if (known) {
                reg_set(dst, val);
                uint16_t stored = 0; reg_get(dst, stored);
                return "; " + dst + " = " + reg_fmt(dst, stored);
            }
        } else if ((mnem == "xor" || mnem == "sub") &&
                   x86.operands[1].type == X86_OP_REG &&
                   x86.operands[0].reg  == x86.operands[1].reg) {
            // xor/sub reg, reg  →  reg = 0
            reg_set(dst, 0);
            return "; " + dst + " = " + reg_fmt(dst, 0);
        } else if (mnem == "add" && curKnown &&
                   x86.operands[1].type == X86_OP_IMM) {
            uint16_t val = static_cast<uint16_t>(cur + x86.operands[1].imm);
            reg_set(dst, val);
            return "; " + dst + " = " + reg_fmt(dst, val);
        } else if (mnem == "sub" && curKnown &&
                   x86.operands[1].type == X86_OP_IMM) {
            uint16_t val = static_cast<uint16_t>(cur - x86.operands[1].imm);
            reg_set(dst, val);
            return "; " + dst + " = " + reg_fmt(dst, val);
        }
    }

    // Stack / control-flow instructions — track SP
    if (mnem == "push" || mnem == "call") {
        SP -= 2;
        return "; sp = " + reg_fmt("sp", SP);
    } else if (mnem == "pop" || mnem == "ret" || mnem == "retf") {
        SP += 2;
        return "; sp = " + reg_fmt("sp", SP);
    } else if (mnem == "int") {
        if (no_int_annot || x86.op_count < 1 ||
            x86.operands[0].type != X86_OP_IMM) {
            return "; interrupt";
        }
        uint8_t int_num = static_cast<uint8_t>(x86.operands[0].imm);
        return format_int_annotation(int_num, AH, AL);
    }
    return "";
}

//=============================================================================
// DOS load simulation (execution engine in sim.h)
//=============================================================================

#include "sim.h"

/// Run DOS load simulation: 1 MiB arena, step loop, breakpoints, INT 21 stubs.
/// @param opts     Parsed CLI options (may be non-const for BP hit counts — cast)
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

    if (!relocs.empty()) {
        std::cout << "\n=== Relocation Fixups ===\n";
        std::cout << "Entry  Image Offset  Original Seg  Relocated Seg  Change\n";
        std::cout << "-----  ------------  ------------  -------------  ------\n";
        for (size_t i = 0; i < relocs.size(); ++i) {
            const auto& r = relocs[i];
            uint32_t fileLocation = static_cast<uint32_t>(s.headerSizeBytes)
                                    + (r.segment * 16u) + r.offset;
            uint32_t imageOffset  = (r.segment * 16u) + r.offset;
            uint16_t originalSeg = 0;
            if (fileLocation + 1 < fileData.size()) {
                originalSeg = fileData[fileLocation] | (fileData[fileLocation + 1] << 8);
            }
            uint16_t relocatedSeg = originalSeg + opts.loadBase;
            std::cout << std::format("{:05}  {:06X}h      {:04X}h          {:04X}h         +{:04X}h\n",
                                     i, imageOffset, originalSeg, relocatedSeg, opts.loadBase);
        }
        std::cout << "\n";
    }

    // sim_run_mz mutates breakpoint hit counters
    Options opts_mut = opts;
    sim_run_mz(opts_mut, header, fileData, relocs,
               s.headerSizeBytes, s.loadImageSize);
}


#endif // ANALYSIS_H
