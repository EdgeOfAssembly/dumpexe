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
#include <sstream>
#include <cctype>

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
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(isByte ? 2 : 4) << val;
    return oss.str();
}

//=============================================================================
// Capstone-powered register trace
//=============================================================================

/// Build a "; reg = value" comment using Capstone's structured operand detail.
/// Updates the global CPU registers (AX, BX, … SP, DS, …) as a side-effect.
/// Requires CS_OPT_DETAIL to have been enabled on the handle.
static inline std::string trace_comment(csh handle, const cs_insn* insn) {
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
        return "; interrupt";
    }
    return "";
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
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            size_t codeSize = std::min((size_t)128, fileData.size() - s.entryPointFileOffset);
            const uint8_t* code = fileData.data() + s.entryPointFileOffset;

            size_t count = cs_disasm(handle, code, codeSize, entryLinear, 20, &insn);

            if (count > 0) {
                for (size_t i = 0; i < count; i++) {
                    std::cout << std::right << std::hex << std::setw(4) << std::setfill('0')
                              << (insn[i].address & 0xFFFF) << ": "
                              << insn[i].mnemonic;
                    if (insn[i].op_str[0]) std::cout << " " << insn[i].op_str;

                    std::string comment = trace_comment(handle, &insn[i]);
                    if (!comment.empty()) std::cout << "  " << comment;

                    std::cout << "\n";
                }
                cs_free(insn, count);
            }
            cs_close(&handle);
        }
    }
}

#endif // ANALYSIS_H
