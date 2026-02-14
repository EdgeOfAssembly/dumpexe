// dumpexe.h - MS-DOS MZ EXE header analysis toolkit
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Header file containing all utility functions, structures, and register definitions
// for analyzing and simulating MS-DOS MZ executable files
//
// This header provides:
// - MZ EXE format structures (MZHeader, RelocEntry)
// - Utility functions for hex/dec formatting and TDUMP-style output
// - Hex dump functionality with zero-compression (like hexdump -C)
// - Command-line options parsing
// - 16-bit x86 CPU register state definitions for simulation
// - Optional Capstone disassembly support

#ifndef DUMPEXE_H
#define DUMPEXE_H

#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <sstream>
#include <algorithm>
#include <stdexcept>

// Optional Capstone support - check if headers are available
#if __has_include(<capstone/capstone.h>)
#include <capstone/capstone.h>
#define HAS_CAPSTONE 1
#else
#define HAS_CAPSTONE 0
#endif

//=============================================================================
// MS-DOS MZ EXE Format Structures
//=============================================================================

#pragma pack(push,1)
struct MZHeader {
    uint16_t signature;
    uint16_t final_len;
    uint16_t num_blocks;
    uint16_t num_reloc;
    uint16_t header_size;
    uint16_t mem_extra;
    uint16_t mem_max;
    int16_t  ss;
    uint16_t sp;
    uint16_t checksum;
    uint16_t ip;
    int16_t  cs;
    uint16_t off_reloc;
    uint16_t overlay_index;
};
#pragma pack(pop)

#pragma pack(push,1)
struct RelocEntry {
    uint16_t offset;
    uint16_t segment;
};
#pragma pack(pop)

//=============================================================================
// 16-bit x86 CPU Register State
//=============================================================================

#pragma pack(push,1)
inline union {
    uint16_t value;
    struct { uint8_t lo; uint8_t hi; };
} __AX__;
#pragma pack(pop)
#define AX __AX__.value
#define AH __AX__.hi
#define AL __AX__.lo

#pragma pack(push,1)
inline union {
    uint16_t value;
    struct { uint8_t lo; uint8_t hi; };
} __BX__;
#pragma pack(pop)
#define BX __BX__.value
#define BH __BX__.hi
#define BL __BX__.lo

#pragma pack(push,1)
inline union {
    uint16_t value;
    struct { uint8_t lo; uint8_t hi; };
} __CX__;
#pragma pack(pop)
#define CX __CX__.value
#define CH __CX__.hi
#define CL __CX__.lo

#pragma pack(push,1)
inline union {
    uint16_t value;
    struct { uint8_t lo; uint8_t hi; };
} __DX__;
#pragma pack(pop)
#define DX __DX__.value
#define DH __DX__.hi
#define DL __DX__.lo

inline uint16_t CS = 0;
inline uint16_t DS = 0;
inline uint16_t ES = 0;
inline uint16_t SS = 0;
inline uint16_t IP = 0;
inline uint16_t BP = 0;
inline uint16_t SP = 0;
inline uint16_t DI = 0;
inline uint16_t SI = 0;

#pragma pack(push,1)
inline union {
    uint16_t value;
    struct {
        unsigned CF   : 1;
        unsigned _r1  : 1;
        unsigned PF   : 1;
        unsigned _r2  : 1;
        unsigned AF   : 1;
        unsigned _r3  : 1;
        unsigned ZF   : 1;
        unsigned SF   : 1;
        unsigned TF   : 1;
        unsigned IF   : 1;
        unsigned DF   : 1;
        unsigned OF   : 1;
        unsigned IOPL : 2;
        unsigned NT   : 1;
        unsigned _r4  : 1;
    };
} __FLAGS__;
#pragma pack(pop)
#define FLAGS __FLAGS__.value
#define CF __FLAGS__.CF
#define PF __FLAGS__.PF
#define AF __FLAGS__.AF
#define ZF __FLAGS__.ZF
#define SF __FLAGS__.SF
#define TF __FLAGS__.TF
#define IF __FLAGS__.IF
#define DF __FLAGS__.DF
#define OF __FLAGS__.OF
#define IOPL __FLAGS__.IOPL
#define NT __FLAGS__.NT

//=============================================================================
// Formatting and Output Functions
//=============================================================================

static inline std::string hexFormat(uint32_t value, int width = 4) {
    std::ostringstream oss;
    oss << std::uppercase << std::setfill('0') << std::setw(width) << std::hex << value << "h";
    return oss.str();
}

static inline std::string decFormat(uint32_t value, int width = 6) {
    std::ostringstream oss;
    oss << std::setw(width) << std::dec << value << ".";
    return oss.str();
}

static inline void printField(const std::string& name, uint32_t value, int hexWidth = 4) {
    const int nameWidth = 50;
    std::cout << std::left << std::setw(nameWidth) << name
              << std::right << std::setw(hexWidth + 1) << hexFormat(value, hexWidth)
              << "  (" << std::right << std::setw(7) << decFormat(value) << " )\n";
}

static inline void printSegOff(const std::string& name, uint16_t seg, uint16_t off) {
    std::cout << name << "\t\t\t  "
              << std::uppercase << std::setfill('0') << std::hex
              << std::setw(4) << seg << ":" << std::setw(4) << off << "\n";
}

static inline void printHexDump(const std::vector<uint8_t>& data, size_t offset, size_t count,
                  const std::string& title = "") {
    if (count == 0) return;
    if (offset >= data.size()) return;
    if (!title.empty()) {
        std::cout << "\n" << title << "\n";
    }
    size_t maxCount = data.size() - offset;
    count = std::min(count, maxCount);
    std::array<uint8_t, 16> prevLine = {};
    bool prevLineValid = false;
    bool starPrinted = false;
    for (size_t i = 0; i < count; i += 16) {
        std::array<uint8_t, 16> currentLine = {};
        size_t bytesOnLine = std::min((size_t)16, count - i);
        for (size_t j = 0; j < bytesOnLine; j++) {
            currentLine[j] = data[offset + i + j];
        }
        bool isRepeat = false;
        if (prevLineValid && bytesOnLine == 16) {
            isRepeat = (std::memcmp(currentLine.data(), prevLine.data(), 16) == 0);
        }
        if (isRepeat) {
            if (!starPrinted) {
                std::cout << "*\n";
                starPrinted = true;
            }
        } else {
            starPrinted = false;
            std::cout << std::hex << std::nouppercase << std::setw(8) << std::setfill('0')
                      << (offset + i);
            std::cout << "  ";
            for (size_t j = 0; j < 16; j++) {
                if (j < bytesOnLine) {
                    std::cout << std::hex << std::nouppercase << std::setw(2) << std::setfill('0')
                              << (int)currentLine[j];
                } else {
                    std::cout << "  ";
                }
                std::cout << " ";
                if (j == 7) std::cout << " ";
            }
            std::cout << " |";
            for (size_t j = 0; j < bytesOnLine; j++) {
                uint8_t byte = currentLine[j];
                if (byte >= 32 && byte <= 126) std::cout << (char)byte;
                else std::cout << ".";
            }
            for (size_t j = bytesOnLine; j < 16; j++) std::cout << " ";
            std::cout << "|\n";
        }
        prevLine = currentLine;
        prevLineValid = (bytesOnLine == 16);
    }
}

//=============================================================================
// Command-Line Options
//=============================================================================

struct Options {
    std::string filename;
    bool showHelp = false;
    bool showVersion = false;
    bool showReloc = false;
    bool showHexdump = false;
    bool showDisasm = false;
    bool showAll = false;
    bool simulate = false;
    uint16_t loadBase = 0x1000;

    bool parse(int argc, char* argv[]) {
        if (argc < 2) { showHelp = true; return true; }
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "-h" || arg == "--help") showHelp = true;
            else if (arg == "-v" || arg == "--version") showVersion = true;
            else if (arg == "-r" || arg == "--relocation") showReloc = true;
            else if (arg == "-x" || arg == "--hexdump") showHexdump = true;
            else if (arg == "-d" || arg == "--disassemble") showDisasm = true;
            else if (arg == "-a" || arg == "--all") showAll = true;
            else if (arg == "--simulate") simulate = true;
            else if (arg.substr(0, 7) == "--base=") {
                std::string baseStr = arg.substr(7);
                try {
                    int baseValue = std::stoi(baseStr, nullptr, 16);
                    if (baseValue < 0 || baseValue > 0xFFFF) {
                        std::cerr << "Error: Base segment value '" << baseStr << "' out of 16-bit range (0000-FFFF)\n";
                        return false;
                    }
                    loadBase = static_cast<uint16_t>(baseValue);
                } catch (const std::invalid_argument&) {
                    std::cerr << "Error: Invalid base segment value '" << baseStr << "'\n";
                    return false;
                } catch (const std::out_of_range&) {
                    std::cerr << "Error: Base segment value '" << baseStr << "' out of range\n";
                    return false;
                }
            } else if (arg[0] != '-' && filename.empty()) {
                filename = arg;
            } else {
                std::cerr << "Error: Unknown option '" << arg << "'\n";
                return false;
            }
        }
        if (showAll) { showReloc = true; showHexdump = true; showDisasm = true; }
        return true;
    }
};

static inline void usage(const char* progname) {
    std::cout << "dumpexe - MS-DOS MZ EXE header analyzer and single-pass disassembler\n\n";
    std::cout << "Usage: " << progname << " [options] <exe_file>\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help          Show this help message and exit\n";
    std::cout << "  -v, --version       Show version information and exit\n";
    std::cout << "  -r, --relocation    Show relocation table (with padding)\n";
    std::cout << "  -x, --hexdump       Show full hex+ASCII dump from entry point to EOF\n";
    std::cout << "  -d, --disassemble   Show disassembly from entry point to EOF\n";
    std::cout << "  -a, --all           Show all sections (relocation + hexdump + disassembly)\n";
    std::cout << "  --simulate          Enable DOS load simulation with register tracking\n";
    std::cout << "  --base=XXXX         Set load base segment (hex, default: 1000h)\n\n";
    std::cout << "If no section options are given, only the EXE header information is displayed.\n";
    std::cout << "Multiple options can be combined, e.g., -r -x for relocations and hexdump.\n\n";
#if !HAS_CAPSTONE
    std::cout << "Note: This build was compiled without Capstone support.\n";
    std::cout << "      Disassembly features (-d, -a) are not available.\n\n";
#endif
}

//=============================================================================
// Disassembly Functions (Capstone)
//=============================================================================

#if HAS_CAPSTONE

static inline void disassemble(const std::vector<uint8_t>& data, size_t offset, uint16_t cs, uint16_t ip) {
    if (offset >= data.size()) {
        std::cout << "\nDisassembly: Entry point is beyond end of file.\n";
        return;
    }
    std::cout << "\n=== Disassembly (from entry point to EOF) ===\n";
    std::cout << "File Offset  Raw Bytes            Instruction\n";
    std::cout << "-----------  -------------------  -----------\n";
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone disassembler\n";
        return;
    }
    size_t codeSize = data.size() - offset;
    const uint8_t* code = data.data() + offset;
    uint64_t address = (cs * 16) + ip;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) {
        std::cerr << "Error: Failed to allocate memory for Capstone instruction\n";
        cs_close(&handle);
        return;
    }
    const uint8_t* codePtr = code;
    size_t sizeRemaining = codeSize;
    uint64_t currentAddress = address;
    while (cs_disasm_iter(handle, &codePtr, &sizeRemaining, &currentAddress, insn)) {
        size_t fileOffset = offset + (insn->address - address);
        std::cout << std::hex << std::nouppercase << std::setw(8) << std::setfill('0')
                  << fileOffset << "h  ";
        size_t bytesToShow = std::min((size_t)insn->size, (size_t)8);
        for (size_t j = 0; j < bytesToShow; j++) {
            std::cout << std::hex << std::nouppercase << std::setw(2) << std::setfill('0')
                      << (int)insn->bytes[j] << " ";
        }
        for (size_t j = bytesToShow; j < 7; j++) std::cout << "   ";
        std::cout << insn->mnemonic;
        if (strlen(insn->op_str) > 0) std::cout << " " << insn->op_str;
        std::cout << "\n";
    }
    cs_free(insn, 1);
    cs_close(&handle);
}

#else

static inline void disassemble(const std::vector<uint8_t>&, size_t, uint16_t, uint16_t) {
    std::cout << "\nDisassembly not available - rebuild with Capstone support\n";
}

#endif // HAS_CAPSTONE

#endif // DUMPEXE_H
