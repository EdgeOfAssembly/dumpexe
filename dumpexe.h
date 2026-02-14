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

/// Packed MZ EXE header structure (28 bytes minimum)
/// This structure represents the standard MS-DOS executable format header.
/// All multi-byte fields are stored in little-endian byte order.
#pragma pack(push,1)
struct MZHeader {
    uint16_t signature;         ///< 0x00: "MZ" signature (0x5A4D in little-endian)
    uint16_t final_len;         ///< 0x02: Bytes in last 512-byte page (0 = full page)
    uint16_t num_blocks;        ///< 0x04: Number of 512-byte pages in file
    uint16_t num_reloc;         ///< 0x06: Number of relocation entries
    uint16_t header_size;       ///< 0x08: Header size in 16-byte paragraphs
    uint16_t mem_extra;         ///< 0x0A: Minimum extra memory needed (paragraphs)
    uint16_t mem_max;           ///< 0x0C: Maximum extra memory wanted (paragraphs, 0xFFFF = all)
    int16_t  ss;                ///< 0x0E: Initial SS register value (relative to load segment)
    uint16_t sp;                ///< 0x10: Initial SP register value
    uint16_t checksum;          ///< 0x12: File checksum (rarely used)
    uint16_t ip;                ///< 0x14: Initial IP register value (entry point offset)
    int16_t  cs;                ///< 0x16: Initial CS register value (relative to load segment)
    uint16_t off_reloc;         ///< 0x18: File offset to relocation table
    uint16_t overlay_index;     ///< 0x1A: Overlay number (0 for main program)
};
#pragma pack(pop)

/// Relocation table entry (4 bytes)
/// Each entry specifies a location in the image that needs to be adjusted
/// by adding the actual load segment when the program is loaded into memory.
#pragma pack(push,1)
struct RelocEntry {
    uint16_t offset;            ///< Offset within segment
    uint16_t segment;           ///< Segment value (relative to start of image)
};
#pragma pack(pop)

//=============================================================================
// 16-bit x86 CPU Register State
//=============================================================================
// These structures define the complete register state for a 16-bit x86 CPU,
// used during simulation and register tracing. The unions allow accessing
// 16-bit registers and their 8-bit high/low components.

/// AX register with byte-level access (AL/AH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit AX register
    struct {
        uint8_t lo;             ///< AL - low byte
        uint8_t hi;             ///< AH - high byte
    };
} __AX__;
#pragma pack(pop)

#define AX __AX__.value         ///< Access full 16-bit AX register
#define AH __AX__.hi            ///< Access high byte (AH)
#define AL __AX__.lo            ///< Access low byte (AL)

/// BX register with byte-level access (BL/BH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit BX register
    struct {
        uint8_t lo;             ///< BL - low byte
        uint8_t hi;             ///< BH - high byte
    };
} __BX__;
#pragma pack(pop)

#define BX __BX__.value         ///< Access full 16-bit BX register
#define BH __BX__.hi            ///< Access high byte (BH)
#define BL __BX__.lo            ///< Access low byte (BL)

/// CX register with byte-level access (CL/CH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit CX register
    struct {
        uint8_t lo;             ///< CL - low byte
        uint8_t hi;             ///< CH - high byte
    };
} __CX__;
#pragma pack(pop)

#define CX __CX__.value         ///< Access full 16-bit CX register
#define CH __CX__.hi            ///< Access high byte (CH)
#define CL __CX__.lo            ///< Access low byte (CL)

/// DX register with byte-level access (DL/DH)
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< 16-bit DX register
    struct {
        uint8_t lo;             ///< DL - low byte
        uint8_t hi;             ///< DH - high byte
    };
} __DX__;
#pragma pack(pop)

#define DX __DX__.value         ///< Access full 16-bit DX register
#define DH __DX__.hi            ///< Access high byte (DH)
#define DL __DX__.lo            ///< Access low byte (DL)

/// Segment registers - 16-bit only, no byte access
inline uint16_t CS = 0;                ///< Code Segment
inline uint16_t DS = 0;                ///< Data Segment
inline uint16_t ES = 0;                ///< Extra Segment
inline uint16_t SS = 0;                ///< Stack Segment

/// Pointer and index registers - 16-bit only
inline uint16_t IP = 0;                ///< Instruction Pointer
inline uint16_t BP = 0;                ///< Base Pointer
inline uint16_t SP = 0;                ///< Stack Pointer
inline uint16_t DI = 0;                ///< Destination Index
inline uint16_t SI = 0;                ///< Source Index

/// CPU FLAGS register with bitfield access
/// The FLAGS register contains status and control bits set by various CPU operations
#pragma pack(push,1)
inline union {
    uint16_t value;             ///< Full 16-bit FLAGS register value
    struct {
        unsigned CF   : 1;      ///< Bit 0: Carry Flag
        unsigned _r1  : 1;      ///< Bit 1: Reserved (always 1)
        unsigned PF   : 1;      ///< Bit 2: Parity Flag
        unsigned _r2  : 1;      ///< Bit 3: Reserved
        unsigned AF   : 1;      ///< Bit 4: Auxiliary Carry Flag
        unsigned _r3  : 1;      ///< Bit 5: Reserved
        unsigned ZF   : 1;      ///< Bit 6: Zero Flag
        unsigned SF   : 1;      ///< Bit 7: Sign Flag
        unsigned TF   : 1;      ///< Bit 8: Trap Flag (single-step)
        unsigned IF   : 1;      ///< Bit 9: Interrupt Enable Flag
        unsigned DF   : 1;      ///< Bit 10: Direction Flag
        unsigned OF   : 1;      ///< Bit 11: Overflow Flag
        unsigned IOPL : 2;      ///< Bits 12-13: I/O Privilege Level (286+)
        unsigned NT   : 1;      ///< Bit 14: Nested Task Flag (286+)
        unsigned _r4  : 1;      ///< Bit 15: Reserved
    };
} __FLAGS__;
#pragma pack(pop)

#define FLAGS __FLAGS__.value   ///< Access full 16-bit FLAGS register
#define CF __FLAGS__.CF         ///< Access Carry Flag
#define PF __FLAGS__.PF         ///< Access Parity Flag
#define AF __FLAGS__.AF         ///< Access Auxiliary Carry Flag
#define ZF __FLAGS__.ZF         ///< Access Zero Flag
#define SF __FLAGS__.SF         ///< Access Sign Flag
#define TF __FLAGS__.TF         ///< Access Trap Flag
#define IF __FLAGS__.IF         ///< Access Interrupt Enable Flag
#define DF __FLAGS__.DF         ///< Access Direction Flag
#define OF __FLAGS__.OF         ///< Access Overflow Flag
#define IOPL __FLAGS__.IOPL     ///< Access I/O Privilege Level
#define NT __FLAGS__.NT         ///< Access Nested Task Flag

//=============================================================================
// Formatting and Output Functions
//=============================================================================

/// Format a value as hexadecimal with 'h' suffix (TDUMP style)
/// @param value The numeric value to format
/// @param width Number of hex digits (default 4)
/// @return Formatted string like "1000h" or "0ABCDh"
static inline std::string hexFormat(uint32_t value, int width = 4) {
    std::ostringstream oss;
    oss << std::uppercase << std::setfill('0') << std::setw(width) << std::hex << value << "h";
    return oss.str();
}

/// Format a value as decimal with trailing dot (TDUMP style)
/// @param value The numeric value to format
/// @param width Minimum field width (default 6)
/// @return Formatted string like "  1024."
static inline std::string decFormat(uint32_t value, int width = 6) {
    std::ostringstream oss;
    oss << std::setw(width) << std::dec << value << ".";
    return oss.str();
}

/// Print a field in TDUMP style with hex and decimal values
/// Format: "Field Name                          HEXh  ( DEC. )"
/// @param name Field name (left-aligned in 50-char column)
/// @param value Numeric value to display
/// @param hexWidth Number of hex digits (default 4)
static inline void printField(const std::string& name, uint32_t value, int hexWidth = 4) {
    const int nameWidth = 50;
    std::cout << std::left << std::setw(nameWidth) << name 
              << std::right << std::setw(hexWidth + 1) << hexFormat(value, hexWidth)
              << "  (" << std::right << std::setw(7) << decFormat(value) << " )\n";
}

/// Print a segment:offset pair (e.g., CS:IP or SS:SP)
/// @param name Descriptive label for the seg:off pair
/// @param seg Segment value (16-bit)
/// @param off Offset value (16-bit)
static inline void printSegOff(const std::string& name, uint16_t seg, uint16_t off) {
    std::cout << name << "\t\t\t  " 
              << std::uppercase << std::setfill('0') << std::hex
              << std::setw(4) << seg << ":" << std::setw(4) << off << "\n";
}

/// Print hex dump of data in canonical hexdump -C format with zero-compression
/// This function displays binary data in a two-panel format: hex bytes on the left,
/// ASCII representation on the right. Consecutive identical lines are compressed
/// to a single '*' character (like hexdump -C does).
///
/// @param data Vector containing the binary data
/// @param offset Starting offset in the data vector
/// @param count Number of bytes to dump
/// @param title Optional title to print before the dump
static inline void printHexDump(const std::vector<uint8_t>& data, size_t offset, size_t count, 
                  const std::string& title = "") {
    if (count == 0) return;
    
    // If the offset is past the end of the data, there is nothing to dump.
    if (offset >= data.size()) return;
    
    if (!title.empty()) {
        std::cout << "\n" << title << "\n";
    }
    
    size_t maxCount = data.size() - offset;
    count = std::min(count, maxCount);
    
    // For zero-compression: track previous line and whether we've printed the '*'
    std::array<uint8_t, 16> prevLine = {};
    bool prevLineValid = false;
    bool starPrinted = false;
    
    for (size_t i = 0; i < count; i += 16) {
        // Read current line (up to 16 bytes)
        std::array<uint8_t, 16> currentLine = {};
        size_t bytesOnLine = std::min((size_t)16, count - i);
        for (size_t j = 0; j < bytesOnLine; j++) {
            currentLine[j] = data[offset + i + j];
        }
        
        // Check if this line is identical to the previous line
        // (only for complete 16-byte lines to match hexdump -C behavior)
        bool isRepeat = false;
        if (prevLineValid && bytesOnLine == 16) {
            isRepeat = (std::memcmp(currentLine.data(), prevLine.data(), 16) == 0);
        }
        
        if (isRepeat) {
            // Line repeats - print '*' only once
            if (!starPrinted) {
                std::cout << "*\n";
                starPrinted = true;
            }
            // Skip printing the actual line content
        } else {
            // Line is different from previous, print it normally
            starPrinted = false;
            
            // Print address (8 hex digits, lowercase)
            std::cout << std::hex << std::nouppercase << std::setw(8) << std::setfill('0') 
                      << (offset + i);
            
            // Print hex bytes (16 bytes per line, with space after 8th byte)
            std::cout << "  ";
            for (size_t j = 0; j < 16; j++) {
                if (j < bytesOnLine) {
                    std::cout << std::hex << std::nouppercase << std::setw(2) << std::setfill('0') 
                              << (int)currentLine[j];
                } else {
                    std::cout << "  ";  // Padding for incomplete lines
                }
                std::cout << " ";
                if (j == 7) {
                    std::cout << " ";  // Extra space after 8th byte
                }
            }
            
            // Print ASCII representation
            std::cout << " |";
            for (size_t j = 0; j < bytesOnLine; j++) {
                uint8_t byte = currentLine[j];
                // Print printable ASCII chars, otherwise show dot
                if (byte >= 32 && byte <= 126) {
                    std::cout << (char)byte;
                } else {
                    std::cout << ".";
                }
            }
            // Pad ASCII panel to 16 characters for incomplete lines
            for (size_t j = bytesOnLine; j < 16; j++) {
                std::cout << " ";
            }
            std::cout << "|";
            
            std::cout << "\n";
        }
        
        // Save current line as previous for next iteration
        prevLine = currentLine;
        prevLineValid = (bytesOnLine == 16);
    }
}

//=============================================================================
// Command-Line Options
//=============================================================================

/// Structure holding all command-line options and flags
struct Options {
    std::string filename;       ///< EXE file to analyze
    bool showHelp = false;      ///< -h, --help
    bool showVersion = false;   ///< -v, --version
    bool showReloc = false;     ///< -r, --relocation
    bool showHexdump = false;   ///< -x, --hexdump
    bool showDisasm = false;    ///< -d, --disassemble
    bool showAll = false;       ///< -a, --all
    bool simulate = false;      ///< --simulate
    uint16_t loadBase = 0x1000; ///< --base=XXXX (default: 1000h, after PSP)
    
    /// Parse command-line arguments
    /// @param argc Argument count from main()
    /// @param argv Argument vector from main()
    /// @return true if parsing succeeded, false on error
    bool parse(int argc, char* argv[]) {
        if (argc < 2) {
            // No arguments - print usage
            showHelp = true;
            return true;
        }
        
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            
            if (arg == "-h" || arg == "--help") {
                showHelp = true;
            } else if (arg == "-v" || arg == "--version") {
                showVersion = true;
            } else if (arg == "-r" || arg == "--relocation") {
                showReloc = true;
            } else if (arg == "-x" || arg == "--hexdump") {
                showHexdump = true;
            } else if (arg == "-d" || arg == "--disassemble") {
                showDisasm = true;
            } else if (arg == "-a" || arg == "--all") {
                showAll = true;
            } else if (arg == "--simulate") {
                simulate = true;
            } else if (arg.substr(0, 7) == "--base=") {
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
                    std::cerr << "Expected hexadecimal value (e.g., 1000, 2000, ABCD)\n";
                    return false;
                } catch (const std::out_of_range&) {
                    std::cerr << "Error: Base segment value '" << baseStr << "' out of range\n";
                    return false;
                }
            } else if (arg[0] != '-' && filename.empty()) {
                // Not a flag, assume it's the filename
                filename = arg;
            } else {
                std::cerr << "Error: Unknown option '" << arg << "'\n";
                return false;
            }
        }
        
        // If --all is set, enable all display sections
        if (showAll) {
            showReloc = true;
            showHexdump = true;
            showDisasm = true;
        }
        
        return true;
    }
};

/// Print usage information
static inline void usage(const char* progname) {
    std::cout << "dumpexe - MS-DOS MZ EXE header analyzer and disassembler\n\n";
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

/// Disassemble code using Capstone from entry point to end of file
/// @param data Vector containing the binary data
/// @param offset Starting offset in the data vector (entry point)
/// @param cs Initial CS register value
/// @param ip Initial IP register value
static inline void disassemble(const std::vector<uint8_t>& data, size_t offset, uint16_t cs, uint16_t ip) {
    if (offset >= data.size()) {
        std::cout << "\nDisassembly: Entry point is beyond end of file.\n";
        return;
    }
    
    std::cout << "\n=== Disassembly (from entry point to EOF) ===\n";
    std::cout << "File Offset  Raw Bytes            Instruction\n";
    std::cout << "-----------  -------------------  -----------\n";
    
    csh handle;
    
    // Initialize Capstone for x86 16-bit mode
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK) {
        std::cerr << "Error: Failed to initialize Capstone disassembler\n";
        return;
    }
    
    // Use cs_disasm_iter for memory-efficient streaming disassembly
    size_t codeSize = data.size() - offset;
    const uint8_t* code = data.data() + offset;
    uint64_t address = (cs * 16) + ip;  // Linear address
    
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
        // Print file offset
        size_t fileOffset = offset + (insn->address - address);
        std::cout << std::hex << std::nouppercase << std::setw(8) << std::setfill('0')
                  << fileOffset << "h  ";
        
        // Print raw bytes (up to 8 bytes to keep formatting reasonable)
        size_t bytesToShow = std::min((size_t)insn->size, (size_t)8);
        for (size_t j = 0; j < bytesToShow; j++) {
            std::cout << std::hex << std::nouppercase << std::setw(2) << std::setfill('0')
                      << (int)insn->bytes[j] << " ";
        }
        // Pad to 20 characters
        for (size_t j = bytesToShow; j < 7; j++) {
            std::cout << "   ";
        }
        
        // Print mnemonic and operands
        std::cout << insn->mnemonic;
        if (strlen(insn->op_str) > 0) {
            std::cout << " " << insn->op_str;
        }
        std::cout << "\n";
    }
    
    cs_free(insn, 1);
    cs_close(&handle);
}

#else

/// Stub disassemble function when Capstone is not available
static inline void disassemble(const std::vector<uint8_t>&, size_t, uint16_t, uint16_t) {
    std::cout << "\nDisassembly not available - rebuild with Capstone support\n";
}

#endif // HAS_CAPSTONE

#endif // DUMPEXE_H
