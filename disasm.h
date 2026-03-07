// disasm.h - Disassembly functions (Capstone-guarded)
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Provides disassemble() using Capstone when available, and a no-op stub
// otherwise. All functions are static inline.

#ifndef DISASM_H
#define DISASM_H

#include <iostream>
#include <iomanip>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>

// Optional Capstone support - check if headers are available
#if __has_include(<capstone/capstone.h>)
#include <capstone/capstone.h>
#define HAS_CAPSTONE 1
#else
#define HAS_CAPSTONE 0
#endif

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

#endif // DISASM_H
