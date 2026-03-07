// disasm.h - Disassembly functions (Capstone)
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Provides disassemble() using the Capstone disassembly framework.
// Capstone is a mandatory build dependency; include <capstone/capstone.h>
// must resolve at compile time. All functions are static inline.

#ifndef DISASM_H
#define DISASM_H

#include <format>
#include <iostream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <capstone/capstone.h>
#include "options.h"
#include "int_annotate.h"

//=============================================================================
// Disassembly Functions (Capstone)
//=============================================================================

/// Disassemble code using Capstone from entry point to end of file
/// @param data   Vector containing the binary data
/// @param offset Starting offset in the data vector (entry point)
/// @param cs     Initial CS register value
/// @param ip     Initial IP register value
/// @param opts   Parsed CLI options (noIntAnnot flag)
static inline void disassemble(const std::vector<uint8_t>& data, size_t offset,
                                uint16_t cs, uint16_t ip,
                                const Options& opts) {
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

    // Enable detail mode before cs_malloc so detail buffer is allocated
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

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

    // Track last seen AH/AL immediate values for INT annotation.
    // 0x100 (> 0xFF) means "unknown".
    uint32_t lastAh = 0x100;
    uint32_t lastAl = 0x100;

    while (cs_disasm_iter(handle, &codePtr, &sizeRemaining, &currentAddress, insn)) {
        // Print file offset
        size_t fileOffset = offset + (insn->address - address);
        std::cout << std::format("{:08x}h  ", fileOffset);

        // Print raw bytes (up to 8 bytes to keep formatting reasonable)
        size_t bytesToShow = std::min((size_t)insn->size, (size_t)8);
        for (size_t j = 0; j < bytesToShow; j++) {
            std::cout << std::format("{:02x} ", insn->bytes[j]);
        }
        // Pad to 8 bytes for consistent column alignment
        for (size_t j = bytesToShow; j < 8; j++) {
            std::cout << "   ";
        }

        // Print mnemonic and operands
        std::cout << insn->mnemonic;
        if (strlen(insn->op_str) > 0) {
            std::cout << " " << insn->op_str;
        }

        // Track 'mov ah, imm8' or 'mov ax, imm16' to improve INT annotations
        if (insn->detail && strcmp(insn->mnemonic, "mov") == 0 &&
            insn->detail->x86.op_count == 2 &&
            insn->detail->x86.operands[0].type == X86_OP_REG &&
            insn->detail->x86.operands[1].type == X86_OP_IMM) {
            x86_reg dst_reg = insn->detail->x86.operands[0].reg;
            uint32_t imm    = static_cast<uint32_t>(
                                  insn->detail->x86.operands[1].imm);
            if (dst_reg == X86_REG_AH) {
                lastAh = imm & 0xFF;
            } else if (dst_reg == X86_REG_AX) {
                lastAh = (imm >> 8) & 0xFF;
                lastAl = imm & 0xFF;
            } else if (dst_reg == X86_REG_AL) {
                lastAl = imm & 0xFF;
            }
        }

        // Annotate INT instructions
        if (!opts.noIntAnnot && strcmp(insn->mnemonic, "int") == 0 &&
            insn->size >= 2 && insn->bytes[0] == 0xCD) {
            uint8_t int_num = insn->bytes[1];
            uint8_t use_ah = (lastAh <= 0xFF) ? static_cast<uint8_t>(lastAh)
                                               : uint8_t{0xFF};
            uint8_t use_al = (lastAl <= 0xFF) ? static_cast<uint8_t>(lastAl)
                                               : uint8_t{0xFF};
            // Only annotate with a description when AH is known; otherwise
            // just label the interrupt number to avoid false matches.
            std::string annot = (lastAh <= 0xFF)
                ? format_int_annotation(int_num, use_ah, use_al)
                : std::format("; INT {:02X}h", int_num);
            // Pad to a consistent column before the comment
            size_t op_len  = std::strlen(insn->op_str);
            size_t line_len = std::strlen(insn->mnemonic) +
                              (op_len > 0 ? 1 + op_len : 0);
            int pad = std::max(1, 24 - static_cast<int>(line_len));
            std::cout << std::string(pad, ' ') << annot;
            // Reset AH/AL after INT (interrupt may clobber registers)
            lastAh = 0x100;
            lastAl = 0x100;
        }

        std::cout << "\n";
    }

    cs_free(insn, 1);
    cs_close(&handle);
}

#endif // DISASM_H
