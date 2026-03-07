// sys_analysis.h - DOS device driver (.SYS) analysis functions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// All functions are static inline. Provides TDUMP-style output for DOS
// device driver headers using the same formatting conventions as analysis.h.

#ifndef SYS_ANALYSIS_H
#define SYS_ANALYSIS_H

#include <iostream>
#include <format>
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "sys.h"
#include "formatting.h"
#include "options.h"
#include "disasm.h"

//=============================================================================
// SYS Header Helpers
//=============================================================================

/// Print the 8-byte character device name, replacing non-printable bytes with '.'
/// @param name 8-byte device name from SYSHeader
static inline void print_sys_device_name(const char name[8]) {
    std::string display;
    display.reserve(8);
    for (int i = 0; i < 8; i++) {
        uint8_t b = static_cast<uint8_t>(name[i]);
        display += (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
    }
    // Trim trailing spaces for readability
    auto last = display.find_last_not_of(' ');
    std::cout << std::format("{:<50}{}\n", "Device Name", (last != std::string::npos ? display.substr(0, last + 1) : display));
}

/// Check if the 7-byte block device signature matches any known driver
/// @param sig 7-byte signature from SYSHeader::block::signature
/// @return Description string if found, empty string_view otherwise
static inline std::string_view check_known_signature(const char sig[7]) {
    for (const auto& entry : KNOWN_SIGNATURES) {
        if (std::memcmp(sig, entry.sig.data(), 7) == 0)
            return entry.desc;
    }
    return {};
}

/// Decode and print device attribute bitfield
/// @param attributes The 16-bit attributes word from SYSHeader
static inline void decode_sys_attributes(uint16_t attributes) {
    bool isChar = (attributes & SYS_ATTR_CHAR_DEVICE) != 0;

    std::cout << std::format("{:<50}{}\n", "Device Type",
                             isChar ? "Character device" : "Block device");

    if (attributes & SYS_ATTR_IOCTL)
        std::cout << std::format("{:<50}{}\n", "  IOCTL", "supported");
    if (attributes & SYS_ATTR_OPEN_CLOSE)
        std::cout << std::format("{:<50}{}\n", "  OPEN/CLOSE/RemovableMedia", "supported (DOS 3.0+)");
    if (attributes & SYS_ATTR_IOCTL_CHECK)
        std::cout << std::format("{:<50}{}\n", "  Generic IOCTL check", "supported (DOS 5.0+)");
    if (attributes & SYS_ATTR_GENERIC_IOCTL)
        std::cout << std::format("{:<50}{}\n", "  Generic IOCTL", "supported (DOS 3.2+)");

    if (isChar) {
        if (attributes & SYS_ATTR_CHAR_OUTPUT_BUSY)
            std::cout << std::format("{:<50}{}\n", "  Output until busy", "supported (DOS 3.0+)");
        if (attributes & SYS_ATTR_SPECIAL)
            std::cout << std::format("{:<50}{}\n", "  Special (INT 29 fast console)", "yes");
        if (attributes & SYS_ATTR_CLOCK)
            std::cout << std::format("{:<50}{}\n", "  CLOCK$ device", "yes");
        if (attributes & SYS_ATTR_NUL)
            std::cout << std::format("{:<50}{}\n", "  NUL device", "yes");
        if (attributes & SYS_ATTR_STDOUT)
            std::cout << std::format("{:<50}{}\n", "  Standard output", "yes");
        if (attributes & SYS_ATTR_STDIN)
            std::cout << std::format("{:<50}{}\n", "  Standard input", "yes");
    } else {
        if (attributes & SYS_ATTR_NON_IBM)
            std::cout << std::format("{:<50}{}\n", "  Non-IBM format", "yes");
        if (attributes & SYS_ATTR_NETWORK)
            std::cout << std::format("{:<50}{}\n", "  Network device (remote)", "yes");
        if (attributes & SYS_ATTR_32BIT_SECTOR)
            std::cout << std::format("{:<50}{}\n", "  32-bit sector addressing", "yes (DOS 3.31+)");
    }
}

/// Print all fields of the SYS device driver header in TDUMP style
/// @param header The parsed SYSHeader struct
/// @param fileSize Total file size in bytes
static inline void print_sys_header(const SYSHeader& header, int64_t fileSize) {
    std::cout << "\n=== DOS Device Driver Header ===\n\n";

    // Next driver pointer
    if (header.next_driver == 0xFFFFFFFF)
        std::cout << std::format("{:<50}{}\n", "Next Driver Pointer", "FFFFFFFFh  (last in chain)");
    else
        std::cout << std::format("{:<50}{}\n", "Next Driver Pointer",
                                 std::format("{:08X}h", header.next_driver));

    // Attributes (raw value)
    print_field("Attributes", header.attributes);
    decode_sys_attributes(header.attributes);

    // Entry points
    print_field("Strategy Entry Point (offset)", header.strategy);
    print_field("Interrupt Entry Point (offset)", header.interrupt);

    bool isChar = (header.attributes & SYS_ATTR_CHAR_DEVICE) != 0;
    if (isChar) {
        print_sys_device_name(header.name);
    } else {
        print_field("Number of Units (drives)", header.block.num_units);

        // Check for known signature
        char sig7[7];
        std::memcpy(sig7, header.block.signature, 7);
        auto desc = check_known_signature(sig7);

        std::string sigStr;
        sigStr.reserve(7);
        for (int i = 0; i < 7; i++) {
            uint8_t b = static_cast<uint8_t>(header.block.signature[i]);
            sigStr += (b >= 32 && b <= 126) ? static_cast<char>(b) : '.';
        }

        if (!desc.empty())
            std::cout << std::format("{:<50}\"{}\"  ({})\n", "Driver Signature", sigStr, desc);
        else
            std::cout << std::format("{:<50}\"{}\"\n", "Driver Signature", sigStr);
    }

    std::cout << std::format("{:<50}{} bytes\n", "File Size", fileSize);
}

//=============================================================================
// Main SYS Analysis Entry Point
//=============================================================================

/// Analyze a DOS device driver (.SYS) file and print its header information.
/// Optionally dumps hex and/or disassembles from strategy/interrupt entry points.
/// @param opts    Parsed command-line options
/// @param data    Full file contents as a byte vector
/// @param fileSize Actual file size in bytes
static inline void analyze_sys(const Options& opts, const std::vector<uint8_t>& data, int64_t fileSize) {
    if (data.size() < sizeof(SYSHeader)) {
        std::cerr << "Error: File is too small to contain a valid SYS device driver header\n";
        return;
    }

    SYSHeader header;
    std::memcpy(&header, data.data(), sizeof(header));

    print_sys_header(header, fileSize);

    if (opts.showHexdump || opts.showAll) {
        const std::size_t dataSize = data.size();
        const std::size_t strategyOffset = static_cast<std::size_t>(header.strategy);
        if (strategyOffset < dataSize) {
            print_hex_dump(data, strategyOffset, dataSize - strategyOffset,
                           "=== Hex Dump from Strategy Entry Point ===");
        }

        const std::size_t interruptOffset = static_cast<std::size_t>(header.interrupt);
        if (interruptOffset < dataSize && interruptOffset != strategyOffset) {
            print_hex_dump(data, interruptOffset, dataSize - interruptOffset,
                           "=== Hex Dump from Interrupt Entry Point ===");
        }
    }

    // Disassembly from strategy entry point
    if (opts.showDisasm || opts.showAll) {
        std::cout << "\n=== Disassembly from Strategy Entry Point ===\n";
        // Strategy offset is from start of driver (file offset 0)
        disassemble(data, header.strategy, 0, header.strategy, opts);

        if (header.interrupt != header.strategy) {
            std::cout << "\n=== Disassembly from Interrupt Entry Point ===\n";
            disassemble(data, header.interrupt, 0, header.interrupt, opts);
        }
    }
}

#endif // SYS_ANALYSIS_H
