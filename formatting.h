// formatting.h - Formatting and output utility functions
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// All functions are static inline (private API, no external linkage).
// Provides TDUMP-style hex/dec formatting and hexdump output.
// Uses std::format (C++23) for all string construction.

#ifndef FORMATTING_H
#define FORMATTING_H

#include <format>
#include <iostream>
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <cstring>
#include <algorithm>

//=============================================================================
// Formatting and Output Functions
//=============================================================================

/// Format a value as hexadecimal with 'h' suffix (TDUMP style)
/// @param value The numeric value to format
/// @param width Number of hex digits (default 4)
/// @return Formatted string like "1000h" or "0ABCDh"
static inline auto hex_format(uint32_t value, int width = 4) {
    return std::format("{:0{}X}h", value, width);
}

/// Format a value as decimal with trailing dot (TDUMP style)
/// @param value The numeric value to format
/// @param width Minimum field width (default 6)
/// @return Formatted string like "  1024."
static inline auto dec_format(uint32_t value, int width = 6) {
    return std::format("{:{}}.", value, width);
}

/// Print a field in TDUMP style with hex and decimal values
/// Format: "Field Name                          HEXh  ( DEC. )"
/// @param name Field name (left-aligned in 50-char column)
/// @param value Numeric value to display
/// @param hex_width Number of hex digits (default 4)
static inline void print_field(const std::string& name, uint32_t value, int hex_width = 4) {
    std::cout << std::format("{:<50}{:>{}}  ({:>7} )\n",
                             name,
                             hex_format(value, hex_width), hex_width + 1,
                             dec_format(value));
}

/// Print a segment:offset pair (e.g., CS:IP or SS:SP)
/// @param name Descriptive label for the seg:off pair
/// @param seg Segment value (16-bit)
/// @param off Offset value (16-bit)
static inline void print_seg_off(const std::string& name, uint16_t seg, uint16_t off) {
    std::cout << std::format("{}\t\t\t  {:04X}:{:04X}\n", name, seg, off);
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
static inline void print_hex_dump(const std::vector<uint8_t>& data, size_t offset, size_t count,
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
        } else {
            // Line is different from previous, print it normally
            starPrinted = false;

            // Print address (8 hex digits, lowercase)
            std::cout << std::format("{:08x}  ", offset + i);

            // Print hex bytes (16 bytes per line, with space after 8th byte)
            for (size_t j = 0; j < 16; j++) {
                if (j < bytesOnLine) {
                    std::cout << std::format("{:02x} ", currentLine[j]);
                } else {
                    std::cout << "   ";  // Padding for incomplete lines
                }
                if (j == 7) {
                    std::cout << " ";  // Extra space after 8th byte
                }
            }

            // Print ASCII representation
            std::cout << " |";
            for (size_t j = 0; j < bytesOnLine; j++) {
                uint8_t byte = currentLine[j];
                // Print printable ASCII chars, otherwise show dot
                std::cout << (char)((byte >= 32 && byte <= 126) ? byte : '.');
            }
            // Pad ASCII panel to 16 characters for incomplete lines
            for (size_t j = bytesOnLine; j < 16; j++) {
                std::cout << " ";
            }
            std::cout << "|\n";
        }

        // Save current line as previous for next iteration
        prevLine = currentLine;
        prevLineValid = (bytesOnLine == 16);
    }
}

#endif // FORMATTING_H
