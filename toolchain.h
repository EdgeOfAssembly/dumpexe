/**
 * @file toolchain.h
 * @brief Non-Pascal toolchain fingerprints: COM-in-EXE (com2exe), JWASM/TASM TSR.
 *
 * Ground truth: CuteMouse 2.1b4 (/tmp/cutemouse21b4) — JWASM/TASM sources +
 * bin EXE files built via jwasmd -mt, tlink, exe2bin, com2exe -s512.
 *
 * Default ON (disable with --no-toolchain). Complements pascal_mt.h.
 */
#ifndef TOOLCHAIN_H
#define TOOLCHAIN_H

#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include "exe.h"
#include "options.h"

//=============================================================================
// Report
//=============================================================================

struct ToolchainReport
{
    bool detected = false;
    double confidence = 0.0;

    bool com_in_exe = false;       ///< com2exe-style COM wrapped as MZ
    bool cute_mouse = false;       ///< CuteMouse driver strings
    bool jwasm_tasm_hint = false;  ///< assembler-built (not high-level RTL)

    uint16_t header_bytes = 0;
    uint16_t entry_cs = 0;
    uint16_t entry_ip = 0;
    uint16_t com_org = 0; ///< typically 0x100 for COM image

    std::string product;  ///< e.g. "CuteMouse"
    std::string version;  ///< e.g. "2.1" / "2.1 beta4"
    std::string toolchain;
    ///< e.g. "JWASM/TASM tiny + com2exe (CuteMouse-style)"

    std::vector<std::string> evidence;
};

//=============================================================================
// Helpers
//=============================================================================

static inline bool toolchain_find_ascii(const std::vector<uint8_t>& data,
                                        std::string_view needle,
                                        size_t& out_off)
{
    if (needle.empty() || data.size() < needle.size())
        return false;
    for (size_t i = 0; i + needle.size() <= data.size(); ++i)
    {
        if (std::memcmp(data.data() + i, needle.data(), needle.size()) == 0)
        {
            out_off = i;
            return true;
        }
    }
    return false;
}

static inline std::string toolchain_read_asciiz(const std::vector<uint8_t>& data,
                                                size_t off,
                                                size_t max_len = 64)
{
    std::string s;
    for (size_t i = off; i < data.size() && s.size() < max_len; ++i)
    {
        const uint8_t c = data[i];
        if (c == 0)
            break;
        if (c < 32 || c >= 127)
            break;
        s.push_back(static_cast<char>(c));
    }
    return s;
}

//=============================================================================
// Analyze
//=============================================================================

/**
 * @brief Detect COM-in-EXE wrappers and known assembler-built products.
 */
static inline ToolchainReport toolchain_analyze(const std::vector<uint8_t>& fileData,
                                                const MZHeader& header,
                                                size_t header_bytes)
{
    ToolchainReport rep;
    rep.header_bytes = static_cast<uint16_t>(header_bytes);
    rep.entry_cs = static_cast<uint16_t>(header.cs);
    rep.entry_ip = header.ip;

    // --- com2exe / COM-in-EXE heuristic ---
    // Classic: CS=FFF0h, IP=0100h, small header (0x20), often 0 relocs.
    // Load math: (int16)CS*16+IP == 0 → entry at start of load image, COM org 100h.
    const bool cs_fff0 = (static_cast<uint16_t>(header.cs) == 0xFFF0);
    const bool ip_100 = (header.ip == 0x0100);
    const bool small_hdr = (header_bytes > 0 && header_bytes <= 0x40);
    const bool few_relocs = (header.num_reloc == 0);

    if (cs_fff0 && ip_100 && small_hdr)
    {
        rep.com_in_exe = true;
        rep.com_org = 0x100;
        rep.jwasm_tasm_hint = true;
        rep.evidence.push_back(
            "MZ CS:IP = FFF0:0100 (COM-in-EXE / com2exe-style load)");
        if (few_relocs)
            rep.evidence.push_back("zero relocation entries (typical com2exe)");
        if (header_bytes == 0x20)
            rep.evidence.push_back("32-byte MZ header (com2exe -s512 style)");
    }
    else if (ip_100 && small_hdr && few_relocs &&
             static_cast<uint16_t>(header.ss) == 0xFFF0u)
    {
        rep.com_in_exe = true;
        rep.com_org = 0x100;
        rep.evidence.push_back("IP=0100h + SS=FFF0h COM-wrapper heuristic");
    }

    // --- CuteMouse product strings (ground truth: cutemouse 2.1 beta4) ---
    size_t off = 0;
    if (toolchain_find_ascii(fileData, "CuteMouse", off))
    {
        rep.cute_mouse = true;
        rep.product = "CuteMouse";
        rep.jwasm_tasm_hint = true;
        rep.evidence.push_back(
            std::format("string \"CuteMouse\" at file 0x{:X}", off));
        // Prefer full banner
        size_t voff = 0;
        if (toolchain_find_ascii(fileData, "CuteMouse v", voff))
        {
            rep.version = toolchain_read_asciiz(fileData, voff + 11, 24);
            rep.evidence.push_back(
                std::format("banner at 0x{:X}: CuteMouse v{}", voff, rep.version));
        }
        else if (toolchain_find_ascii(fileData, "CuteMouse ", off))
        {
            rep.version = toolchain_read_asciiz(fileData, off + 10, 16);
        }
    }
    if (toolchain_find_ascii(fileData, "CTMOUSE", off))
    {
        rep.evidence.push_back(std::format("string \"CTMOUSE\" at file 0x{:X}", off));
        if (!rep.cute_mouse)
        {
            rep.cute_mouse = true;
            rep.product = "CuteMouse";
        }
    }

    // INT 33h mouse API is expected in mouse drivers (weak hint only)
    // Look for CD 33 sequence
    for (size_t i = 0; i + 1 < fileData.size(); ++i)
    {
        if (fileData[i] == 0xCD && fileData[i + 1] == 0x33)
        {
            rep.evidence.push_back(
                std::format("INT 33h opcode at file 0x{:X}", i));
            break;
        }
    }

    // Aggregate
    if (rep.com_in_exe && rep.cute_mouse)
    {
        rep.detected = true;
        rep.confidence = 0.95;
        rep.toolchain =
            "JWASM/TASM tiny model + exe2bin + com2exe (CuteMouse build)";
    }
    else if (rep.cute_mouse)
    {
        rep.detected = true;
        rep.confidence = 0.85;
        rep.toolchain = "Assembler-built DOS mouse driver (CuteMouse)";
    }
    else if (rep.com_in_exe)
    {
        rep.detected = true;
        rep.confidence = 0.75;
        rep.toolchain = "COM-in-EXE wrapper (com2exe or equivalent)";
    }

    return rep;
}

static inline void toolchain_print_report(const ToolchainReport& rep)
{
    if (!rep.detected)
        return;
    std::cout << "\n=== Toolchain (auto) ===\n";
    std::cout << std::format("Confidence:  {:.0f}%\n", rep.confidence * 100.0);
    if (!rep.toolchain.empty())
        std::cout << std::format("Toolchain:   {}\n", rep.toolchain);
    if (!rep.product.empty())
        std::cout << std::format("Product:     {} {}\n", rep.product, rep.version);
    if (rep.com_in_exe)
    {
        std::cout << std::format(
            "COM-in-EXE:  yes  (CS:IP={:04X}:{:04X}, COM org={:04X}h)\n",
            rep.entry_cs, rep.entry_ip, rep.com_org);
        std::cout << "Note:        Image is a COM program wrapped as MZ; "
                     "prefer org 100h labels when mapping symbols.\n";
    }
    if (rep.jwasm_tasm_hint && !rep.cute_mouse)
        std::cout << "Assembler:   JWASM/TASM-style (heuristic)\n";
    if (!rep.evidence.empty())
    {
        std::cout << "Evidence:\n";
        for (const auto& e : rep.evidence)
            std::cout << "  - " << e << "\n";
    }
    std::cout << "=== End Toolchain ===\n";
}

static inline void dump_toolchain(const Options& opts,
                                  const std::vector<uint8_t>& fileData,
                                  const MZHeader& header,
                                  size_t header_bytes)
{
    if (!opts.toolchainDetect)
        return;
    const ToolchainReport rep =
        toolchain_analyze(fileData, header, header_bytes);
    if (!opts.jsonOut)
        toolchain_print_report(rep);
}

#endif // TOOLCHAIN_H
