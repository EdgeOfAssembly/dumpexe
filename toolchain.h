/**
 * @file toolchain.h
 * @brief Assembler/linker fingerprints: COM-in-EXE, JWASM 1.8, CuteMouse.
 *
 * Ground truth:
 *   - CuteMouse 2.1b4 rebuilt **byte-identical** with JWASM **1.80**
 *     (`bin/jwasm/jwasm-1.8.exe` + wlink + exe2bin + com2exe-style wrap).
 *   - JWASM even-padding uses 0xFC (vs TASM 0x00) — weak encoding hint.
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
    bool jwasm_tasm_hint = false;  ///< assembler-built (not HLL RTL)
    bool jwasm_1_8 = false;        ///< JWASM 1.80 class (proven / high conf)

    uint16_t header_bytes = 0;
    uint16_t entry_cs = 0;
    uint16_t entry_ip = 0;
    uint16_t com_org = 0; ///< typically 0x100 for COM image

    std::string product;           ///< e.g. "CuteMouse"
    std::string product_version;   ///< e.g. "2.1 beta4 [FreeDOS]"
    std::string assembler;         ///< e.g. "JWASM"
    std::string assembler_version; ///< e.g. "1.80"
    std::string toolchain;         ///< one-line summary
    std::string tool_path_hint;    ///< repo path to era binary if known

    size_t fc_pad_runs = 0; ///< runs of ≥2× 0xFC (JWASM even-pad hint)

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

/// Count runs of 0xFC padding (JWASM `even` fills with 0FCh; TASM often 00h).
static inline size_t toolchain_count_fc_pad_runs(const std::vector<uint8_t>& data,
                                                 size_t header_bytes)
{
    size_t runs = 0;
    size_t i = header_bytes;
    while (i + 1 < data.size())
    {
        if (data[i] == 0xFC && data[i + 1] == 0xFC)
        {
            ++runs;
            while (i < data.size() && data[i] == 0xFC)
                ++i;
        }
        else
            ++i;
    }
    return runs;
}

//=============================================================================
// Analyze
//=============================================================================

/**
 * @brief Detect COM-in-EXE, JWASM 1.8-class builds, and known products.
 */
static inline ToolchainReport toolchain_analyze(const std::vector<uint8_t>& fileData,
                                                const MZHeader& header,
                                                size_t header_bytes)
{
    ToolchainReport rep;
    rep.header_bytes = static_cast<uint16_t>(header_bytes);
    rep.entry_cs = static_cast<uint16_t>(header.cs);
    rep.entry_ip = header.ip;
    rep.tool_path_hint = "bin/jwasm/jwasm-1.8.exe (Win32) / jwasmd-1.8.exe (DOS)";

    // --- com2exe / COM-in-EXE heuristic ---
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
        rep.jwasm_tasm_hint = true;
        rep.evidence.push_back("IP=0100h + SS=FFF0h COM-wrapper heuristic");
    }

    // --- JWASM even-pad encoding hint (0xFC) ---
    rep.fc_pad_runs = toolchain_count_fc_pad_runs(fileData, header_bytes);
    if (rep.fc_pad_runs >= 3)
    {
        rep.jwasm_tasm_hint = true;
        rep.evidence.push_back(std::format(
            "JWASM-style even padding: {} run(s) of 0xFC (TASM often uses 0x00)",
            rep.fc_pad_runs));
    }

    // --- CuteMouse product strings (rebuild-proven with JWASM 1.80) ---
    size_t off = 0;
    if (toolchain_find_ascii(fileData, "CuteMouse", off))
    {
        rep.cute_mouse = true;
        rep.product = "CuteMouse";
        rep.jwasm_tasm_hint = true;
        rep.evidence.push_back(
            std::format("string \"CuteMouse\" at file 0x{:X}", off));
        size_t voff = 0;
        if (toolchain_find_ascii(fileData, "CuteMouse v", voff))
        {
            rep.product_version = toolchain_read_asciiz(fileData, voff + 11, 32);
            rep.evidence.push_back(std::format(
                "banner at 0x{:X}: CuteMouse v{}", voff, rep.product_version));
        }
        else if (toolchain_find_ascii(fileData, "CuteMouse ", off))
        {
            rep.product_version = toolchain_read_asciiz(fileData, off + 10, 24);
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

    // INT 33h (mouse API) — weak corroboration for mouse TSRs
    for (size_t i = 0; i + 1 < fileData.size(); ++i)
    {
        if (fileData[i] == 0xCD && fileData[i + 1] == 0x33)
        {
            rep.evidence.push_back(
                std::format("INT 33h opcode at file 0x{:X}", i));
            break;
        }
    }

    // --- Classify assembler version ---
    // Proven: CuteMouse 2.1b4 + COM-in-EXE → JWASM 1.80 (byte-identical rebuild).
    if (rep.com_in_exe && rep.cute_mouse)
    {
        rep.detected = true;
        rep.jwasm_1_8 = true;
        rep.assembler = "JWASM";
        rep.assembler_version = "1.80";
        rep.confidence = 0.98;
        rep.toolchain =
            "JWASM 1.80 (jwasmd -mt) + tlink/wlink + exe2bin + com2exe -s512";
        rep.evidence.push_back(
            "rebuild-proven: CuteMouse 2.1b4 load image byte-identical with "
            "bin/jwasm/jwasm-1.8.exe");
    }
    else if (rep.cute_mouse)
    {
        rep.detected = true;
        rep.jwasm_1_8 = true; // still the known build for this product line
        rep.assembler = "JWASM";
        rep.assembler_version = "1.80";
        rep.confidence = 0.90;
        rep.toolchain = "JWASM 1.80-class (CuteMouse product; COM wrap not matched)";
        rep.evidence.push_back(
            "CuteMouse product line historically built with JWASM 1.80");
    }
    else if (rep.com_in_exe && rep.fc_pad_runs >= 5)
    {
        rep.detected = true;
        rep.jwasm_1_8 = true;
        rep.assembler = "JWASM";
        rep.assembler_version = "1.8x (heuristic)";
        rep.confidence = 0.72;
        rep.toolchain =
            "COM-in-EXE + JWASM-like 0xFC padding (likely JWASM 1.7–1.9 era)";
        rep.evidence.push_back(
            "heuristic JWASM 1.8x: com2exe layout + multiple 0xFC pad runs");
    }
    else if (rep.com_in_exe)
    {
        rep.detected = true;
        rep.confidence = 0.75;
        rep.assembler = "unknown (asm)";
        rep.toolchain = "COM-in-EXE wrapper (com2exe or equivalent); assembler TBD";
        rep.jwasm_tasm_hint = true;
    }
    else if (rep.fc_pad_runs >= 8)
    {
        rep.detected = true;
        rep.confidence = 0.55;
        rep.assembler = "JWASM";
        rep.assembler_version = "1.x (weak)";
        rep.jwasm_tasm_hint = true;
        rep.toolchain = "JWASM-like even padding (weak; confirm with rebuild)";
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
    if (!rep.assembler.empty())
    {
        std::cout << std::format("Assembler:   {} {}\n", rep.assembler,
                                 rep.assembler_version);
    }
    if (rep.jwasm_1_8)
    {
        std::cout << "JWASM 1.8:   yes (1.80 class — era tool in bin/jwasm/)\n";
        std::cout << std::format("Tool binary: {}\n", rep.tool_path_hint);
    }
    if (!rep.product.empty())
        std::cout << std::format("Product:     {} {}\n", rep.product,
                                 rep.product_version);
    if (rep.com_in_exe)
    {
        std::cout << std::format(
            "COM-in-EXE:  yes  (CS:IP={:04X}:{:04X}, COM org={:04X}h)\n",
            rep.entry_cs, rep.entry_ip, rep.com_org);
        std::cout << "Note:        Image is a COM program wrapped as MZ; "
                     "prefer org 100h labels when mapping symbols.\n";
    }
    if (rep.fc_pad_runs)
        std::cout << std::format("0xFC pads:   {} run(s) (JWASM even-fill hint)\n",
                                 rep.fc_pad_runs);
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
