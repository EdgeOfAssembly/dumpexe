/**
 * @file toolchain.h
 * @brief Assembler/linker fingerprints: COM-in-EXE, JWASM 1.8, CuteMouse.
 *
 * Ground truth:
 *   - CuteMouse 2.1b4 rebuilt **byte-identical** with JWASM **1.80**
 *     (`bin/jwasm/jwasm-1.8.exe` + wlink + exe2bin + com2exe-style wrap).
 *   - JWASM even-padding uses 0xFC (vs TASM 0x00) — weak encoding hint.
 *
 * Also reports packer/compiler banners when the characteristic string is
 * present: PKLITE, LZEXE (LZ91/LZ09 at 0x1C), Microsoft EXEPACK
 * ("Packed file is corrupt"), DIET (signature at 0x1C, file(1) Magdir/msdos),
 * LHarc / "LHA ", Turbo C, Turbo C++, Borland C++, Microsoft C, QuickBASIC,
 * Clipper, TopSpeed, Watcom. BRUN alone is not QuickBASIC. No guessed
 * binary signatures. The same string scan runs for MZ, COM, and SYS.
 * Does not replace Pascal MT+ or Turbo Pascal reports.
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

    bool pklite = false;
    bool lzexe = false;
    bool exepack = false;
    bool diet = false;
    bool lharc = false;
    std::string packer;            ///< PKLITE / LZEXE / Microsoft EXEPACK / DIET / LHarc
    std::string compiler_fp;       ///< Turbo C / Borland C++ / Microsoft C / …

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
// Packer / compiler fingerprints
//=============================================================================

/**
 * @brief Record packer and compiler fingerprints from known strings.
 *
 * LZEXE and DIET are the 4-byte stubs at file offset 0x1C (file(1)
 * Magdir/msdos: "LZ91", "LZ09", "diet"). PKLITE is the ASCII banner
 * "PKLITE" / "PKLITE Copr." anywhere in the image. Microsoft EXEPACK is the
 * stub text "Packed file is corrupt" (the bare "RB" byte pattern is not
 * used). Compiler hits are literal banners only: "Turbo C++", "Borland C++",
 * "Turbo-C - Copyright", "MS Run-Time Library", "QuickBASIC", "Clipper",
 * "TopSpeed", "Watcom". LHarc is the literal "LHarc" or "LHA " (trailing
 * space). "BRUN" alone is ignored. The first packer and the first compiler
 * name win; later banners are still recorded as evidence.
 *
 * @param fileData Image bytes.
 * @param rep      Report to fill. Existing fields are left intact.
 */
static inline void toolchain_scan_fingerprints(const std::vector<uint8_t>& fileData,
                                               ToolchainReport& rep)
{
    size_t off = 0;
    if (toolchain_find_ascii(fileData, "PKLITE", off))
    {
        rep.pklite = true;
        rep.packer = "PKLITE";
        rep.evidence.push_back(
            std::format("PKLITE banner at file 0x{:X}", off));
    }
    if (fileData.size() >= 0x1C + 4)
    {
        const uint8_t* p = fileData.data() + 0x1C;
        if (std::memcmp(p, "LZ91", 4) == 0 || std::memcmp(p, "LZ09", 4) == 0)
        {
            rep.lzexe = true;
            if (rep.packer.empty())
                rep.packer = "LZEXE";
            rep.evidence.push_back(std::format(
                "LZEXE signature \"{}{}{}{}\" at file 0x1C",
                static_cast<char>(p[0]), static_cast<char>(p[1]),
                static_cast<char>(p[2]), static_cast<char>(p[3])));
        }
        if (std::memcmp(p, "diet", 4) == 0 || std::memcmp(p, "DIET", 4) == 0)
        {
            rep.diet = true;
            if (rep.packer.empty())
                rep.packer = "DIET";
            rep.evidence.push_back("DIET signature at file 0x1C");
        }
    }
    if (toolchain_find_ascii(fileData, "Packed file is corrupt", off))
    {
        rep.exepack = true;
        if (rep.packer.empty())
            rep.packer = "Microsoft EXEPACK";
        rep.evidence.push_back(std::format(
            "EXEPACK stub \"Packed file is corrupt\" at file 0x{:X}", off));
    }
    if (toolchain_find_ascii(fileData, "LHarc", off))
    {
        rep.lharc = true;
        if (rep.packer.empty())
            rep.packer = "LHarc";
        rep.evidence.push_back(std::format("LHarc banner at file 0x{:X}", off));
    }
    else if (toolchain_find_ascii(fileData, "LHA ", off))
    {
        rep.lharc = true;
        if (rep.packer.empty())
            rep.packer = "LHarc";
        rep.evidence.push_back(std::format("LHA banner at file 0x{:X}", off));
    }

    struct CompilerBanner
    {
        const char* needle;
        const char* name;
    };
    static const CompilerBanner kCompilers[] = {
        {"Turbo C++", "Turbo C++"},
        {"Borland C++", "Borland C++"},
        {"Turbo-C - Copyright", "Turbo C"},
        {"MS Run-Time Library", "Microsoft C"},
        {"QuickBASIC", "QuickBASIC"},
        {"Clipper", "Clipper"},
        {"TopSpeed", "TopSpeed"},
        {"Watcom", "Watcom"},
    };
    for (const CompilerBanner& b : kCompilers)
    {
        if (!toolchain_find_ascii(fileData, b.needle, off))
            continue;
        if (rep.compiler_fp.empty())
            rep.compiler_fp = b.name;
        rep.evidence.push_back(std::format(
            "{} banner \"{}\" at file 0x{:X}", b.name, b.needle, off));
    }
}

/// True when a packer banner or stub signature was recorded.
static inline bool toolchain_is_packed(const ToolchainReport& rep)
{
    return rep.pklite || rep.lzexe || rep.exepack || rep.diet || rep.lharc;
}

/**
 * @brief Mark the report detected from packer/compiler banners alone.
 *
 * Leaves an already-detected JWASM / COM-in-EXE classification in place.
 * Clears the JWASM tool-path hint when the hit is a packer or compiler
 * and not the CuteMouse JWASM rebuild.
 *
 * @param rep Report after @c toolchain_scan_fingerprints.
 */
static inline void toolchain_finish_fingerprints(ToolchainReport& rep)
{
    const bool packed = toolchain_is_packed(rep);
    if (!rep.detected && (packed || !rep.compiler_fp.empty()))
    {
        rep.detected = true;
        rep.confidence = packed ? 0.90 : 0.86;
        if (!rep.packer.empty() && !rep.compiler_fp.empty())
            rep.toolchain = rep.packer + " / " + rep.compiler_fp;
        else if (!rep.packer.empty())
            rep.toolchain = rep.packer + " packed executable";
        else
            rep.toolchain = rep.compiler_fp;
    }
    if (!rep.jwasm_1_8 && (packed || !rep.compiler_fp.empty()))
        rep.tool_path_hint.clear();
}

/**
 * @brief String fingerprints only (no MZ layout or JWASM heuristics).
 *
 * COM, SYS, and an MZ already identified as Turbo Pascal use this so a
 * banner is reported without replacing Pascal MT+ or Turbo Pascal.
 *
 * @param fileData Image bytes.
 * @return Report. @c detected is true when a packer or compiler banner hit.
 */
static inline ToolchainReport toolchain_fingerprints_only(
    const std::vector<uint8_t>& fileData)
{
    ToolchainReport rep;
    toolchain_scan_fingerprints(fileData, rep);
    toolchain_finish_fingerprints(rep);
    return rep;
}

//=============================================================================
// Analyze
//=============================================================================

/**
 * @brief Detect COM-in-EXE, JWASM 1.8-class builds, packers, and RTL banners.
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

    toolchain_scan_fingerprints(fileData, rep);
    const bool packed = toolchain_is_packed(rep);

    // --- com2exe / COM-in-EXE heuristic ---
    // PKLITE and other packers also use CS=FFF0; do not call those com2exe.
    const bool cs_fff0 = (static_cast<uint16_t>(header.cs) == 0xFFF0);
    const bool ip_100 = (header.ip == 0x0100);
    const bool small_hdr = (header_bytes > 0 && header_bytes <= 0x40);
    const bool few_relocs = (header.num_reloc == 0);

    if (!packed && cs_fff0 && ip_100 && small_hdr)
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
    else if (!packed && ip_100 && small_hdr && few_relocs &&
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
    // NOTE: do NOT claim JWASM from 0xFC padding alone — Turbo Pascal EXEs
    // often contain many 0xFC bytes and false-positive (see Catacomb/TP5.5).

    // The JWASM path hint is only evidence for that rebuild, not for packers.
    toolchain_finish_fingerprints(rep);

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
    if (!rep.packer.empty())
        std::cout << std::format("Packer:      {}\n", rep.packer);
    if (!rep.compiler_fp.empty())
        std::cout << std::format("Compiler:    {}\n", rep.compiler_fp);
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
