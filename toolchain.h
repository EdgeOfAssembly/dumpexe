/**
 * @file toolchain.h
 * @brief Assembler/linker fingerprints: COM-in-EXE, JWASM 1.8, CuteMouse.
 *
 * Ground truth:
 *   - CuteMouse 2.1b4 rebuilt **byte-identical** with JWASM **1.80**
 *     (`bin/jwasm/jwasm-1.8.exe` + wlink + exe2bin + com2exe-style wrap).
 *   - JWASM even-padding uses 0xFC (vs TASM 0x00) — weak encoding hint.
 *
 * Also reports packers and compiler banners. PKLITE, LZEXE, and Microsoft
 * EXEPACK are structural MZ matches (signed CS, entry in-file), not a
 * whole-file scan for "PKLITE", "RB", or "Packed file is corrupt".
 * DIET is the 4-byte stub at file offset 0x1C. LHarc / "LHA ", Turbo C,
 * Turbo C++, Borland C++, Microsoft C, QuickBASIC, Clipper, TopSpeed, and
 * Watcom are literal banners. BRUN alone is not QuickBASIC. The same scan
 * runs for MZ, COM, and SYS. Does not replace Pascal MT+ or Turbo Pascal.
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
    std::string packer;            ///< PKLITE M.mm / LZEXE 0.91|0.90 / Microsoft EXEPACK / DIET / LHarc
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

/// MZ words for the structural packer gates, plus the signed CS:IP file offset.
struct ToolchainMzLoc
{
    bool valid = false;
    uint16_t e_crlc = 0;
    uint16_t e_sp = 0;
    uint16_t e_ip = 0;
    int16_t e_cs = 0; ///< Signed initial CS, matching Deark regCS.
    uint16_t e_lfarlc = 0;
    uint16_t e_ovno = 0;
    int64_t start = 0;  ///< e_cparhdr * 16
    int64_t entry = -1; ///< start + int16(e_cs) * 16 + e_ip
};

/**
 * @brief Read one little-endian uint16 if both bytes are inside the image.
 *
 * @param data File bytes.
 * @param off  Offset of the low byte.
 * @param out  Receives the value when the read is in range. Unchanged otherwise.
 * @return True when @p off and the following byte are inside @p data.
 */
static inline bool toolchain_read_u16(const std::vector<uint8_t>& data,
                                      size_t off,
                                      uint16_t& out)
{
    if (off >= data.size() || data.size() - off < 2)
    {
        return false;
    }
    out = static_cast<uint16_t>(data[off]) |
          static_cast<uint16_t>(static_cast<uint16_t>(data[off + 1]) << 8);
    return true;
}

/**
 * @brief Parse an MZ header and the file offset of CS:IP.
 *
 * CS is a signed int16. The entry is @c e_cparhdr*16 + CS*16 + e_ip, computed
 * in a wide integer. A missing MZ signature, a short header, a negative entry,
 * or an entry past the last file byte leaves @c valid false. This does not
 * scan the file.
 *
 * @param data Image bytes.
 * @return Parsed location. @c valid is false when the entry cannot be used.
 */
static inline ToolchainMzLoc toolchain_mz_loc(const std::vector<uint8_t>& data)
{
    ToolchainMzLoc mz;
    if (data.size() < 0x1C)
    {
        return mz;
    }
    if (data[0] != 0x4D || data[1] != 0x5A)
    {
        return mz;
    }

    uint16_t crlc = 0;
    uint16_t cpar = 0;
    uint16_t sp = 0;
    uint16_t ip = 0;
    uint16_t cs_raw = 0;
    uint16_t lfarlc = 0;
    uint16_t ovno = 0;
    if (!toolchain_read_u16(data, 0x06, crlc) ||
        !toolchain_read_u16(data, 0x08, cpar) ||
        !toolchain_read_u16(data, 0x10, sp) ||
        !toolchain_read_u16(data, 0x14, ip) ||
        !toolchain_read_u16(data, 0x16, cs_raw) ||
        !toolchain_read_u16(data, 0x18, lfarlc) ||
        !toolchain_read_u16(data, 0x1A, ovno))
    {
        return mz;
    }

    const int16_t cs = static_cast<int16_t>(cs_raw);
    const int64_t start = static_cast<int64_t>(cpar) * 16;
    const int64_t entry = start + static_cast<int64_t>(cs) * 16 +
                          static_cast<int64_t>(ip);
    if (entry < 0 || static_cast<uint64_t>(entry) >= data.size())
    {
        return mz;
    }

    mz.valid = true;
    mz.e_crlc = crlc;
    mz.e_sp = sp;
    mz.e_ip = ip;
    mz.e_cs = cs;
    mz.e_lfarlc = lfarlc;
    mz.e_ovno = ovno;
    mz.start = start;
    mz.entry = entry;
    return mz;
}

/**
 * @brief Compare a byte pattern at a file offset.
 *
 * @param data  Image bytes.
 * @param off   Offset of the first pattern byte. Negative offsets do not match.
 * @param bytes Expected bytes. Positions whose mask is '?' are not compared.
 * @param wild  Mask of at least @p n bytes. '?' matches any byte; other
 *              characters require the corresponding @p bytes value.
 * @param n     Number of bytes to compare.
 * @return True when the span is inside @p data and every fixed byte matches.
 */
static inline bool toolchain_match_bytes(const std::vector<uint8_t>& data,
                                         int64_t off,
                                         const uint8_t* bytes,
                                         const char* wild,
                                         size_t n)
{
    if (bytes == nullptr || wild == nullptr || n == 0)
    {
        return false;
    }
    if (off < 0)
    {
        return false;
    }
    const uint64_t begin = static_cast<uint64_t>(off);
    if (n > data.size() || begin > static_cast<uint64_t>(data.size()) - n)
    {
        return false;
    }
    for (size_t i = 0; i < n; ++i)
    {
        if (wild[i] == '\0')
        {
            return false;
        }
        if (wild[i] == '?')
        {
            continue;
        }
        if (data[static_cast<size_t>(begin) + i] != bytes[i])
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Find the EXEPACK epilog just after the entry point.
 *
 * The seven bytes CD 21 B8 FF 4C CD 21 must start at an offset in
 * [entry+200, entry+300). No other file range is examined.
 *
 * @param data  Image bytes.
 * @param entry File offset of the DOS entry point.
 * @return True when the epilog starts in that window and fits in @p data.
 */
static inline bool toolchain_find_exepack_epilog(const std::vector<uint8_t>& data,
                                                 int64_t entry)
{
    static constexpr uint8_t kEpilog[] = {
        0xCD, 0x21, 0xB8, 0xFF, 0x4C, 0xCD, 0x21
    };
    static constexpr char kWild[] = "xxxxxxx";
    static_assert(sizeof(kWild) == sizeof(kEpilog) + 1);

    if (entry < 0)
    {
        return false;
    }
    const int64_t window = entry + 200;
    const int64_t window_end = entry + 300;
    for (int64_t at = window; at < window_end; ++at)
    {
        if (toolchain_match_bytes(data, at, kEpilog, kWild, sizeof(kEpilog)))
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Match a normal PKLITE prologue at the entry point.
 *
 * Deark flag 0x01 only. Beta and Megalite prologues are not recognized.
 *
 * @param data  Image bytes.
 * @param entry File offset of the DOS entry point.
 * @return True when one of the four typical PKLITE prologues matches.
 */
static inline bool toolchain_pklite_prologue(const std::vector<uint8_t>& data,
                                             int64_t entry)
{
    static constexpr uint8_t kV100[] = {
        0xB8, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x8C, 0xDB, 0x03, 0xD8, 0x3B
    };
    static constexpr char kV100Wild[] = "x??x??xxxxx";
    static constexpr uint8_t kV112[] = {
        0xB8, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x05, 0x00, 0x00, 0x3B, 0x06
    };
    static constexpr char kV112Wild[] = "x??x??xxxxx";
    static constexpr uint8_t kV201[] = {
        0x50, 0xB8, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x05, 0x00, 0x00, 0x3B
    };
    static constexpr char kV201Wild[] = "xx??x??xxxx";
    static constexpr uint8_t kUn2[] = {
        0x9C, 0xBA, 0x00, 0x00, 0x2D, 0x00, 0x00, 0x81, 0xE1, 0x00, 0x00, 0x81
    };
    static constexpr char kUn2Wild[] = "xx?xx?xxx?xx";
    static_assert(sizeof(kV100Wild) == sizeof(kV100) + 1);
    static_assert(sizeof(kV112Wild) == sizeof(kV112) + 1);
    static_assert(sizeof(kV201Wild) == sizeof(kV201) + 1);
    static_assert(sizeof(kUn2Wild) == sizeof(kUn2) + 1);

    if (toolchain_match_bytes(data, entry, kV100, kV100Wild, sizeof(kV100)))
    {
        return true;
    }
    if (toolchain_match_bytes(data, entry, kV112, kV112Wild, sizeof(kV112)))
    {
        return true;
    }
    if (toolchain_match_bytes(data, entry, kV201, kV201Wild, sizeof(kV201)))
    {
        return true;
    }
    return toolchain_match_bytes(data, entry, kUn2, kUn2Wild, sizeof(kUn2));
}

/**
 * @brief Format the PKLITE name from the little-endian info word at file 0x1C.
 *
 * The version is the low 12 bits. Major is that value shifted right 8.
 * Minor is the low 8 bits, printed as two digits. High flag bits are ignored,
 * so no /l, /s, /e, or /h suffix is appended.
 *
 * @param info Little-endian word from file offset 0x1C.
 * @return "PKLITE" when the 12-bit version is 0, otherwise "PKLITE M.mm".
 */
static inline std::string toolchain_pklite_name(uint16_t info)
{
    const uint16_t ver = static_cast<uint16_t>(info & 0x0fffu);
    if (ver == 0)
    {
        return "PKLITE";
    }
    const unsigned major = static_cast<unsigned>(ver >> 8);
    const unsigned minor = static_cast<unsigned>(ver & 0xffu);
    return std::format("PKLITE {}.{:02}", major, minor);
}

/**
 * @brief Record structural packer hits and literal compiler banners.
 *
 * PKLITE matches only the typical header (e_ip 256, signed CS -16, e_crlc
 * at most 2, entry at the header end) plus one normal prologue. The version
 * word is the little-endian value at file 0x1C. An ASCII "PKLITE" banner is
 * not sufficient.
 *
 * LZEXE matches LZ91 or LZ09 at file 0x1C, with e_crlc 0, e_lfarlc 0x1C,
 * e_ovno 0, and the bytes 06 0E 1F 8B at the entry or one byte later when
 * that byte is 50 (push ax). LZ91 is "LZEXE 0.91" and LZ09 is "LZEXE 0.90".
 * LZ90 is not matched. An LZ91 or LZ09 marker suppresses a later LHarc banner.
 *
 * Microsoft EXEPACK matches e_crlc 0, e_ip 16 or 18 (not 20), e_sp 0x80,
 * the bytes 52 42 at entry-2, and the epilog CD 21 B8 FF 4C CD 21 starting
 * in [entry+200, entry+300). The English sentence "Packed file is corrupt"
 * is neither required nor sufficient. No stub CRC bypass.
 *
 * DIET remains the 4-byte "diet" or "DIET" at file 0x1C. LHarc and the
 * compiler banners are unchanged literal strings. The first packer name
 * wins; later hits stay in the evidence list.
 *
 * @param fileData Image bytes.
 * @param rep      Report to fill. Existing fields are left intact.
 * @return Nothing. Packer flags, @c rep.packer, and evidence are updated in place.
 */
static inline void toolchain_scan_fingerprints(const std::vector<uint8_t>& fileData,
                                               ToolchainReport& rep)
{
    size_t off = 0;
    const ToolchainMzLoc mz = toolchain_mz_loc(fileData);

    uint16_t pklite_info = 0;
    if (mz.valid &&
        mz.e_ip == 256 &&
        mz.e_cs == -16 &&
        mz.e_crlc <= 2 &&
        mz.entry == mz.start &&
        toolchain_pklite_prologue(fileData, mz.entry) &&
        toolchain_read_u16(fileData, 0x1C, pklite_info))
    {
        const std::string name = toolchain_pklite_name(pklite_info);
        rep.pklite = true;
        if (rep.packer.empty())
        {
            rep.packer = name;
        }
        rep.evidence.push_back(std::format(
            "{} entry at file 0x{:X}, version word at file 0x1C",
            name, static_cast<uint64_t>(mz.entry)));
    }

    static constexpr uint8_t kLzStub[] = {0x06, 0x0E, 0x1F, 0x8B};
    static constexpr char kLzStubWild[] = "xxxx";
    static_assert(sizeof(kLzStubWild) == sizeof(kLzStub) + 1);
    bool lz_marker = false;
    bool lz91 = false;
    bool lz09 = false;
    if (fileData.size() >= 0x20)
    {
        const uint8_t* marker = fileData.data() + 0x1C;
        lz91 = std::memcmp(marker, "LZ91", 4) == 0;
        lz09 = std::memcmp(marker, "LZ09", 4) == 0;
        lz_marker = lz91 || lz09;
    }
    const bool lz_stub_at_entry =
        mz.valid &&
        toolchain_match_bytes(fileData, mz.entry, kLzStub, kLzStubWild, sizeof(kLzStub));
    const bool lz_stub_after_push =
        mz.valid &&
        mz.entry >= 0 &&
        static_cast<uint64_t>(mz.entry) < fileData.size() &&
        fileData[static_cast<size_t>(mz.entry)] == 0x50 &&
        toolchain_match_bytes(fileData, mz.entry + 1, kLzStub, kLzStubWild, sizeof(kLzStub));
    if (mz.valid &&
        mz.e_crlc == 0 &&
        mz.e_lfarlc == 0x001C &&
        mz.e_ovno == 0 &&
        lz_marker &&
        (lz_stub_at_entry || lz_stub_after_push))
    {
        const char* name = lz91 ? "LZEXE 0.91" : "LZEXE 0.90";
        rep.lzexe = true;
        if (rep.packer.empty())
        {
            rep.packer = name;
        }
        rep.evidence.push_back(std::format(
            "{} marker at file 0x1C, entry at file 0x{:X}",
            name, static_cast<uint64_t>(mz.entry)));
    }

    if (fileData.size() >= 0x1C + 4)
    {
        const uint8_t* p = fileData.data() + 0x1C;
        if (std::memcmp(p, "diet", 4) == 0 || std::memcmp(p, "DIET", 4) == 0)
        {
            rep.diet = true;
            if (rep.packer.empty())
            {
                rep.packer = "DIET";
            }
            rep.evidence.push_back("DIET signature at file 0x1C");
        }
    }

    static constexpr uint8_t kRb[] = {0x52, 0x42};
    static constexpr char kRbWild[] = "xx";
    static_assert(sizeof(kRbWild) == sizeof(kRb) + 1);
    if (mz.valid &&
        mz.e_crlc == 0 &&
        (mz.e_ip == 16 || mz.e_ip == 18) &&
        mz.e_sp == 0x0080 &&
        toolchain_match_bytes(fileData, mz.entry - 2, kRb, kRbWild, sizeof(kRb)) &&
        toolchain_find_exepack_epilog(fileData, mz.entry))
    {
        rep.exepack = true;
        if (rep.packer.empty())
        {
            rep.packer = "Microsoft EXEPACK";
        }
        rep.evidence.push_back(std::format(
            "Microsoft EXEPACK entry at file 0x{:X}, RB at file 0x{:X}",
            static_cast<uint64_t>(mz.entry),
            static_cast<uint64_t>(mz.entry - 2)));
    }
    // LZ91/LZ09 at file 0x1C wins over a later "LHA " banner inside the
    // compressed bytes (Gold of the Aztecs INSTALL.EXE).
    if (!lz_marker && toolchain_find_ascii(fileData, "LHarc", off))
    {
        rep.lharc = true;
        if (rep.packer.empty())
            rep.packer = "LHarc";
        rep.evidence.push_back(std::format("LHarc banner at file 0x{:X}", off));
    }
    else if (!lz_marker && toolchain_find_ascii(fileData, "LHA ", off))
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
 * @brief Packer and compiler fingerprints only (no JWASM or COM-in-EXE).
 *
 * COM, SYS, and an MZ already identified as Turbo Pascal use this so a
 * structural packer or compiler banner is reported without replacing
 * Pascal MT+ or Turbo Pascal.
 *
 * @param fileData Image bytes.
 * @return Report. @c detected is true when a packer or compiler hit is recorded.
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
