/**
 * @file pascal_mt.h
 * @brief Pascal MT+86 3.1.1 (Digital Research) detection and annotation for dumpexe.
 *
 * Patterns derived from MT+86 3.1.1 RTL sources (INIPC.I86, PASLIB, OVLMGRPC.I86)
 * and validated on ICON: Quest for the Ring (ICON.EXE + ICON0/1/2.OVL).
 *
 * Default: analysis ON for every MZ/COM image; print a report only when signatures
 * match. Disable with --no-pascal-mt (cli-design: feature on → only --no-*).
 */
#ifndef PASCAL_MT_H
#define PASCAL_MT_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "options.h"

//=============================================================================
// Types
//=============================================================================

/// One fingerprint / string / code hit in the load image or file.
struct PascalMtHit
{
    size_t file_offset = 0;   ///< absolute file offset
    size_t image_offset = 0;  ///< load-image offset (file - header), or file for COM
    const char* pattern_id = "";
    const char* role = "";
    const char* source_mt = "";
    std::string evidence;
    double confidence = 0.0;
};

/// One near-JMP slot in a Pascal procedure vector table (E9 rel16 run).
struct PascalMtJumpSlot
{
    size_t slot = 0;
    size_t table_image_off = 0; ///< offset of E9 in load image
    size_t table_file_off = 0;
    uint16_t table_ip = 0;
    uint16_t target_ip = 0;
    size_t target_file_off = 0;
    size_t target_image_off = 0;
    std::string prologue_hex; ///< first bytes at target
    const char* kind = "proc_vector"; ///< pascal_near_frame | other
};

/// Result of Pascal MT+ analysis for one binary.
struct PascalMtReport
{
    bool detected = false;
    double confidence = 0.0; ///< 0..1 aggregate
    const char* compiler =
        "Pascal MT+86 for MS-DOS 3.1.1 (Digital Research, 12-03-84)";

    bool has_entry_call = false;
    uint16_t entry_call_target_ip = 0;
    int16_t entry_call_rel16 = 0;

    bool has_segment_table = false;
    uint16_t seg_code_paras = 0;
    uint16_t seg_data_paras = 0;
    uint16_t seg_stack_paras = 0;
    uint16_t seg_extra_paras = 0;

    std::vector<PascalMtHit> hits;
    std::vector<PascalMtJumpSlot> jump_table;
    size_t jump_table_base_ip = 0;
    size_t jump_table_base_image = 0;

    size_t header_bytes = 0;
};

//=============================================================================
// Pattern table (MT+ 3.1.1 RTL — generic, not game-specific)
//=============================================================================

struct PascalMtBytePattern
{
    const char* id;
    const char* role;
    const char* source_mt;
    double confidence;
    /// Hex nybbles without spaces; even length. Empty = not a byte scan.
    const char* hex;
};

/// Code / RTL byte patterns from INIPC.I86 and related.
static constexpr PascalMtBytePattern kPascalMtCodePatterns[] = {
    {"inipc_add_cs_3", "startup_add_code_size",
     "INIPC.I86 ADD AX,CS:[3]", 0.90, "2e03060300"},
    {"inipc_add_cs_5", "startup_add_data_size",
     "INIPC.I86 ADD AX,CS:[5]", 0.90, "2e03060500"},
    {"inipc_add_cs_7", "startup_add_stack_size",
     "INIPC.I86 ADD AX,CS:[7]", 0.90, "2e03060700"},
    {"inipc_cs_word_5", "startup_read_data_size_paras",
     "INIPC.I86 MOV AX,CS:[5]", 0.95, "2ea10500"},
    {"inipc_cs_word_9", "startup_read_extra_size_paras",
     "INIPC.I86 MOV AX,CS:[9]", 0.95, "2ea10900"},
    {"int21_ah09", "dos_print_string",
     "INIPC OUTOFMEM / INT 21 AH=09", 0.85, "b409cd21"},
};

struct PascalMtStringPattern
{
    const char* id;
    const char* role;
    const char* source_mt;
    double confidence;
    const char* text; ///< ASCII substring to find (case-sensitive)
};

/// Signature strings (RTL + common MT+ markers). Game-specific names omitted.
static constexpr PascalMtStringPattern kPascalMtStringPatterns[] = {
    {"str_pascal_mt_error", "rtl_error_string", "PASLIB/runtime", 0.99,
     "Pascal MT+ Error"},
    {"str_pascal_mt_plus", "rtl_banner_string", "PASLIB/runtime", 0.95,
     "Pascal MT+"},
    {"str_out_of_memory", "rtl_oom", "INIPC.I86", 0.90, "OUT OF MEMORY"},
    {"str_pastmp", "rtl_temp_file", "PASLIB temp", 0.85, "PASTMP"},
};

//=============================================================================
// Helpers
//=============================================================================

static inline int pascal_mt_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static inline bool pascal_mt_parse_hex_pat(std::string_view hex, std::vector<uint8_t>& out)
{
    out.clear();
    if (hex.size() % 2 != 0)
        return false;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        const int hi = pascal_mt_hex_nibble(hex[i]);
        const int lo = pascal_mt_hex_nibble(hex[i + 1]);
        if (hi < 0 || lo < 0)
            return false;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return !out.empty();
}

static inline void pascal_mt_find_bytes(const std::vector<uint8_t>& hay,
                                       const std::vector<uint8_t>& needle,
                                       std::vector<size_t>& offs)
{
    offs.clear();
    if (needle.empty() || hay.size() < needle.size())
        return;
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i)
    {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
            offs.push_back(i);
    }
}

static inline bool pascal_mt_is_printable(uint8_t c)
{
    return c >= 32 && c < 127;
}

static inline std::string pascal_mt_hex_preview(const uint8_t* p, size_t n)
{
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i)
        s += std::format("{:02x}", p[i]);
    return s;
}

/// Reasonable paragraph size for MT+ segment table words (not a strict proof).
static inline bool pascal_mt_plausible_paras(uint16_t w)
{
    // 0 is ok for extra; code/data often non-zero. Allow up to 64K paras field.
    return w <= 0x1000; // 64KB paragraphs max as soft bound for table fields
}

//=============================================================================
// Entry CALL + segment table (INIPC layout)
//=============================================================================

/**
 * @brief Detect Pascal MT+ entry: E8 rel16 at image entry, optional CS+3 table.
 * @param image Load image bytes (post-MZ-header for EXE).
 * @param entry_ip Entry IP within image (usually 0 for CS=0).
 */
static inline void pascal_mt_scan_entry(const std::vector<uint8_t>& image,
                                       size_t entry_ip,
                                       size_t header_bytes,
                                       PascalMtReport& rep)
{
    if (entry_ip + 3 > image.size())
        return;
    if (image[entry_ip] != 0xE8)
        return;

    const int16_t rel = static_cast<int16_t>(
        image[entry_ip + 1] | (static_cast<uint16_t>(image[entry_ip + 2]) << 8));
    const uint32_t target =
        static_cast<uint32_t>(entry_ip + 3 + static_cast<int32_t>(rel)) & 0xFFFFu;

    rep.has_entry_call = true;
    rep.entry_call_rel16 = rel;
    rep.entry_call_target_ip = static_cast<uint16_t>(target);

    PascalMtHit h;
    h.image_offset = entry_ip;
    h.file_offset = header_bytes + entry_ip;
    h.pattern_id = "entry_e8";
    h.role = "pascal_mt_startup_call";
    h.source_mt = "INIPC/PASLIB startup";
    h.confidence = 0.85;
    h.evidence = std::format("E8 rel16={:+d} → IP {:04X}h", static_cast<int>(rel),
                             rep.entry_call_target_ip);
    rep.hits.push_back(h);

    // Segment size table immediately after CALL (CS:[3]..[9] in INIPC)
    const size_t tab = entry_ip + 3;
    if (tab + 8 <= image.size())
    {
        const uint16_t w0 = static_cast<uint16_t>(image[tab] | (image[tab + 1] << 8));
        const uint16_t w1 = static_cast<uint16_t>(image[tab + 2] | (image[tab + 3] << 8));
        const uint16_t w2 = static_cast<uint16_t>(image[tab + 4] | (image[tab + 5] << 8));
        const uint16_t w3 = static_cast<uint16_t>(image[tab + 6] | (image[tab + 7] << 8));
        // Heuristic: first two words non-zero and plausible; stack may be small.
        if (w0 != 0 && w1 != 0 && pascal_mt_plausible_paras(w0) &&
            pascal_mt_plausible_paras(w1) && pascal_mt_plausible_paras(w2) &&
            pascal_mt_plausible_paras(w3))
        {
            rep.has_segment_table = true;
            rep.seg_code_paras = w0;
            rep.seg_data_paras = w1;
            rep.seg_stack_paras = w2;
            rep.seg_extra_paras = w3;

            PascalMtHit t;
            t.image_offset = tab;
            t.file_offset = header_bytes + tab;
            t.pattern_id = "entry_segtable";
            t.role = "pascal_mt_segment_table";
            t.source_mt = "INIPC.I86 CS+3..+9 segment sizes";
            t.confidence = 0.95;
            t.evidence = std::format(
                "code={:04X}h data={:04X}h stack={:04X}h extra={:04X}h paras",
                w0, w1, w2, w3);
            rep.hits.push_back(t);
        }
    }
}

//=============================================================================
// Jump table: run of near JMP E9 stubs
//=============================================================================

static inline void pascal_mt_scan_jump_table(const std::vector<uint8_t>& image,
                                            size_t header_bytes,
                                            PascalMtReport& rep)
{
    // Prefer table near IP 0090h when present (common MT+ vector park after init).
    // Also accept the longest E9 run in the first 8 KiB of the image.
    auto score_run = [&](size_t start) -> size_t
    {
        size_t n = 0;
        size_t i = start;
        while (i + 3 <= image.size() && image[i] == 0xE9)
        {
            ++n;
            i += 3;
            if (n > 64)
                break;
        }
        return n;
    };

    size_t best_off = 0;
    size_t best_n = 0;

    // Candidate: 0x90 if looks like a table
    if (image.size() > 0x90 + 9)
    {
        const size_t n = score_run(0x90);
        if (n >= 4)
        {
            best_off = 0x90;
            best_n = n;
        }
    }

    const size_t scan_lim = std::min(image.size(), size_t{0x2000});
    for (size_t i = 0; i + 9 < scan_lim; ++i)
    {
        if (image[i] != 0xE9)
            continue;
        const size_t n = score_run(i);
        if (n > best_n && n >= 6)
        {
            best_n = n;
            best_off = i;
        }
        // skip ahead over this run
        if (n > 0)
            i += n * 3 - 1;
    }

    if (best_n < 4)
        return;

    rep.jump_table_base_image = best_off;
    rep.jump_table_base_ip = best_off; // CS=0 relative
    rep.jump_table.reserve(best_n);

    for (size_t s = 0; s < best_n; ++s)
    {
        const size_t off = best_off + s * 3;
        const int16_t rel = static_cast<int16_t>(
            image[off + 1] | (static_cast<uint16_t>(image[off + 2]) << 8));
        const uint16_t tip = static_cast<uint16_t>(off + 3 + rel);

        PascalMtJumpSlot slot;
        slot.slot = s;
        slot.table_image_off = off;
        slot.table_file_off = header_bytes + off;
        slot.table_ip = static_cast<uint16_t>(off);
        slot.target_ip = tip;
        slot.target_image_off = tip;
        slot.target_file_off = header_bytes + tip;

        if (static_cast<size_t>(tip) + 6u <= image.size())
        {
            slot.prologue_hex = pascal_mt_hex_preview(image.data() + tip, 6);
            // 55 8B EC = push bp; mov bp, sp  (Pascal near frame)
            if (image[tip] == 0x55 && image[tip + 1] == 0x8B && image[tip + 2] == 0xEC)
                slot.kind = "pascal_near_frame";
            else if (image[tip] == 0x55 && image[tip + 1] == 0x8B && image[tip + 2] == 0xC4)
                slot.kind = "pascal_alt_frame"; // push bp; mov ax,sp variants
            else
                slot.kind = "proc_vector";
        }
        rep.jump_table.push_back(std::move(slot));
    }
}

//=============================================================================
// Full analyze
//=============================================================================

/**
 * @brief Analyze file bytes for Pascal MT+ 3.1.1 signatures.
 * @param file_data Entire file (MZ or COM).
 * @param header_bytes MZ header size (0 for COM).
 * @param load_image_size Declared load image size (0 = rest of file).
 * @param entry_ip Entry IP within load image.
 */
static inline PascalMtReport pascal_mt_analyze(const std::vector<uint8_t>& file_data,
                                               size_t header_bytes,
                                               size_t load_image_size,
                                               size_t entry_ip)
{
    PascalMtReport rep;
    rep.header_bytes = header_bytes;

    if (file_data.size() <= header_bytes)
        return rep;

    size_t img_len = load_image_size;
    if (img_len == 0 || header_bytes + img_len > file_data.size())
        img_len = file_data.size() - header_bytes;

    std::vector<uint8_t> image(file_data.begin() + static_cast<std::ptrdiff_t>(header_bytes),
                               file_data.begin() + static_cast<std::ptrdiff_t>(header_bytes + img_len));

    pascal_mt_scan_entry(image, entry_ip, header_bytes, rep);
    pascal_mt_scan_jump_table(image, header_bytes, rep);

    // Code patterns (scan full file for simplicity — patterns are unique enough)
    for (const auto& pat : kPascalMtCodePatterns)
    {
        std::vector<uint8_t> needle;
        if (!pascal_mt_parse_hex_pat(pat.hex, needle))
            continue;
        std::vector<size_t> offs;
        pascal_mt_find_bytes(file_data, needle, offs);
        for (size_t fo : offs)
        {
            PascalMtHit h;
            h.file_offset = fo;
            h.image_offset = fo >= header_bytes ? fo - header_bytes : fo;
            h.pattern_id = pat.id;
            h.role = pat.role;
            h.source_mt = pat.source_mt;
            h.confidence = pat.confidence;
            h.evidence = std::format("bytes {}", pat.hex);
            rep.hits.push_back(std::move(h));
        }
    }

    // String patterns
    for (const auto& sp : kPascalMtStringPatterns)
    {
        const std::string_view needle(sp.text);
        if (needle.empty())
            continue;
        for (size_t fo = 0; fo + needle.size() <= file_data.size(); ++fo)
        {
            if (std::memcmp(file_data.data() + fo, needle.data(), needle.size()) != 0)
                continue;
            PascalMtHit h;
            h.file_offset = fo;
            h.image_offset = fo >= header_bytes ? fo - header_bytes : fo;
            h.pattern_id = sp.id;
            h.role = sp.role;
            h.source_mt = sp.source_mt;
            h.confidence = sp.confidence;
            h.evidence = std::format("\"{}\"", sp.text);
            rep.hits.push_back(std::move(h));
            // continue scan for all occurrences
        }
    }

    // Aggregate detection score
    double score = 0.0;
    bool has_rtl_str = false;
    bool has_inipc = false;
    for (const auto& h : rep.hits)
    {
        if (std::string_view(h.pattern_id).starts_with("str_pascal"))
            has_rtl_str = true;
        if (std::string_view(h.pattern_id).starts_with("inipc_"))
            has_inipc = true;
        score += h.confidence;
    }
    if (rep.has_entry_call && rep.has_segment_table)
        score += 1.5;
    if (!rep.jump_table.empty())
        score += 0.8;
    if (has_rtl_str)
        score += 1.2;
    if (has_inipc)
        score += 1.0;

    // Threshold: need real MT+ signal, not a lone E8
    rep.detected = (has_rtl_str && (rep.has_entry_call || has_inipc)) ||
                   (rep.has_entry_call && rep.has_segment_table && has_inipc) ||
                   (has_rtl_str && has_inipc) ||
                   (rep.has_entry_call && rep.has_segment_table && has_rtl_str) ||
                   (has_rtl_str && !rep.jump_table.empty());

    // Soft detect: entry+segtable+jump table without string (stripped?)
    if (!rep.detected && rep.has_entry_call && rep.has_segment_table &&
        rep.jump_table.size() >= 8 && has_inipc)
        rep.detected = true;

    rep.confidence = std::min(1.0, score / 8.0);
    if (rep.detected && rep.confidence < 0.5)
        rep.confidence = 0.55;

    // Sort hits by file offset
    std::sort(rep.hits.begin(), rep.hits.end(),
              [](const PascalMtHit& a, const PascalMtHit& b)
              { return a.file_offset < b.file_offset; });

    return rep;
}

//=============================================================================
// Report (stdout)
//=============================================================================

static inline void pascal_mt_print_report(const PascalMtReport& rep)
{
    if (!rep.detected)
        return;

    std::cout << "\n=== Pascal MT+ (auto) ===\n";
    std::cout << std::format("Compiler:    {}\n", rep.compiler);
    std::cout << std::format("Confidence:  {:.0f}%\n", rep.confidence * 100.0);
    std::cout << "Note:        Ghidra CODE addr = image_offset "
                 "(file_offset - header); MZ load @ 1000:0000\n";

    if (rep.has_entry_call)
    {
        std::cout << std::format(
            "Entry CALL:  E8 → IP {:04X}h  (rel16 {:+d})\n",
            rep.entry_call_target_ip, static_cast<int>(rep.entry_call_rel16));
    }
    if (rep.has_segment_table)
    {
        std::cout << std::format(
            "Seg table:   code={:04X}h data={:04X}h stack={:04X}h extra={:04X}h "
            "paras (at CS+3 after CALL)\n",
            rep.seg_code_paras, rep.seg_data_paras, rep.seg_stack_paras,
            rep.seg_extra_paras);
    }

    if (!rep.jump_table.empty())
    {
        std::cout << std::format(
            "Jump table:  {} near-JMP (E9) slots @ image IP {:04X}h "
            "(file 0x{:04X})\n",
            rep.jump_table.size(), rep.jump_table_base_ip,
            rep.header_bytes + rep.jump_table_base_image);
        std::cout << "  slot  tblIP  tgtIP  file_off  kind              prologue\n";
        const size_t show = std::min(rep.jump_table.size(), size_t{32});
        for (size_t i = 0; i < show; ++i)
        {
            const auto& s = rep.jump_table[i];
            std::cout << std::format(
                "  {:>4}  {:04X}   {:04X}   0x{:04X}   {:<16}  {}\n",
                s.slot, s.table_ip, s.target_ip, s.target_file_off, s.kind,
                s.prologue_hex);
        }
        if (rep.jump_table.size() > show)
            std::cout << std::format("  … {} more slots\n",
                                     rep.jump_table.size() - show);
    }

    std::cout << std::format("Fingerprint: {} hits (INIPC/PASLIB patterns + strings)\n",
                             rep.hits.size());
    std::cout << "  file_off  img_off  conf  role                         pattern\n";
    for (const auto& h : rep.hits)
    {
        std::cout << std::format(
            "  0x{:06X}  0x{:04X}  {:0.2f}  {:<28}  {}  {}\n",
            h.file_offset, h.image_offset, h.confidence, h.role, h.pattern_id,
            h.evidence);
    }
    std::cout << "=== End Pascal MT+ ===\n";
}

/**
 * @brief Run Pascal MT+ analysis and print if detected (respects opts.pascalMt).
 */
static inline void dump_pascal_mt(const Options& opts,
                                  const std::vector<uint8_t>& file_data,
                                  size_t header_bytes,
                                  size_t load_image_size,
                                  size_t entry_ip)
{
    if (!opts.pascalMt)
        return;
    const PascalMtReport rep =
        pascal_mt_analyze(file_data, header_bytes, load_image_size, entry_ip);
    pascal_mt_print_report(rep);
}

#endif // PASCAL_MT_H
