/**
 * @file dos_extender.h
 * @brief DOS extender / DPMI stub detection + 32-bit payload disasm helper.
 *
 * Fixes the buggy $HOME/dos detector (false positives on bare "DS"/"JK").
 * Uses multi-byte product strings and structured IDs, cross-checked with
 * Ralf Brown Interrupt List notes (Phar Lap, GO32, CauseWay, DPMI, FlashTek
 * X-32, DOS32) and known stubs (DOS/4G, DOS/4GW, CWSDPMI, PMODE/W, Huffman,
 * DOS/32A ID32).
 *
 * When a 32-bit PM extender is found, set Options::x86Bits = 32 and disassemble
 * the payload with Capstone CS_MODE_32 (linear listing; full 32-bit CFG/sim
 * is out of scope for this module).
 */
#ifndef DOS_EXTENDER_H
#define DOS_EXTENDER_H

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <capstone/capstone.h>

#include "exe.h"
#include "options.h"

//=============================================================================
// Report
//=============================================================================

enum class DosExtenderKind : uint8_t {
    None = 0,
    Dos4G,
    Dos4GW,
    Dos32A,
    CwsDpmi,
    CauseWay,
    PmodeW,
    Go32,
    Swat386,
    Huffman,
    PharLap,
    FlashTekX32,
    BorlandDpmi,
    GenericDpmi,
    UnknownPm,
};

struct DosExtenderReport {
    bool detected = false;
    DosExtenderKind kind = DosExtenderKind::None;
    int x86_bits = 16; ///< Capstone width for payload (16 or 32)
    std::string name;
    std::string version;
    std::string detail;
    size_t sig_offset = 0;
    size_t payload_file_off = 0;
    size_t payload_len = 0;
    size_t payload_entry_off = 0;
    bool nested_mz = false;
    size_t nested_mz_off = 0;
    bool has_le = false;
    size_t le_off = 0;
    std::vector<std::string> evidence;
    double confidence = 0.0;
};

//=============================================================================
// Helpers
//=============================================================================

static inline bool dext_find(const std::vector<uint8_t>& data,
                             std::string_view needle,
                             size_t& out_off,
                             size_t start = 0)
{
    if (needle.empty() || data.size() < start + needle.size())
        return false;
    for (size_t i = start; i + needle.size() <= data.size(); ++i)
    {
        if (std::memcmp(data.data() + i, needle.data(), needle.size()) == 0)
        {
            out_off = i;
            return true;
        }
    }
    return false;
}

static inline bool dext_border_ok(const std::vector<uint8_t>& data, size_t pos)
{
    if (pos >= data.size())
        return true;
    const uint8_t c = data[pos];
    return !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
             (c >= '0' && c <= '9') || c == '_');
}

/// Prefer token-like matches (avoids mid-string false hits).
static inline bool dext_find_token(const std::vector<uint8_t>& data,
                                   std::string_view needle,
                                   size_t& out_off)
{
    if (needle.empty() || data.size() < needle.size())
        return false;
    for (size_t i = 0; i + needle.size() <= data.size(); ++i)
    {
        if (std::memcmp(data.data() + i, needle.data(), needle.size()) != 0)
            continue;
        const bool left =
            (i == 0) || dext_border_ok(data, i - 1) || data[i - 1] < 0x20;
        const bool right = dext_border_ok(data, i + needle.size());
        if (left && right)
        {
            out_off = i;
            return true;
        }
    }
    return false;
}

static inline const char* dext_kind_name(DosExtenderKind k)
{
    switch (k)
    {
    case DosExtenderKind::Dos4G:       return "DOS/4G";
    case DosExtenderKind::Dos4GW:      return "DOS/4GW";
    case DosExtenderKind::Dos32A:      return "DOS/32A";
    case DosExtenderKind::CwsDpmi:     return "CWSDPMI";
    case DosExtenderKind::CauseWay:    return "CauseWay";
    case DosExtenderKind::PmodeW:      return "PMODE/W";
    case DosExtenderKind::Go32:        return "GO32";
    case DosExtenderKind::Swat386:     return "386SWAT";
    case DosExtenderKind::Huffman:     return "Doug Huffman DOS extender";
    case DosExtenderKind::PharLap:     return "Phar Lap 386|DOS-Extender";
    case DosExtenderKind::FlashTekX32: return "FlashTek X-32/X-32VM";
    case DosExtenderKind::BorlandDpmi: return "Borland DPMI (DPMILOAD/RTM)";
    case DosExtenderKind::GenericDpmi: return "DPMI/VCPI client (generic)";
    case DosExtenderKind::UnknownPm:   return "Protected-mode payload";
    default:                           return "none";
    }
}

static inline size_t dext_mz_declared_size(const MZHeader& h)
{
    if (h.num_blocks == 0)
        return 0;
    if (h.final_len == 0)
        return static_cast<size_t>(h.num_blocks) * 512u;
    return (static_cast<size_t>(h.num_blocks) - 1u) * 512u + h.final_len;
}

static inline bool dext_find_le_lx(const std::vector<uint8_t>& data, size_t& out_off)
{
    if (data.size() >= 0x40)
    {
        const uint32_t e = static_cast<uint32_t>(data[0x3C]) |
                           (static_cast<uint32_t>(data[0x3D]) << 8) |
                           (static_cast<uint32_t>(data[0x3E]) << 16) |
                           (static_cast<uint32_t>(data[0x3F]) << 24);
        if (e >= 0x40 && e + 4 <= data.size())
        {
            if (data[e] == 'L' && (data[e + 1] == 'E' || data[e + 1] == 'X'))
            {
                out_off = e;
                return true;
            }
        }
    }
    const size_t lim = std::min(data.size(), size_t{0x40000});
    for (size_t i = 0; i + 4 <= lim; i += 4)
    {
        if (data[i] == 'L' && (data[i + 1] == 'E' || data[i + 1] == 'X') &&
            data[i + 2] == 0 && data[i + 3] == 0)
        {
            out_off = i;
            return true;
        }
    }
    return false;
}

static inline void dext_set_payload_from_nested_mz(const std::vector<uint8_t>& data,
                                                   size_t nested_off,
                                                   DosExtenderReport& rep)
{
    if (nested_off + sizeof(MZHeader) > data.size())
        return;
    MZHeader nh{};
    std::memcpy(&nh, data.data() + nested_off, sizeof(nh));
    if (nh.signature != MZ_SIGNATURE)
        return;
    const size_t hdr = static_cast<size_t>(nh.header_size) * 16u;
    if (hdr == 0 || nested_off + hdr > data.size())
        return;
    rep.nested_mz = true;
    rep.nested_mz_off = nested_off;
    rep.payload_file_off = nested_off + hdr;
    const size_t decl = dext_mz_declared_size(nh);
    const size_t remain = data.size() - rep.payload_file_off;
    size_t img_len = (decl > hdr) ? (decl - hdr) : remain;
    if (img_len > remain)
        img_len = remain;
    rep.payload_len = img_len;
    const int32_t delta =
        static_cast<int32_t>(static_cast<int16_t>(nh.cs)) * 16 +
        static_cast<int32_t>(nh.ip);
    if (delta >= 0 && static_cast<size_t>(delta) < img_len)
        rep.payload_entry_off = rep.payload_file_off + static_cast<size_t>(delta);
    else
        rep.payload_entry_off = rep.payload_file_off;
}

//=============================================================================
// Analyze
//=============================================================================

static inline DosExtenderReport dos_extender_analyze(const std::vector<uint8_t>& data,
                                                     const MZHeader& header)
{
    DosExtenderReport rep;
    if (data.size() < sizeof(MZHeader) || header.signature != MZ_SIGNATURE)
        return rep;

    const size_t declared = dext_mz_declared_size(header);
    size_t off = 0;

    auto hit = [&](DosExtenderKind kind, std::string_view name, size_t sig_off,
                   int bits, double conf, std::string_view why) {
        if (rep.detected && conf < rep.confidence)
            return;
        rep.detected = true;
        rep.kind = kind;
        rep.name = std::string(name);
        rep.sig_offset = sig_off;
        rep.x86_bits = bits;
        rep.confidence = conf;
        rep.evidence.push_back(std::format("0x{:X}: {}", sig_off, why));
    };

    // Specific products — never bare "DS" / "JK"
    if (dext_find(data, "DOS/4GW", off) || dext_find(data, "DOS4GW", off))
    {
        hit(DosExtenderKind::Dos4GW, "DOS/4GW", off, 32, 0.95, "string DOS/4GW");
        rep.detail = "Rational Systems / Watcom protected-mode runtime";
    }
    else if (dext_find_token(data, "DOS/4G", off))
    {
        hit(DosExtenderKind::Dos4G, "DOS/4G", off, 32, 0.92, "string DOS/4G");
        rep.detail = "Rational Systems DOS/4G";
    }

    if (dext_find(data, "DOS/32A", off))
    {
        size_t id = off;
        dext_find(data, "ID32", id);
        hit(DosExtenderKind::Dos32A, "DOS/32A", id, 32, 0.93, "DOS/32A / ID32");
        rep.detail = "DOS/32 Advanced";
    }

    if (dext_find(data, "CWSDPMI", off))
        hit(DosExtenderKind::CwsDpmi, "CWSDPMI", off, 32, 0.9, "CWSDPMI");

    if (dext_find(data, "CAUSEWAY", off) || dext_find(data, "CauseWay", off))
    {
        hit(DosExtenderKind::CauseWay, "CauseWay", off, 32, 0.9, "CauseWay");
        rep.detail = "Michael Devore CauseWay (RBIL)";
    }

    if (dext_find(data, "PMODE/W", off) || dext_find(data, "PMODEW", off))
        hit(DosExtenderKind::PmodeW, "PMODE/W", off, 32, 0.9, "PMODE/W");

    if (dext_find_token(data, "GO32", off))
    {
        hit(DosExtenderKind::Go32, "GO32", off, 32, 0.85, "GO32");
        rep.detail = "DJGPP GO32 (RBIL INT 78h family)";
    }

    if (dext_find(data, "386SWAT", off))
        hit(DosExtenderKind::Swat386, "386SWAT", off, 32, 0.85, "386SWAT");

    if (dext_find(data, "Doug Huffman", off) ||
        dext_find(data, "dos extender Copyright 1991 by Doug Huffman", off))
    {
        size_t h = 0;
        if (!dext_find(data, "Doug Huffman", h))
            dext_find(data, "dos extender Copyright", h);
        hit(DosExtenderKind::Huffman, "Doug Huffman DOS extender", h, 32, 0.96,
            "Doug Huffman 1991");
        rep.detail = "32-bit DPMI/VCPI client; nested MZ payload common";
        rep.version = "1991";
    }

    if (dext_find(data, "Phar Lap", off) || dext_find(data, "PHARLAP", off) ||
        dext_find(data, "386|DOS-Extender", off))
    {
        hit(DosExtenderKind::PharLap, "Phar Lap", off, 32, 0.88, "Phar Lap");
        rep.detail = "Phar Lap 386|DOS-Extender (RBIL)";
    }

    if (dext_find(data, "FlashTek", off) || dext_find(data, "X-32VM", off))
    {
        hit(DosExtenderKind::FlashTekX32, "FlashTek X-32", off, 32, 0.85,
            "FlashTek/X-32");
        rep.detail = "FlashTek X-32/X-32VM (RBIL INT 21h)";
    }

    if (dext_find(data, "DPMILOAD", off) || dext_find(data, "32RTM", off))
        hit(DosExtenderKind::BorlandDpmi, "Borland DPMI", off, 32, 0.8,
            "DPMILOAD/RTM");

    size_t le_off = 0;
    if (dext_find_le_lx(data, le_off))
    {
        rep.has_le = true;
        rep.le_off = le_off;
        rep.evidence.push_back(std::format("0x{:X}: LE/LX header", le_off));
        if (!rep.detected)
            hit(DosExtenderKind::UnknownPm, "LE/LX image", le_off, 32, 0.75,
                "LE/LX");
        else
            rep.x86_bits = 32;
        if (rep.payload_len == 0)
        {
            rep.payload_file_off = le_off;
            rep.payload_len = data.size() - le_off;
            rep.payload_entry_off = le_off;
        }
    }

    size_t nested = 0;
    if (declared > 0 && declared + sizeof(MZHeader) <= data.size() &&
        data[declared] == 'M' && data[declared + 1] == 'Z')
    {
        nested = declared;
        rep.evidence.push_back(
            std::format("0x{:X}: nested MZ after outer declared size", nested));
        dext_set_payload_from_nested_mz(data, nested, rep);
        if (!rep.detected)
            hit(DosExtenderKind::UnknownPm, "Nested MZ wrap", nested, 32, 0.7,
                "nested MZ");
        else
        {
            rep.x86_bits = 32;
            rep.confidence = std::max(rep.confidence, 0.85);
        }
    }

    if (!rep.detected)
    {
        size_t d1 = 0, d2 = 0;
        const bool dpmi = dext_find(data, "DPMI", d1);
        const bool vcpi = dext_find(data, "VCPI", d2);
        if (dpmi || vcpi)
        {
            hit(DosExtenderKind::GenericDpmi, "DPMI/VCPI client",
                dpmi ? d1 : d2, 32, 0.55, dpmi ? "DPMI" : "VCPI");
            rep.detail = "Needs DPMI host (RBIL INT 31h); product unknown";
        }
    }

    if (rep.detected && rep.x86_bits == 32 && rep.payload_len == 0 &&
        declared > 0 && declared < data.size())
    {
        rep.payload_file_off = declared;
        rep.payload_len = data.size() - declared;
        rep.payload_entry_off = declared;
        rep.evidence.push_back(std::format(
            "payload default: after MZ declared size 0x{:X}", declared));
    }

    return rep;
}

static inline void dos_extender_print_report(const DosExtenderReport& rep)
{
    if (!rep.detected)
        return;
    std::cout << "\n=== DOS extender / DPMI ===\n";
    std::cout << std::format("Product:     {} ({})\n", rep.name,
                             dext_kind_name(rep.kind));
    if (!rep.version.empty())
        std::cout << std::format("Version:     {}\n", rep.version);
    if (!rep.detail.empty())
        std::cout << std::format("Detail:      {}\n", rep.detail);
    std::cout << std::format(
        "CPU mode:    {}-bit payload (Capstone CS_MODE_{})\n", rep.x86_bits,
        rep.x86_bits == 32 ? "32" : "16");
    std::cout << std::format("Confidence:  {:.0f}%\n", rep.confidence * 100.0);
    std::cout << std::format("Signature:   file 0x{:X}\n", rep.sig_offset);
    if (rep.nested_mz)
        std::cout << std::format("Nested MZ:   0x{:X}\n", rep.nested_mz_off);
    if (rep.has_le)
        std::cout << std::format("LE/LX:       0x{:X}\n", rep.le_off);
    if (rep.payload_len > 0)
    {
        std::cout << std::format(
            "Payload:     off=0x{:X} len=0x{:X} entry=0x{:X}\n",
            rep.payload_file_off, rep.payload_len, rep.payload_entry_off);
    }
    for (const auto& e : rep.evidence)
        std::cout << "  - " << e << "\n";
    if (rep.x86_bits == 32)
    {
        std::cout << "Note: -d uses 32-bit Capstone on the payload; "
                     "full LE load / DPMI simulation not implemented.\n";
    }
}

/**
 * @brief Linear Capstone disassembly of extender payload (16- or 32-bit).
 */
static inline void dos_extender_disasm_payload(const std::vector<uint8_t>& data,
                                               const DosExtenderReport& rep,
                                               const Options& opts,
                                               size_t max_insns = 80)
{
    if (!rep.detected || rep.payload_len == 0)
        return;
    if (rep.payload_entry_off >= data.size())
        return;

    const size_t start = rep.payload_entry_off;
    const size_t end = std::min(data.size(), rep.payload_file_off + rep.payload_len);
    if (start >= end)
        return;

    const cs_mode mode =
        (rep.x86_bits == 32) ? CS_MODE_32 : CS_MODE_16;
    csh handle{};
    if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
    {
        std::cerr << "dos_extender: cs_open failed\n";
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    std::cout << std::format(
        "\n=== {}-bit disassembly (payload entry file 0x{:X}) ===\n",
        rep.x86_bits, start);

    const uint8_t* code = data.data() + start;
    size_t size = end - start;
    uint64_t addr = static_cast<uint64_t>(start);
    cs_insn* insn = cs_malloc(handle);
    if (!insn)
    {
        cs_close(&handle);
        return;
    }

    size_t n = 0;
    while (n < max_insns && size > 0)
    {
        const uint8_t* p = code;
        size_t sz = size;
        uint64_t a = addr;
        if (!cs_disasm_iter(handle, &p, &sz, &a, insn))
            break;
        const size_t consumed = size - sz;
        std::cout << std::format("{:08X}:  ", static_cast<unsigned>(insn->address));
        for (size_t b = 0; b < insn->size && b < 8; ++b)
            std::cout << std::format("{:02X}", code[b]);
        for (size_t b = insn->size; b < 8; ++b)
            std::cout << "  ";
        std::cout << std::format("  {:8} {}\n", insn->mnemonic, insn->op_str);
        code = p;
        size = sz;
        addr = a;
        ++n;
        if (consumed == 0)
            break;
    }
    if (n == 0)
        std::cout << "(no instructions decoded)\n";
    else if (!opts.jsonOut)
        std::cout << std::format("({} instructions; use larger window later)\n", n);

    cs_free(insn, 1);
    cs_close(&handle);
}

#endif // DOS_EXTENDER_H
