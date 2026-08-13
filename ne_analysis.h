// ne_analysis.h - Windows 3.x NE (New Executable) analysis
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Detect NE via MZ e_lfanew, dump header / segments / modules / resources,
// and optionally disassemble code segments (Capstone 16-bit).

#ifndef NE_ANALYSIS_H
#define NE_ANALYSIS_H

#include "ne.h"
#include "options.h"
#include "formatting.h"
#include "disasm.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

//=============================================================================
// Helpers
//=============================================================================

/// Read little-endian u16 from buffer (bounds-checked).
static inline bool ne_read_u16(const std::vector<uint8_t>& data, size_t off,
                               uint16_t& out)
{
    if (off + 2 > data.size())
        return false;
    out = static_cast<uint16_t>(data[off]) |
          (static_cast<uint16_t>(data[off + 1]) << 8);
    return true;
}

/// Read little-endian u32 from buffer (bounds-checked).
static inline bool ne_read_u32(const std::vector<uint8_t>& data, size_t off,
                               uint32_t& out)
{
    if (off + 4 > data.size())
        return false;
    out = static_cast<uint32_t>(data[off]) |
          (static_cast<uint32_t>(data[off + 1]) << 8) |
          (static_cast<uint32_t>(data[off + 2]) << 16) |
          (static_cast<uint32_t>(data[off + 3]) << 24);
    return true;
}

/// True if file is MZ with a valid NE header at e_lfanew.
static inline bool ne_probe(const std::vector<uint8_t>& data, uint32_t& e_lfanew_out)
{
    if (data.size() < MZ_E_LFANEW_MIN)
        return false;
    if (data[0] != 'M' || data[1] != 'Z')
        return false;
    uint32_t e_lfanew = 0;
    if (!ne_read_u32(data, MZ_E_LFANEW_OFF, e_lfanew))
        return false;
    if (e_lfanew < MZ_E_LFANEW_MIN || e_lfanew + sizeof(NEHeader) > data.size())
        return false;
    uint16_t magic = 0;
    if (!ne_read_u16(data, static_cast<size_t>(e_lfanew), magic))
        return false;
    if (magic != NE_SIGNATURE)
        return false;
    e_lfanew_out = e_lfanew;
    return true;
}

static inline const char* ne_exetyp_name(uint8_t t)
{
    switch (t)
    {
    case NE_EXETYP_OS2:     return "OS/2";
    case NE_EXETYP_WINDOWS: return "Windows";
    case NE_EXETYP_DOS4:    return "European DOS 4.x";
    case NE_EXETYP_WIN386:  return "Windows 386";
    case NE_EXETYP_BOSS:    return "BOSS";
    default:                return "Unknown";
    }
}

static inline const char* ne_rt_name(uint16_t type_id)
{
    const uint16_t id = type_id & 0x7FFFu;
    switch (id)
    {
    case NE_RT_CURSOR:       return "CURSOR";
    case NE_RT_BITMAP:       return "BITMAP";
    case NE_RT_ICON:         return "ICON";
    case NE_RT_MENU:         return "MENU";
    case NE_RT_DIALOG:       return "DIALOG";
    case NE_RT_STRING:       return "STRING";
    case NE_RT_FONTDIR:      return "FONTDIR";
    case NE_RT_FONT:         return "FONT";
    case NE_RT_ACCELERATOR:  return "ACCELERATOR";
    case NE_RT_RCDATA:       return "RCDATA";
    case NE_RT_GROUP_CURSOR: return "GROUP_CURSOR";
    case NE_RT_GROUP_ICON:   return "GROUP_ICON";
    case NE_RT_VERSION:      return "VERSION";
    default:                 return "UNKNOWN";
    }
}

/// Length-prefixed string at absolute file offset (Pascal-style).
static inline std::string ne_pstring(const std::vector<uint8_t>& data, size_t off)
{
    if (off >= data.size())
        return {};
    const size_t n = data[off];
    if (off + 1 + n > data.size())
        return {};
    return std::string(reinterpret_cast<const char*>(data.data() + off + 1), n);
}

//=============================================================================
// Parsed view
//=============================================================================

struct NEParsed {
    uint32_t e_lfanew = 0;
    NEHeader hdr{};
    std::vector<NESegment> segs;
    std::vector<std::string> module_names; ///< imported module names (KERNEL, …)
    std::string module_name;               ///< resident name ordinal 0
    std::string description;               ///< non-resident name ordinal 0
    bool ok = false;
    std::string error;
};

static inline bool ne_parse(const std::vector<uint8_t>& data, NEParsed& out)
{
    out = NEParsed{};
    if (!ne_probe(data, out.e_lfanew))
    {
        out.error = "Not an NE executable (no MZ+e_lfanew+NE)";
        return false;
    }
    std::memcpy(&out.hdr, data.data() + out.e_lfanew, sizeof(NEHeader));
    if (out.hdr.magic != NE_SIGNATURE)
    {
        out.error = "NE magic mismatch";
        return false;
    }

    const size_t ne_base = static_cast<size_t>(out.e_lfanew);
    const size_t seg_off = ne_base + out.hdr.segtab;
    out.segs.resize(out.hdr.cseg);
    for (uint16_t i = 0; i < out.hdr.cseg; ++i)
    {
        const size_t off = seg_off + static_cast<size_t>(i) * sizeof(NESegment);
        if (off + sizeof(NESegment) > data.size())
        {
            out.error = "Segment table truncated";
            return false;
        }
        std::memcpy(&out.segs[i], data.data() + off, sizeof(NESegment));
    }

    // Module reference table: array of offsets into imported names table
    const size_t modtab = ne_base + out.hdr.modtab;
    const size_t imptab = ne_base + out.hdr.imptab;
    for (uint16_t i = 0; i < out.hdr.cmod; ++i)
    {
        uint16_t name_off = 0;
        if (!ne_read_u16(data, modtab + static_cast<size_t>(i) * 2, name_off))
            break;
        out.module_names.push_back(ne_pstring(data, imptab + name_off));
    }

    // Resident name table: length-prefixed names + ordinal u16; ends with len=0
    {
        size_t p = ne_base + out.hdr.restab;
        bool first = true;
        while (p < data.size())
        {
            const uint8_t len = data[p];
            if (len == 0)
                break;
            if (p + 1 + len + 2 > data.size())
                break;
            std::string name(reinterpret_cast<const char*>(data.data() + p + 1), len);
            uint16_t ord = 0;
            ne_read_u16(data, p + 1 + len, ord);
            if (first)
            {
                out.module_name = std::move(name);
                first = false;
            }
            p += 1 + len + 2;
        }
    }

    // Non-resident name table (file offset)
    if (out.hdr.nrestab != 0 && out.hdr.nrestab < data.size())
    {
        size_t p = static_cast<size_t>(out.hdr.nrestab);
        if (p < data.size() && data[p] != 0)
        {
            const uint8_t len = data[p];
            if (p + 1 + len <= data.size())
                out.description.assign(
                    reinterpret_cast<const char*>(data.data() + p + 1), len);
        }
    }

    out.ok = true;
    return true;
}

/// File offset of segment data (0 if empty sector field).
static inline size_t ne_seg_file_offset(const NEHeader& hdr, const NESegment& seg)
{
    if (seg.sector == 0)
        return 0;
    const unsigned shift = hdr.align;
    return static_cast<size_t>(seg.sector) << shift;
}

/// On-disk length of segment (0 in header means 65536).
static inline size_t ne_seg_file_length(const NESegment& seg)
{
    return seg.cbseg == 0 ? 65536u : static_cast<size_t>(seg.cbseg);
}

//=============================================================================
// Printing
//=============================================================================

static inline void ne_print_header(const NEParsed& ne, int64_t fileSize)
{
    const NEHeader& h = ne.hdr;
    std::cout << "\n=== New Executable (NE) — Windows 3.x era ===\n";
    std::cout << "File size                                  "
              << std::hex << fileSize << "h  (" << std::dec << fileSize << ")\n";
    std::cout << "e_lfanew (NE header file offset)           "
              << std::hex << ne.e_lfanew << "h\n";
    std::cout << "Linker version                             "
              << std::dec << static_cast<unsigned>(h.ver) << "."
              << static_cast<unsigned>(h.rev) << "\n";
    std::cout << "Module flags                               "
              << std::hex << h.flags << "h\n";
    std::cout << "Automatic data segment                     "
              << std::dec << h.autodata << "\n";
    std::cout << "Initial heap / stack                       "
              << h.heap << " / " << h.stack << " bytes\n";
    std::cout << "Entry point (CS:IP)                        "
              << std::hex << h.cs << ":" << h.ip
              << "  (seg index " << std::dec << h.cs << ")\n";
    std::cout << "Stack (SS:SP)                              "
              << std::hex << h.ss << ":" << h.sp << std::dec << "\n";
    std::cout << "Segment count                              " << h.cseg << "\n";
    std::cout << "Module ref count                           " << h.cmod << "\n";
    std::cout << "Sector alignment shift                     " << h.align
              << "  (sector size " << (1u << h.align) << ")\n";
    std::cout << "Target OS                                  "
              << static_cast<unsigned>(h.exetyp) << " ("
              << ne_exetyp_name(h.exetyp) << ")\n";
    std::cout << "Expected Windows version                   "
              << static_cast<unsigned>(h.expver_maj) << "."
              << static_cast<unsigned>(h.expver_min) << "\n";
    if (!ne.module_name.empty())
        std::cout << "Module name (resident)                     "
                  << ne.module_name << "\n";
    if (!ne.description.empty())
        std::cout << "Description (non-resident)                 "
                  << ne.description << "\n";
}

static inline void ne_print_segments(const NEParsed& ne)
{
    std::cout << "\n=== Segment table (" << ne.segs.size() << " entries) ===\n";
    std::cout << "Idx  Type  Flags   Sector   FileOff    Length   MinAlloc\n";
    for (size_t i = 0; i < ne.segs.size(); ++i)
    {
        const NESegment& s = ne.segs[i];
        const char* kind = (s.flags & NE_SEG_DATA) ? "DATA" : "CODE";
        const size_t foff = ne_seg_file_offset(ne.hdr, s);
        const size_t flen = ne_seg_file_length(s);
        std::cout << std::dec << std::setw(3) << (i + 1) << "  "
                  << kind << "  "
                  << std::hex << std::setw(4) << s.flags << "h  "
                  << std::setw(6) << s.sector << "h  "
                  << std::setw(8) << foff << "h  "
                  << std::setw(6) << flen << "h  "
                  << std::setw(6) << (s.minalloc == 0 ? 65536u : s.minalloc)
                  << "h\n";
    }
    std::cout << std::dec;
}

static inline void ne_print_modules(const NEParsed& ne)
{
    if (ne.module_names.empty())
        return;
    std::cout << "\n=== Imported modules (" << ne.module_names.size() << ") ===\n";
    for (size_t i = 0; i < ne.module_names.size(); ++i)
        std::cout << "  [" << (i + 1) << "] " << ne.module_names[i] << "\n";
}

static inline void ne_print_resources(const std::vector<uint8_t>& data,
                                      const NEParsed& ne)
{
    const size_t ne_base = static_cast<size_t>(ne.e_lfanew);
    const size_t rsrctab = ne_base + ne.hdr.rsrctab;
    // Resource table may equal resident name table if no resources
    if (ne.hdr.rsrctab == 0 || ne.hdr.rsrctab == ne.hdr.restab)
    {
        std::cout << "\n=== Resource table ===\n  (none)\n";
        return;
    }
    if (rsrctab + 2 > data.size())
    {
        std::cout << "\n=== Resource table ===\n  (truncated)\n";
        return;
    }

    uint16_t align_shift = 0;
    ne_read_u16(data, rsrctab, align_shift);
    std::cout << "\n=== Resource table (align_shift=" << align_shift << ") ===\n";

    size_t pos = rsrctab + 2;
    while (pos + 8 <= data.size())
    {
        uint16_t type_id = 0, count = 0;
        uint32_t reserved = 0;
        ne_read_u16(data, pos, type_id);
        if (type_id == 0)
            break;
        ne_read_u16(data, pos + 2, count);
        ne_read_u32(data, pos + 4, reserved);
        pos += 8;

        std::string type_label;
        if (type_id & 0x8000u)
            type_label = std::string(ne_rt_name(type_id)) +
                         " (int " + std::to_string(type_id & 0x7FFFu) + ")";
        else
            type_label = "\"" + ne_pstring(data, rsrctab + type_id) + "\"";

        std::cout << "Type " << type_label << " — " << count << " resource(s)\n";

        for (uint16_t i = 0; i < count; ++i)
        {
            if (pos + sizeof(NEResource) > data.size())
                break;
            NEResource res{};
            std::memcpy(&res, data.data() + pos, sizeof(NEResource));
            pos += sizeof(NEResource);

            const size_t file_off =
                static_cast<size_t>(res.offset) << align_shift;
            const size_t file_len =
                static_cast<size_t>(res.length) << align_shift;

            std::string id_label;
            if (res.id & 0x8000u)
                id_label = "#" + std::to_string(res.id & 0x7FFFu);
            else
                id_label = "\"" + ne_pstring(data, rsrctab + res.id) + "\"";

            std::cout << "  id=" << id_label
                      << "  flags=" << std::hex << res.flags << "h"
                      << "  off=" << file_off << "h"
                      << "  len=" << file_len << "h"
                      << std::dec << "\n";
        }
    }
}

/// Disassemble a code segment (linear Capstone 16-bit).
static inline void ne_disasm_segment(const std::vector<uint8_t>& data,
                                     const NEParsed& ne,
                                     size_t seg_index_0based,
                                     size_t max_bytes = 256)
{
    if (seg_index_0based >= ne.segs.size())
        return;
    const NESegment& seg = ne.segs[seg_index_0based];
    if (seg.flags & NE_SEG_DATA)
        return;
    const size_t foff = ne_seg_file_offset(ne.hdr, seg);
    size_t flen = ne_seg_file_length(seg);
    if (foff == 0 || foff >= data.size())
        return;
    if (foff + flen > data.size())
        flen = data.size() - foff;
    if (flen > max_bytes)
        flen = max_bytes;

    std::cout << "\n=== Disassembly CODE segment " << (seg_index_0based + 1)
              << " (file " << std::hex << foff << "h, first "
              << std::dec << flen << " bytes) ===\n";

    Options o{};
    o.showDisasm = true;
    o.noIntAnnot = true;
    o.writeAsmFile = false;
    const uint16_t cs = static_cast<uint16_t>(seg_index_0based + 1);
    // disassemble(data, file_offset, cs, ip, opts) — image from offset, entry ip
    disassemble(data, foff, cs, /*ip=*/0, o);
}

//=============================================================================
// Top-level analyze
//=============================================================================

/// Analyze an NE file: headers always; segments/modules/resources by default;
/// -d disassembles entry code segment (and optionally all CODE with -a).
static inline int analyze_ne(const Options& opts,
                             const std::vector<uint8_t>& fileData,
                             int64_t fileSize)
{
    NEParsed ne;
    if (!ne_parse(fileData, ne))
    {
        std::cerr << "Error: " << ne.error << "\n";
        return 1;
    }

    if (opts.jsonOut)
    {
        // Minimal JSON for scripting (full schema later)
        std::cout << "{\n"
                  << "  \"tool\": \"dumpexe\",\n"
                  << "  \"format\": \"ne\",\n"
                  << "  \"file\": \"" << opts.filename << "\",\n"
                  << "  \"e_lfanew\": " << ne.e_lfanew << ",\n"
                  << "  \"linker\": \"" << static_cast<unsigned>(ne.hdr.ver)
                  << "." << static_cast<unsigned>(ne.hdr.rev) << "\",\n"
                  << "  \"exetyp\": " << static_cast<unsigned>(ne.hdr.exetyp)
                  << ",\n"
                  << "  \"cseg\": " << ne.hdr.cseg << ",\n"
                  << "  \"cmod\": " << ne.hdr.cmod << ",\n"
                  << "  \"entry_cs\": " << ne.hdr.cs << ",\n"
                  << "  \"entry_ip\": " << ne.hdr.ip << ",\n"
                  << "  \"module\": \"" << ne.module_name << "\",\n"
                  << "  \"description\": \"" << ne.description << "\"\n"
                  << "}\n";
        return 0;
    }

    std::cout << "Display of File " << opts.filename << "\n";
    ne_print_header(ne, fileSize);
    ne_print_segments(ne);
    ne_print_modules(ne);
    ne_print_resources(fileData, ne);

    if (opts.showDisasm || opts.showAll)
    {
        // Entry segment is 1-based CS index
        if (ne.hdr.cs >= 1 && ne.hdr.cs <= ne.segs.size())
        {
            const size_t idx = static_cast<size_t>(ne.hdr.cs - 1);
            const NESegment& seg = ne.segs[idx];
            const size_t foff = ne_seg_file_offset(ne.hdr, seg);
            size_t flen = ne_seg_file_length(seg);
            if (foff < fileData.size())
            {
                if (foff + flen > fileData.size())
                    flen = fileData.size() - foff;
                // Start disasm at entry IP within segment
                const size_t entry_off = foff + ne.hdr.ip;
                const size_t remain =
                    (entry_off < foff + flen) ? (foff + flen - entry_off) : 0;
                const size_t dump_len =
                    remain > 512 ? 512 : remain;
                if (dump_len > 0)
                {
                    std::cout << "\n=== Disassembly at entry CS:IP "
                              << std::hex << ne.hdr.cs << ":" << ne.hdr.ip
                              << " (file " << entry_off << "h) ===\n"
                              << std::dec;
                    Options o = opts;
                    o.writeAsmFile = false;
                    // Start at entry instruction; IP for labels = entry IP
                    disassemble(fileData, entry_off, ne.hdr.cs, ne.hdr.ip, o);
                }
            }
        }
        if (opts.showAll)
        {
            for (size_t i = 0; i < ne.segs.size(); ++i)
            {
                if (!(ne.segs[i].flags & NE_SEG_DATA))
                    ne_disasm_segment(fileData, ne, i, 128);
            }
        }
    }

    if (opts.simulate)
    {
        std::cerr << "Note: --simulate is DOS real-mode only; "
                     "NE/Win16 simulation is not implemented yet.\n";
    }

    return 0;
}

#endif // NE_ANALYSIS_H
