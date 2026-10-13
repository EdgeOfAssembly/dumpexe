// ne_reloc.h - NE (Win16) entry table, export names, per-segment
// relocation records (chained fixups) and a fixup-aware segment listing.
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// P7 of the multipass plan. Detection stays by header (ne_probe on
// e_lfanew), never by extension.

#ifndef NE_RELOC_H
#define NE_RELOC_H

#include <capstone/capstone.h>
#include <cstdint>
#include <format>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include "ne.h"
#include "ne_names.h"

/** @brief One entry-table entry (exported ordinal). */
struct NeEntry
{
    uint16_t ord = 0;
    uint8_t seg = 0;      ///< 1-based segment; 0xFE constant; 0 unused
    uint16_t off = 0;
    bool movable = false;
    uint8_t flags = 0;
};

/** @brief One export: ordinal, name, where it points. */
struct NeExport
{
    uint16_t ord = 0;
    std::string name;
    bool resident = false;
    uint8_t seg = 0;
    uint16_t off = 0;
};

/** @brief One relocation record of a segment. */
struct NeReloc
{
    size_t index = 0;          ///< 0-based record number in the segment's table
    uint8_t atype = 0;         ///< 0 lobyte, 2 segment, 3 far ptr, 5 offset16, 11 ptr48, 13 off32
    uint8_t rtype = 0;         ///< &3: 0 internal, 1 import ordinal, 2 import name, 3 osfixup; &4 additive
    uint16_t head = 0;         ///< first site (chain head unless additive)
    uint16_t a = 0;            ///< internal: segnum (0xFF movable); import: module index
    uint16_t b = 0;            ///< internal: offset or entry ordinal; import: ordinal / name offset
    std::vector<uint16_t> sites; ///< every patched offset (chain walked)
    std::string target;        ///< rendered target, e.g. KERNEL.91 or 2:0123
    std::string note;          ///< known name, e.g. InitTask
};

/** @brief Whole-module NE fixup model. */
struct NeModel
{
    std::map<uint16_t, NeEntry> entries;
    std::vector<NeExport> exports;               ///< ordinal order
    std::vector<std::vector<NeReloc>> relocs;    ///< per segment (0-based)
    std::vector<std::map<uint16_t, size_t>> site_of; ///< per segment: site -> reloc vector index
};

static inline const char* ne_atype_name(uint8_t t)
{
    switch (t)
    {
    case 0: return "lobyte";
    case 2: return "segment";
    case 3: return "far";
    case 5: return "offset";
    case 11: return "ptr48";
    case 13: return "offset32";
    default: return "?";
    }
}

static inline size_t ne_atype_size(uint8_t t)
{
    switch (t)
    {
    case 0: return 1;
    case 2: case 5: return 2;
    case 3: case 13: return 4;
    case 11: return 6;
    default: return 2;
    }
}

/**
 * @brief Parse the entry table (bundles) of @p ne.
 */
static inline void ne_parse_entries(const std::vector<uint8_t>& d, const NEParsed& ne, NeModel& m)
{
    size_t p = ne.e_lfanew + ne.hdr.enttab;
    const size_t end = std::min(d.size(), p + ne.hdr.cbenttab);
    uint16_t ord = 1;
    while (p + 2 <= end)
    {
        const uint8_t cnt = d[p];
        const uint8_t ind = d[p + 1];
        p += 2;
        if (cnt == 0)
            break;
        if (ind == 0)
        {
            ord = static_cast<uint16_t>(ord + cnt);
            continue;
        }
        const size_t sz = (ind == 0xFF) ? 6 : 3;
        for (unsigned k = 0; k < cnt && p + sz <= end; ++k, p += sz, ++ord)
        {
            NeEntry e;
            e.ord = ord;
            e.flags = d[p];
            if (ind == 0xFF)
            {
                e.movable = true;
                e.seg = d[p + 3];
                e.off = static_cast<uint16_t>(d[p + 4] | (d[p + 5] << 8));
            }
            else
            {
                e.seg = ind;
                e.off = static_cast<uint16_t>(d[p + 1] | (d[p + 2] << 8));
            }
            m.entries[ord] = e;
        }
    }
}

/**
 * @brief Read a names table (count-prefixed name, then ordinal) from @p p
 *        to @p end; the first name (module name / description) is skipped.
 */
static inline void ne_read_names(const std::vector<uint8_t>& d, size_t p, size_t end, bool resident,
                                 std::map<uint16_t, NeExport>& out)
{
    bool first = true;
    end = std::min(end, d.size());
    while (p < end)
    {
        const uint8_t len = d[p];
        if (len == 0 || p + 1 + len + 2 > end)
            break;
        std::string name(reinterpret_cast<const char*>(d.data() + p + 1), len);
        const uint16_t ord = static_cast<uint16_t>(d[p + 1 + len] | (d[p + 2 + len] << 8));
        p += 1 + len + 2;
        if (first)
        {
            first = false;
            continue;
        }
        NeExport e;
        e.ord = ord;
        e.name = std::move(name);
        e.resident = resident;
        out.emplace(ord, std::move(e));
    }
}

/**
 * @brief Build the export list from the resident and non-resident names
 *        tables, joined with the entry table.
 */
static inline void ne_parse_exports(const std::vector<uint8_t>& d, const NEParsed& ne, NeModel& m)
{
    std::map<uint16_t, NeExport> ex;
    const size_t base = ne.e_lfanew;
    ne_read_names(d, base + ne.hdr.restab, base + ne.hdr.modtab, true, ex);
    if (ne.hdr.nrestab != 0)
        ne_read_names(d, ne.hdr.nrestab, static_cast<size_t>(ne.hdr.nrestab) + ne.hdr.cbnrestab, false, ex);
    for (auto& [ord, e] : ex)
    {
        if (auto it = m.entries.find(ord); it != m.entries.end())
        {
            e.seg = it->second.seg;
            e.off = it->second.off;
        }
        m.exports.push_back(e);
    }
}

/** @brief Imported name at @p off in the imported-names table. */
static inline std::string ne_import_name(const std::vector<uint8_t>& d, const NEParsed& ne, uint16_t off)
{
    return ne_pstring(d, ne.e_lfanew + ne.hdr.imptab + off);
}

/**
 * @brief Parse the relocation records of every segment that has them and
 *        walk the chains (non-additive records: the word at each site
 *        holds the next site, 0xFFFF ends).
 */
static inline void ne_parse_relocs(const std::vector<uint8_t>& d, const NEParsed& ne, NeModel& m)
{
    m.relocs.assign(ne.segs.size(), {});
    m.site_of.assign(ne.segs.size(), {});
    std::map<uint16_t, std::string> exp_name;
    for (const NeExport& e : m.exports)
        exp_name[e.ord] = e.name;
    for (size_t s = 0; s < ne.segs.size(); ++s)
    {
        const NESegment& seg = ne.segs[s];
        if ((seg.flags & NE_SEG_RELOCINFO) == 0 || seg.sector == 0)
            continue;
        const size_t foff = ne_seg_file_offset(ne.hdr, seg);
        const size_t flen = ne_seg_file_length(seg);
        size_t p = foff + flen;
        if (p + 2 > d.size())
            continue;
        const uint16_t cnt = static_cast<uint16_t>(d[p] | (d[p + 1] << 8));
        p += 2;
        for (size_t i = 0; i < cnt && p + 8 <= d.size(); ++i, p += 8)
        {
            NeReloc r;
            r.index = i;
            r.atype = d[p];
            r.rtype = d[p + 1];
            r.head = static_cast<uint16_t>(d[p + 2] | (d[p + 3] << 8));
            r.a = static_cast<uint16_t>(d[p + 4] | (d[p + 5] << 8));
            r.b = static_cast<uint16_t>(d[p + 6] | (d[p + 7] << 8));
            switch (r.rtype & 3)
            {
            case 0:
            {
                const uint8_t sn = static_cast<uint8_t>(r.a & 0xFF);
                if (sn == 0xFF)
                {
                    auto it = m.entries.find(r.b);
                    r.target = std::format("entry {}", r.b);
                    if (it != m.entries.end())
                        r.target += std::format(" ({}:{:04X})", it->second.seg, it->second.off);
                    if (auto n = exp_name.find(r.b); n != exp_name.end())
                        r.note = n->second;
                }
                else
                {
                    r.target = std::format("{}:{:04X}", sn, r.b);
                }
                break;
            }
            case 1:
            {
                const std::string mod = (r.a >= 1 && r.a <= ne.module_names.size())
                                            ? ne.module_names[r.a - 1]
                                            : std::format("module{}", r.a);
                r.target = std::format("{}.{}", mod, r.b);
                if (const char* n = ne_builtin_ordinal_name(mod, r.b))
                    r.note = n;
                break;
            }
            case 2:
            {
                const std::string mod = (r.a >= 1 && r.a <= ne.module_names.size())
                                            ? ne.module_names[r.a - 1]
                                            : std::format("module{}", r.a);
                r.target = mod + "." + ne_import_name(d, ne, r.b);
                break;
            }
            default:
                r.target = std::format("osfixup {}", r.a);
                break;
            }
            // Sites: additive records patch one place; others walk the chain.
            uint16_t site = r.head;
            std::set<uint16_t> seen;
            const size_t sz = ne_atype_size(r.atype);
            while (site != 0xFFFF && site + sz <= flen && seen.insert(site).second)
            {
                r.sites.push_back(site);
                if (r.rtype & 4)
                    break;
                if (r.atype == 0) // byte fixups do not chain
                    break;
                const size_t at = foff + site;
                if (at + 2 > d.size())
                    break;
                site = static_cast<uint16_t>(d[at] | (d[at + 1] << 8));
            }
            const size_t vi = m.relocs[s].size();
            for (uint16_t st : r.sites)
                m.site_of[s].emplace(st, vi);
            m.relocs[s].push_back(std::move(r));
        }
    }
}

static inline NeModel ne_build_model(const std::vector<uint8_t>& d, const NEParsed& ne)
{
    NeModel m;
    ne_parse_entries(d, ne, m);
    ne_parse_exports(d, ne, m);
    ne_parse_relocs(d, ne, m);
    return m;
}

static inline void ne_print_exports(const NeModel& m, std::ostream& os)
{
    os << std::format("\n=== Exports ({}) ===\n", m.exports.size());
    os << "Ord   Name                              Table         Seg:Off\n";
    for (const NeExport& e : m.exports)
        os << std::format("{:>4}  {:<32}  {:<12}  {}\n", e.ord, e.name,
                          e.resident ? "resident" : "nonresident",
                          e.seg ? std::format("{}:{:04X}", e.seg, e.off) : std::string("-"));
}

static inline void ne_print_relocs(const NeModel& m, std::ostream& os)
{
    for (size_t s = 0; s < m.relocs.size(); ++s)
    {
        if (m.relocs[s].empty())
            continue;
        os << std::format("\n=== Relocations segment {} ({} records) ===\n", s + 1, m.relocs[s].size());
        os << "  #  Type      Kind      Target                         Sites\n";
        for (const NeReloc& r : m.relocs[s])
        {
            std::string sites;
            for (size_t k = 0; k < r.sites.size(); ++k)
            {
                if (k == 8)
                {
                    sites += std::format(" … +{}", r.sites.size() - 8);
                    break;
                }
                sites += std::format("{}{}:{:04X}", k ? " " : "", s + 1, r.sites[k]);
            }
            static const char* kinds[] = {"internal", "import", "import", "osfixup"};
            std::string tgt = r.target + (r.note.empty() ? "" : " (" + r.note + ")");
            os << std::format("{:>3}  {:<8}  {:<8}{} {:<30} {}\n", r.index, ne_atype_name(r.atype),
                              kinds[r.rtype & 3], (r.rtype & 4) ? "+" : " ", tgt, sites);
        }
    }
}

/**
 * @brief Linear listing of @p len bytes of segment @p seg (0-based) from
 *        @p ip, with relocation sites resolved: `call far KERNEL.91` for a
 *        far-pointer fixup on 9A/EA, otherwise the fixup as a comment.
 */
static inline void ne_list_segment(const std::vector<uint8_t>& d, const NEParsed& ne, const NeModel& m,
                                   size_t seg, uint16_t ip, size_t len, std::ostream& os)
{
    const size_t foff = ne_seg_file_offset(ne.hdr, ne.segs[seg]);
    size_t flen = ne_seg_file_length(ne.segs[seg]);
    if (foff >= d.size())
        return;
    flen = std::min(flen, d.size() - foff);
    csh h;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &h) != CS_ERR_OK)
        return;
    cs_insn* in = cs_malloc(h);
    const auto& sites = m.site_of[seg];
    size_t off = ip;
    const size_t stop = std::min(flen, static_cast<size_t>(ip) + len);
    while (off < stop)
    {
        const uint8_t* code = d.data() + foff + off;
        size_t sz = std::min<size_t>(15, flen - off);
        uint64_t addr = off;
        // A relocation site must not be swallowed by a misdecode across
        // records: decode normally, then look for sites inside.
        if (!cs_disasm_iter(h, &code, &sz, &addr, in))
        {
            os << std::format("{}:{:04X}  {:02X}{:<12}  db {:02X}h\n", seg + 1, off, d[foff + off], "",
                              d[foff + off]);
            ++off;
            continue;
        }
        std::string bytes;
        for (size_t k = 0; k < in->size && k < 6; ++k)
            bytes += std::format("{:02X}", in->bytes[k]);
        std::string text = std::format("{:<8} {}", in->mnemonic, in->op_str);
        std::string note;
        for (size_t k = 0; k < in->size; ++k)
        {
            auto it = sites.find(static_cast<uint16_t>(off + k));
            if (it == sites.end())
                continue;
            const NeReloc& r = m.relocs[seg][it->second];
            const uint8_t op = in->bytes[0];
            if (k == 1 && r.atype == 3 && (op == 0x9A || op == 0xEA) && in->size == 5)
                text = std::format("{:<8} {}", op == 0x9A ? "call" : "jmp", "far " + r.target);
            else
                note += std::format("{}fixup {} {} at +{}", note.empty() ? "" : "; ",
                                    ne_atype_name(r.atype), r.target, k);
            if (!r.note.empty())
                note += note.empty() ? r.note : " (" + r.note + ")";
            note += std::format(" [reloc {}]", r.index);
        }
        os << std::format("{}:{:04X}  {:<12}  {}{}\n", seg + 1, off, bytes, text,
                          note.empty() ? "" : "  ; " + note);
        off += in->size;
    }
    cs_free(in, 1);
    cs_close(&h);
}

#endif // NE_RELOC_H
