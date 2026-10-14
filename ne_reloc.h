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
#include <iostream>
#include <ostream>
#include <sstream>
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
    /// Segments whose relocation table is the same bytes as an earlier
    /// segment's: index of that segment (parsed once). Else itself.
    std::vector<size_t> alias;
    size_t dropped_records = 0; ///< records past the module budget
};

/** @brief Segment whose parsed relocations apply to segment @p s. */
static inline size_t ne_reloc_owner(const NeModel& m, size_t s)
{
    return s < m.alias.size() ? m.alias[s] : s;
}

static inline std::string ne_entry_loc(uint8_t seg, uint16_t off)
{
    if (seg == 0)
        return "-";
    if (seg == 0xFE)
        return std::format("const {:04X}", off);
    return std::format("{}:{:04X}", seg, off);
}

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
            if (static_cast<unsigned>(ord) + cnt > 0xFFFF)
                break;
            ord = static_cast<uint16_t>(ord + cnt);
            continue;
        }
        const size_t sz = (ind == 0xFF) ? 6 : 3;
        for (unsigned k = 0; k < cnt && p + sz <= end && ord != 0xFFFF; ++k, p += sz, ++ord)
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
    m.alias.resize(ne.segs.size());
    std::map<std::pair<size_t, size_t>, size_t> table_seen;
    // Module budget: every record is 8 file bytes, so a sane file never has
    // more than size/8 in total. Tables shared by several segments (same
    // file window) are parsed once.
    size_t budget = d.size() / 8;
    std::map<uint16_t, std::string> exp_name;
    for (const NeExport& e : m.exports)
        exp_name[e.ord] = e.name;
    for (size_t s = 0; s < ne.segs.size(); ++s)
    {
        m.alias[s] = s;
        const NESegment& seg = ne.segs[s];
        if ((seg.flags & NE_SEG_RELOCINFO) == 0 || seg.sector == 0)
            continue;
        const size_t foff = ne_seg_file_offset(ne.hdr, seg);
        const size_t flen = ne_seg_file_length(seg);
        size_t p = foff + flen;
        if (p + 2 > d.size())
            continue;
        if (auto it = table_seen.find({foff, flen}); it != table_seen.end())
        {
            m.alias[s] = it->second;
            continue;
        }
        table_seen.emplace(std::pair<size_t, size_t>{foff, flen}, s);
        uint16_t cnt = static_cast<uint16_t>(d[p] | (d[p + 1] << 8));
        p += 2;
        if (cnt > budget)
        {
            m.dropped_records += cnt - budget;
            cnt = static_cast<uint16_t>(budget);
        }
        // Records that fit in the file only.
        cnt = static_cast<uint16_t>(std::min<size_t>(cnt, (d.size() - p) / 8));
        // One visited set per segment: chains that merge are walked once,
        // so total work is bounded by the segment length (review R3).
        std::vector<uint8_t> visited(flen + 1, 0);
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
                        r.target += " (" + ne_entry_loc(it->second.seg, it->second.off) + ")";
                    if (auto n = exp_name.find(r.b); n != exp_name.end())
                        r.note = n->second;
                }
                else
                {
                    r.target = std::format("{}:{:04X}", sn, r.b);
                    if (sn == 0 || sn > ne.segs.size())
                        r.note = "segment out of range";
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
            const size_t sz = ne_atype_size(r.atype);
            while (site != 0xFFFF && site + sz <= flen && !visited[site])
            {
                visited[site] = 1;
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
        budget -= std::min(budget, m.relocs[s].size());
    }
}

/**
 * @brief Roots of CODE segment @p s (0-based): entry, exports, internal
 *        far fixup targets that land in it.
 */
static inline std::vector<CfgLin> ne_segment_roots(const std::vector<uint8_t>& d, const NEParsed& ne,
                                                   const NeModel& m, size_t s, size_t flen)
{
    std::set<CfgLin> r;
    const unsigned sn = static_cast<unsigned>(s + 1);
    if (ne.hdr.cs == sn && ne.hdr.ip < flen)
        r.insert(ne.hdr.ip);
    for (const auto& [ord, e] : m.entries)
        if (e.seg == sn && e.off < flen)
            r.insert(e.off);
    for (size_t from = 0; from < m.relocs.size(); ++from)
        for (const NeReloc& x : m.relocs[from])
        {
            if ((x.rtype & 3) != 0)
                continue;
            // Segment-only fixup on the selector of 9A/EA: the offset is the
            // literal word before it (Borland/MS far calls between segments).
            if (x.atype == 2 && static_cast<uint8_t>(x.a & 0xFF) == sn && from < ne.segs.size())
            {
                const size_t ffo = ne_seg_file_offset(ne.hdr, ne.segs[from]);
                for (uint16_t site : x.sites)
                {
                    const size_t at = ffo + site;
                    if (site < 3 || at + 2 > d.size())
                        continue;
                    if (d[at - 3] != 0x9A && d[at - 3] != 0xEA)
                        continue;
                    const uint16_t off = static_cast<uint16_t>(d[at - 2] | (d[at - 1] << 8));
                    if (off < flen)
                        r.insert(off);
                }
                continue;
            }
            if (x.atype != 3)
                continue;
            const uint8_t t = static_cast<uint8_t>(x.a & 0xFF);
            if (t == sn && x.b < flen)
                r.insert(x.b);
            else if (t == 0xFF)
                if (auto it = m.entries.find(x.b); it != m.entries.end() && it->second.seg == sn &&
                                                      it->second.off < flen)
                    r.insert(it->second.off);
        }
    return {r.begin(), r.end()};
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
                          ne_entry_loc(e.seg, e.off));
}

static inline void ne_print_relocs(const NeModel& m, std::ostream& os)
{
    // S5: no line cap. Each listed record is 8 distinct file bytes (shared
    // tables are aliased, counts are clipped to the file), so the output is
    // bounded by the input size.
    for (size_t s = 0; s < m.relocs.size(); ++s)
    {
        if (ne_reloc_owner(m, s) != s)
        {
            os << std::format("\n=== Relocations segment {}: same table as segment {} ===\n", s + 1,
                              ne_reloc_owner(m, s) + 1);
            continue;
        }
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
 * @brief Name relocation sites in an already rendered multi-pass listing
 *        (lines "    IIII  BYTES  mnemonic ops"). A far-pointer fixup on
 *        9A/EA becomes `call far KERNEL.91`; other sites get a comment.
 *        Labels, INT notes and procedure gaps stay as they were.
 */
static inline std::string ne_annotate_listing(const std::string& text, const NeModel& m, size_t seg)
{
    seg = ne_reloc_owner(m, seg);
    if (seg >= m.site_of.size() || m.site_of[seg].empty())
        return text;
    const auto& sites = m.site_of[seg];
    std::string out;
    out.reserve(text.size() + text.size() / 8);
    size_t pos = 0;
    while (pos < text.size())
    {
        size_t nl = text.find('\n', pos);
        const size_t e = nl == std::string::npos ? text.size() : nl;
        std::string line = text.substr(pos, e - pos);
        pos = nl == std::string::npos ? text.size() : nl + 1;
        // Parse "    IIII  HEX...  rest".
        size_t i = 0;
        while (i < line.size() && line[i] == ' ')
            ++i;
        auto ishex = [](char c) { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); };
        size_t j = i;
        while (j < line.size() && ishex(line[j]))
            ++j;
        size_t k = j;
        while (k < line.size() && line[k] == ' ')
            ++k;
        size_t b = k;
        while (b < line.size() && ishex(line[b]))
            ++b;
        if (i < 4 || j - i != 4 || k - j < 2 || b == k || (b - k) % 2 != 0 || b >= line.size() ||
            line[b] != ' ')
        {
            out += line;
            out += '\n';
            continue;
        }
        const uint16_t ip = static_cast<uint16_t>(std::stoul(line.substr(i, 4), nullptr, 16));
        const size_t nbytes = (b - k) / 2;
        std::string note;
        bool far_named = false;
        std::string far_text;
        for (size_t q = 0; q < nbytes; ++q)
        {
            auto it = sites.find(static_cast<uint16_t>(ip + q));
            if (it == sites.end())
                continue;
            const NeReloc& r = m.relocs[seg][it->second];
            const std::string op = line.substr(k, 2);
            if (q == 1 && r.atype == 3 && nbytes == 5 && (op == "9A" || op == "EA"))
            {
                far_named = true;
                far_text = std::format("{:<8} far {}", op == "9A" ? "call" : "jmp", r.target);
            }
            else
            {
                note += std::format("{}fixup {} {} at +{}", note.empty() ? "" : "; ",
                                    ne_atype_name(r.atype), r.target, q);
            }
            if (!r.note.empty())
                note += note.empty() ? r.note : " (" + r.note + ")";
            note += std::format(" [reloc {}]", r.index);
        }
        if (far_named)
        {
            size_t mpos = b;
            while (mpos < line.size() && line[mpos] == ' ')
                ++mpos;
            // Keep any trailing comment of the original line.
            const size_t sc = line.find(';', mpos);
            const std::string tail = sc == std::string::npos ? "" : "  " + line.substr(sc);
            line = line.substr(0, mpos) + far_text + tail;
        }
        if (!note.empty())
            line += "  ; " + note;
        out += line;
        out += '\n';
    }
    return out;
}

/** @brief Restores std::cout's buffer on scope exit (exception-safe). */
struct NeCoutCapture
{
    std::ostringstream buf;
    std::streambuf* old;
    NeCoutCapture() : old(std::cout.rdbuf(buf.rdbuf())) {}
    ~NeCoutCapture() { std::cout.rdbuf(old); }
    NeCoutCapture(const NeCoutCapture&) = delete;
    NeCoutCapture& operator=(const NeCoutCapture&) = delete;
};

#endif // NE_RELOC_H
