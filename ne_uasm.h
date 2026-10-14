// ne_uasm.h - P7: per-segment verified UASM listings for NE (Win16) and the
// map that bin2ne uses to rebuild the file.
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Each CODE segment is its own flat listing (offset 0 = segment offset 0),
// built from the segment's roots (entry CS:IP, exported entries, internal
// fixup targets) and verified by the assembler like an MZ image. Relocation
// sites keep their on-disk bytes (chain links and placeholders), so the
// segment assembles to exactly its file bytes. Everything that is not CODE
// segment data (headers, tables, DATA segments, relocation records,
// resources) goes to a skeleton copy of the file with the code bytes zeroed;
// bin2ne lays the assembled segments back onto it.

#ifndef NE_UASM_H
#define NE_UASM_H

#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "listing.h"
#include "ne_analysis.h"

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

/**
 * @brief --uasm on an NE file. Writes STEM_segN.asm per CODE segment,
 *        STEM.neskel and STEM.nemap.
 * @return 0 when every CODE segment listing verified identical, else 1.
 */
static inline int ne_emit_uasm(const Options& opts, const std::vector<uint8_t>& d)
{
    NEParsed ne;
    if (!ne_parse(d, ne))
    {
        std::cerr << "dumpexe: --uasm: NE parse failed\n";
        return 1;
    }
    const NeModel model = ne_build_model(d, ne);
    namespace fs = std::filesystem;
    fs::path stem;
    if (!opts.outputPath.empty() && opts.outputPath != "-")
    {
        stem = fs::path(opts.outputPath);
        if (stem.extension() == ".asm")
            stem.replace_extension();
    }
    else
    {
        // Next to the input, like the MZ/COM .asm.
        stem = fs::path(opts.filename);
        stem.replace_extension();
    }
    std::vector<uint8_t> skel = d;
    std::ofstream map(stem.string() + ".nemap");
    map << "# dumpexe NE map: bin2ne MAP OUT lays each assembled segment onto the skeleton\n";
    map << "skel " << stem.filename().string() << ".neskel\n";
    map << "size " << d.size() << "\n";
    int rc = 0;
    std::set<std::pair<size_t, size_t>> done;
    std::string seg_list;
    for (size_t s = 0; s < ne.segs.size(); ++s)
    {
        size_t foff = 0;
        size_t flen = 0;
        if (!ne_code_disasm_window(d, ne, s, foff, flen) || flen == 0)
            continue;
        if (!done.insert({foff, flen}).second)
            continue; // same bytes as an earlier segment
        std::vector<uint8_t> img(d.begin() + static_cast<std::ptrdiff_t>(foff),
                                 d.begin() + static_cast<std::ptrdiff_t>(foff + flen));
        std::vector<CfgLin> roots = ne_segment_roots(d, ne, model, s, flen);
        const CfgLin entry = roots.empty() ? 0 : roots.front();
        Options co = opts;
        co.showCfg = false;
        auto build = [&](std::span<const CfgLin> extra) -> CfgGraph
        {
            std::vector<CfgLin> all(roots.begin() + (roots.empty() ? 0 : 1), roots.end());
            all.insert(all.end(), extra.begin(), extra.end());
            CfgGraph g = cfg_build(img, entry, 0, 0, foff, true, 20000, {}, 0, dx::Fmt::Mz, false, all);
            cfg_annotate(g, img);
            return g;
        };
        CfgGraph g = roots.empty() ? CfgGraph{} : build({});
        size_t n_insns = 0;
        int st = 0;
        const std::string name = std::format("{}_seg{}.asm", stem.filename().string(), s + 1);
        const std::string text = listing_emit_uasm_verified(
            g, img, entry, co, std::format("{} segment {}", opts.filename, s + 1), false, false, {},
            n_insns, &st, nullptr, 0, 0, roots.empty() ? std::function<CfgGraph(std::span<const CfgLin>)>{} : build);
        const fs::path out = stem.parent_path() / name;
        std::ofstream(out) << text;
        map << std::format("seg {} {} {} {}_seg{}.bin\n", s + 1, foff, flen, stem.filename().string(), s + 1);
        seg_list += std::format(" {}", s + 1);
        std::fill(skel.begin() + static_cast<std::ptrdiff_t>(foff),
                  skel.begin() + static_cast<std::ptrdiff_t>(foff + flen), uint8_t{0});
        std::cerr << std::format("listing: wrote UASM {} ({} insns{})\n", out.string(), n_insns,
                                 st == 0 ? "" : ", NOT VERIFIED");
        if (st != 0)
            rc = 1;
    }
    // Every segment zeroed in the skeleton; bin2ne refuses a map missing one.
    map << "segs" << seg_list << "\n";
    std::ofstream(stem.string() + ".neskel", std::ios::binary)
        .write(reinterpret_cast<const char*>(skel.data()), static_cast<std::streamsize>(skel.size()));
    std::cerr << std::format("listing: wrote {}.nemap and {}.neskel; rebuild: uasm -bin each _segN.asm "
                             "to _segN.bin, then bin2ne {}.nemap OUT\n",
                             stem.string(), stem.string(), stem.string());
    return rc;
}

#endif // NE_UASM_H
