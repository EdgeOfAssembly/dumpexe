/**
 * @file listing.h
 * @brief Multi-pass annotated assembly listing for dumpexe (-d / -a).
 *
 * Product decision: there is NO separate --listing flag. Multi-pass listing
 * *is* what -d/--disassemble means. Bare dumpexe <file> stays light (no dump).
 *
 * Passes (on IR / CFG — not text re-parse):
 *   1. Decode via CFG build (block IR)
 *   2. Annotate INT / tags from cfg_annotate
 *   3. Discover proc starts → symbols func_<IP>
 *   4. Emit: labels, rewritten near call/jmp/jcc, blank line after proc regions
 *
 * Default: also write <stem>.asm (disable with --no-asm-file). -o overrides path.
 * An existing default .asm is kept; -o PATH may replace the named file.
 */
#ifndef LISTING_H
#define LISTING_H

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <format>
#include <functional>
#include <fstream>
#include <iterator>
#include <iostream>
#include <map>
#include <set>
#include <span>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#include "cfg.h"
#include "int_annotate.h"
#include "options.h"
#include "symbols.h"
#include "toolchain.h"
#include "turbo_pascal.h"
#include "repack.h"
#include "uasm_scratch.h"

//=============================================================================
// Paths
//=============================================================================

/// Default listing path: same directory/stem as input, extension .asm
static inline std::string listing_default_asm_path(const std::string& input_path)
{
    if (input_path.empty())
        return "out.asm";
    // Strip trailing slashes
    std::string p = input_path;
    while (p.size() > 1 && (p.back() == '/' || p.back() == '\\'))
        p.pop_back();
    // Find last slash
    size_t slash = p.find_last_of("/\\");
    std::string dir = (slash == std::string::npos) ? std::string() : p.substr(0, slash + 1);
    std::string base = (slash == std::string::npos) ? p : p.substr(slash + 1);
    // Strip extension
    size_t dot = base.find_last_of('.');
    if (dot != std::string::npos && dot > 0)
        base = base.substr(0, dot);
    return dir + base + ".asm";
}

/**
 * @brief Procedure label for a linear address.
 *
 * Four uppercase hex digits through 0xFFFF (`func_0100`). A larger address
 * uses only the digits it needs (`func_10000`).
 *
 * @param ip Linear address inside the load image.
 * @return `func_` plus @ref cfg_lin_hex.
 */
static inline std::string listing_symbol_name(CfgLin ip)
{
    return "func_" + cfg_lin_hex(ip);
}

/**
 * @brief True for a near control transfer whose operand is a code target.
 *
 * Far `lcall` / `ljmp` / `callf` / `jmpf` are excluded. Their Capstone text is
 * `seg, off` or `seg:off`; operand 0 is the segment and must not become
 * `func_<segment>`.
 *
 * @param m Lowercase mnemonic (`call`, `jmp`, `je`, `loop`, …).
 * @return true when the operand should be a label or an IP, not a linear address.
 */
static inline bool listing_is_near_xfer(std::string_view m)
{
    if (cfg_is_far_xfer(m))
        return false;
    if (m == "call" || m == "jmp" || m == "loop" || m == "loope" || m == "loopz" ||
        m == "loopne" || m == "loopnz" || m == "jcxz" || m == "jecxz")
    {
        return true;
    }
    // `jmpf` starts with 'j' but is far; cfg_is_far_xfer already rejected it.
    return m.size() >= 2 && m[0] == 'j';
}

/**
 * @brief Define loc_XXXX for jcc/loop targets that are real instruction starts.
 *
 * Call, jmp, and entry symbols already in @p sym are left alone (`func_` wins).
 * A target that is not on an instruction boundary is not labeled; the emitter
 * prints it as a numeric IP in the same base as the address column.
 *
 * @param g   CFG whose blocks hold the owned instruction starts.
 * @param sym Symbol table updated in place.
 */
static inline void listing_add_loc_labels(const CfgGraph& g,
                                         std::map<CfgLin, std::string>& sym)
{
    std::set<CfgLin> starts;
    for (const auto& kv : g.blocks)
    {
        for (const CfgInsn& in : kv.second.insns)
            starts.insert(in.ip);
    }
    for (const auto& kv : g.blocks)
    {
        for (const CfgEdge& e : kv.second.outs)
        {
            if (!e.has_target || e.kind != CfgEdgeKind::CondTrue)
                continue;
            if (!starts.count(e.to_ip) || sym.count(e.to_ip))
                continue;
            sym[e.to_ip] = "loc_" + cfg_lin_hex(e.to_ip);
        }
    }
}

//=============================================================================
// Symbol discovery (pass 3)
//=============================================================================

static inline void listing_collect_symbols(const CfgGraph& g,
                                           CfgLin entry_ip,
                                           std::map<CfgLin, std::string>& sym,
                                           std::set<CfgLin>& proc_starts,
                                           const SymbolMap* external = nullptr)
{
    auto add = [&](CfgLin ip, std::string_view why)
    {
        (void)why;
        if (!g.blocks.count(ip) && ip != entry_ip)
        {
            // still allow label at known edge targets even if block missing
        }
        proc_starts.insert(ip);
        if (!sym.count(ip))
            sym[ip] = listing_symbol_name(ip);
    };

    // External ground-truth names first (CuteMouse .sym, TLINK maps, …)
    if (external)
    {
        for (const auto& kv : external->by_ip)
        {
            sym[kv.first] = kv.second;
            proc_starts.insert(kv.first);
        }
    }

    add(entry_ip, "entry");
    if (!sym.count(entry_ip))
        sym[entry_ip] = listing_symbol_name(entry_ip);

    for (const auto& kv : g.blocks)
    {
        const CfgBlock& b = kv.second;
        if (b.is_entry || b.is_call_target || b.is_table_entry)
            add(b.start_ip, "cfg-flag");

        // Pascal near frame at block start
        if (!b.insns.empty())
        {
            const auto& in0 = b.insns[0];
            if (in0.size >= 3 && in0.bytes[0] == 0x55 && in0.bytes[1] == 0x8B &&
                in0.bytes[2] == 0xEC)
                add(b.start_ip, "pascal-frame");
        }

        for (const CfgEdge& e : b.outs)
        {
            if (!e.has_target)
                continue;
            if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Table ||
                e.kind == CfgEdgeKind::Jump)
            {
                // Jump to lower/equal often loop — still a label target
                if (g.blocks.count(e.to_ip) || e.kind == CfgEdgeKind::Call ||
                    e.kind == CfgEdgeKind::Table)
                    add(e.to_ip, "edge-target");
            }
        }
    }
}

//=============================================================================
// Operand rewrite (pass 4 at emit)
//=============================================================================

/**
 * @brief Human-listing operand for a near target outside the load image.
 *
 * @param load_cs  Load segment (`--base` / graph CS). Not a paragraph frame.
 * @param seg_base Paragraph frame of the branch (`cs * 16`). May be negative.
 * @param linear   Wrapped target `frame + uint16 offset`. Not an in-image IP.
 * @return `SSSS:OOOO (outside image)`, four uppercase hex digits each.
 */
static inline std::string listing_outside_near_op(uint16_t load_cs,
                                                  int32_t seg_base,
                                                  CfgLin linear)
{
    const uint16_t off = cfg_ip16(linear, seg_base);
    // Frames are paragraph-aligned, including a negative CS*16.
    const int32_t seg = static_cast<int32_t>(load_cs) + (seg_base / 16);
    return std::format("{:04X}:{:04X} (outside image)",
                       static_cast<uint16_t>(seg),
                       off);
}

/// Replace immediate near targets in Capstone op text with symbol when possible.
/// @param ip_numeric When true (human listing), a branch with no label is printed
///        as the segment IP (`0x14d`), the same base as the address column — not
///        Capstone's CS*16+IP linear form. A near target outside the load image
///        is `SSSS:OOOO (outside image)`. JWASM/TP export leaves this false.
/// @param load_cs Load segment recorded on the CFG (`--base`). Used only for the
///        outside-image form. Callers that are not a human listing pass 0.
static inline std::string listing_rewrite_ops(std::string_view mnem,
                                              std::string_view op_str,
                                              const CfgBlock& blk,
                                              const std::map<CfgLin, std::string>& sym,
                                              bool ip_numeric = false,
                                              uint16_t load_cs = 0)
{
    // Prefer CFG edge targets for call / uncond jmp / table
    CfgLin edge_tgt = 0;
    bool have_edge = false;
    for (const CfgEdge& e : blk.outs)
    {
        if (!e.has_target)
            continue;
        if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Jump ||
            e.kind == CfgEdgeKind::Table || e.kind == CfgEdgeKind::CondTrue)
        {
            // For jcc, CondTrue is taken target; still rewrite if op matches
            edge_tgt = e.to_ip;
            have_edge = true;
            if (e.kind == CfgEdgeKind::Call || e.kind == CfgEdgeKind::Jump ||
                e.kind == CfgEdgeKind::Table)
                break;
        }
    }

    std::string m(mnem);
    for (char& c : m)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Far transfers keep Capstone's segment/offset text. Do not rewrite them
    // to a near label (including `jmpf`, which starts with 'j').
    if (cfg_is_far_xfer(m))
        return std::string(op_str);

    // word ptr / byte ptr — leave memory ops alone
    std::string op(op_str);
    if (op.find('[') != std::string::npos)
        return op;

    // Near target whose linear is outside the image. has_target is false and
    // to_ip is the wrapped linear (0 means the edge was synthetic, not a
    // computed near immediate). Far text and in-image labels stay below.
    if (ip_numeric && listing_is_near_xfer(m) && op.find(':') == std::string::npos)
    {
        for (const CfgEdge& e : blk.outs)
        {
            if (e.has_target || e.to_ip == 0)
            {
                continue;
            }
            if (e.kind != CfgEdgeKind::Call && e.kind != CfgEdgeKind::Jump &&
                e.kind != CfgEdgeKind::Table && e.kind != CfgEdgeKind::CondTrue)
            {
                continue;
            }
            return listing_outside_near_op(load_cs, blk.seg_base, e.to_ip);
        }
    }

    // Human listing: labels when the target is known, else the IP itself.
    if (ip_numeric && have_edge && listing_is_near_xfer(m) &&
        op.find(':') == std::string::npos)
    {
        const auto it = sym.find(edge_tgt);
        if (it != sym.end())
            return it->second;
        return std::format("0x{:x}", edge_tgt);
    }

    if (!have_edge || !sym.count(edge_tgt))
        return std::string(op_str);

    if (!listing_is_near_xfer(m))
        return std::string(op_str);

    // Far pointer "seg:off" — historical path still rewrites near call/jmp/jcc.
    if (op.find(':') != std::string::npos && op.find("ptr") == std::string::npos)
    {
        // still try near-only rewrite if no second colon issues
    }

    // use edge: entire operand becomes the label for near call/jmp/jcc/loop.
    // `jmpf` starts with 'j' but is far and was returned above.
    if (!cfg_is_far_xfer(m) &&
        (m == "call" || m == "jmp" || m.starts_with("j") || m == "loop" || m == "loope" ||
         m == "loopz" || m == "loopne" || m == "loopnz"))
        return sym.at(edge_tgt);

    return op;
}

static inline bool listing_is_ret_mnem(std::string_view m)
{
    return m == "ret" || m == "retn" || m == "retf" || m == "retfq" || m == "iret" ||
           m == "iretd";
}

/**
 * @brief Index of the opcode after segment, lock, and rep prefixes.
 *
 * Does not skip 66h, 67h, or 0Fh. If any of those bytes appears anywhere in
 * the instruction, @p blocked is set and the UASM path must stay `db`.
 *
 * @param in       Instruction bytes.
 * @param blocked  Set when 66h, 67h, or 0Fh appears.
 * @return Opcode index, or @p in.size when every byte is a skipped prefix.
 */
static inline size_t listing_uasm_opcode_index(const CfgInsn& in, bool& blocked)
{
    blocked = false;
    for (uint8_t k = 0; k < in.size; ++k)
    {
        const uint8_t b = in.bytes[k];
        if (b == 0x66 || b == 0x67 || b == 0x0F)
        {
            blocked = true;
        }
    }
    size_t i = 0;
    while (i < in.size)
    {
        const uint8_t p = in.bytes[i];
        if (p == 0x26 || p == 0x2E || p == 0x36 || p == 0x3E || p == 0xF0 ||
            p == 0xF2 || p == 0xF3)
        {
            ++i;
            continue;
        }
        break;
    }
    return i;
}

/**
 * @brief 8086 name for opcodes 98h and 99h.
 *
 * Capstone may print `cwde`/`cwtl` or `cdq`/`cwtd`. A 66h prefix is not
 * skipped, so `66 98` stays `cwde`. This is not a blind rename of every
 * `cwde` inside listing_masm_mnem.
 *
 * @param in    Instruction bytes.
 * @param mnem  Lowercase mnemonic, already split from its operands.
 * @return `cbw`, `cwd`, or @p mnem unchanged.
 */
static inline std::string listing_uasm_fix_mnem(const CfgInsn& in,
                                                std::string_view mnem)
{
    bool blocked = false;
    const size_t opi = listing_uasm_opcode_index(in, blocked);
    (void)blocked;
    if (opi >= in.size)
    {
        return std::string(mnem);
    }
    const uint8_t op = in.bytes[opi];
    if (op == 0x98 && (mnem == "cwde" || mnem == "cwtl"))
    {
        return "cbw";
    }
    if (op == 0x99 && (mnem == "cdq" || mnem == "cwtd"))
    {
        return "cwd";
    }
    return std::string(mnem);
}

//=============================================================================
// Emit listing text
//=============================================================================

static inline std::string listing_emit_text(const CfgGraph& g,
                                            CfgLin entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external = nullptr)
{
    std::map<CfgLin, std::string> sym;
    std::set<CfgLin> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    listing_add_loc_labels(g, sym);
    n_insns = 0;

    std::ostringstream out;
    out << "; dumpexe multi-pass listing (not single-stream Capstone only)\n";
    out << std::format("; source: {}\n", source_name);
    out << std::format("; CS={:04X}h  entry={}h  blocks={}  symbols={}\n",
                       g.cs_seg, cfg_lin_hex(entry_ip), g.blocks.size(), sym.size());
    out << "; labels: func_<IP> for entry/call/jmp; loc_<IP> for jcc/loop on insn boundaries\n";
    out << "; call/jmp/jcc/loop near targets rewritten to labels when known\n";
    out << "; blank line after procedure regions ending in ret/retf/iret\n";
    if (external && !external->source_path.empty())
        out << std::format("; symbol map: {} ({} names)\n", external->source_path,
                           external->count);
    out << ";\n\n";

    std::vector<const CfgBlock*> order;
    order.reserve(g.blocks.size());
    for (const auto& kv : g.blocks)
        order.push_back(&kv.second);
    std::sort(order.begin(), order.end(),
              [](const CfgBlock* a, const CfgBlock* b)
              { return a->start_ip < b->start_ip; });

    // Cap emission for huge graphs (still enough for ICON entry + many procs)
    const size_t max_blocks = opts.cfgMaxBlocks ? opts.cfgMaxBlocks : 500;
    // For listing, allow more than CFG print default when user wants -d
    const size_t list_cap = std::max(max_blocks, size_t{2000});

    size_t shown = 0;
    size_t omitted = 0;
    for (const CfgBlock* bp : order)
    {
        bool has_entry = bp->is_entry || bp->start_ip == entry_ip;
        if (!has_entry)
        {
            for (const CfgInsn& in : bp->insns)
            {
                if (in.ip == entry_ip)
                {
                    has_entry = true;
                    break;
                }
            }
        }
        // Address order must not drop the block that holds the program entry.
        if (!has_entry && shown >= list_cap)
        {
            ++omitted;
            continue;
        }
        if (shown < list_cap)
        {
            ++shown;
        }
        const CfgBlock& b = *bp;

        // Label at proc start
        if (proc_starts.count(b.start_ip) || sym.count(b.start_ip))
        {
            const std::string& name =
                sym.count(b.start_ip) ? sym[b.start_ip] : listing_symbol_name(b.start_ip);
            out << name << ":";
            if (b.is_entry)
                out << "                ; entry";
            else if (b.is_table_entry)
                out << "                ; jump-table slot";
            else if (b.is_call_target)
                out << "                ; call target";
            out << "\n";
        }

        // INT annotations map by IP
        std::map<CfgLin, std::string> int_notes;
        for (const auto& site : b.ints)
        {
            std::string note;
            if (!opts.noIntAnnot)
            {
                if (site.ah != 0xFF)
                    note = format_int_annotation(site.int_num, site.ah, site.al);
                else
                    note = std::format("; INT {:02X}h", site.int_num);
                if (!site.path.empty())
                    note += std::format("  ; path \"{}\"", site.path);
            }
            int_notes[site.ip] = note;
        }

        for (const auto& in : b.insns)
        {
            ++n_insns;
            // loc_ (or other sym) that is not the block-start label already printed.
            if (in.ip != b.start_ip && sym.count(in.ip))
                out << sym[in.ip] << ":\n";
            // bytes
            std::string hex;
            for (uint8_t i = 0; i < in.size && i < 8; ++i)
                hex += std::format("{:02X}", in.bytes[i]);

            // split mnem / ops from text "mnem ops"
            std::string mnem = in.text;
            std::string ops;
            size_t sp = in.text.find(' ');
            if (sp != std::string::npos)
            {
                mnem = in.text.substr(0, sp);
                ops = in.text.substr(sp + 1);
            }
            std::string mlow = mnem;
            for (char& c : mlow)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            // Mnemonic only. Operands stay Capstone text (0x42 must survive).
            {
                const std::string fixed = listing_uasm_fix_mnem(in, mlow);
                if (fixed != mlow)
                {
                    mlow = fixed;
                    mnem = fixed;
                }
            }

            std::string rops = listing_rewrite_ops(mlow, ops, b, sym, true, g.cs_seg);
            std::string far_note;
            if (cfg_is_far_xfer(mlow))
            {
                for (const CfgEdge& e : b.outs)
                {
                    if (!e.has_target)
                    {
                        continue;
                    }
                    if (e.kind != CfgEdgeKind::Call && e.kind != CfgEdgeKind::Jump &&
                        e.kind != CfgEdgeKind::Table)
                    {
                        continue;
                    }
                    far_note = std::format("  ; → func_{}", cfg_lin_hex(e.to_ip));
                    break;
                }
            }

            out << std::format("    {}  {:<16}  {:<8} {}", cfg_lin_hex(in.ip), hex, mnem,
                               rops);
            out << far_note;

            if (int_notes.count(in.ip))
            {
                size_t line_len = mnem.size() + (rops.empty() ? 0 : 1 + rops.size());
                int pad = std::max(1, 20 - static_cast<int>(line_len));
                out << std::string(static_cast<size_t>(pad), ' ') << int_notes[in.ip];
            }
            else if (!b.tags.empty() && &in == &b.insns[0])
            {
                // tag comment on first insn
                out << "  ;";
                for (size_t t = 0; t < b.tags.size() && t < 3; ++t)
                    out << " " << b.tags[t];
            }
            out << "\n";
        }

        // Blank line after procedure region: block ends with ret and is a proc start
        // or sole successor-less ret block
        bool ends_ret = false;
        if (!b.insns.empty())
        {
            std::string tm = b.insns.back().text;
            size_t sp2 = tm.find(' ');
            std::string lastm = (sp2 == std::string::npos) ? tm : tm.substr(0, sp2);
            for (char& c : lastm)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            ends_ret = listing_is_ret_mnem(lastm);
        }
        if (ends_ret && (proc_starts.count(b.start_ip) || b.is_call_target ||
                         b.is_entry || b.is_table_entry))
            out << "\n";
    }

    if (omitted > 0)
    {
        out << std::format(
            "\n; ... {} more blocks omitted (raise --cfg-max=N for listing cap)\n",
            omitted);
        std::cerr << "listing: truncated " << omitted << " blocks\n";
    }

    out << std::format("\n; end listing: {} instructions, {} procedure labels\n",
                       n_insns, n_procs);
    return out.str();
}

//=============================================================================
// JWASM / MASM assemblable export (when toolchain is JWASM)
//=============================================================================

/// Capstone / 0x… → MASM-ish operand text for JWASM 1.8.
static inline std::string listing_masm_ops(std::string ops)
{
    // 0xAB → 0ABh (leading 0 if starts with A–F)
    std::string out;
    out.reserve(ops.size() + 8);
    for (size_t i = 0; i < ops.size();)
    {
        if (i + 2 < ops.size() && ops[i] == '0' &&
            (ops[i + 1] == 'x' || ops[i + 1] == 'X'))
        {
            size_t j = i + 2;
            while (j < ops.size() && std::isxdigit(static_cast<unsigned char>(ops[j])))
                ++j;
            std::string hex = ops.substr(i + 2, j - (i + 2));
            for (char& c : hex)
                c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
            if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F')
                out.push_back('0');
            out += hex;
            out.push_back('h');
            i = j;
            continue;
        }
        out.push_back(ops[i]);
        ++i;
    }
    // strip spaces around + - in brackets lightly
    return out;
}

static inline std::string listing_masm_mnem(std::string m)
{
    for (char& c : m)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (m == "popaw")
        return "popa";
    if (m == "pushaw")
        return "pusha";
    if (m == "retn")
        return "ret";
    if (m == "retf" || m == "retfq")
        return "retf";
    if (m == "callw")
        return "call";
    if (m == "jmpw")
        return "jmp";
    return m;
}

/**
 * @brief Emit JWASM 1.8-assemblable tiny-model source covering the full image.
 *
 * Policy: if dumpexe identifies JWASM, the .asm product must be compilable
 * with bin/jwasm/jwasm-1.8.exe (not a hex dump listing).
 */
static inline std::string listing_emit_jwasm(const CfgGraph& g,
                                            const std::vector<uint8_t>& image,
                                            CfgLin entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            const ToolchainReport& tc,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external)
{
    std::map<CfgLin, std::string> sym;
    std::set<CfgLin> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    // Index instructions by IP (first wins)
    std::map<CfgLin, CfgInsn> at;
    std::map<CfgLin, const CfgBlock*> blk_at;
    for (const auto& kv : g.blocks)
    {
        const CfgBlock& b = kv.second;
        for (const auto& in : b.insns)
        {
            if (!at.count(in.ip))
            {
                at[in.ip] = in;
                blk_at[in.ip] = &b;
            }
        }
    }

    std::ostringstream out;
    // Memory model policy:
    //   • pure .COM or COM-in-EXE → always tiny (≤64KB single segment; no exceptions)
    //   • else if --model= set → user value
    //   • else → small (default when unknown)
    const bool is_com_image = tc.com_in_exe; // COM-wrapped MZ; pure COM sets this too via caller
    std::string model;
    std::string model_why;
    if (is_com_image)
    {
        model = "tiny";
        model_why = " (forced: .COM / COM-in-EXE ≤64K — no exceptions)";
        if (opts.memModelUserSet && opts.memModel != "tiny")
            model_why += " [--model= ignored for COM]";
    }
    else if (opts.memModelUserSet)
    {
        model = opts.memModel;
        model_why = " (--model=)";
    }
    else
    {
        model = "small";
        model_why = " (default when unknown)";
    }

    out << "; dumpexe JWASM-export — assemblable with JWASM 1.80\n";
    out << std::format("; source binary: {}\n", source_name);
    out << std::format("; toolchain: {} {}\n", tc.assembler, tc.assembler_version);
    out << std::format("; memory model: {}{}\n", model, model_why);
    out << "; assemble: wine bin/jwasm/jwasm-1.8.exe -Fo out.obj this.asm\n";
    out << ";   (model is in the source via .model — do not also pass -mt/-ms)\n";
    out << "; layout: full load image as db + labels (byte-exact; disasm in comments)\n";
    if (external && !external->source_path.empty())
        out << std::format("; symbols: {}\n", external->source_path);
    out << ";\n";
    out << std::format(".model {}\n", model);
    out << ".code\n";
    // .COM / COM-in-EXE: image[0] is first COM byte at runtime org 100h
    if (model == "tiny")
        out << "org 100h\n";
    else
        out << "org 0\n";
    out << "\n";

    const size_t img_sz = image.size();
    auto emit_label = [&](CfgLin ip)
    {
        if (!sym.count(ip) && !proc_starts.count(ip))
            return;
        const std::string name =
            sym.count(ip) ? sym[ip] : listing_symbol_name(ip);
        out << name << ":";
        if (ip == entry_ip)
            out << "\t\t; entry";
        out << "\n";
    };

    auto emit_db_run = [&](size_t from, size_t to, std::string_view comment)
    {
        if (from >= to || from >= img_sz)
            return;
        if (to > img_sz)
            to = img_sz;
        for (size_t i = from; i < to;)
        {
            out << "\tdb\t";
            size_t line_end = std::min(to, i + 12);
            for (size_t j = i; j < line_end; ++j)
            {
                if (j > i)
                    out << ", ";
                // MASM: hex constants need leading digit
                out << std::format("0{:02X}h", image[j]);
            }
            if (i == from && !comment.empty())
                out << "\t; " << comment;
            out << "\n";
            i = line_end;
        }
    };

    /*
     * Byte-exact export: emit the full image as db with labels + disasm comments.
     * Capstone→MASM text is not reliable enough for JWASM 1.8 (CPU level, PTR
     * sizes, popa/pusha, …). Raw bytes always assemble and preserve layout;
     * comments keep the listing readable. Rebuild: jwasm -mt → link → com2exe.
     */
    size_t ip = 0;
    while (ip < img_sz)
    {
        const CfgLin uip = static_cast<CfgLin>(ip);
        emit_label(uip);

        auto it = at.find(uip);
        if (it != at.end() && it->second.size > 0 &&
            ip + it->second.size <= img_sz)
        {
            const CfgInsn& in = it->second;
            bool match = true;
            for (uint8_t k = 0; k < in.size; ++k)
            {
                if (image[ip + k] != in.bytes[k])
                {
                    match = false;
                    break;
                }
            }
            std::string comment;
            if (match)
            {
                std::string mnem = in.text;
                std::string ops;
                size_t sp = in.text.find(' ');
                if (sp != std::string::npos)
                {
                    mnem = in.text.substr(0, sp);
                    ops = in.text.substr(sp + 1);
                }
                std::string mlow = listing_masm_mnem(mnem);
                const CfgBlock* bp = blk_at.count(uip) ? blk_at[uip] : nullptr;
                std::string rops = ops;
                if (bp)
                    rops = listing_rewrite_ops(mlow, ops, *bp, sym);
                rops = listing_masm_ops(rops);
                comment = rops.empty() ? mlow : (mlow + " " + rops);
                ++n_insns;
                emit_db_run(ip, ip + in.size, comment);
                ip += in.size;
            }
            else
            {
                emit_db_run(ip, ip + 1, {});
                ++ip;
            }
            continue;
        }

        size_t run_end = ip + 1;
        while (run_end < img_sz)
        {
            const CfgLin u = static_cast<CfgLin>(run_end);
            if (at.count(u) || sym.count(u) || proc_starts.count(u))
                break;
            ++run_end;
        }
        emit_db_run(ip, run_end, {});
        ip = run_end;
    }

    // Entry symbol for END
    std::string entry_name =
        sym.count(entry_ip) ? sym[entry_ip] : listing_symbol_name(entry_ip);
    out << "\nend " << entry_name << "\n";
    out << std::format("; end JWASM-export: {} insns, {} labels, image {} bytes\n",
                       n_insns, n_procs, img_sz);
    return out.str();
}

//=============================================================================
// Turbo Pascal–oriented export (when TP 5.x detected)
//=============================================================================

/**
 * @brief TASM-oriented reconstruction of a Turbo Pascal load image.
 *
 * Not a .PAS source (TPC compiles Pascal). Emits:
 *   - .MODEL LARGE|SMALL|… (COM → always tiny)
 *   - PROC/ENDP around Pascal frames where detected
 *   - byte-exact db with Capstone comments (TASM can assemble the bytes)
 *   - far-call density notes for unit linkage
 *
 * Assemble sketch: tasm /ml export.asm  (object is RE aid; full EXE still from TPC)
 */
static inline std::string listing_emit_turbo_pascal(const CfgGraph& g,
                                                    const std::vector<uint8_t>& image,
                                                    CfgLin entry_ip,
                                                    const Options& opts,
                                                    const std::string& source_name,
                                                    const TurboPascalReport& tp,
                                                    bool com_in_exe,
                                                    size_t& n_procs,
                                                    size_t& n_insns,
                                                    const SymbolMap* external)
{
    std::map<CfgLin, std::string> sym;
    std::set<CfgLin> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::map<CfgLin, CfgInsn> at;
    for (const auto& kv : g.blocks)
        for (const auto& in : kv.second.insns)
            if (!at.count(in.ip))
                at[in.ip] = in;

    // Model: COM → tiny always; else --model=; else LARGE if far-heavy TP, else small
    std::string model;
    std::string model_why;
    if (com_in_exe)
    {
        model = "tiny";
        model_why = " (forced: .COM / COM-in-EXE ≤64K)";
    }
    else if (opts.memModelUserSet)
    {
        model = opts.memModel;
        model_why = " (--model=)";
    }
    else if (tp.far_calls_entry >= 4 || tp.frame_5589e5 + tp.frame_558bec >= 40)
    {
        model = "large"; // typical TP program with units / far calls
        model_why = " (auto: TP far-call / dense frames → large)";
    }
    else
    {
        model = "small";
        model_why = " (default when unknown)";
    }

    std::ostringstream out;
    out << "; dumpexe Turbo Pascal export — TASM-oriented load-image reconstruction\n";
    out << "; NOT a .PAS file (TPC compiles Pascal source; this is RE assembly)\n";
    out << std::format("; source binary: {}\n", source_name);
    out << std::format("; compiler: {} {}\n", tp.compiler, tp.version);
    if (!tp.product.empty())
        out << std::format("; product: {}\n", tp.product);
    out << std::format("; toolchain: {}\n", tp.toolchain);
    out << std::format("; memory model: {}{}\n", model, model_why);
    out << "; frames: 55 89 E5 (TP near) / 55 8B EC; RTL \"Runtime error \"\n";
    out << "; assemble (bytes): tasm /ml this.asm   →  this.obj\n";
    if (tp.version == "5.5")
    {
        out << "; original rebuild: TPC 5.5 + TASM {$L} units (see MAKECAT.BAT)\n";
    }
    else
    {
        out << std::format("; detected compiler version: {} (not a proven 5.5 rebuild)\n",
                           tp.version);
    }
    if (external && !external->source_path.empty())
        out << std::format("; symbols: {}\n", external->source_path);
    out << ";\n";

    // TASM: .MODEL TPASCAL is for TP-linked units; full EXE image uses LARGE/SMALL.
    if (model == "tiny")
        out << ".MODEL TINY\n";
    else if (model == "small")
        out << ".MODEL SMALL\n";
    else if (model == "medium")
        out << ".MODEL MEDIUM\n";
    else if (model == "compact")
        out << ".MODEL COMPACT\n";
    else if (model == "huge")
        out << ".MODEL HUGE\n";
    else
        out << ".MODEL LARGE\n";
    out << ".CODE\n";
    if (model == "tiny")
        out << "org 100h\n";
    else
        out << "org 0\n";
    out << "\n";

    const size_t img_sz = image.size();
    auto emit_db_run = [&](size_t from, size_t to, std::string_view comment)
    {
        if (from >= to || from >= img_sz)
            return;
        if (to > img_sz)
            to = img_sz;
        for (size_t i = from; i < to;)
        {
            out << "\tdb\t";
            size_t line_end = std::min(to, i + 12);
            for (size_t j = i; j < line_end; ++j)
            {
                if (j > i)
                    out << ", ";
                out << std::format("0{:02X}h", image[j]);
            }
            if (i == from && !comment.empty())
                out << "\t; " << comment;
            out << "\n";
            i = line_end;
        }
    };

    size_t ip = 0;
    bool in_proc = false;
    std::string cur_proc;
    auto close_proc = [&]()
    {
        if (in_proc)
        {
            out << cur_proc << "\tENDP\n\n";
            in_proc = false;
            cur_proc.clear();
        }
    };

    while (ip < img_sz)
    {
        const CfgLin uip = static_cast<CfgLin>(ip);

        // New procedure label
        if (sym.count(uip) || proc_starts.count(uip))
        {
            close_proc();
            const std::string name =
                sym.count(uip) ? sym[uip] : listing_symbol_name(uip);
            cur_proc = name;
            out << name;
            if (uip == entry_ip)
                out << "\tPROC\tFAR\t; program entry (CS:IP)";
            else
            {
                // Heuristic: Pascal near frame at start → NEAR PROC
                bool near_fr = false;
                if (ip + 3 <= img_sz)
                {
                    if (image[ip] == 0x55 && image[ip + 1] == 0x89 &&
                        image[ip + 2] == 0xE5)
                        near_fr = true;
                    if (image[ip] == 0x55 && image[ip + 1] == 0x8B &&
                        image[ip + 2] == 0xEC)
                        near_fr = true;
                }
                if (near_fr)
                    out << "\tPROC\tNEAR\t; Pascal frame";
                else
                    out << "\tPROC\tNEAR";
            }
            out << "\n";
            in_proc = true;
        }

        auto it = at.find(uip);
        if (it != at.end() && it->second.size > 0 &&
            ip + it->second.size <= img_sz)
        {
            const CfgInsn& in = it->second;
            bool match = true;
            for (uint8_t k = 0; k < in.size; ++k)
                if (image[ip + k] != in.bytes[k])
                {
                    match = false;
                    break;
                }
            std::string comment;
            if (match)
            {
                std::string mnem = in.text;
                std::string ops;
                size_t sp = in.text.find(' ');
                if (sp != std::string::npos)
                {
                    mnem = in.text.substr(0, sp);
                    ops = in.text.substr(sp + 1);
                }
                std::string mlow = listing_masm_mnem(mnem);
                std::string rops = listing_masm_ops(ops);
                comment = rops.empty() ? mlow : (mlow + " " + rops);
                // Tag Pascal frame / far call
                if (in.size >= 3 && in.bytes[0] == 0x55 && in.bytes[1] == 0x89 &&
                    in.bytes[2] == 0xE5)
                    comment += "  [TP near frame]";
                if (in.bytes[0] == 0x9A)
                    comment += "  [far call / unit]";
                if (in.bytes[0] == 0xCB)
                    comment += "  [retf]";
                if (in.bytes[0] == 0xC2 || in.bytes[0] == 0xC3)
                    comment += "  [ret]";
                ++n_insns;
                emit_db_run(ip, ip + in.size, comment);
                ip += in.size;
            }
            else
            {
                emit_db_run(ip, ip + 1, {});
                ++ip;
            }
            continue;
        }

        size_t run_end = ip + 1;
        while (run_end < img_sz)
        {
            const CfgLin u = static_cast<CfgLin>(run_end);
            if (at.count(u) || sym.count(u) || proc_starts.count(u))
                break;
            ++run_end;
        }
        emit_db_run(ip, run_end, {});
        ip = run_end;
    }
    close_proc();

    std::string entry_name =
        sym.count(entry_ip) ? sym[entry_ip] : listing_symbol_name(entry_ip);
    out << "\n\tEND\t" << entry_name << "\n";
    out << std::format(
        "; end Turbo Pascal export: {} insns, {} labels, image {} bytes\n", n_insns,
        n_procs, img_sz);
    return out.str();
}

//=============================================================================
// Public API
//=============================================================================

enum class ListingExportKind
{
    Human,
    Jwasm,
    TurboPascal,
    Uasm
};

//=============================================================================
// UASM export (--uasm): assemblable source, no address or hex column
//=============================================================================

/// Max bytes in one UASM segment. A 16-bit segment cannot be larger.
inline constexpr size_t kUasmSegBytes = 65536;

/**
 * @brief MASM immediate in the same 0NNh shape listing_masm_ops emits.
 *
 * @param value Unsigned immediate (8- or 16-bit).
 * @return Uppercase hex with a leading 0 when the first digit is A–F, plus h.
 */
static inline std::string listing_uasm_imm(unsigned value)
{
    std::string hex = std::format("{:X}", value);
    if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F')
    {
        hex.insert(hex.begin(), '0');
    }
    hex.push_back('h');
    return hex;
}

/**
 * @brief CPU generation a decoded instruction needs, if it is not plain 8086.
 *
 * @param in CFG instruction (raw bytes).
 * @return 0 = 8086, 1 = 186, 2 = 286, 3 = 386.
 */
static inline int listing_uasm_cpu_level(const CfgInsn& in)
{
    size_t i = 0;
    while (i < in.size)
    {
        const uint8_t p = in.bytes[i];
        if (p == 0x26 || p == 0x2E || p == 0x36 || p == 0x3E || p == 0xF0 ||
            p == 0xF2 || p == 0xF3)
        {
            ++i;
            continue;
        }
        break;
    }
    if (i >= in.size)
    {
        return 0;
    }
    const uint8_t op = in.bytes[i];
    if (op == 0x66 || op == 0x67 || op == 0x0F)
    {
        return 3;
    }
    if (op == 0x63)
    {
        return 2;
    }
    if (op == 0x60 || op == 0x61 || op == 0x62 || op == 0x68 || op == 0x69 ||
        op == 0x6A || op == 0x6B || (op >= 0x6C && op <= 0x6F) || op == 0xC0 ||
        op == 0xC1 || op == 0xC8 || op == 0xC9)
    {
        return 1;
    }
    return 0;
}

/**
 * @brief Trim leading and trailing ASCII space from @p text.
 *
 * @param text Operand fragment.
 * @return Trimmed copy. Empty when @p text is only space.
 */
static inline std::string listing_uasm_trim(std::string_view text)
{
    size_t begin = 0;
    size_t end = text.size();
    while (begin < end &&
           std::isspace(static_cast<unsigned char>(text[begin])) != 0)
    {
        ++begin;
    }
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(text[end - 1])) != 0)
    {
        --end;
    }
    return std::string(text.substr(begin, end - begin));
}

/**
 * @brief Bare string mnemonic for a string opcode, or nullptr.
 *
 * @param opcode Opcode byte after prefixes (A4–A7, AA–AF).
 * @return `movsb` and the rest, or nullptr when @p opcode is not a string op.
 */
static inline const char* listing_uasm_string_base(uint8_t opcode)
{
    switch (opcode)
    {
    case 0xA4: return "movsb";
    case 0xA5: return "movsw";
    case 0xA6: return "cmpsb";
    case 0xA7: return "cmpsw";
    case 0xAA: return "stosb";
    case 0xAB: return "stosw";
    case 0xAC: return "lodsb";
    case 0xAD: return "lodsw";
    case 0xAE: return "scasb";
    case 0xAF: return "scasw";
    default: return nullptr;
    }
}

/**
 * @brief Rewrite bare decimal immediate tokens to listing_uasm_imm form.
 *
 * A token is a maximal digit run that is not part of an identifier, has no
 * sign, and has no `h` suffix. `0xNN` is already rewritten by listing_masm_ops.
 * `1` becomes `1h`, `0` becomes `0h`.
 *
 * @param ops Operand text after listing_masm_ops.
 * @return Operand text with those immediates in 0NNh form.
 */
static inline std::string listing_uasm_decimal_imms(std::string_view ops)
{
    std::string out;
    out.reserve(ops.size() + 8);
    size_t i = 0;
    while (i < ops.size())
    {
        const unsigned char c = static_cast<unsigned char>(ops[i]);
        if (std::isdigit(c) == 0)
        {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        const bool boundary =
            (i == 0) ||
            (std::isalnum(static_cast<unsigned char>(ops[i - 1])) == 0 &&
             ops[i - 1] != '_' && ops[i - 1] != '$' && ops[i - 1] != '.');
        const bool sign = (i > 0) && (ops[i - 1] == '+' || ops[i - 1] == '-');
        size_t j = i;
        while (j < ops.size() &&
               std::isdigit(static_cast<unsigned char>(ops[j])) != 0)
        {
            ++j;
        }
        const bool suffix_h =
            (j < ops.size()) && (ops[j] == 'h' || ops[j] == 'H');
        const bool tail_ident =
            (j < ops.size()) &&
            (std::isalpha(static_cast<unsigned char>(ops[j])) != 0 ||
             ops[j] == '_');
        if (!boundary || sign || suffix_h || tail_ident || (j - i) > 8)
        {
            out.append(ops.substr(i, j - i));
            i = j;
            continue;
        }
        unsigned value = 0;
        for (size_t k = i; k < j; ++k)
        {
            value = value * 10u + static_cast<unsigned>(ops[k] - '0');
        }
        out += listing_uasm_imm(value);
        i = j;
    }
    return out;
}

/**
 * @brief Spell one UASM line from Capstone text and the raw bytes.
 *
 * Renames 98h/99h, forces CC to `int 3`, swaps `xchg reg, ax`, drops string
 * memory operands, and inserts `dword ptr` on lds/les. Does not call uasm.
 *
 * @param in    Instruction bytes.
 * @param mnem  Lowercase mnemonic from listing_masm_mnem. May be only the
 *              first word when Capstone's mnemonic itself contains a space.
 * @param ops   Operands after listing_masm_ops and decimal rewrite.
 * @return Nothing. @p mnem and @p ops are updated in place.
 */
static inline void listing_uasm_spell(const CfgInsn& in,
                                      std::string& mnem,
                                      std::string& ops)
{
    bool blocked = false;
    const size_t opi = listing_uasm_opcode_index(in, blocked);
    if (blocked || opi >= in.size)
    {
        return;
    }
    const uint8_t opcode = in.bytes[opi];
    mnem = listing_uasm_fix_mnem(in, mnem);

    if (in.size == 1 && opcode == 0xCC)
    {
        mnem = "int";
        ops = "3";
        return;
    }

    if (in.size == 1 && opcode >= 0x91 && opcode <= 0x97 && mnem == "xchg")
    {
        const size_t comma = ops.find(',');
        if (comma != std::string::npos)
        {
            const std::string left = listing_uasm_trim(ops.substr(0, comma));
            const std::string right = listing_uasm_trim(ops.substr(comma + 1));
            if (right == "ax")
            {
                ops = "ax, " + left;
            }
        }
        return;
    }

    const char* base = listing_uasm_string_base(opcode);
    if (base != nullptr && opi + 1 == in.size)
    {
        int rep = 0;
        for (size_t i = 0; i < opi; ++i)
        {
            if (in.bytes[i] == 0xF2)
            {
                rep = 2;
            }
            else if (in.bytes[i] == 0xF3)
            {
                rep = 3;
            }
        }
        if (rep == 3)
        {
            mnem = std::string("rep ") + base;
        }
        else if (rep == 2)
        {
            mnem = std::string("repne ") + base;
        }
        else
        {
            mnem = base;
        }
        ops.clear();
        return;
    }

    if ((mnem == "lds" || mnem == "les") && ops.find("ptr") != std::string::npos)
    {
        if (ops.find("byte ptr") == std::string::npos &&
            ops.find("word ptr") == std::string::npos &&
            ops.find("dword ptr") == std::string::npos)
        {
            const size_t at = ops.find("ptr");
            ops.replace(at, 3, "dword ptr");
        }
    }
}

/**
 * @brief Sized near branch to a symbol, from the displacement bytes.
 *
 * The target is `seg_base + uint16(ip16 + size + disp)` with disp
 * sign-extended. ip16 is `ip - in.seg_base`. Segment base 0 is today's
 * uint16 wrap. A near displacement does not address the next segment.
 * Far lcall/ljmp are not rewritten. No numeric IP. No per-branch uasm.
 *
 * @param in     Instruction bytes. The opcode must be the first byte.
 * @param ip     Linear address of @p in.
 * @param opcode Opcode byte (EB/E9/E8/70–7F/E0–E3).
 * @param mnem   Lowercase Capstone mnemonic (`je`, `loopne`, …).
 * @param sym    Labels already collected for this image.
 * @param line   Receives `jmp short <sym>` and the other sized forms.
 * @return true when @p sym contains the wrapped linear target.
 */
static inline bool listing_uasm_sized_branch(
    const CfgInsn& in,
    CfgLin ip,
    uint8_t opcode,
    std::string_view mnem,
    const std::map<CfgLin, std::string>& sym,
    std::string& line)
{
    if (in.size < 2 || in.bytes[0] != opcode)
    {
        return false;
    }
    bool rel8 = false;
    std::string text;
    if (opcode == 0xEB && in.size == 2)
    {
        rel8 = true;
        text = "jmp short ";
    }
    else if (opcode == 0xE9 && in.size == 3)
    {
        text = "jmp near ptr ";
    }
    else if (opcode == 0xE8 && in.size == 3)
    {
        text = "call near ptr ";
    }
    else if (opcode >= 0x70 && opcode <= 0x7F && in.size == 2)
    {
        if (mnem.empty())
        {
            return false;
        }
        rel8 = true;
        text = std::string(mnem) + " short ";
    }
    else if (opcode >= 0xE0 && opcode <= 0xE3 && in.size == 2)
    {
        if (mnem.empty())
        {
            return false;
        }
        rel8 = true;
        text = std::string(mnem) + " short ";
    }
    else
    {
        return false;
    }

    int disp = 0;
    if (rel8)
    {
        disp = static_cast<int>(static_cast<int8_t>(in.bytes[in.size - 1]));
    }
    else
    {
        const unsigned lo = in.bytes[in.size - 2];
        const unsigned hi = in.bytes[in.size - 1];
        disp = static_cast<int>(static_cast<int16_t>(lo | (hi << 8)));
    }
    const uint16_t ip16 = static_cast<uint16_t>(ip - in.seg_base);
    const int sum = static_cast<int>(ip16) + static_cast<int>(in.size) + disp;
    // A rel8 that wraps the 64 KiB segment is A2053 if emitted as `short`.
    // Near E8/E9 stay sized: the wrapped target is still inside the segment.
    if (rel8 && (sum < 0 || sum > 0xFFFF))
    {
        return false;
    }
    const uint16_t target16 = static_cast<uint16_t>(sum);
    const CfgLin target = in.seg_base + target16;
    const auto it = sym.find(target);
    if (it == sym.end())
    {
        return false;
    }
    line = text + it->second;
    return true;
}

/**
 * @brief True when UASM will encode @p mnem/@p ops back to @p in.bytes.
 *
 * Anything else is emitted as db unless isolated verify accepts it.
 * Relative branches and memory operands are not stood behind here: UASM may
 * pick a different short/near form or size. AX imm16 (opcodes
 * 05/0D/15/1D/25/2D/35/3D) is not stood behind when the immediate fits in a
 * signed byte (`imm <= 0x7F` or `imm >= 0xFF80`). UASM shortens that form to
 * `83 /r ib`. Opcode CD immediate 03 is never stood behind: UASM encodes
 * `int 3` and `int 3h` as CC.
 *
 * @param in   Instruction whose bytes already match the image.
 * @param mnem Spelled mnemonic (listing_masm_mnem, then listing_uasm_spell).
 * @param ops  Spelled operands (may be empty).
 * @return true when the spelled text is the one encoding of these bytes.
 */

static inline bool listing_uasm_stand_behind(const CfgInsn& in,
                                            std::string_view mnem,
                                            std::string_view ops)
{
    std::string got;
    got.assign(mnem);
    if (!ops.empty())
    {
        got.push_back(' ');
        got.append(ops);
    }
    for (char& c : got)
    {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    auto eq = [&](const std::string& exp) -> bool
    {
        std::string e = exp;
        for (char& c : e)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return got == e;
    };

    if (in.size == 0)
    {
        return false;
    }
    const uint8_t* b = in.bytes;
    static const char* r16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};

    if (in.size == 1)
    {
        switch (b[0])
        {
        case 0x90: return eq("nop");
        case 0xC3: return eq("ret");
        case 0xCB: return eq("retf");
        case 0xF4: return eq("hlt");
        case 0xF5: return eq("cmc");
        case 0xF8: return eq("clc");
        case 0xF9: return eq("stc");
        case 0xFA: return eq("cli");
        case 0xFB: return eq("sti");
        case 0xFC: return eq("cld");
        case 0xFD: return eq("std");
        case 0x98: return eq("cbw");
        case 0x99: return eq("cwd");
        case 0x9E: return eq("sahf");
        case 0x9F: return eq("lahf");
        case 0x9C: return eq("pushf");
        case 0x9D: return eq("popf");
        case 0x27: return eq("daa");
        case 0x2F: return eq("das");
        case 0x37: return eq("aaa");
        case 0x3F: return eq("aas");
        case 0xCE: return eq("into");
        case 0xCF: return eq("iret");
        case 0xD7: return eq("xlat") || eq("xlatb");
        case 0x06: return eq("push es");
        case 0x07: return eq("pop es");
        case 0x0E: return eq("push cs");
        case 0x16: return eq("push ss");
        case 0x17: return eq("pop ss");
        case 0x1E: return eq("push ds");
        case 0x1F: return eq("pop ds");
        case 0xCC: return eq("int 3");
        default: break;
        }
        if (b[0] >= 0x40 && b[0] <= 0x47)
        {
            return eq(std::string("inc ") + r16[b[0] - 0x40]);
        }
        if (b[0] >= 0x48 && b[0] <= 0x4F)
        {
            return eq(std::string("dec ") + r16[b[0] - 0x48]);
        }
        if (b[0] >= 0x50 && b[0] <= 0x57)
        {
            return eq(std::string("push ") + r16[b[0] - 0x50]);
        }
        if (b[0] >= 0x58 && b[0] <= 0x5F)
        {
            return eq(std::string("pop ") + r16[b[0] - 0x58]);
        }
        if (b[0] >= 0x91 && b[0] <= 0x97)
        {
            return eq(std::string("xchg ax, ") + r16[b[0] - 0x90]);
        }
        return false;
    }

    if (in.size == 2 && b[0] == 0xCD)
    {
        // int 3 / int 3h / int 03h all assemble to CC, never CD 03.
        if (b[1] == 0x03)
        {
            return false;
        }
        return eq("int " + listing_uasm_imm(b[1]));
    }
    if (in.size == 2 && b[0] >= 0xB0 && b[0] <= 0xB7)
    {
        static const char* r8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
        return eq(std::string("mov ") + r8[b[0] - 0xB0] + ", " +
                  listing_uasm_imm(b[1]));
    }
    if (in.size == 3 && b[0] >= 0xB8 && b[0] <= 0xBF)
    {
        const unsigned imm = static_cast<unsigned>(b[1]) |
                             (static_cast<unsigned>(b[2]) << 8);
        return eq(std::string("mov ") + r16[b[0] - 0xB8] + ", " + listing_uasm_imm(imm));
    }
    if (in.size == 3 && (b[0] == 0xC2 || b[0] == 0xCA))
    {
        const unsigned imm = static_cast<unsigned>(b[1]) |
                             (static_cast<unsigned>(b[2]) << 8);
        // ret 0h / retf 0h assemble as the 1-byte C3/CB forms. Keep the bytes.
        if (imm == 0)
        {
            return false;
        }
        const char* m = (b[0] == 0xC2) ? "ret " : "retf ";
        return eq(std::string(m) + listing_uasm_imm(imm));
    }
    if (in.size == 2 && (b[0] == 0x04 || b[0] == 0x0C || b[0] == 0x14 || b[0] == 0x1C ||
                         b[0] == 0x24 || b[0] == 0x2C || b[0] == 0x34 || b[0] == 0x3C))
    {
        static const char* alu[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        return eq(std::string(alu[b[0] >> 3]) + " al, " + listing_uasm_imm(b[1]));
    }
    if (in.size == 3 && (b[0] == 0x05 || b[0] == 0x0D || b[0] == 0x15 || b[0] == 0x1D ||
                         b[0] == 0x25 || b[0] == 0x2D || b[0] == 0x35 || b[0] == 0x3D))
    {
        static const char* alu[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
        const unsigned imm = static_cast<unsigned>(b[1]) |
                             (static_cast<unsigned>(b[2]) << 8);
        // UASM shortens a signed-byte AX immediate to `83 /r ib`.
        if (imm <= 0x7F || imm >= 0xFF80)
        {
            return false;
        }
        return eq(std::string(alu[b[0] >> 3]) + " ax, " + listing_uasm_imm(imm));
    }
    return false;
}

/**
 * @brief Scratch directory for one listing_emit_uasm call.
 *
 * listing_uasm_scratch_template picks the mkdtemp parent: an absolute
 * existing TMPDIR, otherwise /tmp. Destruction unlinks every directory
 * entry except "." and "..", then removes the directory, so an unexpected
 * assembler .err cannot leak a dumpexe-uasm-* directory.
 */
class ListingUasmScratch
{
public:
    /**
     * @brief Create the scratch directory and remember its paths.
     *
     * mkdtemp failure leaves the object not ready.
     */
    ListingUasmScratch()
    {
        char tmpl[kListingUasmScratchBound] = {};
        const char* env = std::getenv("TMPDIR");
        if (!listing_uasm_scratch_template(env, tmpl, sizeof(tmpl)))
        {
            return;
        }
        if (::mkdtemp(tmpl) == nullptr)
        {
            return;
        }
        dir_ = tmpl;
        asm_path_ = dir_ + "/line.asm";
        bin_path_ = dir_ + "/line.bin";
        err_path_ = dir_ + "/line.err";
        lst_path_ = dir_ + "/line.lst";
        ready_ = true;
    }

    ListingUasmScratch(const ListingUasmScratch&) = delete;

    /**
     * @brief Copying the scratch paths would double-unlink them.
     * @return Nothing. Deleted.
     */
    ListingUasmScratch& operator=(const ListingUasmScratch&) = delete;

    /**
     * @brief Unlink every scratch entry except "." and "..", then rmdir.
     * @return Nothing.
     */
    ~ListingUasmScratch()
    {
        if (dir_.empty())
        {
            return;
        }
        std::vector<std::string> names;
        if (DIR* handle = ::opendir(dir_.c_str()))
        {
            while (const dirent* ent = ::readdir(handle))
            {
                if (std::strcmp(ent->d_name, ".") == 0 ||
                    std::strcmp(ent->d_name, "..") == 0)
                {
                    continue;
                }
                names.emplace_back(ent->d_name);
            }
            ::closedir(handle);
        }
        for (const std::string& name : names)
        {
            const std::string path = dir_ + "/" + name;
            ::unlink(path.c_str());
        }
        ::rmdir(dir_.c_str());
    }

    /**
     * @brief True when mkdtemp succeeded.
     * @return false when the scratch directory was not created.
     */
    bool ready() const
    {
        return ready_;
    }

    /**
     * @brief Path of the reused assembly file.
     * @return Absolute .asm path, empty when not ready.
     */
    const std::string& asm_path() const
    {
        return asm_path_;
    }

    /**
     * @brief Path of the reused binary file.
     * @return Absolute .bin path, empty when not ready.
     */
    const std::string& bin_path() const
    {
        return bin_path_;
    }

    /**
     * @brief Scratch directory. The child assembler runs here.
     * @return Absolute directory, empty when not ready.
     */
    const std::string& dir() const
    {
        return dir_;
    }

    /**
     * @brief Path of the listing UASM writes for the one batched assemble.
     * @return Absolute .lst path, empty when not ready.
     */
    const std::string& lst_path() const
    {
        return lst_path_;
    }

    /**
     * @brief Path of the .err UASM writes beside line.asm.
     * @return Absolute .err path, empty when not ready.
     */
    const std::string& err_path() const
    {
        return err_path_;
    }

private:
    std::string dir_;
    std::string asm_path_;
    std::string bin_path_;
    std::string err_path_;
    std::string lst_path_;
    bool ready_ = false;
};

/**
 * @brief True when one spelled line may be sent to the batched assembler.
 *
 * Level 2 and 3 stay db. A line that could close the batch file, name a
 * func_/loc_ label, or exceed one instruction is rejected.
 *
 * @param line   Spelled mnemonic and operands. No newline.
 * @param level  listing_uasm_cpu_level. 0 or 1 are assembled.
 * @param nbytes Decoded instruction length.
 * @return false when the line must stay db without a spawn.
 */
static inline bool listing_uasm_line_batchable(std::string_view line,
                                               int level,
                                               size_t nbytes)
{
    if (level >= 2 || nbytes == 0 || nbytes > 16 || line.empty() || line.size() > 200)
    {
        return false;
    }
    if (line.find(';') != std::string_view::npos ||
        line.find('\n') != std::string_view::npos ||
        line.find('\r') != std::string_view::npos ||
        line.find("func_") != std::string_view::npos ||
        line.find("loc_") != std::string_view::npos)
    {
        return false;
    }
    if (line.front() == '.' || line.front() == ' ' || line.front() == '\t')
    {
        return false;
    }
    return true;
}

/**
 * @brief True when @p tok is one numeric immediate.
 *
 * The form is a leading digit, then hex digits, then an optional `h` or `H`.
 * A token that starts with a letter or `[` is not numeric.
 *
 * @param tok One operand token, already trimmed.
 * @return true when @p tok matches that immediate form.
 */
static inline bool listing_uasm_numeric_token(std::string_view tok)
{
    if (tok.empty() || tok.front() < '0' || tok.front() > '9')
    {
        return false;
    }
    size_t i = 1;
    while (i < tok.size() &&
           std::isxdigit(static_cast<unsigned char>(tok[i])) != 0)
    {
        ++i;
    }
    if (i == tok.size())
    {
        return true;
    }
    return i + 1 == tok.size() && (tok[i] == 'h' || tok[i] == 'H');
}

/**
 * @brief True when a candidate line is a branch to a numeric operand.
 *
 * Sized branches to labels return early from analyze with `n` set, so they
 * are not candidates. `ret`, `mov`, and `int` are not branches. After the
 * mnemonic, one leading size phrase (`short`, `near`, `near ptr`, `far`,
 * `far ptr`) is ignored. The rest is numeric when it is one immediate token
 * or `seg:off` with both sides in that form. A filtered line stays db.
 *
 * @param line Spelled candidate (`jae 177h`, `call near ptr 0100h`).
 * @return true when the line must not be offered to the assembler.
 */
static inline bool listing_uasm_numeric_branch(std::string_view line)
{
    size_t split = 0;
    while (split < line.size() &&
           std::isspace(static_cast<unsigned char>(line[split])) == 0)
    {
        ++split;
    }
    if (split == 0)
    {
        return false;
    }
    std::string mnem(line.substr(0, split));
    for (char& c : mnem)
    {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    static constexpr std::string_view kBranch[] = {
        "jmp",   "call",  "ja",    "jae",   "jb",    "jbe",   "jc",    "jcxz",
        "je",    "jg",    "jge",   "jl",    "jle",   "jna",   "jnae",  "jnb",
        "jnbe",  "jnc",   "jne",   "jng",   "jnge",  "jnl",   "jnle",  "jno",
        "jnp",   "jns",   "jnz",   "jo",    "jp",    "jpe",   "jpo",   "js",
        "jz",    "jecxz", "loop",  "loope", "loopne", "loopz", "loopnz",
    };
    bool branch = false;
    for (const std::string_view name : kBranch)
    {
        if (mnem == name)
        {
            branch = true;
            break;
        }
    }
    if (!branch)
    {
        return false;
    }
    std::string_view ops = line.substr(split);
    auto trim_ws = [](std::string_view text) -> std::string_view
    {
        while (!text.empty() &&
               std::isspace(static_cast<unsigned char>(text.front())) != 0)
        {
            text.remove_prefix(1);
        }
        while (!text.empty() &&
               std::isspace(static_cast<unsigned char>(text.back())) != 0)
        {
            text.remove_suffix(1);
        }
        return text;
    };
    ops = trim_ws(ops);
    auto starts_phrase = [](std::string_view text, std::string_view phrase) -> bool
    {
        if (text.size() < phrase.size())
        {
            return false;
        }
        for (size_t k = 0; k < phrase.size(); ++k)
        {
            const unsigned char c = static_cast<unsigned char>(text[k]);
            if (static_cast<char>(std::tolower(c)) != phrase[k])
            {
                return false;
            }
        }
        if (text.size() == phrase.size())
        {
            return true;
        }
        return std::isspace(static_cast<unsigned char>(text[phrase.size()])) != 0;
    };
    static constexpr std::string_view kSize[] = {
        "near ptr", "far ptr", "short", "near", "far",
    };
    for (const std::string_view phrase : kSize)
    {
        if (starts_phrase(ops, phrase))
        {
            ops.remove_prefix(phrase.size());
            break;
        }
    }
    ops = trim_ws(ops);
    if (ops.empty())
    {
        return false;
    }
    const size_t colon = ops.find(':');
    if (colon == std::string_view::npos)
    {
        if (ops.find_first_of(" \t") != std::string_view::npos)
        {
            return false;
        }
        return listing_uasm_numeric_token(ops);
    }
    if (ops.find(':', colon + 1) != std::string_view::npos)
    {
        return false;
    }
    const std::string_view seg = trim_ws(ops.substr(0, colon));
    const std::string_view off = trim_ws(ops.substr(colon + 1));
    if (seg.empty() || off.empty() ||
        seg.find_first_of(" \t") != std::string_view::npos ||
        off.find_first_of(" \t") != std::string_view::npos)
    {
        return false;
    }
    return listing_uasm_numeric_token(seg) && listing_uasm_numeric_token(off);
}

/**
 * @brief Absolute path of one regular executable, or empty.
 *
 * A directory can be X_OK and must not win. realpath runs before the child
 * chdir, so a relative --uasm-bin or $DUMPEXE_UASM still execs. PATH search
 * does not pass an empty or relative directory here.
 *
 * @param path Flag or environment path. May be relative. May be empty.
 * @return realpath of @p path when it is a regular file and executable.
 *         Empty for a directory, a missing file, or a path realpath rejects.
 */
static inline std::string listing_uasm_usable_bin(const std::string& path)
{
    if (path.empty())
    {
        return {};
    }
    struct stat st;
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
    {
        return {};
    }
    if (::access(path.c_str(), X_OK) != 0)
    {
        return {};
    }
    char* resolved = ::realpath(path.c_str(), nullptr);
    if (resolved == nullptr)
    {
        return {};
    }
    std::string out(resolved);
    std::free(resolved);
    return out;
}

/**
 * @brief Assembler for --uasm-verify. Never a built-in absolute path.
 *
 * Order: --uasm-bin, else $DUMPEXE_UASM when set and non-empty, else PATH.
 * A path the user named that is not a regular executable does not fall through.
 * An empty PATH component, or one that does not start with '/', is skipped.
 * The returned path is absolute.
 *
 * @param opts Parsed options. uasm_bin may be empty.
 * @return Executable path, or empty when verify cannot run.
 */
static inline std::string listing_uasm_resolve_bin(const Options& opts)
{
    if (!opts.uasm_bin.empty())
    {
        return listing_uasm_usable_bin(opts.uasm_bin);
    }
    if (const char* env = std::getenv("DUMPEXE_UASM"))
    {
        if (env[0] != '\0')
        {
            return listing_uasm_usable_bin(env);
        }
    }
    const char* path_env = std::getenv("PATH");
    if (path_env == nullptr)
    {
        return {};
    }
    std::string_view rest(path_env);
    while (!rest.empty())
    {
        const size_t colon = rest.find(':');
        const std::string_view dir =
            (colon == std::string_view::npos) ? rest : rest.substr(0, colon);
        // A relative or empty entry would stat ./uasm in the caller's cwd.
        if (!dir.empty() && dir.front() == '/')
        {
            std::string full(dir);
            full.push_back('/');
            full.append("uasm");
            const std::string found = listing_uasm_usable_bin(full);
            if (!found.empty())
            {
                return found;
            }
        }
        if (colon == std::string_view::npos)
        {
            break;
        }
        rest.remove_prefix(colon + 1);
    }
    return {};
}

/**
 * @brief Linear IP encoded in a func_/loc_ name.
 *
 * @param name `func_0104` or `loc_00FD`.
 * @param ip   Receives the hex suffix.
 * @return false when the suffix is not hex.
 */
static inline bool listing_uasm_sym_ip(std::string_view name, CfgLin& ip)
{
    const size_t us = name.rfind('_');
    if (us == std::string_view::npos || us + 1 >= name.size())
    {
        return false;
    }
    const std::string_view hex = name.substr(us + 1);
    if (hex.empty() || hex.size() > 8)
    {
        return false;
    }
    uint32_t value = 0;
    for (const char c : hex)
    {
        value <<= 4;
        if (c >= '0' && c <= '9')
        {
            value += static_cast<uint32_t>(c - '0');
        }
        else if (c >= 'A' && c <= 'F')
        {
            value += static_cast<uint32_t>(c - 'A' + 10);
        }
        else if (c >= 'a' && c <= 'f')
        {
            value += static_cast<uint32_t>(c - 'a' + 10);
        }
        else
        {
            return false;
        }
    }
    ip = value;
    return true;
}

/**
 * @brief One batched assemble of every unique candidate line.
 *
 * Level 0 lines are under `.8086`. Level 1 lines follow `.186`. A trailing
 * `db 0CCh` gives the last instruction a location-counter bound. The child
 * is one posix_spawn of @p asm_bin. Results are keyed by level and line text.
 */
struct ListingUasmBatch
{
    bool exit_ok = false;
    std::string version;
    std::map<std::string, std::vector<uint8_t>> bytes;
};

/**
 * @brief Cache key for one verified spelling at a CPU level.
 *
 * @param level 0 or 1.
 * @param line  Spelled text.
 * @return Key shared by the batch result map and the slice walk.
 */
static inline std::string listing_uasm_vkey(int level, std::string_view line)
{
    return std::to_string(level) + "\n" + std::string(line);
}

/**
 * @brief Spawn the assembler once and map each candidate back to its bytes.
 *
 * The child argv includes `-e100000` so UASM's default error limit does not
 * cut off a long rejected batch. Default `--uasm` does not call this.
 *
 * @param scratch  Scratch paths. The child cwd is scratch.dir().
 * @param asm_bin  Executable from listing_uasm_resolve_bin. Not hard-coded.
 * @param cands    Unique (level, line) pairs, level 0 then level 1.
 * @param out      Filled on a successful spawn, even when UASM exits non-zero.
 * @return false when the process could not be spawned or the batch file
 *         could not be written. UASM's own exit status is out.exit_ok.
 */
static inline bool listing_uasm_verify_batch(
    const ListingUasmScratch& scratch,
    const std::string& asm_bin,
    const std::vector<std::pair<int, std::string>>& cands,
    ListingUasmBatch& out)
{
    out = ListingUasmBatch{};
    if (!scratch.ready() || asm_bin.empty() || cands.empty())
    {
        return false;
    }
    ::unlink(scratch.bin_path().c_str());
    ::unlink(scratch.lst_path().c_str());
    ::unlink(scratch.err_path().c_str());
    FILE* af = std::fopen(scratch.asm_path().c_str(), "w");
    if (af == nullptr)
    {
        return false;
    }
    bool wrote = std::fputs(".8086\n.model tiny\n.code\norg 0\n", af) >= 0;
    bool any_186 = false;
    for (const auto& cand : cands)
    {
        if (cand.first <= 0)
        {
            if (wrote && std::fputs(cand.second.c_str(), af) < 0)
            {
                wrote = false;
            }
            if (wrote && std::fputc('\n', af) == EOF)
            {
                wrote = false;
            }
        }
        else
        {
            any_186 = true;
        }
    }
    if (wrote && any_186 && std::fputs(".186\n", af) < 0)
    {
        wrote = false;
    }
    if (wrote && any_186)
    {
        for (const auto& cand : cands)
        {
            if (cand.first <= 0)
            {
                continue;
            }
            if (std::fputs(cand.second.c_str(), af) < 0 || std::fputc('\n', af) == EOF)
            {
                wrote = false;
                break;
            }
        }
    }
    if (wrote && std::fputs("db 0CCh\nend\n", af) < 0)
    {
        wrote = false;
    }
    if (std::fclose(af) != 0)
    {
        wrote = false;
    }
    if (!wrote)
    {
        return false;
    }

    std::string bin_arg = scratch.bin_path();
    std::string asm_arg = scratch.asm_path();
    std::string fl_arg = "-Fl" + scratch.lst_path();
    char arg0[] = "uasm";
    char arg1[] = "-bin";
    char arg2[] = "-nologo";
    // UASM's default error limit would stop a long rejected batch.
    char arg_e[] = "-e100000";
    char arg3[] = "-Fo";
    char* argv[] = {
        arg0, arg1, arg2, arg_e, fl_arg.data(), arg3, bin_arg.data(), asm_arg.data(),
        nullptr};

    posix_spawn_file_actions_t actions;
    if (::posix_spawn_file_actions_init(&actions) != 0)
    {
        return false;
    }
    const int in_rc = ::posix_spawn_file_actions_addopen(
        &actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    const int out_rc = ::posix_spawn_file_actions_addopen(
        &actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    const int err_rc = ::posix_spawn_file_actions_addopen(
        &actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    // uasm writes <basename>.err in its cwd. Keep that file inside the scratch dir.
    const int dir_rc = ::posix_spawn_file_actions_addchdir_np(
        &actions, scratch.dir().c_str());
    if (in_rc != 0 || out_rc != 0 || err_rc != 0 || dir_rc != 0)
    {
        ::posix_spawn_file_actions_destroy(&actions);
        return false;
    }

    // UASM treats $UASM as extra sources and $INCLUDE as search paths.
    // Either can drop an .err into the scratch directory that rmdir would keep.
    extern char** environ;
    std::vector<std::string> env_store;
    if (environ != nullptr)
    {
        for (char** it = environ; *it != nullptr; ++it)
        {
            const std::string_view row(*it);
            if (row.starts_with("UASM=") || row.starts_with("INCLUDE="))
            {
                continue;
            }
            env_store.emplace_back(*it);
        }
    }
    std::vector<char*> envp;
    envp.reserve(env_store.size() + 1);
    for (std::string& row : env_store)
    {
        envp.push_back(row.data());
    }
    envp.push_back(nullptr);

    pid_t pid = 0;
    const int spawned =
        ::posix_spawn(&pid, asm_bin.c_str(), &actions, nullptr, argv, envp.data());
    ::posix_spawn_file_actions_destroy(&actions);
    if (spawned != 0)
    {
        return false;
    }
    int status = 0;
    for (;;)
    {
        const pid_t waited = ::waitpid(pid, &status, 0);
        if (waited < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return false;
        }
        break;
    }
    const bool exited = WIFEXITED(status) != 0 && WEXITSTATUS(status) == 0;

    std::ifstream lst(scratch.lst_path());
    if (!lst)
    {
        return true;
    }
    std::vector<std::pair<uint32_t, std::string>> rows;
    std::string raw;
    while (std::getline(lst, raw))
    {
        if (!raw.empty() && raw.back() == '\r')
        {
            raw.pop_back();
        }
        if (raw.starts_with("Binary Map:") || raw.starts_with("Macros:"))
        {
            break;
        }
        if (out.version.empty())
        {
            const size_t at = raw.find("UASM v");
            if (at != std::string::npos)
            {
                const size_t begin = at + 6;
                size_t end = begin;
                while (end < raw.size() && raw[end] != ',' && raw[end] != ' ')
                {
                    ++end;
                }
                if (end > begin)
                {
                    out.version = raw.substr(begin, end - begin);
                }
            }
        }
        if (raw.size() < 8)
        {
            continue;
        }
        bool addr = true;
        for (size_t i = 0; i < 8; ++i)
        {
            const char c = raw[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
            {
                addr = false;
                break;
            }
        }
        if (!addr)
        {
            continue;
        }
        uint32_t lc = 0;
        for (size_t i = 0; i < 8; ++i)
        {
            const char c = raw[i];
            lc <<= 4;
            lc += (c >= '0' && c <= '9') ? static_cast<uint32_t>(c - '0')
                                         : static_cast<uint32_t>(c - 'A' + 10);
        }
        std::string_view rest(raw);
        rest.remove_prefix(8);
        rest.remove_prefix(std::min(rest.find_first_not_of(' '), rest.size()));
        size_t hex_n = 0;
        while (hex_n < rest.size())
        {
            const char c = rest[hex_n];
            if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'))
            {
                ++hex_n;
                continue;
            }
            break;
        }
        std::string_view source = rest;
        if (hex_n >= 2 && (hex_n % 2) == 0 && hex_n < rest.size() && rest[hex_n] == ' ')
        {
            size_t sp = hex_n;
            while (sp < rest.size() && rest[sp] == ' ')
            {
                ++sp;
            }
            if (sp >= hex_n + 2 && sp < rest.size())
            {
                source = rest.substr(sp);
            }
        }
        rows.emplace_back(lc, std::string(source));
    }
    if (!exited)
    {
        return true;
    }
    std::ifstream bin(scratch.bin_path(), std::ios::binary);
    if (!bin)
    {
        return true;
    }
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(bin)),
                               std::istreambuf_iterator<char>());
    std::vector<std::pair<int, std::string>> ordered;
    ordered.reserve(cands.size());
    for (const auto& cand : cands)
    {
        if (cand.first <= 0)
        {
            ordered.push_back(cand);
        }
    }
    for (const auto& cand : cands)
    {
        if (cand.first > 0)
        {
            ordered.push_back(cand);
        }
    }
    size_t ci = 0;
    for (size_t i = 0; i < rows.size() && ci < ordered.size(); ++i)
    {
        if (rows[i].second == "db 0CCh")
        {
            continue;
        }
        if (rows[i].second != ordered[ci].second)
        {
            break;
        }
        bool have_next = false;
        uint32_t next_lc = 0;
        for (size_t j = i + 1; j < rows.size(); ++j)
        {
            next_lc = rows[j].first;
            have_next = true;
            break;
        }
        if (!have_next || next_lc < rows[i].first)
        {
            break;
        }
        const uint32_t sz = next_lc - rows[i].first;
        if (sz == 0 || sz > 16 ||
            static_cast<size_t>(rows[i].first) + static_cast<size_t>(sz) > bytes.size())
        {
            ++ci;
            continue;
        }
        const size_t at = static_cast<size_t>(rows[i].first);
        out.bytes.emplace(
            listing_uasm_vkey(ordered[ci].first, ordered[ci].second),
            std::vector<uint8_t>(bytes.begin() + static_cast<std::ptrdiff_t>(at),
                                 bytes.begin() + static_cast<std::ptrdiff_t>(at + sz)));
        ++ci;
    }
    out.exit_ok = true;
    return true;
}

/**
 * @brief 1-based batch .asm line of one candidate, if that line is a candidate.
 *
 * Layout is `.8086` / `.model tiny` / `.code` / `org 0`, then level 0 lines,
 * then `.186` when any level is positive, then those lines, then `db 0CCh`
 * and `end`. Directive lines are not candidates.
 *
 * @param cands    Lines written into this batch, level 0 then level 1.
 * @param line_no  1-based source line from a UASM diagnostic.
 * @param index    Receives the index into @p cands.
 * @return false when @p line_no is a directive, out of range, or not positive.
 */
static inline bool listing_uasm_batch_line_cand(
    const std::vector<std::pair<int, std::string>>& cands,
    int line_no,
    size_t& index)
{
    if (line_no <= 0)
    {
        return false;
    }
    std::vector<size_t> ordered;
    bool any_186 = false;
    ordered.reserve(cands.size());
    for (size_t i = 0; i < cands.size(); ++i)
    {
        if (cands[i].first <= 0)
        {
            ordered.push_back(i);
        }
    }
    for (size_t i = 0; i < cands.size(); ++i)
    {
        if (cands[i].first > 0)
        {
            any_186 = true;
            ordered.push_back(i);
        }
    }
    int line = 5;
    size_t oi = 0;
    while (oi < ordered.size() && cands[ordered[oi]].first <= 0)
    {
        if (line == line_no)
        {
            index = ordered[oi];
            return true;
        }
        ++line;
        ++oi;
    }
    if (any_186)
    {
        if (line == line_no)
        {
            return false;
        }
        ++line;
    }
    while (oi < ordered.size())
    {
        if (line == line_no)
        {
            index = ordered[oi];
            return true;
        }
        ++line;
        ++oi;
    }
    return false;
}

/**
 * @brief Source line numbers named by a UASM .err file.
 *
 * Each diagnostic looks like `line.asm(12) : Error A2210: ...`. Only the
 * first `(digits)` on a line is kept. A missing file yields an empty set.
 *
 * @param err_path Scratch .err. May not exist when UASM wrote nothing.
 * @return 1-based line numbers. Empty when none were named.
 */
static inline std::set<int> listing_uasm_err_source_lines(const std::string& err_path)
{
    std::set<int> lines;
    std::ifstream in(err_path);
    if (!in)
    {
        return lines;
    }
    std::string raw;
    while (std::getline(in, raw))
    {
        if (!raw.empty() && raw.back() == '\r')
        {
            raw.pop_back();
        }
        for (size_t i = 0; i < raw.size(); ++i)
        {
            if (raw[i] != '(')
            {
                continue;
            }
            size_t j = i + 1;
            if (j >= raw.size() || raw[j] < '0' || raw[j] > '9')
            {
                continue;
            }
            int n = 0;
            bool overflow = false;
            while (j < raw.size() && raw[j] >= '0' && raw[j] <= '9')
            {
                const int digit = raw[j] - '0';
                if (n > (1000000 - digit) / 10)
                {
                    overflow = true;
                    break;
                }
                n = n * 10 + digit;
                ++j;
            }
            if (!overflow && j < raw.size() && raw[j] == ')' && n > 0)
            {
                lines.insert(n);
            }
            break;
        }
    }
    return lines;
}

/**
 * @brief Bytes recovered from one --uasm-verify candidate list.
 *
 * `ran` is false when the assembler could not be spawned. `complete` is true
 * when every remaining group was assembled or dropped. `dropped` counts
 * candidates that were not assembled. `unverified` counts candidates still
 * queued when recovery stops, including a group popped for a spawn that
 * could not start. `bytes` holds only lines UASM encoded.
 */
struct ListingUasmVerifyOutcome
{
    bool ran = false;
    bool complete = false;
    size_t dropped = 0;
    size_t unverified = 0;
    std::string version;
    std::map<std::string, std::vector<uint8_t>> bytes;
};

/**
 * @brief Assemble candidates, dropping lines UASM rejects.
 *
 * A clean list is one posix_spawn. On a non-zero exit the scratch .err is
 * read for batch line numbers. Named candidates are removed and the rest are
 * assembled again. When the diagnostic names no candidate, the list is split.
 * A singleton that still fails is dropped. At most 16 spawns run. When the
 * cap is hit, or a spawn cannot start, `unverified` is how many candidates
 * are still queued. `complete` is `queue.empty()` on the normal exit.
 *
 * @param scratch Scratch paths. The child cwd is scratch.dir().
 * @param asm_bin Absolute assembler from listing_uasm_resolve_bin.
 * @param cands   Unique (level, line) pairs. Not empty.
 * @return Outcome. `ran` is false when the first spawn cannot start.
 */
static inline ListingUasmVerifyOutcome listing_uasm_verify_recover(
    const ListingUasmScratch& scratch,
    const std::string& asm_bin,
    const std::vector<std::pair<int, std::string>>& cands)
{
    constexpr int kSpawnCap = 16;
    ListingUasmVerifyOutcome out;
    struct Pending
    {
        std::vector<size_t> idx;
    };
    std::vector<Pending> queue;
    Pending first;
    first.idx.reserve(cands.size());
    for (size_t i = 0; i < cands.size(); ++i)
    {
        first.idx.push_back(i);
    }
    queue.push_back(std::move(first));

    auto count_queued = [&]() -> size_t
    {
        size_t total = 0;
        for (const Pending& pending : queue)
        {
            total += pending.idx.size();
        }
        return total;
    };

    bool any_spawn = false;
    int spawns = 0;
    while (!queue.empty() && spawns < kSpawnCap)
    {
        Pending group = std::move(queue.back());
        queue.pop_back();
        if (group.idx.empty())
        {
            continue;
        }
        std::vector<std::pair<int, std::string>> sub;
        sub.reserve(group.idx.size());
        for (const size_t id : group.idx)
        {
            sub.push_back(cands[id]);
        }
        ListingUasmBatch batch;
        if (!listing_uasm_verify_batch(scratch, asm_bin, sub, batch))
        {
            out.ran = any_spawn;
            out.complete = false;
            out.unverified = count_queued() + group.idx.size();
            return out;
        }
        any_spawn = true;
        ++spawns;
        if (out.version.empty() && !batch.version.empty())
        {
            out.version = std::move(batch.version);
        }
        if (batch.exit_ok)
        {
            for (auto& kv : batch.bytes)
            {
                out.bytes.insert_or_assign(kv.first, std::move(kv.second));
            }
            continue;
        }
        const std::set<int> err_lines = listing_uasm_err_source_lines(scratch.err_path());
        std::set<size_t> bad;
        for (const int line_no : err_lines)
        {
            size_t sub_i = 0;
            if (listing_uasm_batch_line_cand(sub, line_no, sub_i))
            {
                bad.insert(sub_i);
            }
        }
        if (!bad.empty())
        {
            Pending keep;
            for (size_t i = 0; i < group.idx.size(); ++i)
            {
                if (bad.count(i) != 0)
                {
                    ++out.dropped;
                }
                else
                {
                    keep.idx.push_back(group.idx[i]);
                }
            }
            if (!keep.idx.empty())
            {
                queue.push_back(std::move(keep));
            }
            continue;
        }
        if (group.idx.size() == 1)
        {
            ++out.dropped;
            continue;
        }
        const size_t mid = group.idx.size() / 2;
        Pending left;
        Pending right;
        for (size_t i = 0; i < group.idx.size(); ++i)
        {
            if (i < mid)
            {
                left.idx.push_back(group.idx[i]);
            }
            else
            {
                right.idx.push_back(group.idx[i]);
            }
        }
        queue.push_back(std::move(right));
        queue.push_back(std::move(left));
    }
    out.ran = any_spawn;
    out.complete = queue.empty();
    out.unverified = count_queued();
    return out;
}

/**
 * @brief Paragraph frame of a relocated mov r16, imm16, when Q8 applies.
 *
 * Requires an EXE load image of at most 65536 bytes (one org-0 segment, not
 * COM), opcode B8–BF at byte 0 with size 3, and a relocation on the
 * immediate word at IP+1. The frame is imm * 16. It must be <= 0xFFFF,
 * inside the image, and not strictly inside a decoded instruction. A frame
 * that starts an instruction, or that lands in db, is accepted.
 *
 * @param image     Load image. image[0] is IP 0.
 * @param at        Decoded instructions keyed by IP.
 * @param reloc_at  Fixup locations from cfg_reloc_sites. The immediate is at IP+1.
 * @param uasm_com  True for a pure COM image. Never rewritten.
 * @param ip        Opcode linear. The size gate keeps this inside one segment.
 * @param in        Decoded instruction whose bytes must match @p image.
 * @param frame_out Byte offset imm * 16 when the function returns true.
 * @return true when the emitter must print the segment expression.
 */
static inline bool listing_uasm_reloc_frame(const std::vector<uint8_t>& image,
                                            const std::map<CfgLin, CfgInsn>& at,
                                            const std::set<uint32_t>& reloc_at,
                                            bool uasm_com,
                                            CfgLin ip,
                                            const CfgInsn& in,
                                            uint32_t& frame_out)
{
    if (uasm_com || image.size() > 65536)
    {
        return false;
    }
    if (in.size != 3)
    {
        return false;
    }
    const size_t at_ip = static_cast<size_t>(ip);
    if (at_ip + 3 > image.size())
    {
        return false;
    }
    const uint8_t op = image[at_ip];
    if (op < 0xB8 || op > 0xBF || in.bytes[0] != op)
    {
        return false;
    }
    for (uint8_t k = 0; k < 3; ++k)
    {
        if (image[at_ip + k] != in.bytes[k])
        {
            return false;
        }
    }
    const uint32_t imm_at = static_cast<uint32_t>(at_ip) + 1u;
    if (!reloc_at.contains(imm_at))
    {
        return false;
    }
    const uint16_t imm = static_cast<uint16_t>(
        image[at_ip + 1] | (static_cast<unsigned>(image[at_ip + 2]) << 8));
    const uint32_t frame = static_cast<uint32_t>(imm) * 16u;
    // frame <= 0xFFFF and frame < 65536 are the same bound. The frame must
    // also be a byte that exists in this single org-0 segment.
    if (frame > 0xFFFFu || static_cast<size_t>(frame) >= image.size())
    {
        return false;
    }
    for (const auto& kv : at)
    {
        const uint32_t ip_i = kv.first;
        const uint32_t sz = kv.second.size;
        if (ip_i < frame && frame < ip_i + sz)
        {
            return false;
        }
    }
    frame_out = frame;
    return true;
}

/**
 * @brief UASM text of one relocated mov r16, imm16.
 *
 * Not assembled by --uasm-verify. The scratch file has no frame
 * label, so verify would demote a correct line to db.
 *
 * @param opcode Opcode B8+r. The low three bits select ax..di.
 * @param frame  Byte offset of the frame label (imm * 16).
 * @return `mov r16, (dxfrm_XXXX - dximg0) SHR 4` with lowercase hex.
 */
static inline std::string listing_uasm_reloc_mov_text(uint8_t opcode, uint32_t frame)
{
    static const char* r16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    const char* reg = r16[opcode - 0xB8];
    return std::format("mov {}, (dxfrm_{:04x} - dximg0) SHR 4", reg, frame);
}

/**
 * @brief True when @p c can appear in a UASM label token.
 *
 * @param c Character to test.
 * @return true for an ASCII letter, digit, or underscore.
 */
static inline bool listing_uasm_label_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_';
}

/**
 * @brief True when @p line is one label definition.
 *
 * @param line Listing line without its newline.
 * @param name Receives the identifier before the colon.
 * @return true when @p line is exactly `name:`.
 */
static inline bool listing_uasm_label_def_line(std::string_view line, std::string& name)
{
    if (line.size() < 2 || line.back() != ':')
    {
        return false;
    }
    const std::string_view body = line.substr(0, line.size() - 1);
    if (body.empty() || !listing_uasm_label_char(body.front()) ||
        (body.front() >= '0' && body.front() <= '9'))
    {
        return false;
    }
    for (const char c : body)
    {
        if (!listing_uasm_label_char(c))
        {
            return false;
        }
    }
    name.assign(body);
    return true;
}

/**
 * @brief Count `name:` lines and whole-token uses of those names.
 *
 * Definition lines are not references. Every other line counts one reference
 * per identifier token equal to a defined name, including `end func_0100`.
 *
 * @param text       Emitted UASM listing.
 * @param defined    Set to the number of definition lines.
 * @param referenced Set to the number of whole-token uses on other lines.
 */
static inline void listing_uasm_count_labels(std::string_view text,
                                            size_t& defined,
                                            size_t& referenced)
{
    defined = 0;
    referenced = 0;

    struct Line
    {
        std::string_view text;
        bool is_def = false;
    };
    std::vector<Line> lines;
    std::set<std::string, std::less<>> names;

    size_t begin = 0;
    while (begin < text.size())
    {
        const size_t nl = text.find('\n', begin);
        const size_t stop = (nl == std::string_view::npos) ? text.size() : nl;
        std::string_view line = text.substr(begin, stop - begin);
        if (!line.empty() && line.back() == '\r')
        {
            line.remove_suffix(1);
        }
        Line row;
        row.text = line;
        std::string name;
        if (listing_uasm_label_def_line(line, name))
        {
            row.is_def = true;
            ++defined;
            names.insert(std::move(name));
        }
        lines.push_back(row);
        if (nl == std::string_view::npos)
        {
            break;
        }
        begin = nl + 1;
    }

    for (const Line& row : lines)
    {
        if (row.is_def)
        {
            continue;
        }
        const std::string_view line = row.text;
        size_t i = 0;
        while (i < line.size())
        {
            if (!listing_uasm_label_char(line[i]))
            {
                ++i;
                continue;
            }
            const size_t start = i;
            ++i;
            while (i < line.size() && listing_uasm_label_char(line[i]))
            {
                ++i;
            }
            const std::string_view tok = line.substr(start, i - start);
            if (names.find(tok) != names.end())
            {
                ++referenced;
            }
        }
    }
}

/**
 * @brief Percent text for one uasm-stats field.
 *
 * @param part  Numerator.
 * @param whole Denominator. Zero yields `0.0` and does not divide.
 * @return `std::format("{:.1f}", 100.0 * part / whole)`, or `0.0`.
 */
static inline std::string listing_uasm_stats_percent(size_t part, size_t whole)
{
    if (whole == 0)
    {
        return "0.0";
    }
    return std::format("{:.1f}", 100.0 * static_cast<double>(part) /
                                     static_cast<double>(whole));
}

/**
 * @brief Print one `uasm-stats:` line to stderr.
 *
 * @param listing   Emitted UASM source (label counts come from this text).
 * @param image     Walked byte count (`emit_lo` through `image.size()`).
 * @param decoded   Sum of in-window CFG instruction sizes.
 * @param text_n    Sum of lengths of slices emitted as instructions.
 * @param verified  True only when --uasm-verify accepted every offered
 *                  candidate. Zero candidates is not verified.
 */
static inline void listing_uasm_print_stats(std::string_view listing,
                                           size_t image,
                                           size_t decoded,
                                           size_t text_n,
                                           bool verified)
{
    const size_t db = image - text_n;
    size_t defined = 0;
    size_t referenced = 0;
    listing_uasm_count_labels(listing, defined, referenced);
    std::cerr << std::format(
        "uasm-stats: image={} decoded={} ({}%) text={} ({}%) db={} ({}%) "
        "labels_defined={} labels_referenced={} verified={}\n",
        image,
        decoded,
        listing_uasm_stats_percent(decoded, image),
        text_n,
        listing_uasm_stats_percent(text_n, image),
        db,
        listing_uasm_stats_percent(db, image),
        defined,
        referenced,
        verified ? "yes" : "no");
}

/**
 * @brief How many func_/loc_ tokens are neither a label nor an equ.
 *
 * @param text Emitted UASM listing.
 * @return Number of distinct undefined func_/loc_ names.
 */
static inline size_t listing_uasm_undefined_labels(std::string_view text)
{
    std::set<std::string, std::less<>> defined;
    std::vector<std::string_view> lines;
    size_t begin = 0;
    while (begin < text.size())
    {
        const size_t nl = text.find('\n', begin);
        const size_t stop = (nl == std::string_view::npos) ? text.size() : nl;
        std::string_view line = text.substr(begin, stop - begin);
        if (!line.empty() && line.back() == '\r')
        {
            line.remove_suffix(1);
        }
        lines.push_back(line);
        std::string name;
        if (listing_uasm_label_def_line(line, name))
        {
            defined.insert(std::move(name));
        }
        else
        {
            size_t i = 0;
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
            {
                ++i;
            }
            size_t j = i;
            while (j < line.size() && listing_uasm_label_char(line[j]))
            {
                ++j;
            }
            if (j > i)
            {
                size_t k = j;
                while (k < line.size() && (line[k] == ' ' || line[k] == '\t'))
                {
                    ++k;
                }
                const std::string_view tail = line.substr(k);
                if (tail == "equ" || tail.starts_with("equ ") || tail.starts_with("equ\t"))
                {
                    defined.emplace(line.substr(i, j - i));
                }
            }
        }
        if (nl == std::string_view::npos)
        {
            break;
        }
        begin = nl + 1;
    }

    std::set<std::string, std::less<>> undef;
    for (const std::string_view line : lines)
    {
        // `; source: func_BEEF.com` is a comment, not a label reference.
        const std::string_view code = line.substr(0, line.find(';'));
        size_t i = 0;
        while (i < code.size())
        {
            if (!listing_uasm_label_char(code[i]))
            {
                ++i;
                continue;
            }
            const size_t start = i;
            ++i;
            while (i < code.size() && listing_uasm_label_char(code[i]))
            {
                ++i;
            }
            const std::string_view tok = code.substr(start, i - start);
            if (!tok.starts_with("func_") && !tok.starts_with("loc_"))
            {
                continue;
            }
            if (defined.find(tok) == defined.end())
            {
                undef.emplace(tok);
            }
        }
    }
    return undef.size();
}

/**
 * @brief True when @p tok is an equ literal UASM will read as a symbol.
 *
 * The shape is `[A-F][0-9A-F]*h` with no leading digit. `func_A004` and
 * `loc_A004` do not match. `0A004h` and `0104h` do not match.
 *
 * @param tok One identifier token from an equ right-hand side.
 * @return true when emitting @p tok would be UASM A2102.
 */
static inline bool listing_uasm_bad_equ_hex_token(std::string_view tok)
{
    if (tok.size() < 2 || tok.back() != 'h')
    {
        return false;
    }
    if (tok.front() < 'A' || tok.front() > 'F')
    {
        return false;
    }
    for (size_t i = 1; i + 1 < tok.size(); ++i)
    {
        const char c = tok[i];
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')))
        {
            return false;
        }
    }
    return true;
}

/**
 * @brief Count distinct equ RHS tokens that are not numeric literals.
 *
 * Only text before ';' is scanned, same as the undefined-label check.
 * A `func_` or `loc_` name is not this error.
 *
 * @param text Emitted UASM listing.
 * @return Number of distinct bad equ literals.
 */
static inline size_t listing_uasm_bad_equ_hex(std::string_view text)
{
    std::set<std::string, std::less<>> bad;
    size_t begin = 0;
    while (begin < text.size())
    {
        const size_t nl = text.find('\n', begin);
        const size_t stop = (nl == std::string_view::npos) ? text.size() : nl;
        std::string_view line = text.substr(begin, stop - begin);
        if (!line.empty() && line.back() == '\r')
        {
            line.remove_suffix(1);
        }
        const std::string_view code = line.substr(0, line.find(';'));
        bool seen_equ = false;
        size_t i = 0;
        while (i < code.size())
        {
            if (!listing_uasm_label_char(code[i]))
            {
                ++i;
                continue;
            }
            const size_t start = i;
            ++i;
            while (i < code.size() && listing_uasm_label_char(code[i]))
            {
                ++i;
            }
            const std::string_view tok = code.substr(start, i - start);
            if (!seen_equ)
            {
                if (tok == "equ")
                {
                    seen_equ = true;
                }
                continue;
            }
            if (listing_uasm_bad_equ_hex_token(tok))
            {
                bad.emplace(tok);
            }
        }
        if (nl == std::string_view::npos)
        {
            break;
        }
        begin = nl + 1;
    }
    return bad.size();
}

/**
 * @brief Emit UASM source that assembles back to the load image.
 *
 * No address column and no hex-byte column. Real instructions go through
 * listing_masm_mnem / listing_masm_ops, then UASM spelling. A line is kept
 * when the whitelist matches, when it is a sized near branch to a known
 * symbol, or when --uasm-verify assembles that line back to the same
 * bytes. Default --uasm does not spawn. A candidate the assembler rejects
 * stays db, and the header then does not say verified. A branch whose
 * operand is a number is not offered and stays db. When recovery stops
 * with candidates still queued, the header says how many were rejected
 * and how many were left unverified. Anything else,
 * including bytes the CFG did not decode, is `db`
 * (0NNh). An image longer than 65536 bytes is successive `sN segment`
 * / `org 0` / `sN ends` chunks (byte alignment, so uasm -mz does not pad).
 * An instruction is never split across a segment. No .stack and no REPACK-V1.
 *
 * Pure COM (not an EXE load image) uses `.model tiny` and `org 100h` and emits
 * only the program bytes, so `uasm -bin` matches the COM file. A COM memory
 * image that already contains a PSP is emitted from org 0 through that PSP,
 * then org 100h. EXE load images, including COM-in-EXE, use org 0 so the
 * `uasm -mz` payload is the full load image.
 *
 * `.8086` may precede `.model`. `.186`, `.286`, and `.386` follow `.model`.
 * UASM treats `.386` before `.MODEL` as USE32, which widens a stood-behind
 * `mov ax, imm16` with a 66h prefix. After `.model` the segment stays USE16
 * and `.386` still enables 386 mnemonics.
 *
 * A relocated mov r16, imm16 (B8–BF, size 3, no prefix) whose immediate word
 * is a fixup, and whose paragraph lands in this image and not strictly inside
 * another decoded instruction, is printed as
 * `mov rx, (dxfrm_XXXX - dximg0) SHR 4`. That line is not passed to
 * --uasm-verify and does not raise the CPU level. It is emitted
 * only for one org-0 segment (image size <= 65536, not COM). dximg0 and
 * dxfrm_ labels are registered before the slice walk, and only when at least
 * one such line is emitted.
 *
 * @param g            CFG for the image (may be empty; gaps are still emitted).
 * @param image        CS-relative bytes. COM-without-PSP includes the 256-byte hole.
 * @param entry_ip     Entry IP inside @p image (0100h for a pure COM).
 * @param opts         Model override for a normal EXE. COM forces tiny.
 * @param source_name  Comment only. Not repeated as an address column.
 * @param tc           Toolchain report; COM-in-EXE selects `.model tiny`.
 * @param uasm_com     True for a pure .COM (not an MZ load image).
 * @param uasm_com_psp True when @p image begins with a real embedded PSP.
 * @param n_procs      Set to the procedure-label count.
 * @param n_insns      Set to how many instructions were emitted as text
 *                     (whitelist, sized branch, or a successful verify).
 * @param external     Optional symbol map (same names as the human listing).
 * @param entry_in_window False when the MZ entry is outside the load image.
 * @param relocs          MZ fixups into @p image. Empty leaves immediates numeric.
 * @param uasm_status     Optional. Set to 1 when labels stay undefined, an
 *                        equ RHS token matches [A-F][0-9A-F]*h, or
 *                        --uasm-verify has no assembler. 0 otherwise.
 * @return UASM source. The last line is `end <entry label>` for COM and a
 *         one-segment image whose entry is inside the image. A multi-segment
 *         image, or an entry outside the image, ends with a bare `end`.
 * @note When @p opts has both --uasm and --uasm-stats, one `uasm-stats:` line
 *       is written to stderr. The line is not part of the returned source.
 */
static inline std::string listing_emit_uasm(const CfgGraph& g,
                                            const std::vector<uint8_t>& image,
                                            CfgLin entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            const ToolchainReport* tc,
                                            bool uasm_com,
                                            bool uasm_com_psp,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external,
                                            bool entry_in_window = true,
                                            std::span<const RelocEntry> relocs = {},
                                            int* uasm_status = nullptr)
{
    if (uasm_status != nullptr)
    {
        *uasm_status = 0;
    }
    std::map<CfgLin, std::string> sym;
    std::set<CfgLin> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    listing_add_loc_labels(g, sym);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::map<CfgLin, CfgInsn> at;
    std::map<CfgLin, const CfgBlock*> blk_at;
    for (const auto& kv : g.blocks)
    {
        const CfgBlock& b = kv.second;
        for (const auto& in : b.insns)
        {
            if (!at.count(in.ip))
            {
                at[in.ip] = in;
                blk_at[in.ip] = &b;
            }
        }
    }

    // CPU level comes only from instructions this emitter prints. Data that
    // Capstone decoded is not a .386/.286/.186 directive.
    int cpu = 0;

    const std::string entry_name =
        sym.count(entry_ip) ? sym[entry_ip] : listing_symbol_name(entry_ip);

    struct Slice
    {
        size_t off = 0;
        size_t len = 0;
        bool insn = false;
        std::string text;
        std::vector<std::string> labels;
        bool sized_branch = false;
        bool branch_ip_ok = false;
        std::string branch_sym;
        CfgLin branch_ip = 0;
    };

    const size_t emit_lo = (uasm_com && !uasm_com_psp)
                               ? static_cast<size_t>(0x100)
                               : static_cast<size_t>(0);
    std::vector<Slice> slices;
    size_t off = emit_lo > image.size() ? image.size() : emit_lo;

    // Q8 labels must exist before the left-to-right slice walk. A frame that
    // sits before its mov is already missed if the label is added inside stood().
    const std::set<uint32_t> reloc_at = cfg_reloc_sites(image, relocs);
    std::set<uint32_t> q8_frames;
    if (!reloc_at.empty() && !uasm_com && image.size() <= 65536)
    {
        for (const auto& kv : at)
        {
            uint32_t frame = 0;
            if (listing_uasm_reloc_frame(image, at, reloc_at, uasm_com, kv.first,
                                         kv.second, frame))
            {
                q8_frames.insert(frame);
            }
        }
    }
    const bool q8_any = !q8_frames.empty();

    auto labels_at = [&](size_t at_off) -> std::vector<std::string>
    {
        std::vector<std::string> labs;
        const CfgLin ip = static_cast<CfgLin>(at_off);
        if (sym.count(ip))
        {
            labs.push_back(sym[ip]);
        }
        else if (proc_starts.count(ip) || (entry_in_window && ip == entry_ip))
        {
            labs.push_back(listing_symbol_name(ip));
        }
        if (q8_any && at_off == 0)
        {
            labs.push_back("dximg0");
        }
        if (q8_any && q8_frames.count(static_cast<uint32_t>(at_off)) != 0)
        {
            labs.push_back(std::format("dxfrm_{:04x}", at_off));
        }
        return labs;
    };

    struct Classified
    {
        size_t n = 0;
        std::string text;
        bool whitelist = false;
        bool branch = false;
        bool branch_ip_ok = false;
        std::string branch_sym;
        CfgLin branch_ip = 0;
        int level = 0;
        std::string candidate;
    };

    auto analyze = [&](size_t at_off) -> Classified
    {
        Classified c;
        const CfgLin ip = static_cast<CfgLin>(at_off);
        const auto it = at.find(ip);
        if (it == at.end() || it->second.size == 0)
        {
            return c;
        }
        const CfgInsn& in = it->second;
        if (at_off + in.size > image.size())
        {
            return c;
        }
        for (uint8_t k = 0; k < in.size; ++k)
        {
            if (image[at_off + k] != in.bytes[k])
            {
                return c;
            }
        }
        uint32_t q8_frame = 0;
        if (listing_uasm_reloc_frame(image, at, reloc_at, uasm_com, ip, in, q8_frame))
        {
            // Skip the whitelist and the verifier. Do not raise cpu.
            c.n = in.size;
            c.text = listing_uasm_reloc_mov_text(image[at_off], q8_frame);
            return c;
        }
        bool blocked = false;
        const size_t opi = listing_uasm_opcode_index(in, blocked);
        if (blocked || opi >= in.size)
        {
            return c;
        }
        const uint8_t opcode = in.bytes[opi];
        std::string mnem = in.text;
        std::string ops;
        const size_t sp = in.text.find(' ');
        if (sp != std::string::npos)
        {
            mnem = in.text.substr(0, sp);
            ops = in.text.substr(sp + 1);
        }
        std::string mlow = listing_masm_mnem(mnem);
        std::string branch;
        if (listing_uasm_sized_branch(in, ip, opcode, mlow, sym, branch))
        {
            c.n = in.size;
            c.branch = true;
            c.text = std::move(branch);
            const size_t bsp = c.text.rfind(' ');
            if (bsp != std::string::npos && bsp + 1 < c.text.size())
            {
                c.branch_sym = c.text.substr(bsp + 1);
                CfgLin tip = 0;
                if (listing_uasm_sym_ip(c.branch_sym, tip))
                {
                    c.branch_ip = tip;
                    c.branch_ip_ok = true;
                }
            }
            return c;
        }
        std::string rops = ops;
        const CfgBlock* bp = blk_at.count(ip) ? blk_at[ip] : nullptr;
        if (bp != nullptr)
        {
            rops = listing_rewrite_ops(mlow, ops, *bp, sym);
        }
        rops = listing_masm_ops(rops);
        rops = listing_uasm_decimal_imms(rops);
        listing_uasm_spell(in, mlow, rops);
        const std::string line = rops.empty() ? mlow : (mlow + " " + rops);
        const int level = listing_uasm_cpu_level(in);
        if (listing_uasm_stand_behind(in, mlow, rops))
        {
            c.n = in.size;
            c.whitelist = true;
            c.level = level;
            c.text = line;
            return c;
        }
        c.level = level;
        c.candidate = line;
        return c;
    };

    // Default --uasm does not spawn. --uasm-verify batches every unique line.
    // One rejected candidate is dropped and retried; it must not mark the
    // whole listing verified. A numeric branch operand is not offered.
    // Zero candidates after the assembler path resolved is not verified and
    // does not spawn.
    bool verified_ok = false;
    bool verify_no_cands = false;
    size_t verify_rejected = 0;
    size_t verify_unverified = 0;
    std::string verified_path;
    std::string verified_ver;
    std::map<std::string, std::vector<uint8_t>> verified_bytes;
    if (opts.uasm_verify)
    {
        verified_path = listing_uasm_resolve_bin(opts);
        if (verified_path.empty())
        {
            std::cerr << "listing: --uasm-verify: assembler not found\n";
            if (uasm_status != nullptr)
            {
                *uasm_status = 1;
            }
        }
        else
        {
            std::vector<std::pair<int, std::string>> cands;
            std::set<std::string> seen;
            for (const auto& kv : at)
            {
                const Classified seen_c = analyze(kv.first);
                if (seen_c.candidate.empty() ||
                    !listing_uasm_line_batchable(seen_c.candidate, seen_c.level,
                                                 kv.second.size) ||
                    listing_uasm_numeric_branch(seen_c.candidate))
                {
                    continue;
                }
                const std::string key = listing_uasm_vkey(seen_c.level, seen_c.candidate);
                if (!seen.insert(key).second)
                {
                    continue;
                }
                cands.emplace_back(seen_c.level, seen_c.candidate);
            }
            if (cands.empty())
            {
                verify_no_cands = true;
            }
            else
            {
                ListingUasmScratch scratch;
                if (!scratch.ready())
                {
                    std::cerr << "listing: --uasm-verify: cannot run assembler\n";
                    if (uasm_status != nullptr)
                    {
                        *uasm_status = 1;
                    }
                }
                else
                {
                    const ListingUasmVerifyOutcome got =
                        listing_uasm_verify_recover(scratch, verified_path, cands);
                    if (!got.ran)
                    {
                        std::cerr << "listing: --uasm-verify: cannot run assembler\n";
                        if (uasm_status != nullptr)
                        {
                            *uasm_status = 1;
                        }
                    }
                    else
                    {
                        verified_ver = got.version;
                        verified_bytes = got.bytes;
                        if (got.dropped == 0 && got.complete)
                        {
                            verified_ok = true;
                        }
                        else if (got.unverified > 0)
                        {
                            verify_rejected = got.dropped;
                            verify_unverified = got.unverified;
                            std::cerr << std::format(
                                "listing: --uasm-verify: {}\n",
                                listing_uasm_rejected_clause(got.dropped,
                                                             got.unverified));
                        }
                        else if (got.dropped > 0)
                        {
                            verify_rejected = got.dropped;
                            std::cerr << std::format(
                                "listing: --uasm-verify: {}\n",
                                listing_uasm_rejected_clause(got.dropped, 0));
                        }
                    }
                }
            }
        }
    }

    auto commit = [&](size_t at_off, Classified& outc) -> size_t
    {
        outc = analyze(at_off);
        if (outc.n > 0)
        {
            if (outc.whitelist)
            {
                cpu = std::max(cpu, outc.level);
            }
            return outc.n;
        }
        if (outc.candidate.empty() || !opts.uasm_verify)
        {
            return 0;
        }
        const auto found = verified_bytes.find(listing_uasm_vkey(outc.level, outc.candidate));
        if (found == verified_bytes.end())
        {
            return 0;
        }
        const auto it = at.find(static_cast<CfgLin>(at_off));
        if (it == at.end() || found->second.size() != it->second.size ||
            std::memcmp(found->second.data(), it->second.bytes, it->second.size) != 0)
        {
            return 0;
        }
        cpu = std::max(cpu, outc.level);
        outc.n = it->second.size;
        outc.text = outc.candidate;
        return outc.n;
    };

    while (off < image.size())
    {
        Classified got;
        const size_t n = commit(off, got);
        Slice sl;
        sl.off = off;
        sl.labels = labels_at(off);
        if (n > 0)
        {
            sl.len = n;
            sl.insn = true;
            sl.text = std::move(got.text);
            sl.sized_branch = got.branch;
            sl.branch_ip_ok = got.branch_ip_ok;
            sl.branch_sym = std::move(got.branch_sym);
            sl.branch_ip = got.branch_ip;
            ++n_insns;
            off += n;
        }
        else
        {
            size_t run = off + 1;
            while (run < image.size())
            {
                if (!labels_at(run).empty())
                {
                    break;
                }
                Classified ignore;
                if (commit(run, ignore) > 0)
                {
                    break;
                }
                ++run;
            }
            sl.len = run - off;
            sl.insn = false;
            off = run;
        }
        slices.push_back(std::move(sl));
    }

    struct Seg
    {
        std::vector<Slice> slices;
        size_t nbytes = 0;
    };
    std::vector<Seg> segs;
    Seg cur;
    auto flush_seg = [&]()
    {
        if (cur.nbytes == 0)
        {
            return;
        }
        segs.push_back(std::move(cur));
        cur = Seg{};
    };
    for (const Slice& sl : slices)
    {
        size_t left = sl.len;
        size_t done = 0;
        bool labs = true;
        while (left > 0)
        {
            if (cur.nbytes >= kUasmSegBytes)
            {
                flush_seg();
            }
            const size_t room = kUasmSegBytes - cur.nbytes;
            if (sl.insn && sl.len > room)
            {
                flush_seg();
                continue;
            }
            const size_t take = sl.insn ? sl.len : std::min(left, room);
            Slice part;
            part.off = sl.off + done;
            part.len = take;
            part.insn = sl.insn;
            part.sized_branch = sl.sized_branch;
            part.branch_ip_ok = sl.branch_ip_ok;
            part.branch_sym = sl.branch_sym;
            part.branch_ip = sl.branch_ip;
            if (sl.insn)
            {
                part.text = sl.text;
            }
            if (labs)
            {
                part.labels = sl.labels;
                labs = false;
            }
            cur.nbytes += take;
            cur.slices.push_back(std::move(part));
            done += take;
            left -= take;
            if (cur.nbytes >= kUasmSegBytes)
            {
                flush_seg();
            }
        }
    }
    flush_seg();
    if (segs.empty())
    {
        segs.push_back(Seg{});
    }

    const bool tiny = uasm_com || (tc && tc->com_in_exe);
    std::string model;
    if (tiny)
    {
        model = "tiny";
    }
    else if (opts.memModelUserSet)
    {
        model = opts.memModel;
    }
    else
    {
        model = "small";
    }

    const char* cpu_dir = ".8086";
    if (cpu >= 3)
    {
        cpu_dir = ".386";
    }
    else if (cpu >= 2)
    {
        cpu_dir = ".286";
    }
    else if (cpu >= 1)
    {
        cpu_dir = ".186";
    }

    const bool multi = segs.size() > 1;
    // Past 64 KiB the image is sN segment blocks. COM stays one .code segment.
    // uasm -bin accepts "end func_XXXX" only when that label is in UASM's
    // first segment. .model tiny + .code is that case. .model small opens
    // its own segment before s0, so "end func_XXXX" is error A2203. A bare
    // "end" is valid for both -bin and -mz. An in-image entry past 64 KiB
    // keeps its real label inside sN. An entry outside the image is not
    // labeled func_FFFF.
    const bool use_segments = multi && !uasm_com;

    struct SegSpan
    {
        bool has_org = false;
        uint32_t org = 0;
        size_t start = 0;
        size_t end = 0;
    };
    std::vector<SegSpan> spans(segs.size());
    for (size_t si = 0; si < segs.size(); ++si)
    {
        if (segs[si].slices.empty())
        {
            continue;
        }
        spans[si].start = segs[si].slices.front().off;
        spans[si].end = segs[si].slices.back().off + segs[si].slices.back().len;
        if (!(use_segments || si == 0))
        {
            continue;
        }
        spans[si].has_org = true;
        spans[si].org = (uasm_com && !uasm_com_psp) ? 0x100u : 0u;
    }

    std::set<std::string, std::less<>> defined_labs;
    bool entry_labeled = false;
    for (const Seg& seg : segs)
    {
        for (const Slice& sl : seg.slices)
        {
            for (const std::string& lab : sl.labels)
            {
                defined_labs.insert(lab);
                if (lab == entry_name)
                {
                    entry_labeled = true;
                }
            }
        }
    }
    if (!entry_labeled && entry_in_window && !use_segments)
    {
        defined_labs.insert(entry_name);
    }

    std::map<std::string, CfgLin, std::less<>> needed;
    std::map<std::string, std::set<size_t>, std::less<>> ref_segs;
    std::set<std::string, std::less<>> failed_equ;
    for (size_t si = 0; si < segs.size(); ++si)
    {
        for (const Slice& sl : segs[si].slices)
        {
            if (!sl.sized_branch || sl.branch_sym.empty())
            {
                continue;
            }
            if (defined_labs.count(sl.branch_sym) != 0)
            {
                continue;
            }
            if (!sl.branch_ip_ok)
            {
                failed_equ.insert(sl.branch_sym);
                continue;
            }
            needed.emplace(sl.branch_sym, sl.branch_ip);
            ref_segs[sl.branch_sym].insert(si);
        }
    }

    struct EquAt
    {
        bool ok = false;
        size_t seg = 0;
        uint32_t org = 0;
        uint32_t addr = 0;
    };
    auto express = [&](CfgLin target) -> EquAt
    {
        EquAt equ;
        for (size_t si = 0; si < spans.size(); ++si)
        {
            if (segs[si].slices.empty())
            {
                continue;
            }
            if (target < spans[si].start || target >= spans[si].end)
            {
                continue;
            }
            if (!spans[si].has_org)
            {
                return equ;
            }
            const uint64_t addr = static_cast<uint64_t>(spans[si].org) +
                                  (static_cast<uint64_t>(target) - spans[si].start);
            if (addr > 0xFFFFu)
            {
                return equ;
            }
            equ.ok = true;
            equ.seg = si;
            equ.org = spans[si].org;
            equ.addr = static_cast<uint32_t>(addr);
            return equ;
        }
        for (size_t si = 0; si < spans.size(); ++si)
        {
            if (!spans[si].has_org || segs[si].slices.empty())
            {
                continue;
            }
            if (target < spans[si].start)
            {
                if (si != 0 || target > 0xFFFFu)
                {
                    continue;
                }
                equ.ok = true;
                equ.seg = 0;
                equ.org = spans[0].org;
                equ.addr = static_cast<uint32_t>(target);
                return equ;
            }
            if (target < spans[si].start + kUasmSegBytes)
            {
                const uint64_t addr = static_cast<uint64_t>(spans[si].org) +
                                      (static_cast<uint64_t>(target) - spans[si].start);
                if (addr > 0xFFFFu)
                {
                    continue;
                }
                equ.ok = true;
                equ.seg = si;
                equ.org = spans[si].org;
                equ.addr = static_cast<uint32_t>(addr);
                return equ;
            }
        }
        return equ;
    };
    auto equ_hex = [](uint32_t value, bool org_term) -> std::string
    {
        if (org_term)
        {
            return value == 0 ? std::string("0") : listing_uasm_imm(value);
        }
        if (value <= 0xFFFFu)
        {
            // UASM reads A004h as a symbol (A2102). Keep four digits when the
            // first is 0-9; prepend one 0 when it is A-F. Not {:05X}.
            std::string hex = std::format("{:04X}", value);
            if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F')
            {
                hex.insert(hex.begin(), '0');
            }
            hex.push_back('h');
            return hex;
        }
        std::string hex = std::format("{:X}", value);
        if (!hex.empty() && hex[0] >= 'A' && hex[0] <= 'F')
        {
            hex.insert(hex.begin(), '0');
        }
        hex.push_back('h');
        return hex;
    };

    std::map<size_t, std::vector<std::string>> equ_by_seg;
    for (const auto& kv : needed)
    {
        const std::string& name = kv.first;
        const bool flabel = name.starts_with("func_") || name.starts_with("loc_");
        const EquAt at_equ = flabel ? express(kv.second) : EquAt{};
        if (!flabel || !at_equ.ok)
        {
            failed_equ.insert(name);
            continue;
        }
        // A near call cannot name a symbol in another UASM segment (A2170).
        bool cross = false;
        const auto refs = ref_segs.find(name);
        if (refs != ref_segs.end())
        {
            for (const size_t si : refs->second)
            {
                if (si != at_equ.seg)
                {
                    cross = true;
                    break;
                }
            }
        }
        if (cross)
        {
            failed_equ.insert(name);
            continue;
        }
        equ_by_seg[at_equ.seg].push_back(std::format(
            "{} equ s{}_base+({}-{})",
            name,
            at_equ.seg,
            equ_hex(at_equ.addr, false),
            equ_hex(at_equ.org, true)));
    }
    // A sized branch to a label defined on a slice in another sN segment is
    // A2170. Equs and undefined names are already in failed_equ and demote
    // every use. A defined label demotes only the slice whose segment is not
    // lab_seg, so a same-segment sized use of that name stays. This is the
    // only demotion, so n_insns drops once per demoted slice.
    std::map<std::string, size_t, std::less<>> lab_seg;
    for (size_t si = 0; si < segs.size(); ++si)
    {
        for (const Slice& sl : segs[si].slices)
        {
            for (const std::string& lab : sl.labels)
            {
                lab_seg.emplace(lab, si);
            }
        }
    }
    for (size_t si = 0; si < segs.size(); ++si)
    {
        for (Slice& sl : segs[si].slices)
        {
            if (!sl.sized_branch || sl.branch_sym.empty())
            {
                continue;
            }
            const auto found = lab_seg.find(sl.branch_sym);
            const bool cross = found != lab_seg.end() && found->second != si;
            if (failed_equ.count(sl.branch_sym) == 0 && !cross)
            {
                continue;
            }
            sl.insn = false;
            sl.sized_branch = false;
            sl.text.clear();
            sl.branch_sym.clear();
            if (n_insns > 0)
            {
                --n_insns;
            }
        }
    }

    std::ostringstream out;
    // .386 before .model is USE32 in UASM and widens imm16 mov. .8086 is safe
    // above .model; .186/.286/.386 stay below it so the segment remains USE16.
    if (cpu == 0)
    {
        out << cpu_dir << "\n";
    }
    out << "; dumpexe UASM export\n";
    out << std::format("; source: {}\n", source_name);
    if (!entry_in_window)
    {
        out << "; entry is past the 64 KiB decode window\n";
    }
    if (verified_ok)
    {
        if (verified_ver.empty())
        {
            out << std::format("; verified: uasm at {}\n", verified_path);
        }
        else
        {
            out << std::format("; verified: uasm {} at {}\n", verified_ver, verified_path);
        }
    }
    else if (verify_unverified > 0)
    {
        // Singular only when the rejected count is 1. Zero stays plural.
        out << std::format(
            "; NOT VERIFIED ({})\n",
            listing_uasm_rejected_clause(verify_rejected, verify_unverified));
    }
    else if (verify_rejected > 0)
    {
        out << std::format(
            "; NOT VERIFIED ({})\n",
            listing_uasm_rejected_clause(verify_rejected, 0));
    }
    else if (verify_no_cands)
    {
        out << "; NOT VERIFIED (0 candidates)\n";
    }
    else
    {
        out << "; NOT VERIFIED\n";
    }
    out << std::format(".model {}\n", model);
    if (cpu != 0)
    {
        out << cpu_dir << "\n";
    }

    auto emit_db = [&](size_t db_off, size_t db_len)
    {
        size_t i = 0;
        while (i < db_len)
        {
            size_t run = 1;
            while (i + run < db_len && image[db_off + i + run] == image[db_off + i])
            {
                ++run;
            }
            if (run >= 8)
            {
                out << "    db " << run << " dup ("
                    << std::format("0{:02X}h", image[db_off + i]) << ")\n";
                i += run;
                continue;
            }
            out << "    db ";
            size_t produced = 0;
            while (i < db_len && produced < 12)
            {
                size_t r = 1;
                while (i + r < db_len && image[db_off + i + r] == image[db_off + i])
                {
                    ++r;
                }
                if (r >= 8)
                {
                    break;
                }
                if (produced)
                {
                    out << ", ";
                }
                out << std::format("0{:02X}h", image[db_off + i]);
                ++i;
                ++produced;
            }
            out << "\n";
        }
    };

    bool saw_entry = false;
    auto emit_slice = [&](const Slice& sl)
    {
        for (const std::string& lab : sl.labels)
        {
            out << lab << ":\n";
            if (lab == entry_name)
            {
                saw_entry = true;
            }
        }
        if (sl.len == 0)
        {
            return;
        }
        if (sl.insn)
        {
            out << "    " << sl.text << "\n";
            return;
        }
        emit_db(sl.off, sl.len);
    };

    auto emit_base = [&](size_t seg_index)
    {
        const auto it = equ_by_seg.find(seg_index);
        if (it == equ_by_seg.end())
        {
            return;
        }
        out << "s" << seg_index << "_base:\n";
        for (const std::string& eq : it->second)
        {
            out << eq << "\n";
        }
    };

    auto emit_seg_body = [&](const Seg& seg, bool first_code, size_t seg_index)
    {
        if (!uasm_com)
        {
            if (first_code || use_segments)
            {
                out << "org 0\n";
                emit_base(seg_index);
            }
            for (const Slice& sl : seg.slices)
            {
                emit_slice(sl);
            }
            return;
        }
        if (uasm_com_psp)
        {
            if (first_code)
            {
                out << "org 0\n";
                emit_base(seg_index);
            }
            bool org100 = false;
            for (const Slice& sl : seg.slices)
            {
                if (!org100 && sl.off >= 0x100)
                {
                    out << "org 100h\n";
                    org100 = true;
                }
                emit_slice(sl);
            }
            if (first_code && !org100)
            {
                out << "org 100h\n";
            }
            return;
        }
        if (first_code)
        {
            out << "org 100h\n";
            emit_base(seg_index);
        }
        for (const Slice& sl : seg.slices)
        {
            emit_slice(sl);
        }
    };

    if (!use_segments)
    {
        bool first = true;
        size_t n = 0;
        for (const Seg& seg : segs)
        {
            out << ".code\n";
            emit_seg_body(seg, first, n);
            first = false;
            ++n;
        }
    }
    else
    {
        size_t n = 0;
        for (const Seg& seg : segs)
        {
            out << "s" << n << " segment byte public 'CODE'\n";
            emit_seg_body(seg, n == 0, n);
            out << "s" << n << " ends\n";
            ++n;
        }
    }

    if (use_segments || !entry_in_window)
    {
        out << "end\n";
    }
    else
    {
        if (!saw_entry)
        {
            out << entry_name << ":\n";
        }
        out << "end " << entry_name << "\n";
    }
    const std::string listing = out.str();
    if (opts.uasm && opts.uasm_stats)
    {
        const size_t image_n =
            (emit_lo < image.size()) ? (image.size() - emit_lo) : size_t{0};
        size_t decoded_n = 0;
        for (const auto& kv : at)
        {
            const size_t ip = kv.first;
            const size_t sz = kv.second.size;
            if (ip >= emit_lo && ip + sz <= image.size())
            {
                decoded_n += sz;
            }
        }
        size_t text_n = 0;
        for (const Seg& seg : segs)
        {
            for (const Slice& sl : seg.slices)
            {
                if (sl.insn)
                {
                    text_n += sl.len;
                }
            }
        }
        listing_uasm_print_stats(listing, image_n, decoded_n, text_n, verified_ok);
    }
    const size_t undef = listing_uasm_undefined_labels(listing);
    if (undef != 0)
    {
        std::cerr << "listing: " << undef << " undefined labels\n";
        if (uasm_status != nullptr)
        {
            *uasm_status = 1;
        }
    }
    const size_t bad_hex = listing_uasm_bad_equ_hex(listing);
    if (bad_hex != 0)
    {
        std::cerr << "listing: " << bad_hex << " invalid equ hex literals\n";
        if (uasm_status != nullptr)
        {
            *uasm_status = 1;
        }
    }
    return listing;
}

/**
 * @brief Build multi-pass listing text for a CS-relative image.
 * @param relocs MZ fixups into the load image. Passed to the CFG and to --uasm.
 * @param cfg_out Optional annotated CFG. Assigned only when
 *        @c cfg_build_annotated ran. Left untouched when null, when
 *        @p entry_in_window is false, or when the image slice is empty.
 * @param entry_seg_base Segment base of @p entry_ip (`cs * 16`). 0 for COM
 *        and for an entry outside the image.
 * @return false on hard failure (empty image / capstone)
 */
static inline bool listing_generate(const std::vector<uint8_t>& fileData,
                                    size_t image_file_off,
                                    size_t image_len,
                                    CfgLin entry_ip,
                                    uint16_t cs_seg,
                                    uint16_t file_cs,
                                    const Options& opts,
                                    const std::string& source_name,
                                    std::string& out_text,
                                    size_t& n_procs,
                                    size_t& n_insns,
                                    ListingExportKind& kind_out,
                                    const ToolchainReport* tc = nullptr,
                                    const TurboPascalReport* tp = nullptr,
                                    bool uasm_com = false,
                                    bool uasm_com_psp = false,
                                    std::string* human_stdout = nullptr,
                                    bool entry_in_window = true,
                                    std::span<const RelocEntry> relocs = {},
                                    CfgGraph* cfg_out = nullptr,
                                    CfgLin entry_seg_base = 0,
                                    int* uasm_status = nullptr)
{
    out_text.clear();
    n_procs = 0;
    n_insns = 0;
    kind_out = ListingExportKind::Human;
    if (human_stdout)
        human_stdout->clear();
    if (image_file_off >= fileData.size())
        return false;
    size_t len = std::min(image_len, fileData.size() - image_file_off);
    if (len == 0)
        return false;

    Options cfg_opts = opts;
    cfg_opts.showCfg = false;
    CfgGraph g{};
    // An entry outside the image is not seeded. *cfg_out stays untouched
    // on that path so the caller can still build from linear 0.
    if (entry_in_window)
    {
        g = cfg_build_annotated(fileData, image_file_off, len, entry_ip, cs_seg,
                                file_cs, cfg_opts, relocs, entry_seg_base,
                                uasm_com ? dx::Fmt::Com : dx::Fmt::Mz, uasm_com);
        if (cfg_out != nullptr)
        {
            // Printers do not read flow. Move it aside so the copy does not
            // duplicate the trace, then put it back on the local graph.
            std::optional<dx::FlowTrace> held = std::move(g.flow);
            g.flow.reset();
            *cfg_out = g;
            g.flow = std::move(held);
        }
    }
    if (g.blocks.empty() && !opts.uasm)
    {
        out_text = "; dumpexe listing: no basic blocks recovered\n";
        return true;
    }

    SymbolMap sm = symbols_load_for_input(opts, source_name);
    const SymbolMap* ext = sm.count ? &sm : nullptr;

    std::vector<uint8_t> image(
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off),
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off + len));

    // --uasm owns the .asm file. Do not embed REPACK-V1. -d still gets the
    // address listing on stdout (human_stdout), capped like the human emitter.
    if (opts.uasm)
    {
        kind_out = ListingExportKind::Uasm;
        out_text = listing_emit_uasm(g, image, entry_ip, opts, source_name, tc,
                                     uasm_com, uasm_com_psp, n_procs, n_insns, ext,
                                     entry_in_window, relocs, uasm_status);
        if (human_stdout && opts.showDisasm && !opts.jsonOut)
        {
            if (g.blocks.empty())
            {
                *human_stdout = "; dumpexe listing: no basic blocks recovered\n";
            }
            else
            {
                size_t hp = 0;
                size_t hi = 0;
                *human_stdout = listing_emit_text(g, entry_ip, opts, source_name, hp, hi,
                                                  ext);
            }
        }
        return true;
    }

    if (g.blocks.empty())
    {
        out_text = "; dumpexe listing: no basic blocks recovered\n";
        return true;
    }

    const bool want_tp = tp && tp->detected;
    const bool want_jwasm =
        !want_tp && tc &&
        (tc->jwasm_1_8 || tc->assembler == "JWASM" ||
         (tc->com_in_exe && tc->jwasm_tasm_hint));

    if (want_tp)
    {
        kind_out = ListingExportKind::TurboPascal;
        const bool com = tc && tc->com_in_exe;
        out_text = listing_emit_turbo_pascal(g, image, entry_ip, opts, source_name, *tp,
                                             com, n_procs, n_insns, ext);
        // Embed MZ prefix/suffix so .asm alone can rebuild the EXE later
        out_text = repack_embed_meta(fileData, image_file_off, len) + out_text;
    }
    else if (want_jwasm)
    {
        kind_out = ListingExportKind::Jwasm;
        out_text = listing_emit_jwasm(g, image, entry_ip, opts, source_name, *tc,
                                      n_procs, n_insns, ext);
        out_text = repack_embed_meta(fileData, image_file_off, len) + out_text;
    }
    else
    {
        kind_out = ListingExportKind::Human;
        out_text =
            listing_emit_text(g, entry_ip, opts, source_name, n_procs, n_insns, ext);
    }
    return true;
}

/**
 * @brief True when @p a and @p b name the same path.
 *
 * Compares lexical forms and, when both exist, `equivalent`. `-` is never
 * the same as a file.
 */
static inline bool listing_paths_same(const std::string& a, const std::string& b)
{
    if (a.empty() || b.empty() || a == "-" || b == "-")
    {
        return false;
    }
    const std::filesystem::path left = std::filesystem::path(a).lexically_normal();
    const std::filesystem::path right = std::filesystem::path(b).lexically_normal();
    if (left == right)
    {
        return true;
    }
    std::error_code ec;
    return std::filesystem::equivalent(a, b, ec);
}

/// Write listing to stdout and/or default/override .asm file.
/// @param human_stdout Address listing for -d/--uasm. Empty when --uasm is off
///        or -d was not requested. Ignored unless @p kind is Uasm.
/// @return 0 when the listing was delivered, there was nothing to write, or the
///         default `<stem>.asm` could not be created (the error is on stderr;
///         stdout already has the listing). 1 when a path was refused or a
///         named `-o` write failed.
static inline int listing_deliver(const Options& opts,
                                  const std::string& input_path,
                                  const std::string& text,
                                  size_t n_procs,
                                  size_t n_insns,
                                  ListingExportKind kind,
                                  const std::string& human_stdout = {})
{
    if (text.empty())
        return 0;

    // -o FILE owns the listing. Do not also print it. -o - stays on stdout.
    const bool named_file = !opts.outputPath.empty() && opts.outputPath != "-";
    if (!opts.jsonOut && !named_file)
    {
        const bool uasm_file = opts.uasm && kind == ListingExportKind::Uasm;
        if (uasm_file && opts.outputPath == "-")
        {
            // --uasm -o - : UASM source only. -d/-a do not add an address listing.
            std::cout << text;
            if (text.back() != '\n')
                std::cout << '\n';
        }
        else if (uasm_file)
        {
            if (!human_stdout.empty())
            {
                std::cout << "\n=== Multi-pass assembly listing ===\n";
                std::cout << human_stdout;
                if (human_stdout.back() != '\n')
                    std::cout << '\n';
            }
        }
        else
        {
            if (kind == ListingExportKind::Jwasm)
                std::cout << "\n=== JWASM-assemblable export ===\n";
            else if (kind == ListingExportKind::TurboPascal)
                std::cout << "\n=== Turbo Pascal–oriented export (TASM bytes) ===\n";
            else
                std::cout << "\n=== Multi-pass assembly listing ===\n";
            std::cout << text;
            if (!text.empty() && text.back() != '\n')
                std::cout << "\n";
        }
    }

    const bool want_file =
        !opts.outputPath.empty() || opts.writeAsmFile;
    if (want_file)
    {
        std::string path = opts.outputPath.empty()
                               ? listing_default_asm_path(input_path)
                               : opts.outputPath;
        if (path == "-")
        {
            // --json owns stdout. Do not claim a UASM listing was written there.
            if (!opts.jsonOut)
            {
                std::cerr << std::format(
                    "listing: {} procs, {} insns (stdout only, -o -)\n", n_procs,
                    n_insns);
            }
            return 0;
        }
        if (opts.outputPath.empty() && !opts.writeAsmFile)
            return 0;
        // Default <stem>.asm is kept. A path the user named with -o may replace
        // a regular file, but not the input and not a symlink.
        if (opts.outputPath.empty() && output_file_exists(path))
        {
            std::cerr << "listing: refuse to overwrite '" << path << "'\n";
            return 1;
        }
        if (!opts.outputPath.empty() && listing_paths_same(path, input_path))
        {
            std::cerr << "listing: refuse to overwrite input '" << path << "'\n";
            return 1;
        }
        if (!opts.outputPath.empty())
        {
            std::error_code ec;
            const std::filesystem::file_status st =
                std::filesystem::symlink_status(path, ec);
            if (!ec && std::filesystem::is_symlink(st))
            {
                std::cerr << "listing: refuse to follow symlink '" << path << "'\n";
                return 1;
            }
        }
        if (opts.outputPath.empty())
        {
            // Default <stem>.asm: do not follow a dangling symlink. A create
            // error is reported and is not a hard failure: -d already printed
            // the listing, and a later unpack must still run (a read-only
            // directory is not "unpack failed").
            std::string werr;
            if (!output_create_nofollow(path, text.data(), text.size(), werr))
            {
                std::cerr << "Error: cannot write listing to '" << path << "'\n";
                return 0;
            }
        }
        else
        {
            std::string werr;
            if (!output_write_nofollow(path, text.data(), text.size(), werr))
            {
                std::cerr << "Error: cannot write listing to '" << path << "'\n";
                return 1;
            }
        }
        if (kind == ListingExportKind::Jwasm)
            std::cerr << std::format(
                "listing: wrote JWASM-assemblable {} ({} procs, {} insns)\n"
                "         assemble: wine bin/jwasm/jwasm-1.8.exe -Fo out.obj {}\n",
                path, n_procs, n_insns, path);
        else if (kind == ListingExportKind::TurboPascal)
            std::cerr << std::format(
                "listing: wrote Turbo Pascal export {} ({} procs, {} insns)\n"
                "         TASM bytes: tasm /ml {}\n"
                "         original build: TPC 5.5 + TASM {{$L}} units\n",
                path, n_procs, n_insns, path);
        else if (kind == ListingExportKind::Uasm)
            std::cerr << std::format(
                "listing: wrote UASM {} ({} procs, {} insns)\n",
                path, n_procs, n_insns);
        else
            std::cerr << std::format("listing: wrote {} ({} procs, {} insns)\n", path,
                                     n_procs, n_insns);
    }
    return 0;
}

/**
 * @brief Run multi-pass listing / JWASM / Turbo Pascal / UASM export.
 *
 * @param uasm_com     Pure .COM (org 100h program bytes). Not an MZ load image.
 * @param uasm_com_psp The COM image starts with an embedded PSP.
 * @param relocs       MZ fixups into the load image. Empty for COM and non-MZ.
 * @param cfg_out      Optional annotated CFG. Same contract as
 *                     @c listing_generate: written only when
 *                     @c cfg_build_annotated ran. Null skips the copy.
 * @param entry_seg_base Segment base of @p entry_ip (`cs * 16`). 0 for COM.
 *
 * --uasm skips auto-repack. The .asm file is UASM source, not a REPACK-V1 listing.
 */
static inline int listing_run(const std::vector<uint8_t>& fileData,
                              size_t image_file_off,
                              size_t image_len,
                              CfgLin entry_ip,
                              uint16_t cs_seg,
                              uint16_t file_cs,
                              const Options& opts,
                               const std::string& input_path,
                               const ToolchainReport* tc = nullptr,
                               const TurboPascalReport* tp = nullptr,
                               bool uasm_com = false,
                               bool uasm_com_psp = false,
                               bool entry_in_window = true,
                               std::span<const RelocEntry> relocs = {},
                               CfgGraph* cfg_out = nullptr,
                               CfgLin entry_seg_base = 0)
{
    std::string text;
    std::string human;
    size_t n_procs = 0, n_insns = 0;
    ListingExportKind kind = ListingExportKind::Human;
    int uasm_status = 0;
    std::string* human_ptr =
        (opts.uasm && opts.showDisasm && !opts.jsonOut) ? &human : nullptr;
    if (!listing_generate(fileData, image_file_off, image_len, entry_ip, cs_seg, file_cs,
                          opts, input_path, text, n_procs, n_insns, kind, tc, tp, uasm_com,
                          uasm_com_psp, human_ptr, entry_in_window, relocs, cfg_out,
                          entry_seg_base, &uasm_status))
    {
        std::cerr << "listing: empty load image\n";
        return 1;
    }
    const int delivered = listing_deliver(opts, input_path, text, n_procs, n_insns, kind, human);

    // Default ON: after TP/JWASM export, write runnable <stem>.repack.exe.
    // A refused <stem>.asm must not skip this. --uasm is not a repack carrier.
    if (!opts.uasm &&
        (kind == ListingExportKind::TurboPascal || kind == ListingExportKind::Jwasm))
    {
        std::string written;
        if (!repack_auto(opts, input_path, fileData, image_file_off, image_len, text,
                         written) &&
            opts.writeRepack)
        {
            std::cerr << "repack: failed\n";
        }
    }
    if (delivered != 0)
    {
        return delivered;
    }
    return uasm_status;
}

/**
 * @brief Backward-compatible entry: multi-pass listing from a file slice.
 *
 * @param data   Full file bytes
 * @param offset File offset where the disassembly window starts
 * @param cs     Capstone CS base (segment)
 * @param ip     Entry IP (also used as first IP in window when window==entry)
 * @param opts   Options
 * @param window_bytes Length from the file offset of IP 0 (after the rewind
 *        below). Not from @p offset. Zero decodes through EOF.
 * @param input_path Original filename for .asm default naming (may be empty)
 *
 * When @p offset is the entry-point file offset and @p ip fits in it, the
 * image is rewound so image[@p ip] is that byte. @p window_bytes is counted
 * from the rewound offset. COM still passes offset 0 and the real entry IP.
 */
static inline void disassemble(const std::vector<uint8_t>& data, size_t offset,
                               uint16_t cs, uint16_t ip, const Options& opts,
                               size_t window_bytes = 0,
                               const std::string& input_path = {})
{
    if (offset >= data.size())
    {
        if (!opts.jsonOut)
            std::cout << "\nDisassembly: Entry point is beyond end of file.\n";
        return;
    }
    // Treat [offset, EOF) as image with entry at `ip` only when offset maps to
    // image IP 0. For classic MZ call (offset=entry file off, ip=entry IP),
    // use a synthetic image starting at entry with entry_ip=0... but then
    // symbols won't match real IPs. Prefer: image from offset with base IP = ip.
    //
    // CFG expects image[0] = IP 0. So for entry-only window we need file bytes
    // from (offset - ip) if ip is within image... For MZ, callers should use
    // listing_run on full load image. This wrapper builds a padded view:
    // if ip > 0 and offset >= ip, start image at offset-ip so image[ip]=entry.
    size_t img_off = offset;
    size_t entry = ip;
    if (ip > 0 && offset >= static_cast<size_t>(ip))
    {
        img_off = offset - static_cast<size_t>(ip);
        entry = ip;
    }
    else
    {
        // Slice mode (SYS strategy/interrupt windows, some NE segments): the
        // file offset is the entry byte and IP is not an index into this slice.
        // Keep entry as 0 and accept func_0000 as entry for slice mode.
        // .COM is not this path — analyze_com() builds an org-0100h image.
        img_off = offset;
        entry = 0;
    }
    // Zero means through EOF so MZ/SYS/COM callers stay unchanged.
    size_t img_len = data.size() - img_off;
    if (window_bytes != 0)
    {
        img_len = std::min(window_bytes, img_len);
    }
    const std::string path = input_path.empty() ? std::string("binary") : input_path;
    if (listing_run(data, img_off, img_len, static_cast<uint16_t>(entry), cs, cs, opts,
                    path) != 0)
    {
        return;
    }
}

#endif // LISTING_H
