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
#include <fcntl.h>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <span>
#include <spawn.h>
#include <sstream>
#include <string>
#include <string_view>
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

static inline std::string listing_symbol_name(uint16_t ip)
{
    return std::format("func_{:04X}", ip);
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
                                         std::map<uint16_t, std::string>& sym)
{
    std::set<uint16_t> starts;
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
            sym[e.to_ip] = std::format("loc_{:04X}", e.to_ip);
        }
    }
}

//=============================================================================
// Symbol discovery (pass 3)
//=============================================================================

static inline void listing_collect_symbols(const CfgGraph& g,
                                           uint16_t entry_ip,
                                           std::map<uint16_t, std::string>& sym,
                                           std::set<uint16_t>& proc_starts,
                                           const SymbolMap* external = nullptr)
{
    auto add = [&](uint16_t ip, std::string_view why)
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

/// Replace immediate near targets in Capstone op text with symbol when possible.
/// @param ip_numeric When true (human listing), a branch with no label is printed
///        as the segment IP (`0x14d`), the same base as the address column — not
///        Capstone's CS*16+IP linear form. JWASM/TP export leaves this false.
static inline std::string listing_rewrite_ops(std::string_view mnem,
                                              std::string_view op_str,
                                              const CfgBlock& blk,
                                              const std::map<uint16_t, std::string>& sym,
                                              bool ip_numeric = false)
{
    // Prefer CFG edge targets for call / uncond jmp / table
    uint16_t edge_tgt = 0;
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
                                            uint16_t entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external = nullptr)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    listing_add_loc_labels(g, sym);
    n_insns = 0;

    std::ostringstream out;
    out << "; dumpexe multi-pass listing (not single-stream Capstone only)\n";
    out << std::format("; source: {}\n", source_name);
    out << std::format("; CS={:04X}h  entry={:04X}h  blocks={}  symbols={}\n",
                       g.cs_seg, entry_ip, g.blocks.size(), sym.size());
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
        std::map<uint16_t, std::string> int_notes;
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

            std::string rops = listing_rewrite_ops(mlow, ops, b, sym, true);
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
                    far_note = std::format("  ; → func_{:04X}", e.to_ip);
                    break;
                }
            }

            out << std::format("    {:04X}  {:<16}  {:<8} {}", in.ip, hex, mnem,
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
                                            uint16_t entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            const ToolchainReport& tc,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    // Index instructions by IP (first wins)
    std::map<uint16_t, CfgInsn> at;
    std::map<uint16_t, const CfgBlock*> blk_at;
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
    auto emit_label = [&](uint16_t ip)
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
        const uint16_t uip = static_cast<uint16_t>(ip & 0xFFFF);
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
            const uint16_t u = static_cast<uint16_t>(run_end & 0xFFFF);
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
                                                    uint16_t entry_ip,
                                                    const Options& opts,
                                                    const std::string& source_name,
                                                    const TurboPascalReport& tp,
                                                    bool com_in_exe,
                                                    size_t& n_procs,
                                                    size_t& n_insns,
                                                    const SymbolMap* external)
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::map<uint16_t, CfgInsn> at;
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
        const uint16_t uip = static_cast<uint16_t>(ip & 0xFFFF);

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
            const uint16_t u = static_cast<uint16_t>(run_end & 0xFFFF);
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
 * The target is `uint16_t(ip + size + disp)` with disp sign-extended.
 * Far lcall/ljmp are not rewritten. No numeric IP. No per-branch uasm.
 *
 * @param in     Instruction bytes. The opcode must be the first byte.
 * @param ip     IP of @p in.
 * @param opcode Opcode byte (EB/E9/E8/70–7F/E0–E3).
 * @param mnem   Lowercase Capstone mnemonic (`je`, `loopne`, …).
 * @param sym    Labels already collected for this image.
 * @param line   Receives `jmp short <sym>` and the other sized forms.
 * @return true when @p sym contains the encoded target.
 */
static inline bool listing_uasm_sized_branch(
    const CfgInsn& in,
    uint16_t ip,
    uint8_t opcode,
    std::string_view mnem,
    const std::map<uint16_t, std::string>& sym,
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
    const int sum = static_cast<int>(ip) + static_cast<int>(in.size) + disp;
    const uint16_t target = static_cast<uint16_t>(sum);
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
 * @brief Scratch .asm/.bin pair for one listing_emit_uasm call.
 *
 * The directory is created with mkdtemp under /tmp. Both files are unlinked
 * on every return path, including when verify is never called.
 */
class ListingUasmScratch
{
public:
    /**
     * @brief Create the scratch directory and remember the two paths.
     */
    ListingUasmScratch()
    {
        char tmpl[] = "/tmp/dumpexe-uasm-XXXXXX";
        if (::mkdtemp(tmpl) == nullptr)
        {
            return;
        }
        dir_ = tmpl;
        asm_path_ = dir_ + "/line.asm";
        bin_path_ = dir_ + "/line.bin";
        err_path_ = dir_ + "/line.err";
        ready_ = true;
        uasm_ok_ = (::access("/usr/bin/uasm", X_OK) == 0);
    }

    ListingUasmScratch(const ListingUasmScratch&) = delete;

    /**
     * @brief Copying the scratch paths would double-unlink them.
     * @return Nothing. Deleted.
     */
    ListingUasmScratch& operator=(const ListingUasmScratch&) = delete;

    /**
     * @brief Unlink the scratch .asm and .bin, then remove the directory.
     * @return Nothing.
     */
    ~ListingUasmScratch()
    {
        if (!asm_path_.empty())
        {
            ::unlink(asm_path_.c_str());
        }
        if (!bin_path_.empty())
        {
            ::unlink(bin_path_.c_str());
        }
        if (!err_path_.empty())
        {
            ::unlink(err_path_.c_str());
        }
        if (!dir_.empty())
        {
            ::rmdir(dir_.c_str());
        }
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
     * @brief True when /usr/bin/uasm is executable.
     * @return false when the assembler is missing.
     */
    bool uasm_ok() const
    {
        return uasm_ok_;
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

private:
    std::string dir_;
    std::string asm_path_;
    std::string bin_path_;
    std::string err_path_;
    bool ready_ = false;
    bool uasm_ok_ = false;
};

/**
 * @brief Assemble one line with /usr/bin/uasm and compare the bytes.
 *
 * Level 0 writes `.8086` before `.model tiny`. Level 1 writes `.186` after
 * `.model tiny`. Level 2 and 3 are not assembled. `org 100h` does not pad, so
 * the output must equal @p in.bytes. The spawn argv is uasm, -bin, -nologo,
 * -Fo, the bin path, and the asm path. No shell.
 *
 * @param scratch Scratch paths for this listing_emit_uasm call.
 * @param line    One instruction. The caller rejects comments and labels.
 * @param level   listing_uasm_cpu_level of @p in. Must be 0 or 1.
 * @param in      Instruction whose bytes are the expected output.
 * @return true when uasm's output equals @p in.bytes.
 */
static inline bool listing_uasm_verify_one(const ListingUasmScratch& scratch,
                                          const std::string& line,
                                          int level,
                                          const CfgInsn& in)
{
    if (!scratch.ready() || !scratch.uasm_ok() || level >= 2 || in.size == 0 ||
        in.size > 16)
    {
        return false;
    }
    ::unlink(scratch.bin_path().c_str());
    FILE* af = std::fopen(scratch.asm_path().c_str(), "w");
    if (af == nullptr)
    {
        return false;
    }
    bool wrote = true;
    if (level == 0 && std::fputs(".8086\n", af) < 0)
    {
        wrote = false;
    }
    if (wrote && std::fputs(".model tiny\n", af) < 0)
    {
        wrote = false;
    }
    if (wrote && level == 1 && std::fputs(".186\n", af) < 0)
    {
        wrote = false;
    }
    if (wrote && std::fputs(".code\norg 100h\n", af) < 0)
    {
        wrote = false;
    }
    if (wrote && std::fwrite(line.data(), 1, line.size(), af) != line.size())
    {
        wrote = false;
    }
    if (wrote && std::fputs("\nend\n", af) < 0)
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
    char arg0[] = "uasm";
    char arg1[] = "-bin";
    char arg2[] = "-nologo";
    char arg3[] = "-Fo";
    char* argv[] = {
        arg0, arg1, arg2, arg3, bin_arg.data(), asm_arg.data(), nullptr};

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

    extern char** environ;
    pid_t pid = 0;
    const int spawned = ::posix_spawn(&pid, "/usr/bin/uasm", &actions, nullptr,
                                      argv, environ);
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
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
    {
        return false;
    }

    FILE* bf = std::fopen(scratch.bin_path().c_str(), "rb");
    if (bf == nullptr)
    {
        return false;
    }
    uint8_t got[16];
    const size_t nread = std::fread(got, 1, sizeof(got), bf);
    const int extra = std::fgetc(bf);
    std::fclose(bf);
    if (extra != EOF || nread != in.size)
    {
        return false;
    }
    return std::memcmp(got, in.bytes, nread) == 0;
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
 * @param ip        Opcode IP. Already below 65536 because it is a uint16_t.
 * @param in        Decoded instruction whose bytes must match @p image.
 * @param frame_out Byte offset imm * 16 when the function returns true.
 * @return true when the emitter must print the segment expression.
 */
static inline bool listing_uasm_reloc_frame(const std::vector<uint8_t>& image,
                                            const std::map<uint16_t, CfgInsn>& at,
                                            const std::set<uint32_t>& reloc_at,
                                            bool uasm_com,
                                            uint16_t ip,
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
 * Not assembled by listing_uasm_verify_one. The scratch file has no frame
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
 * @brief Emit UASM source that assembles back to the load image.
 *
 * No address column and no hex-byte column. Real instructions go through
 * listing_masm_mnem / listing_masm_ops, then UASM spelling. A line is kept
 * when the whitelist matches, when it is a sized near branch to a known
 * symbol, or when /usr/bin/uasm assembles that one line back to the same
 * bytes. Anything else, including bytes the CFG did not decode, is `db`
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
 * listing_uasm_verify_one and does not raise the CPU level. It is emitted
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
 * @param entry_in_window False when the MZ entry is past the 64 KiB window.
 * @param relocs          MZ fixups into @p image. Empty leaves immediates numeric.
 * @return UASM source. The last line is `end <entry label>` for COM and a
 *         one-segment image whose entry is inside the window. A multi-segment
 *         image, or an entry past the window, ends with a bare `end`.
 */
static inline std::string listing_emit_uasm(const CfgGraph& g,
                                            const std::vector<uint8_t>& image,
                                            uint16_t entry_ip,
                                            const Options& opts,
                                            const std::string& source_name,
                                            const ToolchainReport* tc,
                                            bool uasm_com,
                                            bool uasm_com_psp,
                                            size_t& n_procs,
                                            size_t& n_insns,
                                            const SymbolMap* external,
                                            bool entry_in_window = true,
                                            std::span<const RelocEntry> relocs = {})
{
    std::map<uint16_t, std::string> sym;
    std::set<uint16_t> proc_starts;
    listing_collect_symbols(g, entry_ip, sym, proc_starts, external);
    listing_add_loc_labels(g, sym);
    n_procs = proc_starts.size();
    n_insns = 0;

    std::map<uint16_t, CfgInsn> at;
    std::map<uint16_t, const CfgBlock*> blk_at;
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
        if (at_off > 0xFFFFu)
        {
            return labs;
        }
        const uint16_t ip = static_cast<uint16_t>(at_off);
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

    // Local to this emit. Not a process-lifetime static.
    ListingUasmScratch scratch;
    std::map<std::string, bool> verify_cache;
    auto verify_cached = [&](const std::string& line, const CfgInsn& insn) -> bool
    {
        if (line.empty() ||
            line.find(';') != std::string::npos ||
            line.find('\n') != std::string::npos ||
            line.find("func_") != std::string::npos ||
            line.find("loc_") != std::string::npos)
        {
            return false;
        }
        const int level = listing_uasm_cpu_level(insn);
        if (level >= 2)
        {
            return false;
        }
        std::string key;
        key.reserve(line.size() + 1 + insn.size);
        key.append(line);
        key.push_back('\0');
        key.append(reinterpret_cast<const char*>(insn.bytes), insn.size);
        const auto found = verify_cache.find(key);
        if (found != verify_cache.end())
        {
            return found->second;
        }
        const bool ok = listing_uasm_verify_one(scratch, line, level, insn);
        verify_cache.emplace(std::move(key), ok);
        return ok;
    };

    auto stood = [&](size_t at_off, std::string& text_out) -> size_t
    {
        text_out.clear();
        if (at_off > 0xFFFFu)
        {
            return 0;
        }
        const uint16_t ip = static_cast<uint16_t>(at_off);
        const auto it = at.find(ip);
        if (it == at.end() || it->second.size == 0)
        {
            return 0;
        }
        const CfgInsn& in = it->second;
        if (at_off + in.size > image.size())
        {
            return 0;
        }
        for (uint8_t k = 0; k < in.size; ++k)
        {
            if (image[at_off + k] != in.bytes[k])
            {
                return 0;
            }
        }
        uint32_t q8_frame = 0;
        if (listing_uasm_reloc_frame(image, at, reloc_at, uasm_com, ip, in, q8_frame))
        {
            // Skip the whitelist and listing_uasm_verify_one. Do not raise cpu.
            text_out = listing_uasm_reloc_mov_text(image[at_off], q8_frame);
            return in.size;
        }
        bool blocked = false;
        const size_t opi = listing_uasm_opcode_index(in, blocked);
        if (blocked || opi >= in.size)
        {
            return 0;
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
            text_out = std::move(branch);
            return in.size;
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
        if (listing_uasm_stand_behind(in, mlow, rops))
        {
            cpu = std::max(cpu, listing_uasm_cpu_level(in));
            text_out = rops.empty() ? mlow : (mlow + " " + rops);
            return in.size;
        }
        const std::string line = rops.empty() ? mlow : (mlow + " " + rops);
        if (verify_cached(line, in))
        {
            cpu = std::max(cpu, listing_uasm_cpu_level(in));
            text_out = line;
            return in.size;
        }
        return 0;
    };

    while (off < image.size())
    {
        std::string insn_text;
        const size_t n = stood(off, insn_text);
        Slice sl;
        sl.off = off;
        sl.labels = labels_at(off);
        if (n > 0)
        {
            sl.len = n;
            sl.insn = true;
            sl.text = std::move(insn_text);
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
                std::string ignore;
                if (stood(run, ignore) > 0)
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
    // Past 64KB the image is sN segment blocks. COM stays one .code segment.
    // uasm -bin accepts "end func_XXXX" only when that label is in UASM's
    // first segment. .model tiny + .code is that case. .model small opens
    // its own segment before s0, so "end func_XXXX" is error A2203. A bare
    // "end" is valid for both -bin and -mz. When the entry is inside the
    // decoded image, its label stays in sN. An entry past 64 KiB is not
    // labeled func_FFFF.
    const bool use_segments = multi && !uasm_com;

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

    auto emit_seg_body = [&](const Seg& seg, bool first_code)
    {
        if (!uasm_com)
        {
            if (first_code || use_segments)
            {
                out << "org 0\n";
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
        }
        for (const Slice& sl : seg.slices)
        {
            emit_slice(sl);
        }
    };

    if (!use_segments)
    {
        bool first = true;
        for (const Seg& seg : segs)
        {
            out << ".code\n";
            emit_seg_body(seg, first);
            first = false;
        }
    }
    else
    {
        size_t n = 0;
        for (const Seg& seg : segs)
        {
            out << "s" << n << " segment byte public 'CODE'\n";
            emit_seg_body(seg, n == 0);
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
    return out.str();
}

/**
 * @brief Build multi-pass listing text for a CS-relative image.
 * @param relocs MZ fixups into the load image. Passed to the CFG and to --uasm.
 * @return false on hard failure (empty image / capstone)
 */
static inline bool listing_generate(const std::vector<uint8_t>& fileData,
                                    size_t image_file_off,
                                    size_t image_len,
                                    uint16_t entry_ip,
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
                                    std::span<const RelocEntry> relocs = {})
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
    // An entry past 64 KiB is not seeded at FFFF. The window stays 64 KiB.
    if (entry_in_window)
    {
        g = cfg_build_annotated(fileData, image_file_off, len, entry_ip, cs_seg,
                                file_cs, cfg_opts, relocs);
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
                                     entry_in_window, relocs);
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
 *
 * --uasm skips auto-repack. The .asm file is UASM source, not a REPACK-V1 listing.
 */
static inline int listing_run(const std::vector<uint8_t>& fileData,
                              size_t image_file_off,
                              size_t image_len,
                              uint16_t entry_ip,
                              uint16_t cs_seg,
                              uint16_t file_cs,
                              const Options& opts,
                               const std::string& input_path,
                               const ToolchainReport* tc = nullptr,
                               const TurboPascalReport* tp = nullptr,
                               bool uasm_com = false,
                               bool uasm_com_psp = false,
                               bool entry_in_window = true,
                               std::span<const RelocEntry> relocs = {})
{
    std::string text;
    std::string human;
    size_t n_procs = 0, n_insns = 0;
    ListingExportKind kind = ListingExportKind::Human;
    std::string* human_ptr =
        (opts.uasm && opts.showDisasm && !opts.jsonOut) ? &human : nullptr;
    if (!listing_generate(fileData, image_file_off, image_len, entry_ip, cs_seg, file_cs,
                          opts, input_path, text, n_procs, n_insns, kind, tc, tp, uasm_com,
                          uasm_com_psp, human_ptr, entry_in_window, relocs))
    {
        if (!opts.jsonOut && !opts.uasm_stdout_only())
            std::cout << "\nListing: image offset outside file or empty.\n";
        return 0;
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
    return delivered;
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
