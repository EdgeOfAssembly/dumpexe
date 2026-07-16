// cfg.h - Static control-flow graph (CFG) recovery for 16-bit x86
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Recursive-descent / leader-based CFG: basic blocks + edges (fall-through,
// jmp, jcc true/false, call, ret). Optional scan for near-jump tables
// (Pascal MT+ style E9 stubs). Same-segment near control flow only.
//
// This builds a *graph*, not a path tree: joins reuse the same block node.

#ifndef CFG_H
#define CFG_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <format>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <vector>
#include <capstone/capstone.h>

#include "options.h"

//=============================================================================
// CFG data structures
//=============================================================================

enum class CfgEdgeKind : uint8_t {
    FallThrough,
    Jump,       ///< unconditional near jmp
    CondTrue,   ///< jcc taken
    CondFalse,  ///< jcc not taken (fall-through successor, labeled)
    Call,       ///< near call (edge to callee; caller also has FallThrough continue)
    Ret,        ///< ret / retf — no concrete target
    Table,      ///< discovered via jump-table slot
};

static inline const char* cfg_edge_name(CfgEdgeKind k) {
    switch (k) {
    case CfgEdgeKind::FallThrough: return "fall";
    case CfgEdgeKind::Jump:        return "jmp";
    case CfgEdgeKind::CondTrue:    return "jcc-true";
    case CfgEdgeKind::CondFalse:   return "jcc-false";
    case CfgEdgeKind::Call:        return "call";
    case CfgEdgeKind::Ret:         return "ret";
    case CfgEdgeKind::Table:       return "table";
    }
    return "?";
}

struct CfgEdge {
    uint16_t    to_ip = 0;   ///< successor block start (0 if Ret/unknown)
    CfgEdgeKind kind  = CfgEdgeKind::FallThrough;
    bool        has_target = true;
};

struct CfgInsn {
    uint16_t    ip = 0;
    size_t      file_off = 0;
    uint8_t     size = 0;
    std::string text;        ///< "mnemonic op_str"
    uint8_t     bytes[16]{}; ///< raw bytes (for INT / pattern scan)
};

/// DOS interrupt site recovered inside a block
struct CfgIntSite {
    uint16_t ip = 0;
    uint8_t  int_num = 0;
    uint8_t  ah = 0xFF;      ///< 0xFF = unknown
    uint8_t  al = 0xFF;
    bool     ah_from_pred = false; ///< AH recovered from predecessor BB
    uint16_t dx = 0xFFFF;    ///< last known DX imm (0xFFFF = unknown)
    bool     dx_from_pred = false;
    std::string note;        ///< short RBIL-ish or FCB hint
    std::string path;        ///< FCB/handle filename if recovered
};

/// Immediate / nearby reference to a string in the image
struct CfgStringXref {
    uint16_t at_ip = 0;      ///< insn or site IP
    uint16_t str_ip = 0;     ///< offset of string within image (IP space)
    std::string str;         ///< printable form (truncated)
};

struct CfgBlock {
    uint16_t start_ip = 0;
    uint16_t end_ip   = 0;   ///< exclusive (first IP past last insn)
    size_t   file_off = 0;   ///< file offset of start
    bool     is_entry = false;
    bool     is_table_entry = false;
    bool     is_call_target = false;
    bool     is_interesting = false; ///< INT / file / string xref
    std::vector<CfgInsn> insns;
    std::vector<CfgEdge> outs;
    std::vector<uint16_t> preds; ///< filled after build
    std::vector<CfgIntSite> ints;
    std::vector<CfgStringXref> str_xrefs;
    std::vector<std::string> tags; ///< e.g. "FCB-open", "overlay", "video"
};

struct CfgStringLit {
    uint16_t off = 0;        ///< image offset
    std::string text;
};

struct CfgGraph {
    uint16_t cs_seg = 0;           ///< CS used for linear addressing in Capstone
    size_t   image_file_base = 0;  ///< file offset of IP 0000 in this CS image
    size_t   image_size = 0;
    std::map<uint16_t, CfgBlock> blocks; ///< keyed by start_ip
    std::set<uint16_t> unresolved;       ///< jump/call targets outside image
    size_t n_edges = 0;
    size_t n_loops_back = 0;             ///< edges to lower-or-equal IP (heuristic)
    std::vector<CfgStringLit> strings;   ///< recovered literals in image
    size_t n_int_sites = 0;
    size_t n_str_xrefs = 0;
};

//=============================================================================
// Helpers
//=============================================================================

static inline bool cfg_is_jcc(std::string_view m) {
    if (m.size() < 2 || m[0] != 'j') return false;
    if (m == "jmp" || m == "jecxz") return false;
    // jcxz is a jcc-like
    return true;
}

static inline bool cfg_is_uncond_jmp(std::string_view m) {
    return m == "jmp" || m == "ljmp" || m == "jmpf";
}

static inline bool cfg_is_call(std::string_view m) {
    return m == "call" || m == "lcall" || m == "callf";
}

static inline bool cfg_is_ret(std::string_view m) {
    return m == "ret" || m == "retn" || m == "retf" || m == "retfq" ||
           m == "iret" || m == "iretd";
}

/// Capstone address (CS*16+IP) → IP in segment
static inline uint16_t cfg_addr_to_ip(uint64_t addr, uint16_t cs) {
    return static_cast<uint16_t>(addr - static_cast<uint64_t>(cs) * 16u);
}

static inline bool cfg_ip_in_image(uint16_t ip, size_t image_size) {
    return static_cast<size_t>(ip) < image_size;
}

//=============================================================================
// Jump-table heuristic (Pascal MT+ etc.): run of near JMPs (E9 xx xx)
//=============================================================================

/// Scan [scan_lo, scan_hi) in the *image* (IP space) for consecutive E9 stubs.
/// Returns start IPs of each table slot target (and records slot IPs as leaders).
static inline void cfg_find_near_jmp_tables(const std::vector<uint8_t>& image,
                                            uint16_t scan_lo, uint16_t scan_hi,
                                            std::set<uint16_t>& leaders,
                                            std::set<uint16_t>& table_slots,
                                            size_t min_slots = 4) {
    if (scan_hi > image.size()) scan_hi = static_cast<uint16_t>(std::min(image.size(), size_t{0xFFFF}));
    if (scan_lo >= scan_hi) return;

    size_t i = scan_lo;
    while (i + 3 <= scan_hi) {
        if (image[i] != 0xE9) { ++i; continue; }
        // Count consecutive E9 rel16
        size_t j = i;
        std::vector<uint16_t> slots;
        while (j + 3 <= scan_hi && image[j] == 0xE9) {
            int16_t rel = static_cast<int16_t>(image[j + 1] | (image[j + 2] << 8));
            uint16_t slot_ip = static_cast<uint16_t>(j);
            uint16_t tgt = static_cast<uint16_t>(j + 3 + rel);
            slots.push_back(slot_ip);
            leaders.insert(slot_ip);
            leaders.insert(tgt);
            table_slots.insert(slot_ip);
            j += 3;
        }
        if (slots.size() >= min_slots) {
            // keep leaders already inserted
        } else {
            // too short — remove table_slots marks for these
            for (uint16_t s : slots) table_slots.erase(s);
        }
        i = (j > i) ? j : i + 1;
    }
}

//=============================================================================
// Build CFG
//=============================================================================

/// Build a same-segment CFG for code in @p image (raw bytes at CS:0000).
/// @param entry_ip   start IP (e.g. 0 for ICON after load)
/// @param cs_seg     CS value for Capstone addressing (usually loadBase+header.cs)
/// @param file_base  file offset corresponding to image[0]
/// @param follow_calls if true, treat call targets as leaders (depth unlimited BFS)
/// @param max_blocks  safety cap
static inline CfgGraph cfg_build(const std::vector<uint8_t>& image,
                                 uint16_t entry_ip,
                                 uint16_t cs_seg,
                                 size_t file_base,
                                 bool follow_calls,
                                 size_t max_blocks = 20000) {
    CfgGraph g;
    g.cs_seg = cs_seg;
    g.image_file_base = file_base;
    g.image_size = image.size();

    if (image.empty() || !cfg_ip_in_image(entry_ip, image.size()))
        return g;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
        return g;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return g;
    }

    std::set<uint16_t> leaders;
    std::set<uint16_t> table_slots;
    leaders.insert(entry_ip);

    // Force leaders at every INT (CD nn) so far-callable DOS helpers that are
    // not reached by near edges still become blocks (FCB open/read etc.).
    for (size_t i = 0; i + 1 < image.size(); ++i) {
        if (image[i] != 0xCD) continue;
        uint8_t inum = image[i + 1];
        // Common DOS/BIOS ints; skip rare/undefined to limit noise
        if (inum == 0x10 || inum == 0x13 || inum == 0x16 || inum == 0x1A ||
            inum == 0x20 || inum == 0x21 || inum == 0x25 || inum == 0x2F ||
            inum == 0x33) {
            uint16_t ip = static_cast<uint16_t>(i);
            leaders.insert(ip);
            // Also a few bytes earlier so mov ah / mov dx sit in the same BB
            if (ip >= 16)
                leaders.insert(static_cast<uint16_t>(ip - 16));
            if (ip >= 8)
                leaders.insert(static_cast<uint16_t>(ip - 8));
        }
    }

    // Heuristic: scan low image for jump tables (ICON has one at ~0090h)
    uint16_t scan_hi = static_cast<uint16_t>(std::min(image.size(), size_t{0x200}));
    cfg_find_near_jmp_tables(image, 0, scan_hi, leaders, table_slots);

    // Also scan a bit after entry for local tables
    if (entry_ip < image.size()) {
        uint16_t lo = entry_ip;
        size_t entry_plus = static_cast<size_t>(entry_ip) + 0x100u;
        uint16_t hi = static_cast<uint16_t>(std::min(image.size(), entry_plus));
        cfg_find_near_jmp_tables(image, lo, hi, leaders, table_slots, 6);
    }

    // --- Pass 1: discover leaders via recursive descent worklist ---
    std::queue<uint16_t> work;
    for (uint16_t L : leaders) work.push(L);
    std::set<uint16_t> visited_decode; // IPs we started decoding from in pass1

    auto enqueue = [&](uint16_t ip) {
        if (!cfg_ip_in_image(ip, image.size())) {
            g.unresolved.insert(ip);
            return;
        }
        if (leaders.insert(ip).second)
            work.push(ip);
    };

    while (!work.empty() && leaders.size() < max_blocks * 2) {
        uint16_t start = work.front();
        work.pop();
        if (!visited_decode.insert(start).second)
            continue;

        uint16_t ip = start;
        // Decode linearly until a control-flow terminator
        for (int step = 0; step < 4096; ++step) {
            if (!cfg_ip_in_image(ip, image.size()))
                break;
            size_t off = ip;
            size_t avail = image.size() - off;
            if (avail == 0) break;
            size_t max_take = std::min(avail, size_t{16});
            const uint8_t* ptr = image.data() + off;
            size_t sz = max_take;
            uint64_t addr = static_cast<uint64_t>(cs_seg) * 16u + ip;
            if (!cs_disasm_iter(handle, &ptr, &sz, &addr, insn) || !insn->detail)
                break;

            const cs_x86& x86 = insn->detail->x86;
            std::string mnem = insn->mnemonic;
            uint16_t next = static_cast<uint16_t>(ip + insn->size);

            auto imm_ip = [&](int op_i) -> bool {
                if (op_i >= x86.op_count) return false;
                if (x86.operands[op_i].type != X86_OP_IMM) return false;
                uint16_t t = cfg_addr_to_ip(
                    static_cast<uint64_t>(x86.operands[op_i].imm), cs_seg);
                enqueue(t);
                return true;
            };

            if (cfg_is_uncond_jmp(mnem)) {
                imm_ip(0);
                // indirect: no static target
                break;
            }
            if (cfg_is_jcc(mnem) || mnem == "jcxz" || mnem == "loop" ||
                mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
                mnem == "loopnz") {
                imm_ip(0);
                enqueue(next); // false / fall-through leader
                break;
            }
            if (cfg_is_call(mnem)) {
                if (follow_calls)
                    imm_ip(0);
                // Fall-through after CALL is real in most code, but entry stubs
                // (Pascal MT+) often park a *data* segment table right after the
                // call. Only enqueue continuation if it does not look like a
                // zero/data hole and is not the middle of a jump table.
                bool looks_data = false;
                if (cfg_ip_in_image(next, image.size())) {
                    // 4+ zero bytes → padding/data
                    int z = 0;
                    for (size_t k = 0; k < 8 && next + k < image.size(); ++k)
                        if (image[next + k] == 0) ++z;
                    if (z >= 6) looks_data = true;
                    // Immediately followed by a known jmp-table E9 run
                    if (static_cast<size_t>(next) + 6 <= image.size() &&
                        image[next] == 0xE9 && image[next + 3] == 0xE9)
                        looks_data = true;
                    // Pascal MT+ segment table words after entry CALL
                    if (static_cast<size_t>(next) + 4 <= image.size() &&
                        image[next] == 0x80 && image[next + 2] == 0xb0)
                        looks_data = true;
                }
                if (!looks_data)
                    enqueue(next);
                break;
            }
            if (cfg_is_ret(mnem) || mnem == "int" || mnem == "into" || mnem == "hlt") {
                // int continues after stub in real CPU, but for static CFG treat
                // as non-terminator for int (DOS often returns). Follow through int.
                if (mnem == "int" || mnem == "into") {
                    ip = next;
                    continue;
                }
                break;
            }

            // If next IP is already a leader, stop before overlapping
            if (leaders.count(next) && next != start) {
                // fall-through into another block
                break;
            }

            ip = next;
            if (insn->size == 0) break;
        }
    }

    // --- Pass 2: form blocks from each leader ---
    std::vector<uint16_t> leader_list(leaders.begin(), leaders.end());
    std::sort(leader_list.begin(), leader_list.end());

    auto next_leader_after = [&](uint16_t ip) -> uint16_t {
        auto it = std::upper_bound(leader_list.begin(), leader_list.end(), ip);
        if (it == leader_list.end())
            return static_cast<uint16_t>(std::min(image.size(), size_t{0xFFFF}));
        return *it;
    };

    for (uint16_t L : leader_list) {
        if (g.blocks.size() >= max_blocks)
            break;
        if (!cfg_ip_in_image(L, image.size()))
            continue;

        CfgBlock blk;
        blk.start_ip = L;
        blk.file_off = file_base + L;
        blk.is_entry = (L == entry_ip);
        blk.is_table_entry = table_slots.count(L) != 0;

        uint16_t limit = next_leader_after(L);
        uint16_t ip = L;
        bool stop = false;

        while (!stop && ip < limit && cfg_ip_in_image(ip, image.size())) {
            size_t off = ip;
            size_t avail = image.size() - off;
            size_t max_take = std::min(avail, size_t{16});
            const uint8_t* ptr = image.data() + off;
            size_t sz = max_take;
            uint64_t addr = static_cast<uint64_t>(cs_seg) * 16u + ip;
            if (!cs_disasm_iter(handle, &ptr, &sz, &addr, insn) || !insn->detail)
                break;

            CfgInsn ci;
            ci.ip = ip;
            ci.file_off = file_base + ip;
            ci.size = static_cast<uint8_t>(std::min(insn->size, (uint16_t)16));
            std::memcpy(ci.bytes, insn->bytes, ci.size);
            ci.text = insn->mnemonic;
            if (insn->op_str[0]) {
                ci.text.push_back(' ');
                ci.text += insn->op_str;
            }
            blk.insns.push_back(ci);

            const cs_x86& x86 = insn->detail->x86;
            std::string mnem = insn->mnemonic;
            uint16_t next = static_cast<uint16_t>(ip + insn->size);

            // Stop decoding through obvious data (00 00 → "add [bx+si], al")
            if ((insn->size == 2 && insn->bytes[0] == 0x00 && insn->bytes[1] == 0x00) ||
                (insn->size == 1 && insn->bytes[0] == 0x00) ||
                (mnem == "add" && ci.text.find("[bx + si], al") != std::string::npos &&
                 insn->bytes[0] == 0x00)) {
                // Count trailing null-ish adds in this block
                size_t nullish = 0;
                for (auto it = blk.insns.rbegin();
                     it != blk.insns.rend() && nullish < 8; ++it) {
                    if (it->text.find("add byte ptr [bx + si], al") != std::string::npos ||
                        it->text == "add byte ptr [bx + si], al")
                        nullish++;
                    else
                        break;
                }
                if (nullish >= 4) {
                    // Drop the junk tail from the block display
                    while (!blk.insns.empty() &&
                           blk.insns.back().text.find("[bx + si], al") != std::string::npos)
                        blk.insns.pop_back();
                    if (!blk.insns.empty())
                        ip = static_cast<uint16_t>(blk.insns.back().ip + blk.insns.back().size);
                    stop = true;
                    break;
                }
            }

            auto edge_imm = [&](CfgEdgeKind kind) {
                if (x86.op_count < 1 || x86.operands[0].type != X86_OP_IMM)
                    return false;
                CfgEdge e;
                e.kind = kind;
                e.to_ip = cfg_addr_to_ip(
                    static_cast<uint64_t>(x86.operands[0].imm), cs_seg);
                e.has_target = cfg_ip_in_image(e.to_ip, image.size());
                if (!e.has_target)
                    g.unresolved.insert(e.to_ip);
                blk.outs.push_back(e);
                if (e.has_target && e.to_ip <= ip)
                    g.n_loops_back++;
                return true;
            };

            if (cfg_is_uncond_jmp(mnem)) {
                if (!edge_imm(table_slots.count(L) ? CfgEdgeKind::Table
                                                   : CfgEdgeKind::Jump)) {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::Jump;
                    e.has_target = false;
                    blk.outs.push_back(e);
                }
                stop = true;
            } else if (cfg_is_jcc(mnem) || mnem == "jcxz" || mnem == "loop" ||
                       mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
                       mnem == "loopnz") {
                edge_imm(CfgEdgeKind::CondTrue);
                CfgEdge f;
                f.kind = CfgEdgeKind::CondFalse;
                f.to_ip = next;
                f.has_target = cfg_ip_in_image(next, image.size());
                blk.outs.push_back(f);
                stop = true;
            } else if (cfg_is_call(mnem)) {
                if (!edge_imm(CfgEdgeKind::Call)) {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::Call;
                    e.has_target = false;
                    blk.outs.push_back(e);
                }
                // Fall-through only if continuation looks like code (not data hole
                // / jump-table / segment-table after Pascal entry call).
                bool cont_ok = cfg_ip_in_image(next, image.size());
                if (cont_ok) {
                    int z = 0;
                    for (size_t k = 0; k < 8 && next + k < image.size(); ++k)
                        if (image[next + k] == 0) ++z;
                    if (z >= 6) cont_ok = false;
                    // Segment table after ICON entry: 80 0c b0 08 ... then zeros
                    if (static_cast<size_t>(next) + 4 < image.size() &&
                        image[next] == 0x80 && image[next + 2] == 0xb0)
                        cont_ok = false;
                    if (table_slots.count(next)) cont_ok = false;
                }
                if (cont_ok && leaders.count(next)) {
                    CfgEdge cont;
                    cont.kind = CfgEdgeKind::FallThrough;
                    cont.to_ip = next;
                    cont.has_target = true;
                    blk.outs.push_back(cont);
                }
                stop = true;
            } else if (cfg_is_ret(mnem) || mnem == "hlt") {
                CfgEdge e;
                e.kind = CfgEdgeKind::Ret;
                e.has_target = false;
                blk.outs.push_back(e);
                stop = true;
            } else if (next >= limit) {
                // fall into next leader
                if (cfg_ip_in_image(next, image.size()) && leaders.count(next)) {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::FallThrough;
                    e.to_ip = next;
                    blk.outs.push_back(e);
                }
                stop = true;
            }

            ip = next;
            if (insn->size == 0) break;
        }

        blk.end_ip = ip;
        if (blk.insns.empty())
            continue;
        g.blocks[L] = std::move(blk);
    }

    // Mark call targets + preds + edge count
    for (auto& [sip, blk] : g.blocks) {
        for (const auto& e : blk.outs) {
            g.n_edges++;
            if (!e.has_target) continue;
            auto it = g.blocks.find(e.to_ip);
            if (it == g.blocks.end()) continue;
            it->second.preds.push_back(sip);
            if (e.kind == CfgEdgeKind::Call)
                it->second.is_call_target = true;
        }
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return g;
}

//=============================================================================
// Annotations: INT sites, string literals, xrefs, tags
//=============================================================================

static inline std::string cfg_int21_hint(uint8_t ah) {
    switch (ah) {
    case 0x02: return "write-char";
    case 0x06: return "direct-console";
    case 0x09: return "print-$string";
    case 0x0F: return "FCB-open";
    case 0x10: return "FCB-close";
    case 0x14: return "FCB-seq-read";
    case 0x15: return "FCB-seq-write";
    case 0x16: return "FCB-create";
    case 0x1A: return "set-DTA";
    case 0x21: return "FCB-rand-read";
    case 0x22: return "FCB-rand-write";
    case 0x25: return "set-vector";
    case 0x27: return "FCB-block-read";
    case 0x28: return "FCB-block-write";
    case 0x2A: return "get-date";
    case 0x2C: return "get-time";
    case 0x30: return "get-DOS-version";
    case 0x35: return "get-vector";
    case 0x3C: return "handle-create";
    case 0x3D: return "handle-open";
    case 0x3E: return "handle-close";
    case 0x3F: return "handle-read";
    case 0x40: return "handle-write";
    case 0x48: return "alloc";
    case 0x49: return "free";
    case 0x4A: return "resize";
    case 0x4B: return "EXEC";
    case 0x4C: return "terminate";
    default:   return {};
    }
}

static inline bool cfg_parse_hex_imm(std::string_view s, uint32_t& out) {
    // Accept 0xNN, 0xNNNN, NNh, plain hex from Capstone op_str fragments
    while (!s.empty() && (s.front() == ' ' || s.front() == ',' || s.front() == '['))
        s.remove_prefix(1);
    if (s.empty()) return false;
    size_t end = 0;
    while (end < s.size() && (std::isxdigit(static_cast<unsigned char>(s[end])) ||
                              s[end] == 'x' || s[end] == 'X' || s[end] == 'h' || s[end] == 'H'))
        end++;
    std::string tok(s.substr(0, end));
    if (tok.empty()) return false;
    if (tok.size() > 1 && (tok.back() == 'h' || tok.back() == 'H'))
        tok.pop_back();
    if (tok.size() > 2 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X'))
        tok = tok.substr(2);
    if (tok.empty()) return false;
    try {
        unsigned long v = std::stoul(tok, nullptr, 16);
        out = static_cast<uint32_t>(v);
        return v <= 0xFFFFUL;
    } catch (...) {
        return false;
    }
}

/// Extract printable C-like and $-terminated / length-ish strings from image.
static inline void cfg_collect_strings(const std::vector<uint8_t>& image,
                                       std::vector<CfgStringLit>& out,
                                       size_t min_len = 4) {
    out.clear();
    const size_t n = image.size();
    size_t i = 0;
    while (i < n) {
        // ASCII run
        if (image[i] >= 32 && image[i] < 127) {
            size_t j = i;
            while (j < n && image[j] >= 32 && image[j] < 127) ++j;
            size_t len = j - i;
            // Allow trailing '$' DOS string just outside run
            if (len >= min_len) {
                CfgStringLit lit;
                lit.off = static_cast<uint16_t>(i);
                lit.text.assign(reinterpret_cast<const char*>(&image[i]), len);
                // Prefer interesting-looking strings; still keep shorter file names
                out.push_back(std::move(lit));
            }
            i = j + 1;
            continue;
        }
        // Pascal-style: length byte then ASCII
        if (image[i] >= min_len && image[i] <= 64 && i + 1 + image[i] <= n) {
            bool ok = true;
            for (size_t k = 0; k < image[i]; ++k) {
                uint8_t c = image[i + 1 + k];
                if (c < 32 || c >= 127) { ok = false; break; }
            }
            if (ok) {
                CfgStringLit lit;
                lit.off = static_cast<uint16_t>(i + 1);
                lit.text.assign(reinterpret_cast<const char*>(&image[i + 1]), image[i]);
                out.push_back(std::move(lit));
                i += 1 + image[i];
                continue;
            }
        }
        ++i;
    }
}

static inline bool cfg_string_interesting(std::string_view s) {
    // Lowercase copy for matching
    std::string lo;
    lo.reserve(s.size());
    for (char c : s)
        lo.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    static const char* keys[] = {
        ".ovl", ".exe", ".com", ".map", ".dat", ".adv", ".gam", ".sys",
        "icon", "error", "can't", "cant", "open", "file", "disk", "save",
        "fcb", "illegal", "copy", "drive", "quest", "help", "press",
        "insert", "mode", "color", "graphics", "pascal", "corrupt",
    };
    for (const char* k : keys)
        if (lo.find(k) != std::string::npos) return true;
    // bare filenames like "dr.dat"
    if (lo.size() >= 5 && lo.size() <= 12 && lo.find('.') != std::string::npos)
        return true;
    return false;
}

static inline void cfg_tag_push(CfgBlock& b, std::string_view tag) {
    for (const auto& t : b.tags)
        if (t == tag) return;
    b.tags.emplace_back(tag);
}

/// Register immediates observed while scanning a block's machine code.
struct CfgRegHint {
    uint16_t ah = 0x100;     ///< >0xFF = unknown
    uint16_t al = 0x100;
    uint32_t dx = 0x10000;   ///< >0xFFFF = unknown
    uint32_t bx = 0x10000;   ///< sometimes FCB in BX
    uint32_t si = 0x10000;
    uint32_t di = 0x10000;
};

/// Scan raw instruction stream of a block (and optionally only up to before_ip).
static inline CfgRegHint cfg_scan_block_regs(const CfgBlock& blk,
                                             uint16_t before_ip = 0xFFFF) {
    CfgRegHint h;
    for (const auto& in : blk.insns) {
        if (before_ip != 0xFFFF && in.ip >= before_ip)
            break;
        const uint8_t* b = in.bytes;
        const uint8_t n = in.size;
        if (n >= 2 && b[0] == 0xB4) // mov ah, imm8
            h.ah = b[1];
        else if (n >= 2 && b[0] == 0xB0) // mov al, imm8
            h.al = b[1];
        else if (n >= 3 && b[0] == 0xB8) { // mov ax, imm16
            h.al = b[1];
            h.ah = b[2];
        } else if (n >= 3 && b[0] == 0xBA) // mov dx, imm16
            h.dx = static_cast<uint32_t>(b[1] | (b[2] << 8));
        else if (n >= 3 && b[0] == 0xBB) // mov bx, imm16
            h.bx = static_cast<uint32_t>(b[1] | (b[2] << 8));
        else if (n >= 3 && b[0] == 0xBE) // mov si, imm16
            h.si = static_cast<uint32_t>(b[1] | (b[2] << 8));
        else if (n >= 3 && b[0] == 0xBF) // mov di, imm16
            h.di = static_cast<uint32_t>(b[1] | (b[2] << 8));
        // Capstone text fallback for lea dx, [imm] etc.
        if (in.text.starts_with("mov dx,") || in.text.starts_with("lea dx,")) {
            uint32_t v = 0;
            auto p = in.text.find_first_of("0123456789");
            if (p != std::string::npos &&
                cfg_parse_hex_imm(std::string_view(in.text).substr(p), v))
                h.dx = v;
        }
    }
    return h;
}

/// Walk predecessors (BFS, limited depth) for AH/AL/DX hints.
static inline CfgRegHint cfg_regs_from_preds(const CfgGraph& g, uint16_t blk_ip,
                                             int max_depth = 6) {
    CfgRegHint best;
    std::queue<std::pair<uint16_t, int>> q;
    std::set<uint16_t> seen;
    q.push({blk_ip, 0});
    seen.insert(blk_ip);

    while (!q.empty()) {
        auto [cur, depth] = q.front();
        q.pop();
        auto it = g.blocks.find(cur);
        if (it == g.blocks.end()) continue;
        // For the starting block we only want preds, not self (self scanned separately)
        if (depth > 0) {
            CfgRegHint h = cfg_scan_block_regs(it->second);
            // Prefer nearer predecessors; only fill unknowns
            if (best.ah > 0xFF && h.ah <= 0xFF) best.ah = h.ah;
            if (best.al > 0xFF && h.al <= 0xFF) best.al = h.al;
            if (best.dx > 0xFFFF && h.dx <= 0xFFFF) best.dx = h.dx;
            if (best.bx > 0xFFFF && h.bx <= 0xFFFF) best.bx = h.bx;
            if (best.si > 0xFFFF && h.si <= 0xFFFF) best.si = h.si;
            if (best.di > 0xFFFF && h.di <= 0xFFFF) best.di = h.di;
            if (best.ah <= 0xFF && best.dx <= 0xFFFF)
                break; // good enough
        }
        if (depth >= max_depth) continue;
        for (uint16_t p : it->second.preds) {
            if (seen.insert(p).second)
                q.push({p, depth + 1});
        }
    }
    return best;
}

/// Parse classic FCB name (8.3 space-padded) at image offset.
static inline bool cfg_parse_fcb_name(const std::vector<uint8_t>& image, uint16_t off,
                                      std::string& out) {
    // Standard FCB: +0 drive, +1..8 name, +9..11 ext
    // Extended FCB: FF + 6 reserved + standard at +7
    if (static_cast<size_t>(off) + 12 > image.size())
        return false;
    uint16_t base = off;
    if (image[off] == 0xFF) {
        if (static_cast<size_t>(off) + 0x13 > image.size())
            return false;
        base = static_cast<uint16_t>(off + 7);
    }
    std::string name, ext;
    for (int i = 0; i < 8; ++i) {
        char c = static_cast<char>(image[base + 1 + i]);
        if (c == ' ' || c == 0) break;
        if (c < 33 || c > 126) return false;
        name.push_back(c);
    }
    for (int i = 0; i < 3; ++i) {
        char c = static_cast<char>(image[base + 9 + i]);
        if (c == ' ' || c == 0) break;
        if (c < 33 || c > 126) return false;
        ext.push_back(c);
    }
    if (name.empty()) return false;
    // Reject pure garbage (must look filename-ish)
    bool alnum = false;
    for (char c : name)
        if (std::isalnum(static_cast<unsigned char>(c))) alnum = true;
    if (!alnum) return false;
    out = ext.empty() ? name : name + "." + ext;
    return true;
}

/// Asciiz path at image offset (handle open).
static inline bool cfg_parse_asciiz_path(const std::vector<uint8_t>& image, uint16_t off,
                                         std::string& out) {
    if (off >= image.size()) return false;
    std::string s;
    for (size_t i = off; i < image.size() && i < static_cast<size_t>(off) + 80; ++i) {
        char c = static_cast<char>(image[i]);
        if (c == 0) break;
        if (c < 32 || c > 126) return false;
        s.push_back(c);
    }
    if (s.size() < 3 || s.size() > 64) return false;
    out = s;
    return true;
}

/// Tag a real filename / path (FCB, handle, or Pascal inline string).
static inline void cfg_tag_filename(CfgBlock& b, std::string_view path) {
    std::string lo;
    for (char c : path)
        lo.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lo.find(".ovl") != std::string::npos)
        cfg_tag_push(b, "overlay-name");
    if (lo.find(".map") != std::string::npos)
        cfg_tag_push(b, "map-file");
    if (lo.find(".dat") != std::string::npos)
        cfg_tag_push(b, "dat-file");
    if (lo.find(".adv") != std::string::npos)
        cfg_tag_push(b, "adv-file");
    if (lo.find(".gam") != std::string::npos)
        cfg_tag_push(b, "save-game");
    if (lo.find(".exe") != std::string::npos || lo.find(".com") != std::string::npos)
        cfg_tag_push(b, "exe-name");
    // Only emit path: for short name-like strings (avoid UI sentences)
    if (path.size() <= 24 && (lo.find('.') != std::string::npos ||
                              lo.find("icon") != std::string::npos))
        cfg_tag_push(b, std::string("path:") + std::string(path));
}

/// UI / message string tags (not filenames).
static inline void cfg_tag_message(CfgBlock& b, std::string_view text) {
    std::string lo;
    for (char c : text)
        lo.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    if (lo.find("illegal") != std::string::npos || lo.find("copy") != std::string::npos)
        cfg_tag_push(b, "copy-protect?");
    if (lo.find("save") != std::string::npos || lo.find(".gam") != std::string::npos)
        cfg_tag_push(b, "save-game");
    if (lo.find("error") != std::string::npos || lo.find("can't") != std::string::npos ||
        lo.find("cant") != std::string::npos)
        cfg_tag_push(b, "error-msg");
    if (lo.find(".ovl") != std::string::npos)
        cfg_tag_push(b, "overlay-name");
    if (lo.find(".map") != std::string::npos || lo.find(".dat") != std::string::npos ||
        lo.find(".adv") != std::string::npos)
        cfg_tag_push(b, "data-file");
}

static inline void cfg_apply_int21_tags(CfgBlock& blk, CfgIntSite& site) {
    if (site.int_num != 0x21 || site.ah == 0xFF)
        return;
    site.note = cfg_int21_hint(site.ah);
    if (!site.note.empty())
        cfg_tag_push(blk, site.note);
    if (site.ah == 0x0F || site.ah == 0x10 || site.ah == 0x14 ||
        site.ah == 0x15 || site.ah == 0x16 || site.ah == 0x21 ||
        site.ah == 0x22 || site.ah == 0x27 || site.ah == 0x28)
        cfg_tag_push(blk, "FCB-I/O");
    if (site.ah == 0x3D || site.ah == 0x3F || site.ah == 0x3C ||
        site.ah == 0x3E || site.ah == 0x40)
        cfg_tag_push(blk, "handle-I/O");
    if (site.ah == 0x4B)
        cfg_tag_push(blk, "EXEC/overlay?");
    if (site.ah == 0x09)
        cfg_tag_push(blk, "dos-print");
    if (!site.path.empty())
        cfg_tag_filename(blk, site.path);
}

/// Find which basic block contains IP (start <= ip < end).
static inline CfgBlock* cfg_block_at(CfgGraph& g, uint16_t ip) {
    // blocks are keyed by start; find greatest start <= ip
    auto it = g.blocks.upper_bound(ip);
    if (it == g.blocks.begin()) return nullptr;
    --it;
    if (ip >= it->second.start_ip && ip < it->second.end_ip)
        return &it->second;
    // also accept exact start
    if (ip == it->second.start_ip)
        return &it->second;
    return nullptr;
}

/// Pascal MT+ inline strings:  CALL  $+3+len+1  /  db len, 'chars...'
/// The CALL's return address points at the length byte; used as string ptr.
static inline void cfg_find_pascal_inline_strings(CfgGraph& g,
                                                  const std::vector<uint8_t>& image) {
    const size_t n = image.size();
    for (size_t i = 0; i + 4 < n; ++i) {
        if (image[i] != 0xE8) continue; // near call
        int16_t rel = static_cast<int16_t>(image[i + 1] | (image[i + 2] << 8));
        if (rel < 2 || rel > 80) continue;
        size_t str_at = i + 3;
        if (str_at >= n) continue;
        uint8_t len = image[str_at];
        // rel should skip length byte + payload: rel == 1+len
        if (len < 3 || len > 64 || static_cast<int>(1 + len) != rel)
            continue;
        if (str_at + 1 + len > n) continue;
        bool ok = true;
        for (size_t k = 0; k < len; ++k) {
            uint8_t c = image[str_at + 1 + k];
            if (c < 32 || c >= 127) { ok = false; break; }
        }
        if (!ok) continue;
        std::string s(reinterpret_cast<const char*>(&image[str_at + 1]), len);
        uint16_t call_ip = static_cast<uint16_t>(i);
        CfgBlock* blk = cfg_block_at(g, call_ip);
        if (!blk) {
            // create soft xref on nearest block start if any
            continue;
        }
        CfgStringXref xr;
        xr.at_ip = call_ip;
        xr.str_ip = static_cast<uint16_t>(str_at + 1);
        xr.str = s;
        // dedup
        bool dup = false;
        for (const auto& x : blk->str_xrefs)
            if (x.str_ip == xr.str_ip) { dup = true; break; }
        if (!dup) {
            blk->str_xrefs.push_back(xr);
            g.n_str_xrefs++;
        }
        // Filename-like → strong tags
        bool looks_file = (s.find('.') != std::string::npos && s.size() <= 16) ||
                          cfg_string_interesting(s);
        if (looks_file && s.size() <= 24 && s.find(' ') == std::string::npos)
            cfg_tag_filename(*blk, s);
        else
            cfg_tag_message(*blk, s);
        cfg_tag_push(*blk, "pascal-inline-str");
        blk->is_interesting = true;
    }
}

/// Annotate blocks with INT sites, string xrefs, pred AH/DX, FCB paths, tags.
static inline void cfg_annotate(CfgGraph& g, const std::vector<uint8_t>& image) {
    cfg_collect_strings(image, g.strings, 4);

    std::map<uint16_t, const CfgStringLit*> by_off;
    for (const auto& s : g.strings)
        by_off[s.off] = &s;

    auto find_string_at = [&](uint16_t off) -> const CfgStringLit* {
        auto it = by_off.find(off);
        if (it != by_off.end()) return it->second;
        for (const auto& s : g.strings) {
            if (off >= s.off && off < s.off + s.text.size())
                return &s;
        }
        return nullptr;
    };

    auto try_resolve_path = [&](const CfgIntSite& site, uint16_t ptr,
                                std::string& path) -> bool {
        if (ptr == 0xFFFF) return false;
        // Handle-style asciiz
        if (site.ah == 0x3D || site.ah == 0x3C || site.ah == 0x4B ||
            site.ah == 0x09) {
            if (cfg_parse_asciiz_path(image, ptr, path))
                return true;
            // $-string for AH=09
            if (site.ah == 0x09) {
                const CfgStringLit* lit = find_string_at(ptr);
                if (lit) { path = lit->text; return true; }
            }
        }
        // FCB-style
        if (site.ah == 0x0F || site.ah == 0x10 || site.ah == 0x14 ||
            site.ah == 0x15 || site.ah == 0x16 || site.ah == 0x21 ||
            site.ah == 0x22 || site.ah == 0x27 || site.ah == 0x28 ||
            site.ah == 0xFF /* unknown, try both */) {
            if (cfg_parse_fcb_name(image, ptr, path))
                return true;
        }
        // Fallback: try both
        if (cfg_parse_fcb_name(image, ptr, path))
            return true;
        if (cfg_parse_asciiz_path(image, ptr, path))
            return true;
        return false;
    };

    // --- Pass 1: per-block INT discovery + local AH/DX ---
    for (auto& [sip, blk] : g.blocks) {
        (void)sip;
        CfgRegHint local{};

        for (const auto& in : blk.insns) {
            // Update local regs from this insn alone by reusing full scan pattern
            // (cheap: scan single-insn fake — just use bytes)
            if (in.size >= 2 && in.bytes[0] == 0xB4) local.ah = in.bytes[1];
            else if (in.size >= 2 && in.bytes[0] == 0xB0) local.al = in.bytes[1];
            else if (in.size >= 3 && in.bytes[0] == 0xB8) {
                local.al = in.bytes[1];
                local.ah = in.bytes[2];
            } else if (in.size >= 3 && in.bytes[0] == 0xBA)
                local.dx = static_cast<uint32_t>(in.bytes[1] | (in.bytes[2] << 8));
            else if (in.size >= 3 && in.bytes[0] == 0xBB)
                local.bx = static_cast<uint32_t>(in.bytes[1] | (in.bytes[2] << 8));

            if (in.size >= 2 && in.bytes[0] == 0xCD) {
                CfgIntSite site;
                site.ip = in.ip;
                site.int_num = in.bytes[1];
                if (local.ah <= 0xFF) site.ah = static_cast<uint8_t>(local.ah);
                if (local.al <= 0xFF) site.al = static_cast<uint8_t>(local.al);
                if (local.dx <= 0xFFFF) site.dx = static_cast<uint16_t>(local.dx);

                if (site.int_num == 0x10) {
                    site.note = "video";
                    cfg_tag_push(blk, "INT10-video");
                } else if (site.int_num == 0x16) {
                    site.note = "keyboard";
                    cfg_tag_push(blk, "INT16-kbd");
                } else if (site.int_num == 0x13) {
                    site.note = "disk";
                    cfg_tag_push(blk, "INT13-disk");
                    if (site.ah == 0x02) cfg_tag_push(blk, "disk-read");
                    if (site.ah == 0x04) cfg_tag_push(blk, "disk-verify");
                } else if (site.int_num == 0x20) {
                    cfg_tag_push(blk, "terminate");
                }

                cfg_apply_int21_tags(blk, site);
                blk.ints.push_back(std::move(site));
                g.n_int_sites++;
                // INT 21 may clobber AH
                if (in.bytes[1] == 0x21) {
                    local.ah = 0x100;
                    local.al = 0x100;
                }
            }

            // String immeds from text
            std::string ops = in.text;
            size_t pos = 0;
            while (pos < ops.size()) {
                while (pos < ops.size() && !std::isxdigit(static_cast<unsigned char>(ops[pos])) &&
                       ops[pos] != '0')
                    ++pos;
                if (pos >= ops.size()) break;
                size_t rest = pos;
                size_t tlen = 0;
                while (rest + tlen < ops.size() &&
                       (std::isxdigit(static_cast<unsigned char>(ops[rest + tlen])) ||
                        ops[rest + tlen] == 'x' || ops[rest + tlen] == 'X' ||
                        ops[rest + tlen] == 'h' || ops[rest + tlen] == 'H'))
                    tlen++;
                uint32_t imm = 0;
                if (tlen >= 2 &&
                    cfg_parse_hex_imm(std::string_view(ops).substr(rest, tlen), imm) &&
                    imm <= 0xFFFF) {
                    const CfgStringLit* lit = find_string_at(static_cast<uint16_t>(imm));
                    if (lit && (cfg_string_interesting(lit->text) || lit->text.size() >= 6)) {
                        bool dup = false;
                        for (const auto& x : blk.str_xrefs)
                            if (x.str_ip == lit->off) { dup = true; break; }
                        if (!dup) {
                            CfgStringXref xr;
                            xr.at_ip = in.ip;
                            xr.str_ip = lit->off;
                            xr.str = lit->text.size() > 48 ? lit->text.substr(0, 48) + "..."
                                                           : lit->text;
                            blk.str_xrefs.push_back(std::move(xr));
                            g.n_str_xrefs++;
                            // short name-like → filename tags; else message tags
                            if (lit->text.size() <= 16 &&
                                lit->text.find('.') != std::string::npos)
                                cfg_tag_filename(blk, lit->text);
                            else
                                cfg_tag_message(blk, lit->text);
                        }
                    }
                }
                pos = rest + (tlen ? tlen : 1);
            }
        }

        // LE16 in block → interesting strings (mov dx/bx/si, offset …)
        if (blk.start_ip < blk.end_ip && blk.end_ip <= image.size()) {
            for (uint16_t off = blk.start_ip; off + 1 < blk.end_ip; ++off) {
                bool is_imm_load = false;
                if (off >= 1) {
                    uint8_t op = image[off - 1];
                    if (op == 0xBA || op == 0xBB || op == 0xBE || op == 0xBF ||
                        op == 0xB8 || op == 0xB9)
                        is_imm_load = true;
                }
                if (!is_imm_load) continue;
                uint16_t val = static_cast<uint16_t>(image[off] | (image[off + 1] << 8));
                auto it = by_off.find(val);
                if (it == by_off.end() || !cfg_string_interesting(it->second->text))
                    continue;
                const CfgStringLit* lit = it->second;
                bool dup = false;
                for (const auto& x : blk.str_xrefs)
                    if (x.str_ip == lit->off) { dup = true; break; }
                if (dup) continue;
                CfgStringXref xr;
                xr.at_ip = static_cast<uint16_t>(off - 1);
                xr.str_ip = lit->off;
                xr.str = lit->text.size() > 48 ? lit->text.substr(0, 48) + "..."
                                               : lit->text;
                blk.str_xrefs.push_back(std::move(xr));
                g.n_str_xrefs++;
                if (lit->text.size() <= 16 && lit->text.find('.') != std::string::npos)
                    cfg_tag_filename(blk, lit->text);
                else
                    cfg_tag_message(blk, lit->text);
            }
        }
    }

    // Pascal inline CALL/string pattern (ICON: call; db 9,'icon0.ovl')
    cfg_find_pascal_inline_strings(g, image);

    // --- Pass 2: predecessor AH/DX recovery + FCB/handle path ---
    for (auto& [sip, blk] : g.blocks) {
        (void)sip;
        for (auto& site : blk.ints) {
            CfgRegHint local = cfg_scan_block_regs(blk, site.ip);
            if (site.ah == 0xFF && local.ah <= 0xFF)
                site.ah = static_cast<uint8_t>(local.ah);
            if (site.al == 0xFF && local.al <= 0xFF)
                site.al = static_cast<uint8_t>(local.al);
            if (site.dx == 0xFFFF && local.dx <= 0xFFFF)
                site.dx = static_cast<uint16_t>(local.dx);

            if (site.ah == 0xFF || site.dx == 0xFFFF) {
                CfgRegHint pred = cfg_regs_from_preds(g, blk.start_ip, 8);
                if (site.ah == 0xFF && pred.ah <= 0xFF) {
                    site.ah = static_cast<uint8_t>(pred.ah);
                    site.ah_from_pred = true;
                }
                if (site.al == 0xFF && pred.al <= 0xFF)
                    site.al = static_cast<uint8_t>(pred.al);
                if (site.dx == 0xFFFF && pred.dx <= 0xFFFF) {
                    site.dx = static_cast<uint16_t>(pred.dx);
                    site.dx_from_pred = true;
                }
                // BX as alternate pointer (rare)
                if (site.dx == 0xFFFF && pred.bx <= 0xFFFF) {
                    site.dx = static_cast<uint16_t>(pred.bx);
                    site.dx_from_pred = true;
                }
            }

            // Re-apply tags now that AH may be known
            cfg_apply_int21_tags(blk, site);

            // Resolve path at DX (or BX/SI if still unknown)
            if (site.path.empty() && site.int_num == 0x21) {
                std::string path;
                uint16_t ptrs[4] = { site.dx, 0xFFFF, 0xFFFF, 0xFFFF };
                CfgRegHint loc2 = cfg_scan_block_regs(blk, site.ip);
                CfgRegHint pred2 = cfg_regs_from_preds(g, blk.start_ip, 8);
                if (loc2.bx <= 0xFFFF) ptrs[1] = static_cast<uint16_t>(loc2.bx);
                else if (pred2.bx <= 0xFFFF) ptrs[1] = static_cast<uint16_t>(pred2.bx);
                if (loc2.si <= 0xFFFF) ptrs[2] = static_cast<uint16_t>(loc2.si);
                else if (pred2.si <= 0xFFFF) ptrs[2] = static_cast<uint16_t>(pred2.si);
                if (loc2.di <= 0xFFFF) ptrs[3] = static_cast<uint16_t>(loc2.di);

                for (uint16_t p : ptrs) {
                    if (p == 0xFFFF) continue;
                    if (try_resolve_path(site, p, path)) {
                        site.path = path;
                        if (site.dx == 0xFFFF) {
                            site.dx = p;
                            site.dx_from_pred = true;
                        }
                        cfg_tag_filename(blk, path);
                        cfg_tag_push(blk, "path-resolved");
                        break;
                    }
                }
            }

            // Default DOS FCB at DS:005C — note when DX=5C on FCB calls
            if (site.int_num == 0x21 && site.dx == 0x005C &&
                (site.ah == 0x0F || site.ah == 0x10 || site.ah == 0x14 ||
                 site.ah == 0x15 || site.ah == 0x16 || site.ah == 0x21 ||
                 site.ah == 0x22 || site.ah == 0x27 || site.ah == 0x28 ||
                 site.ah == 0xFF)) {
                cfg_tag_push(blk, "FCB@DS:5C");
                if (site.path.empty())
                    site.note = site.note.empty()
                        ? "FCB at default DS:005C (name filled at runtime)"
                        : site.note + "; FCB@DS:5C";
            }

            if (site.int_num == 0x21 && site.ah == 0x4C)
                cfg_tag_push(blk, "terminate");
        }

        blk.is_interesting = !blk.ints.empty() || !blk.str_xrefs.empty() ||
                             !blk.tags.empty() || blk.is_entry;
    }
}

//=============================================================================
// Print CFG
//=============================================================================

static inline void cfg_print_block(const CfgBlock& b, const Options& opts) {
    std::cout << std::format("BB {:04X}..{:04X}  file {:08X}h  insns={}  preds={}",
                             b.start_ip, b.end_ip,
                             static_cast<unsigned>(b.file_off),
                             b.insns.size(), b.preds.size());
    if (b.is_entry) std::cout << "  [ENTRY]";
    if (b.is_table_entry) std::cout << "  [JMP-TABLE]";
    if (b.is_call_target) std::cout << "  [CALL-TGT]";
    if (b.is_interesting) std::cout << "  [INTERESTING]";
    std::cout << "\n";

    if (!b.tags.empty()) {
        std::cout << "  tags:";
        for (const auto& t : b.tags)
            std::cout << " [" << t << "]";
        std::cout << "\n";
    }
    for (const auto& site : b.ints) {
        std::cout << std::format("  INT {:02X}h @ {:04X}", site.int_num, site.ip);
        if (site.ah != 0xFF)
            std::cout << std::format("  AH={:02X}h{}", site.ah,
                                     site.ah_from_pred ? "(pred)" : "");
        if (site.al != 0xFF && site.int_num == 0x21)
            std::cout << std::format("  AL={:02X}h", site.al);
        if (site.dx != 0xFFFF)
            std::cout << std::format("  DX={:04X}h{}", site.dx,
                                     site.dx_from_pred ? "(pred)" : "");
        if (!site.note.empty())
            std::cout << "  ; " << site.note;
        if (!site.path.empty())
            std::cout << "  path=\"" << site.path << "\"";
        std::cout << "\n";
    }
    for (const auto& xr : b.str_xrefs) {
        std::cout << std::format("  str xref @ {:04X} -> image:{:04X}  \"{}\"\n",
                                 xr.at_ip, xr.str_ip, xr.str);
    }

    if (!b.preds.empty() && b.preds.size() <= 12) {
        std::cout << "  preds:";
        for (uint16_t p : b.preds)
            std::cout << std::format(" {:04X}", p);
        std::cout << "\n";
    } else if (b.preds.size() > 12) {
        std::cout << std::format("  preds: {} blocks\n", b.preds.size());
    }

    if (!opts.cfgNoInsns) {
        // cfgInsnsPerBlock == 0 → show all
        const size_t lim = (opts.cfgInsnsPerBlock == 0)
            ? b.insns.size()
            : opts.cfgInsnsPerBlock;
        for (size_t i = 0; i < b.insns.size() && i < lim; ++i) {
            const auto& in = b.insns[i];
            std::cout << std::format("    {:04X}:  {}\n", in.ip, in.text);
        }
        if (b.insns.size() > lim)
            std::cout << std::format("    ... {} more insns\n", b.insns.size() - lim);
    }

    for (const auto& e : b.outs) {
        if (e.has_target)
            std::cout << std::format("  -> {:04X}  [{}]\n", e.to_ip, cfg_edge_name(e.kind));
        else
            std::cout << std::format("  -> ???   [{}]\n", cfg_edge_name(e.kind));
    }
    std::cout << "\n";
}

/// True if block is a file/I/O “seed” for the load graph.
static inline bool cfg_is_io_seed(const CfgBlock& b) {
    for (const auto& t : b.tags) {
        if (t.starts_with("path:") || t == "overlay-name" || t == "map-file" ||
            t == "dat-file" || t == "adv-file" || t == "save-game" ||
            t == "FCB-I/O" || t == "FCB@DS:5C" || t == "handle-I/O" ||
            t == "path-resolved" || t == "FCB-open" || t == "FCB-block-read" ||
            t == "FCB-seq-read" || t == "FCB-create" || t == "set-DTA" ||
            t == "EXEC/overlay?" || t == "pascal-inline-str") {
            // pascal-inline-str alone is noisy; require filename-ish tag too
            if (t == "pascal-inline-str") continue;
            return true;
        }
    }
    for (const auto& s : b.ints) {
        if (s.int_num == 0x21 && s.ah != 0xFF) {
            if (s.ah == 0x0F || s.ah == 0x14 || s.ah == 0x16 || s.ah == 0x1A ||
                s.ah == 0x21 || s.ah == 0x27 || s.ah == 0x3D || s.ah == 0x3F ||
                s.ah == 0x4B)
                return true;
        }
    }
    for (const auto& t : b.tags)
        if (t.starts_with("path:") && t.size() <= 20)
            return true;
    return false;
}

static inline std::string cfg_seed_label(const CfgBlock& b) {
    std::string lab;
    for (const auto& t : b.tags) {
        if (t.starts_with("path:")) {
            if (!lab.empty()) lab += " ";
            lab += t;
        }
    }
    for (const auto& t : b.tags) {
        if (t == "overlay-name" || t == "map-file" || t == "dat-file" ||
            t == "FCB@DS:5C" || t == "FCB-I/O" || t == "FCB-block-read" ||
            t == "set-DTA" || t == "FCB-open") {
            if (!lab.empty()) lab += " ";
            lab += "[" + t + "]";
        }
    }
    for (const auto& s : b.ints) {
        if (s.int_num == 0x21 && s.ah != 0xFF) {
            if (!lab.empty()) lab += " ";
            lab += std::format("INT21/AH={:02X}", s.ah);
            if (!s.path.empty()) lab += "(\"" + s.path + "\")";
        }
    }
    if (lab.empty()) lab = "(io-site)";
    return lab;
}

/// Walk reverse edges to build a caller chain (prefer Call edges).
static inline void cfg_print_load_graph(const CfgGraph& g, const Options& opts) {
    std::cout << "=== Load / I/O call graph (reverse preds from path+FCB seeds) ===\n";
    std::cout << "Walks predecessors of file-related blocks (depth-limited).\n"
                 "Call edges preferred in the chain display.\n\n";

    std::vector<const CfgBlock*> seeds;
    for (const auto& kv : g.blocks)
        if (cfg_is_io_seed(kv.second))
            seeds.push_back(&kv.second);
    std::sort(seeds.begin(), seeds.end(),
              [](const CfgBlock* a, const CfgBlock* b) {
                  return a->start_ip < b->start_ip;
              });

    if (seeds.empty()) {
        std::cout << "(no path/FCB seeds found)\n\n";
        return;
    }

    // Build reverse adjacency: to_ip -> list of (from_ip, edge kind)
    std::map<uint16_t, std::vector<std::pair<uint16_t, CfgEdgeKind>>> rev;
    for (const auto& [sip, blk] : g.blocks) {
        for (const auto& e : blk.outs) {
            if (!e.has_target) continue;
            rev[e.to_ip].push_back({sip, e.kind});
        }
        // preds may include fall-through-only; ensure listed
        for (uint16_t p : blk.preds)
            rev[blk.start_ip].push_back({p, CfgEdgeKind::FallThrough});
    }
    // dedup rev lists
    for (auto& [to, vec] : rev) {
        std::sort(vec.begin(), vec.end(),
                  [](auto& a, auto& b) {
                      if (a.first != b.first) return a.first < b.first;
                      return static_cast<int>(a.second) < static_cast<int>(b.second);
                  });
        vec.erase(std::unique(vec.begin(), vec.end(),
                              [](auto& a, auto& b) {
                                  return a.first == b.first && a.second == b.second;
                              }),
                  vec.end());
        (void)to;
    }

    const int max_depth = opts.cfgLoadDepth ? static_cast<int>(opts.cfgLoadDepth) : 6;
    const size_t max_seeds = opts.cfgLoadMaxSeeds ? opts.cfgLoadMaxSeeds : 40;
    size_t shown = 0;

    for (const CfgBlock* seed : seeds) {
        // Skip pure message sites: keep filename / FCB / overlay / map
        bool keep = false;
        for (const auto& t : seed->tags) {
            if (t.starts_with("path:") || t == "overlay-name" || t == "map-file" ||
                t == "dat-file" || t == "adv-file" || t == "FCB@DS:5C" ||
                t == "FCB-I/O" || t == "FCB-block-read" || t == "set-DTA" ||
                t == "FCB-open" || t == "handle-I/O")
                keep = true;
        }
        for (const auto& s : seed->ints)
            if (s.int_num == 0x21 &&
                (s.ah == 0x0F || s.ah == 0x1A || s.ah == 0x27 || s.ah == 0x14 ||
                 s.ah == 0x3D))
                keep = true;
        if (!keep) continue;
        if (shown >= max_seeds) {
            std::cout << std::format("... ({} more seeds omitted; --cfg-load-max=N)\n\n",
                                     seeds.size() - shown);
            break;
        }
        shown++;

        std::cout << std::format("SEED {:04X}  {}\n", seed->start_ip, cfg_seed_label(*seed));

        // BFS reverse: who reaches this seed
        std::queue<std::pair<uint16_t, int>> q;
        std::map<uint16_t, std::pair<uint16_t, CfgEdgeKind>> parent; // child -> (parent, edge)
        std::set<uint16_t> seen;
        q.push({seed->start_ip, 0});
        seen.insert(seed->start_ip);

        std::vector<uint16_t> callers; // depth-1 call parents
        std::vector<uint16_t> frontier;

        while (!q.empty()) {
            auto [cur, depth] = q.front();
            q.pop();
            if (depth >= max_depth) continue;
            auto it = rev.find(cur);
            if (it == rev.end()) continue;
            for (auto [frm, kind] : it->second) {
                if (!seen.insert(frm).second) continue;
                parent[frm] = {cur, kind};
                q.push({frm, depth + 1});
                if (depth == 0 && kind == CfgEdgeKind::Call)
                    callers.push_back(frm);
                if (depth + 1 == max_depth)
                    frontier.push_back(frm);
            }
        }

        // Immediate CFG preds
        if (!seed->preds.empty()) {
            std::cout << "  preds:";
            size_t n = 0;
            for (uint16_t p : seed->preds) {
                if (n++ >= 12) {
                    std::cout << " ...";
                    break;
                }
                std::cout << std::format(" {:04X}", p);
                auto bit = g.blocks.find(p);
                if (bit != g.blocks.end()) {
                    for (const auto& e : bit->second.outs) {
                        if (e.has_target && e.to_ip == seed->start_ip) {
                            std::cout << std::format("({})", cfg_edge_name(e.kind));
                            break;
                        }
                    }
                }
            }
            std::cout << "\n";
        }

        // Callers (direct call edges into seed)
        if (!callers.empty()) {
            std::cout << "  called-from:";
            for (uint16_t c : callers) {
                std::cout << std::format(" {:04X}", c);
                auto bit = g.blocks.find(c);
                if (bit != g.blocks.end() && !bit->second.tags.empty()) {
                    for (const auto& t : bit->second.tags) {
                        if (t.starts_with("path:") || t == "overlay-name") {
                            std::cout << "[" << t << "]";
                            break;
                        }
                    }
                }
            }
            std::cout << "\n";
        }

        // One sample reverse path: pick a deepest node and walk to seed
        uint16_t tip = seed->start_ip;
        int tip_depth = 0;
        for (const auto& [node, pr] : parent) {
            // compute depth by walking
            int d = 0;
            uint16_t x = node;
            std::set<uint16_t> guard;
            while (parent.count(x) && guard.insert(x).second) {
                x = parent[x].first;
                d++;
            }
            if (d > tip_depth) {
                tip_depth = d;
                tip = node;
            }
        }
        if (tip != seed->start_ip && tip_depth > 0) {
            std::vector<std::pair<uint16_t, CfgEdgeKind>> chain;
            uint16_t x = tip;
            std::set<uint16_t> guard;
            while (x != seed->start_ip && parent.count(x) && guard.insert(x).second) {
                auto [to, kind] = parent[x];
                chain.push_back({x, kind});
                x = to;
            }
            chain.push_back({seed->start_ip, CfgEdgeKind::FallThrough});
            std::cout << "  sample-chain (" << tip_depth << "): ";
            for (size_t i = 0; i < chain.size(); ++i) {
                if (i) {
                    std::cout << std::format(" -[{}]-> ", cfg_edge_name(chain[i - 1].second));
                }
                std::cout << std::format("{:04X}", chain[i].first);
            }
            std::cout << "\n";
        }

        // Who does this seed call? (forward one hop) — useful for open→read
        if (!seed->outs.empty()) {
            std::cout << "  calls/outs:";
            size_t n = 0;
            for (const auto& e : seed->outs) {
                if (!e.has_target) continue;
                if (e.kind != CfgEdgeKind::Call && e.kind != CfgEdgeKind::Jump &&
                    e.kind != CfgEdgeKind::FallThrough)
                    continue;
                if (n++ >= 8) {
                    std::cout << " ...";
                    break;
                }
                std::cout << std::format(" {}:{:04X}", cfg_edge_name(e.kind), e.to_ip);
            }
            std::cout << "\n";
        }
        std::cout << "\n";
    }

    // Compact overlay relationship from path tags alone
    std::cout << "--- Path string sites (filename anchors) ---\n";
    for (const CfgBlock* seed : seeds) {
        for (const auto& t : seed->tags) {
            if (!t.starts_with("path:")) continue;
            std::string name = t.substr(5);
            if (name.size() > 20) continue;
            std::cout << std::format("  {:04X}  {}\n", seed->start_ip, name);
        }
    }
    std::cout << "\n";
}

static inline void cfg_print(const CfgGraph& g, const Options& opts) {
    std::cout << "\n=== Control-Flow Graph (static, same-segment) ===\n";
    std::cout << std::format("CS segment:     {:04X}h\n", g.cs_seg);
    std::cout << std::format("Image file base:{:08X}h  size {:X}h ({} bytes)\n",
                             static_cast<unsigned>(g.image_file_base),
                             static_cast<unsigned>(g.image_size),
                             g.image_size);
    std::cout << std::format("Basic blocks:   {}\n", g.blocks.size());
    std::cout << std::format("Edges:          {}\n", g.n_edges);
    std::cout << std::format("Back-edges~:    {}  (to_ip <= from_ip, heuristic)\n",
                             g.n_loops_back);
    std::cout << std::format("INT sites:      {}\n", g.n_int_sites);
    std::cout << std::format("String xrefs:   {}\n", g.n_str_xrefs);
    std::cout << std::format("String lits:    {}\n", g.strings.size());
    if (!g.unresolved.empty())
        std::cout << std::format("Unresolved tgts:{}\n", g.unresolved.size());

    std::cout << "\nNote: CFG is a directed graph (joins share nodes; loops = back-edges).\n"
                 "      Not a path tree. Indirect jmp/call targets may be missing.\n"
                 "      INT AH is best-effort (same BB + predecessor walk).\n\n";

    cfg_print_load_graph(g, opts);

    std::vector<const CfgBlock*> order;
    order.reserve(g.blocks.size());
    for (const auto& kv : g.blocks)
        order.push_back(&kv.second);
    std::sort(order.begin(), order.end(),
              [](const CfgBlock* a, const CfgBlock* b) {
                  return a->start_ip < b->start_ip;
              });

    // --- Always print INTERESTING summary first (file I/O RE gold) ---
    std::vector<const CfgBlock*> interesting;
    for (const CfgBlock* bp : order)
        if (bp->is_interesting &&
            (!bp->ints.empty() || !bp->str_xrefs.empty() || !bp->tags.empty()))
            interesting.push_back(bp);

    std::cout << "=== Interesting blocks (INT / file strings / tags) ===\n";
    std::cout << std::format("Count: {}\n\n", interesting.size());
    if (interesting.empty()) {
        std::cout << "(none tagged — try without --cfg-no-calls, or binary has few ints)\n\n";
    } else {
        // Compact index table
        std::cout << "IP       Tags / summary\n";
        std::cout << "-------  --------------------------------------------------\n";
        for (const CfgBlock* bp : interesting) {
            std::cout << std::format("{:04X}     ", bp->start_ip);
            if (!bp->tags.empty()) {
                for (size_t i = 0; i < bp->tags.size(); ++i) {
                    if (i) std::cout << ", ";
                    std::cout << bp->tags[i];
                }
            }
            if (!bp->ints.empty()) {
                if (!bp->tags.empty()) std::cout << " | ";
                for (size_t i = 0; i < bp->ints.size() && i < 3; ++i) {
                    if (i) std::cout << "; ";
                    const auto& s = bp->ints[i];
                    std::cout << std::format("INT{:02X}", s.int_num);
                    if (s.ah != 0xFF) std::cout << std::format("/AH={:02X}", s.ah);
                    if (!s.note.empty()) std::cout << "(" << s.note << ")";
                    if (!s.path.empty()) std::cout << "[\"" << s.path << "\"]";
                }
                if (bp->ints.size() > 3)
                    std::cout << std::format(" +{} more", bp->ints.size() - 3);
            }
            // Prefer path: tags over random string noise
            bool showed_path = false;
            for (const auto& t : bp->tags) {
                if (t.starts_with("path:")) {
                    if (!showed_path) {
                        std::cout << " | " << t;
                        showed_path = true;
                    }
                }
            }
            if (!showed_path && !bp->str_xrefs.empty()) {
                std::cout << " | \"" << bp->str_xrefs[0].str << "\"";
                if (bp->str_xrefs.size() > 1)
                    std::cout << std::format(" +{} strs", bp->str_xrefs.size() - 1);
            }
            std::cout << "\n";
        }
        std::cout << "\n";

        // Full detail for interesting blocks (always, capped)
        std::cout << "=== Interesting block detail ===\n\n";
        size_t cap = opts.cfgInterestingMax ? opts.cfgInterestingMax : 80;
        for (size_t i = 0; i < interesting.size() && i < cap; ++i)
            cfg_print_block(*interesting[i], opts);
        if (interesting.size() > cap)
            std::cout << std::format("... ({} more interesting blocks; --cfg-interesting-max=N)\n\n",
                                     interesting.size() - cap);
    }

    if (opts.cfgInterestingOnly) {
        size_t n_tab = 0;
        for (const auto* bp : order)
            if (bp->is_table_entry) n_tab++;
        if (n_tab)
            std::cout << std::format("Jump-table slots identified: {}\n", n_tab);
        return;
    }

    // --- Full graph dump (optional) ---
    std::cout << "=== All basic blocks (truncated) ===\n\n";
    const size_t max_show = opts.cfgMaxBlocks ? opts.cfgMaxBlocks : 500;
    size_t shown = 0;
    for (const CfgBlock* bp : order) {
        if (shown >= max_show) {
            std::cout << std::format("... ({} more blocks omitted; raise --cfg-max=N)\n",
                                     order.size() - shown);
            break;
        }
        cfg_print_block(*bp, opts);
        shown++;
    }

    size_t n_tab = 0;
    for (const auto* bp : order)
        if (bp->is_table_entry) n_tab++;
    if (n_tab)
        std::cout << std::format("Jump-table slots identified: {}\n", n_tab);
}

/// Convenience: build+print CFG for a loaded MZ image region.
static inline void cfg_analyze_image(const std::vector<uint8_t>& fileData,
                                     size_t image_file_off,
                                     size_t image_len,
                                     uint16_t entry_ip,
                                     uint16_t cs_seg,
                                     const Options& opts) {
    if (image_file_off >= fileData.size()) {
        std::cout << "\nCFG: image offset outside file.\n";
        return;
    }
    size_t len = std::min(image_len, fileData.size() - image_file_off);
    std::vector<uint8_t> image(fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off),
                               fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off + len));

    // Build budget is independent of print limit (--cfg-max only affects dump).
    CfgGraph g = cfg_build(image, entry_ip, cs_seg, image_file_off,
                           opts.cfgFollowCalls, 20000);
    cfg_annotate(g, image);
    cfg_print(g, opts);
}

#endif // CFG_H
