// cfg.h - Static control-flow graph (CFG) recovery for 16-bit x86
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Recursive-descent / leader-based CFG: basic blocks + edges (fall-through,
// jmp, jcc true/false, call, ret). Optional scan for near-jump tables
// (Pascal MT+ style E9 stubs). Near control flow. A direct far transfer
// whose segment word is relocated is followed at seg*16+off inside this
// load image. A far transfer that is not relocated is followed only when
// its segment immediate equals the file CS (M1).
//
// This builds a *graph*, not a path tree: joins reuse the same block node.

#ifndef CFG_H
#define CFG_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <format>
#include <fstream>
#include <iostream>
#include <map>
#include <queue>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <capstone/capstone.h>

#include "exe.h"
#include "options.h"

//=============================================================================
// Linear addresses
//=============================================================================

/// Image-linear address. image[0] is 0. Not a truncated real-mode IP.
using CfgLin = uint32_t;

/**
 * @brief Uppercase hex for a linear address.
 *
 * Values at or below 0xFFFF stay four digits (`0100`). Larger values use
 * only the digits they need (`10000`), with no extra zero padding.
 *
 * @param v Linear address.
 * @return Hex text without a 0x prefix.
 */
static inline std::string cfg_lin_hex(CfgLin v)
{
    if (v <= 0xFFFFu)
    {
        return std::format("{:04X}", v);
    }
    return std::format("{:X}", v);
}

/**
 * @brief Signed distance from a paragraph frame to an image linear.
 *
 * @param linear Non-negative image offset. Capstone is addressed with this.
 * @param frame  Paragraph frame (`cs * 16`). May be negative.
 * @return `linear - frame`. @p frame is not converted to an unsigned type.
 */
static inline int64_t cfg_frame_dist(CfgLin linear, int32_t frame)
{
    return static_cast<int64_t>(linear) - static_cast<int64_t>(frame);
}

/**
 * @brief True when @p linear lies in the 64 KiB window that starts at @p frame.
 *
 * The distance is not wrapped. A negative frame stays signed.
 *
 * @param linear Image offset.
 * @param frame  Paragraph frame. May be negative.
 * @return true when `0 <= linear - frame <= 0xFFFF`.
 */
static inline bool cfg_in_frame(CfgLin linear, int32_t frame)
{
    const int64_t dist = cfg_frame_dist(linear, frame);
    return dist >= 0 && dist <= static_cast<int64_t>(0xFFFF);
}

/**
 * @brief Real-mode IP of @p linear inside @p frame.
 *
 * @param linear Image offset. Meaningful when cfg_in_frame is true.
 * @param frame  Paragraph frame. May be negative.
 * @return `(uint16_t)(linear - frame)`.
 */
static inline uint16_t cfg_ip16(CfgLin linear, int32_t frame)
{
    return static_cast<uint16_t>(cfg_frame_dist(linear, frame));
}

/**
 * @brief Near target `frame + uint16(imm - frame)`.
 *
 * Capstone's immediate is a non-negative linear. The frame is subtracted
 * in int64. A negative frame is never cast to uint32_t or uint64_t.
 * The caller still rejects a target that is outside the image.
 *
 * @param imm   Capstone immediate (CS_MODE_16 address).
 * @param frame Paragraph frame of the instruction. May be negative.
 * @param out   Receives the linear target when it is >= 0.
 * @return false when the target is negative. Do not enqueue it.
 */
static inline bool cfg_near_target(uint64_t imm, int32_t frame, CfgLin& out)
{
    const uint16_t target16 = static_cast<uint16_t>(
        static_cast<int64_t>(imm) - static_cast<int64_t>(frame));
    const int64_t next =
        static_cast<int64_t>(frame) + static_cast<int64_t>(target16);
    if (next < 0)
    {
        return false;
    }
    out = static_cast<CfgLin>(next);
    return true;
}

/**
 * @brief Fall-through linear, wrapping inside the 64 KiB frame.
 *
 * `ip16 = (uint16_t)(linear - frame)`, then `frame + uint16(ip16 + size)`.
 * Not `linear + size`. A nop at IP 0xFFFF continues at IP 0 of this frame.
 *
 * @param linear Instruction linear. Capstone's address, not the frame.
 * @param frame  Paragraph frame. May be negative.
 * @param size   Decoded length. The caller rejects a size that crosses the segment.
 * @param out    Receives the next linear when it is >= 0.
 * @return false when the next linear is negative.
 */
static inline bool cfg_fall_next(CfgLin linear, int32_t frame, uint16_t size,
                                 CfgLin& out)
{
    const uint16_t ip16 = cfg_ip16(linear, frame);
    const uint16_t next16 = static_cast<uint16_t>(ip16 + size);
    const int64_t next =
        static_cast<int64_t>(frame) + static_cast<int64_t>(next16);
    if (next < 0)
    {
        return false;
    }
    out = static_cast<CfgLin>(next);
    return true;
}

/**
 * @brief True when @p next16 wrapped below @p ip16.
 *
 * @param ip16   IP of the instruction inside its segment.
 * @param next16 IP of the following instruction, mod 65536.
 * @return true when the fall-through crossed the segment end.
 */
static inline bool cfg_ip16_wrapped(uint16_t ip16, uint16_t next16)
{
    return next16 < ip16;
}

/**
 * @brief Slot for a signed entry frame that cannot cross a CfgLin parameter.
 *
 * listing_run takes CfgLin. A negative frame must not be converted to
 * uint32_t. The MZ caller stores the frame here and passes 0. cfg_build
 * consumes the value once. dumpexe analyzes one image at a time.
 *
 * @return The process-lifetime slot.
 */
static inline int32_t& cfg_entry_frame_slot()
{
    static int32_t frame = 0;
    return frame;
}

/**
 * @brief Store a one-shot signed entry frame for the next cfg_build.
 *
 * @param frame Paragraph frame. A negative value is the override. 0 clears it.
 */
static inline void cfg_set_entry_frame_override(int32_t frame)
{
    cfg_entry_frame_slot() = frame;
}

/**
 * @brief Read and clear the one-shot entry frame.
 *
 * @return The stored frame. The slot is 0 afterwards.
 */
static inline int32_t cfg_take_entry_frame_override()
{
    int32_t& slot = cfg_entry_frame_slot();
    const int32_t frame = slot;
    slot = 0;
    return frame;
}

/**
 * @brief CfgLin base argument for listing_run.
 *
 * A negative @p frame is not converted to uint32_t. It is stored as the
 * one-shot override and this returns 0. A non-negative frame is returned
 * unchanged and any override is cleared.
 *
 * @param frame Signed paragraph frame from mz_entry_image_ip.
 * @return Value safe to pass as listing_run's segment base.
 */
static inline CfgLin cfg_listing_entry_base(int32_t frame)
{
    if (frame < 0)
    {
        cfg_set_entry_frame_override(frame);
        return 0;
    }
    cfg_set_entry_frame_override(0);
    return static_cast<CfgLin>(frame);
}

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
    CfgLin      to_ip = 0;   ///< successor block start (0 if Ret/unknown)
    CfgEdgeKind kind  = CfgEdgeKind::FallThrough;
    bool        has_target = true;
};

struct CfgInsn {
    CfgLin      ip = 0;          ///< image-linear address of the opcode
    int32_t     seg_base = 0;    ///< paragraph frame (cs * 16); may be negative
    size_t      file_off = 0;
    uint8_t     size = 0;
    std::string text;        ///< "mnemonic op_str"
    uint8_t     bytes[16]{}; ///< raw bytes (for INT / pattern scan)
};

/// DOS interrupt site recovered inside a block
struct CfgIntSite {
    CfgLin   ip = 0;
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
    CfgLin at_ip = 0;        ///< insn or site linear address
    CfgLin str_ip = 0;       ///< offset of string within image
    std::string str;         ///< printable form (truncated)
};

struct CfgBlock {
    CfgLin start_ip = 0;
    CfgLin end_ip   = 0;     ///< exclusive linear (first byte past last insn)
    int32_t seg_base = 0;    ///< paragraph frame (cs * 16); may be negative
    size_t   file_off = 0;   ///< file offset of start
    bool     is_entry = false;
    bool     is_table_entry = false;
    bool     is_call_target = false;
    bool     is_interesting = false; ///< INT / file / string xref
    std::vector<CfgInsn> insns;
    std::vector<CfgEdge> outs;
    std::vector<CfgLin> preds; ///< filled after build
    std::vector<CfgIntSite> ints;
    std::vector<CfgStringXref> str_xrefs;
    std::vector<std::string> tags; ///< e.g. "FCB-open", "overlay", "video"
};

struct CfgStringLit {
    CfgLin off = 0;          ///< image offset
    std::string text;
    bool interesting = false; ///< cfg_string_interesting, computed once
};

struct CfgGraph {
    uint16_t cs_seg = 0;           ///< Load base. Display only; not a flow segment.
    size_t   image_file_base = 0;  ///< file offset of image[0]
    size_t   image_size = 0;
    std::map<CfgLin, CfgBlock> blocks; ///< keyed by start_ip (linear)
    std::set<CfgLin> unresolved;       ///< jump/call targets outside image
    size_t n_edges = 0;
    size_t n_loops_back = 0;             ///< edges to lower-or-equal IP (heuristic)
    std::vector<CfgStringLit> strings;   ///< recovered literals in image
    size_t n_int_sites = 0;
    size_t n_str_xrefs = 0;
};

//=============================================================================
// Helpers
//=============================================================================

/**
 * @brief True for a direct far call or jump.
 *
 * Capstone prints `lcall 0x60, 0x2368` / `ljmp 0x60:0x1234` with operand 0 as
 * the segment immediate and operand 1 as the offset. Operand 0 is not an IP.
 *
 * @param m Lowercase mnemonic.
 * @return true for `lcall`, `ljmp`, `callf`, or `jmpf`.
 */
static inline bool cfg_is_far_xfer(std::string_view m)
{
    return m == "lcall" || m == "ljmp" || m == "callf" || m == "jmpf";
}

/**
 * @brief Offset of a direct far transfer that stays in this segment.
 *
 * Operand 0 is the segment. Operand 1 is the offset. A different segment is
 * external: the caller must not enqueue either immediate.
 *
 * @param x86    Capstone operand detail for one instruction.
 * @param file_cs File CS to match. For an MZ image this is MZHeader::cs,
 *                 not the load base. For a COM image it is the load base.
 * @param off_out Receives operand 1 when the segment matches.
 * @return true when both operands are immediates and operand 0 equals @p file_cs.
 * @note Not used when the segment word itself is a relocation. See cfg_far_reloc_site.
 */
static inline bool cfg_far_same_seg_off(const cs_x86& x86,
                                        uint16_t file_cs,
                                        uint16_t& off_out)
{
    if (x86.op_count < 2)
    {
        return false;
    }
    if (x86.operands[0].type != X86_OP_IMM || x86.operands[1].type != X86_OP_IMM)
    {
        return false;
    }
    const uint64_t seg = static_cast<uint64_t>(x86.operands[0].imm);
    if (seg != static_cast<uint64_t>(file_cs))
    {
        return false;
    }
    off_out = static_cast<uint16_t>(x86.operands[1].imm);
    return true;
}

/**
 * @brief How a direct far 9Ah/EAh relates to the relocation table.
 */
enum class CfgFarRelocKind : uint8_t
{
    NotPinned, ///< Segment word is not relocated. The caller keeps M1.
    Outside,   ///< Pinned, but the linear target is not an in-image IP.
    InImage    ///< @c CfgFarReloc::ip is the in-image target. Do not also apply M1.
};

/**
 * @brief In-image result of a relocation-pinned far transfer.
 */
struct CfgFarReloc
{
    CfgFarRelocKind kind = CfgFarRelocKind::NotPinned;
    CfgLin ip = 0;       ///< Target linear. Valid when @c kind is InImage.
    CfgLin seg_base = 0; ///< Target segment base (`seg_word * 16`) when pinned.
};

/**
 * @brief Load-image linear addresses of MZ relocation fixups.
 *
 * Each location is segment * 16 + offset. image[0] is IP 0. A location at
 * or past the image is ignored. One set is built per cfg_build.
 *
 * @param image  Load image bytes.
 * @param relocs Relocation table. Empty yields an empty set.
 * @return In-image fixup locations.
 */
static inline std::set<uint32_t> cfg_reloc_sites(const std::vector<uint8_t>& image,
                                                 std::span<const RelocEntry> relocs)
{
    std::set<uint32_t> sites;
    for (const RelocEntry& r : relocs)
    {
        const uint32_t loc = static_cast<uint32_t>(r.segment) * 16u +
                             static_cast<uint32_t>(r.offset);
        if (static_cast<size_t>(loc) < image.size())
        {
            sites.insert(loc);
        }
    }
    return sites;
}

/**
 * @brief Classify a direct far 9Ah/EAh against the relocation table.
 *
 * Pinned only when @p size is 5, the opcode at @p ip is 9Ah or EAh (no
 * prefix; opcode index 0), and @p reloc_at contains the segment word at
 * IP+3. Both words are little-endian in the image. The target linear
 * address is seg_word * 16 + off_word. A pinned target at or past the
 * image is Outside, including when that linear is above 0xFFFF: the caller
 * must not enqueue it and must not fall through to M1. A pinned target
 * inside the image is InImage even when the linear is above 0xFFFF.
 *
 * @param image    Load image. image[0] is linear 0.
 * @param ip       Instruction linear address. The opcode byte is image[@p ip].
 * @param size     Decoded instruction length.
 * @param reloc_at In-image fixup locations from cfg_reloc_sites.
 * @return InImage with the target linear and segment base, Outside when
 *         pinned but not an in-image root, or NotPinned when M1 still applies.
 */
static inline CfgFarReloc cfg_far_reloc_site(const std::vector<uint8_t>& image,
                                             CfgLin ip,
                                             uint16_t size,
                                             const std::set<uint32_t>& reloc_at)
{
    CfgFarReloc result;
    const size_t at = static_cast<size_t>(ip);
    if (size != 5 || at + 5 > image.size())
    {
        return result;
    }
    const uint8_t op = image[at];
    if (op != 0x9A && op != 0xEA)
    {
        return result;
    }
    const uint32_t seg_at = static_cast<uint32_t>(at) + 3u;
    if (!reloc_at.contains(seg_at))
    {
        return result;
    }
    const uint16_t off_word = static_cast<uint16_t>(
        image[at + 1] | (static_cast<unsigned>(image[at + 2]) << 8));
    const uint16_t seg_word = static_cast<uint16_t>(
        image[at + 3] | (static_cast<unsigned>(image[at + 4]) << 8));
    result.seg_base = static_cast<uint32_t>(seg_word) * 16u;
    result.ip = result.seg_base + static_cast<uint32_t>(off_word);
    if (static_cast<size_t>(result.ip) < image.size())
    {
        result.kind = CfgFarRelocKind::InImage;
        return result;
    }
    result.kind = CfgFarRelocKind::Outside;
    return result;
}

static inline bool cfg_is_jcc(std::string_view m) {
    if (m.size() < 2 || m[0] != 'j') return false;
    if (m == "jmp" || m == "jecxz" || cfg_is_far_xfer(m)) return false;
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

/**
 * @brief True when @p ip is a byte of the load image.
 *
 * No 64 KiB cap. image[0] is linear 0.
 *
 * @param ip         Image-linear address.
 * @param image_size Load-image length in bytes.
 * @return true when @p ip is strictly inside the image.
 */
static inline bool cfg_ip_in_image(CfgLin ip, size_t image_size)
{
    return static_cast<size_t>(ip) < image_size;
}

/// No instruction has claimed this image byte yet.
inline constexpr uint32_t kCfgUnowned = 0xFFFFFFFFu;

/**
 * @brief True when @p ip sits strictly inside an instruction another start owns.
 *
 * @param owner Per-byte map; owner[i] is the instruction start that covers
 *              image byte i, or kCfgUnowned.
 * @param ip    Candidate leader or decode address.
 * @return true if disassembly must not restart at @p ip.
 */
static inline bool cfg_ip_inside_owned(const std::vector<uint32_t>& owner, CfgLin ip)
{
    if (static_cast<size_t>(ip) >= owner.size())
    {
        return false;
    }
    const uint32_t own = owner[static_cast<size_t>(ip)];
    return own != kCfgUnowned && own != ip;
}

/**
 * @brief DOS/BIOS interrupt numbers the CFG still treats as block seeds.
 *
 * @param inum Immediate byte of an `int` instruction.
 * @return true for the historical tracked set (INT 10h/13h/16h/1Ah/20h/21h/…).
 */
static inline bool cfg_is_tracked_int(uint8_t inum)
{
    switch (inum)
    {
    case 0x10:
    case 0x13:
    case 0x16:
    case 0x1A:
    case 0x20:
    case 0x21:
    case 0x25:
    case 0x2F:
    case 0x33:
        return true;
    default:
        return false;
    }
}

/**
 * @brief True when a DOS `int` does not return to the next instruction.
 *
 * INT 20h and INT 27h always terminate. INT 21h terminates only when AH is
 * exactly 00h, 4Ch, or 31h. Unknown AH (greater than 0xFF, including the
 * initial 0x100) is not an exit. INTO (opcode CE) is not an `int`.
 *
 * @param int_num Immediate byte of a CD instruction.
 * @param ah      AH at that interrupt, or a value above 0xFF when unknown.
 * @return true when control does not fall through.
 */
static inline bool cfg_int_noreturn(uint8_t int_num, uint16_t ah)
{
    if (int_num == 0x20 || int_num == 0x27)
    {
        return true;
    }
    if (int_num != 0x21 || ah > 0xFF)
    {
        return false;
    }
    return ah == 0x00 || ah == 0x4C || ah == 0x31;
}

//=============================================================================
// Jump-table heuristic (Pascal MT+ etc.): run of near JMPs (E9 xx xx)
//=============================================================================

/**
 * @brief Scan @p [scan_lo, scan_hi) for consecutive near JMP (E9) stubs.
 *
 * Slot and target leaders use @p frame. The rel16 wraps inside that
 * segment (`frame + uint16(ip16 + 3 + rel)`), not as a truncated linear.
 * A negative frame is not cast to an unsigned type.
 *
 * @param image       Load image. image[0] is linear 0.
 * @param scan_lo     First linear to consider.
 * @param scan_hi     One past the last linear to consider.
 * @param leaders     Leader set updated in place.
 * @param table_slots Slot linears that form a long enough run.
 * @param min_slots   Minimum consecutive E9 stubs.
 * @param owner       Byte ownership from trusted decode. Null skips the check.
 * @param frame       Paragraph frame for slots in this window. May be negative.
 * @param seg_of      Linear to paragraph frame. Existing entries are kept.
 * @param frames      Distinct frames. A new frame is inserted, not every leader.
 */
static inline void cfg_find_near_jmp_tables(const std::vector<uint8_t>& image,
                                            CfgLin scan_lo,
                                            CfgLin scan_hi,
                                            std::set<CfgLin>& leaders,
                                            std::set<CfgLin>& table_slots,
                                            size_t min_slots,
                                            const std::vector<uint32_t>* owner,
                                            int32_t frame,
                                            std::map<CfgLin, int32_t>& seg_of,
                                            std::set<int32_t>& frames)
{
    if (static_cast<size_t>(scan_hi) > image.size())
    {
        scan_hi = static_cast<CfgLin>(image.size());
    }
    if (scan_lo >= scan_hi)
    {
        return;
    }

    auto in_seg = [&](CfgLin lin) -> bool
    {
        return cfg_in_frame(lin, frame);
    };

    auto remember = [&](CfgLin lin)
    {
        if (!seg_of.count(lin))
        {
            seg_of[lin] = frame;
            frames.insert(frame);
        }
        leaders.insert(lin);
    };

    auto slot_rejected = [&](size_t off) -> bool
    {
        if (owner == nullptr)
        {
            return false;
        }
        return cfg_ip_inside_owned(*owner, static_cast<CfgLin>(off));
    };

    size_t i = scan_lo;
    while (i + 3 <= scan_hi)
    {
        // An E9 that is an immediate/displacement of an owned insn is not a slot.
        if (image[i] != 0xE9 || slot_rejected(i) || !in_seg(static_cast<CfgLin>(i)))
        {
            ++i;
            continue;
        }
        size_t j = i;
        std::vector<CfgLin> slots;
        while (j + 3 <= scan_hi && image[j] == 0xE9 && !slot_rejected(j) &&
               in_seg(static_cast<CfgLin>(j)))
        {
            const int16_t rel = static_cast<int16_t>(image[j + 1] | (image[j + 2] << 8));
            const CfgLin slot_ip = static_cast<CfgLin>(j);
            const uint16_t ip16 = cfg_ip16(slot_ip, frame);
            const uint16_t tgt16 = static_cast<uint16_t>(
                static_cast<int>(ip16) + 3 + static_cast<int>(rel));
            const int64_t tgt64 =
                static_cast<int64_t>(frame) + static_cast<int64_t>(tgt16);
            slots.push_back(slot_ip);
            remember(slot_ip);
            // A negative target is not an image linear. Do not cast it.
            if (tgt64 >= 0)
            {
                const CfgLin tgt = static_cast<CfgLin>(tgt64);
                // Drop a target that would restart inside an owned instruction.
                if (owner == nullptr || !cfg_ip_in_image(tgt, image.size()) ||
                    !cfg_ip_inside_owned(*owner, tgt))
                {
                    remember(tgt);
                }
            }
            table_slots.insert(slot_ip);
            j += 3;
        }
        if (slots.size() < min_slots)
        {
            for (CfgLin s : slots)
            {
                table_slots.erase(s);
            }
        }
        i = (j > i) ? j : i + 1;
    }
}

//=============================================================================
// Build CFG
//=============================================================================

/**
 * @brief Build a CFG over a load image using image-linear addresses.
 *
 * image[0] is linear 0. A work item is `{linear, frame}` with
 * `ip16 = (uint16_t)(linear - frame)` and the distance in `0..0xFFFF`.
 * Near flow wraps inside that frame. The frame is int32_t and may be
 * negative; it is never cast through uint32_t or uint64_t. Capstone stays
 * CS_MODE_16 and is given the non-negative linear. @p cs_seg is stored for
 * display only and is not the flow segment.
 *
 * A relocated 9Ah/EAh is followed at `seg*16+off` when that linear is inside
 * the image, including past 64 KiB. Pinned and outside the image stays
 * Outside and does not fall through to M1. An unpinned far transfer whose
 * segment word equals @p file_cs enqueues `off` with segment base 0.
 *
 * @param image           Load-image bytes. image[0] is linear 0.
 * @param entry_ip        Entry linear address.
 * @param cs_seg          Load base recorded on the graph. Not used as Capstone's base.
 * @param file_cs         MZ header CS for M1. COM passes the load base.
 * @param file_base       File offset of image[0].
 * @param follow_calls    When true, call targets are leaders.
 * @param max_blocks      Safety cap on blocks materialized in pass 2.
 * @param relocs          MZ fixups into this load image. Empty keeps M1 only.
 * @param entry_frame  Paragraph frame of @p entry_ip (`cs * 16`). 0 for COM,
 *                      for an MZ entry whose signed delta is 0, and when the
 *                      entry is not inside the image. May be negative. A
 *                      negative value passed through listing_run is taken
 *                      from the one-shot override instead.
 * @return Control-flow graph. Empty when the entry is outside the image.
 */
static inline CfgGraph cfg_build(const std::vector<uint8_t>& image,
                                 CfgLin entry_ip,
                                 uint16_t cs_seg,
                                 uint16_t file_cs,
                                 size_t file_base,
                                 bool follow_calls,
                                 size_t max_blocks = 20000,
                                 std::span<const RelocEntry> relocs = {},
                                 int32_t entry_frame = 0)
{
    CfgGraph g;
    g.cs_seg = cs_seg;
    g.image_file_base = file_base;
    g.image_size = image.size();

    // Consume the override even when this build returns empty, so a negative
    // frame cannot leak into the next image. listing_run cannot carry it.
    {
        const int32_t over = cfg_take_entry_frame_override();
        if (over < 0)
        {
            entry_frame = over;
        }
    }

    if (image.empty() || !cfg_ip_in_image(entry_ip, image.size()))
    {
        return g;
    }
    if (!cfg_in_frame(entry_ip, entry_frame))
    {
        return g;
    }

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle) != CS_ERR_OK)
    {
        return g;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* insn = cs_malloc(handle);
    if (!insn)
    {
        cs_close(&handle);
        return g;
    }

    const std::set<uint32_t> reloc_at = cfg_reloc_sites(image, relocs);

    struct CfgSeed
    {
        CfgLin linear = 0;
        int32_t frame = 0;
    };

    std::set<CfgLin> leaders;
    // Created only by an INT-nearby seed (site-8 / site-16). A non-nearby
    // enqueue promotes the address. A second nearby seed does not.
    std::set<CfgLin> spec_leaders;
    std::set<CfgLin> table_slots;
    std::map<CfgLin, int32_t> leader_seg;
    // Distinct paragraph frames. seg_covering looks these up; it does not
    // walk leader_seg.
    std::set<int32_t> seg_frames;
    seg_frames.insert(entry_frame);
    // Byte ownership: trusted decode claims [linear, linear+size) before any
    // heuristic leader (INT scan, ip-8/ip-16, jump table) may split a block.
    std::vector<uint32_t> owner(image.size(), kCfgUnowned);
    std::set<CfgLin> decoded_from;
    std::queue<CfgSeed> work;
    // Straight-line noreturn sites. A tracked CD is its own leader, so the
    // int block's AH is unknown. This set is what stops that block.
    std::set<CfgLin> noreturn_ips;

    // Rejected: not a leader. Present: already one. Created: just inserted.
    // Does not touch spec_leaders. Nearby must not promote, so the erase
    // stays in enqueue and not on this path.
    enum class CfgPlace
    {
        Rejected,
        Present,
        Created
    };
    auto place_leader = [&](CfgLin linear, int32_t frame) -> CfgPlace
    {
        if (!cfg_in_frame(linear, frame))
        {
            return CfgPlace::Rejected;
        }
        if (!cfg_ip_in_image(linear, image.size()))
        {
            g.unresolved.insert(linear);
            return CfgPlace::Rejected;
        }
        // A leader strictly inside an owned instruction is not a block start.
        if (cfg_ip_inside_owned(owner, linear))
        {
            return CfgPlace::Rejected;
        }
        if (!leaders.insert(linear).second)
        {
            return CfgPlace::Present;
        }
        leader_seg[linear] = frame;
        seg_frames.insert(frame);
        work.push(CfgSeed{linear, frame});
        return CfgPlace::Created;
    };

    // Non-nearby source. Promotes even when the address was already a leader.
    // Nearby does not call this; a second nearby seed must keep the mark.
    auto enqueue = [&](CfgLin linear, int32_t frame)
    {
        if (place_leader(linear, frame) == CfgPlace::Rejected)
        {
            return;
        }
        spec_leaders.erase(linear);
    };

    // Only enqueue_nearby calls this. Creating the leader records it as
    // speculative. An address that is already a leader is left alone.
    auto enqueue_spec = [&](CfgLin linear, int32_t frame)
    {
        if (place_leader(linear, frame) == CfgPlace::Created)
        {
            spec_leaders.insert(linear);
        }
    };

    auto claim = [&](CfgLin linear, uint16_t size)
    {
        for (uint16_t k = 0; k < size; ++k)
        {
            const size_t idx = static_cast<size_t>(linear) + k;
            if (idx >= owner.size())
            {
                break;
            }
            if (owner[idx] == kCfgUnowned)
            {
                owner[idx] = linear;
            }
        }
    };

    auto note_leader = [&](CfgLin linear, int32_t frame)
    {
        if (!leader_seg.count(linear))
        {
            leader_seg[linear] = frame;
            seg_frames.insert(frame);
        }
        leaders.insert(linear);
    };

    // Linear trusted decode. Owns bytes. Does not restart mid-instruction.
    // Near targets and fall-through wrap inside the signed frame.
    auto decode_from = [&](CfgLin start, int32_t frame)
    {
        if (!cfg_in_frame(start, frame))
        {
            return;
        }
        if (!cfg_ip_in_image(start, image.size()))
        {
            return;
        }
        if (owner[static_cast<size_t>(start)] != kCfgUnowned)
        {
            return; // already claimed, or strictly inside another insn
        }
        if (!decoded_from.insert(start).second)
        {
            return;
        }

        CfgLin linear = start;
        // AH for this walk only. 0x100 is unknown. A nop does not clear it.
        uint16_t flow_ah = 0x100;
        for (int step = 0; step < 4096; ++step)
        {
            if (!cfg_in_frame(linear, frame))
            {
                break;
            }
            if (!cfg_ip_in_image(linear, image.size()))
            {
                break;
            }
            if (owner[static_cast<size_t>(linear)] != kCfgUnowned)
            {
                break; // join an instruction already claimed
            }
            const uint16_t ip16 = cfg_ip16(linear, frame);
            const size_t room = static_cast<size_t>(0x10000u - ip16);
            const size_t avail = std::min({
                image.size() - static_cast<size_t>(linear), room, size_t{16}});
            if (avail == 0)
            {
                break;
            }
            const uint8_t* ptr = image.data() + static_cast<size_t>(linear);
            size_t sz = avail;
            uint64_t addr = linear;
            if (!cs_disasm_iter(handle, &ptr, &sz, &addr, insn) || !insn->detail)
            {
                break;
            }
            if (insn->size == 0 || insn->size > room)
            {
                break;
            }
            if (static_cast<size_t>(linear) + insn->size > image.size())
            {
                break;
            }

            bool overlap = false;
            for (uint16_t k = 0; k < insn->size; ++k)
            {
                if (owner[static_cast<size_t>(linear) + k] != kCfgUnowned)
                {
                    overlap = true;
                    break;
                }
            }
            if (overlap)
            {
                break;
            }

            // The first instruction of this walk may cover an interior
            // target (linear != start). Only a later instruction stops,
            // and only when the opcode after prefixes is 00
            // (detail->x86.opcode[0], not bytes[0], so 2E 00 still stops).
            // The covered address must be in leaders and not in
            // spec_leaders. An INT-nearby seed does not end the walk
            // (RG6). Other opcodes do not stop.
            if (linear != start && insn->size > 1 &&
                insn->detail != nullptr &&
                insn->detail->x86.opcode[0] == 0x00)
            {
                bool covers_leader = false;
                for (uint16_t k = 1; k < insn->size; ++k)
                {
                    const CfgLin at = static_cast<CfgLin>(linear + k);
                    if (leaders.count(at) != 0 && spec_leaders.count(at) == 0)
                    {
                        covers_leader = true;
                        break;
                    }
                }
                if (covers_leader)
                {
                    break;
                }
            }

            const cs_x86& x86 = insn->detail->x86;
            std::string mnem = insn->mnemonic;
            const uint16_t next16 = static_cast<uint16_t>(ip16 + insn->size);
            CfgLin next = 0;
            const bool next_ok = cfg_fall_next(linear, frame,
                                              static_cast<uint16_t>(insn->size), next);
            const bool wrapped = cfg_ip16_wrapped(ip16, next16);
            claim(linear, insn->size);

            auto enqueue_near = [&](int op_i) -> bool
            {
                if (op_i >= x86.op_count)
                {
                    return false;
                }
                if (x86.operands[op_i].type != X86_OP_IMM)
                {
                    return false;
                }
                const uint64_t imm = static_cast<uint64_t>(x86.operands[op_i].imm);
                CfgLin tgt = 0;
                if (!cfg_near_target(imm, frame, tgt))
                {
                    return false;
                }
                enqueue(tgt, frame);
                return true;
            };

            if (cfg_is_uncond_jmp(mnem))
            {
                // Far ljmp/jmpf: a relocated segment word wins over M1.
                // Pinned in-image enqueues that linear, even past 64 KiB.
                // Pinned outside enqueues nothing and does not use M1.
                // Not pinned: same-CS operand 1 with segment base 0. No fall-through.
                if (cfg_is_far_xfer(mnem))
                {
                    const CfgFarReloc pin =
                        cfg_far_reloc_site(image, linear, insn->size, reloc_at);
                    if (pin.kind == CfgFarRelocKind::InImage)
                    {
                        enqueue(pin.ip, static_cast<int32_t>(pin.seg_base));
                    }
                    else if (pin.kind == CfgFarRelocKind::NotPinned)
                    {
                        uint16_t far_off = 0;
                        if (cfg_far_same_seg_off(x86, file_cs, far_off))
                        {
                            enqueue(far_off, 0);
                        }
                    }
                }
                else
                {
                    enqueue_near(0);
                }
                break;
            }
            if (cfg_is_jcc(mnem) || mnem == "jcxz" || mnem == "loop" ||
                mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
                mnem == "loopnz")
            {
                // Fall-through first. A forward jcc/loop into the *next*
                // instruction (74 01 B8 ..) must not claim that interior
                // byte before the real opcode is owned. The fall-through
                // wraps inside this frame. A negative next is not enqueued.
                if (next_ok)
                {
                    enqueue(next, frame);
                }
                enqueue_near(0);
                break;
            }
            if (cfg_is_call(mnem))
            {
                // Same order as jcc: own the instruction after CALL before
                // a target that lands inside it can steal those bytes.
                // Always decode that one fall-through instruction. A run of
                // zeros does not suppress it. Still skip an E9/E9 jump table
                // or an 80/b0 segment table parked after a Pascal entry call.
                bool looks_data = false;
                if (next_ok && cfg_ip_in_image(next, image.size()))
                {
                    if (static_cast<size_t>(next) + 6 <= image.size() &&
                        image[static_cast<size_t>(next)] == 0xE9 &&
                        image[static_cast<size_t>(next) + 3] == 0xE9)
                    {
                        looks_data = true;
                    }
                    if (static_cast<size_t>(next) + 4 <= image.size() &&
                        image[static_cast<size_t>(next)] == 0x80 &&
                        image[static_cast<size_t>(next) + 2] == 0xb0)
                    {
                        looks_data = true;
                    }
                }
                if (!looks_data && next_ok)
                {
                    enqueue(next, frame);
                }
                // Far lcall/callf still falls through above. A relocated segment
                // word is followed instead of M1, and only when follow_calls
                // is set (same gate as M1). Pinned outside enqueues nothing.
                if (follow_calls && cfg_is_far_xfer(mnem))
                {
                    const CfgFarReloc pin =
                        cfg_far_reloc_site(image, linear, insn->size, reloc_at);
                    if (pin.kind == CfgFarRelocKind::InImage)
                    {
                        enqueue(pin.ip, static_cast<int32_t>(pin.seg_base));
                    }
                    else if (pin.kind == CfgFarRelocKind::NotPinned)
                    {
                        uint16_t far_off = 0;
                        if (cfg_far_same_seg_off(x86, file_cs, far_off))
                        {
                            enqueue(far_off, 0);
                        }
                    }
                }
                else if (follow_calls)
                {
                    enqueue_near(0);
                }
                break;
            }
            // B4 ib and B8 iw only. Every other opcode, including nop, keeps AH.
            if (insn->size >= 2 && insn->bytes[0] == 0xB4)
            {
                flow_ah = insn->bytes[1];
            }
            else if (insn->size >= 3 && insn->bytes[0] == 0xB8)
            {
                flow_ah = insn->bytes[2];
            }

            if (cfg_is_ret(mnem) || mnem == "int" || mnem == "into" || mnem == "hlt")
            {
                // int returns on DOS unless cfg_int_noreturn says otherwise.
                // This walk still sees mov ah before the INT seed splits CD
                // into its own block, where AH would be unknown.
                if (mnem == "int" || mnem == "into")
                {
                    const bool cd = insn->size >= 2 && insn->bytes[0] == 0xCD;
                    const uint8_t inum = cd ? insn->bytes[1] : 0;
                    if (cd && cfg_int_noreturn(inum, flow_ah))
                    {
                        noreturn_ips.insert(linear);
                        break;
                    }
                    // A returning INT 21h clobbers AH. INTO does not.
                    if (cd && inum == 0x21)
                    {
                        flow_ah = 0x100;
                    }
                    note_leader(linear, frame);
                    if (wrapped)
                    {
                        if (next_ok)
                        {
                            enqueue(next, frame);
                        }
                        break;
                    }
                    if (!next_ok)
                    {
                        break;
                    }
                    linear = next;
                    continue;
                }
                break;
            }

            // Segment wrap is a new leader. Do not keep walking into ip16 0
            // inside this straight-line claim, and do not spill past the segment.
            if (wrapped)
            {
                if (next_ok)
                {
                    enqueue(next, frame);
                }
                break;
            }

            if (!next_ok)
            {
                break;
            }

            // Next linear is already a real leader (insn boundary). Stop before it.
            if (leaders.count(next) && next != start)
            {
                break;
            }

            linear = next;
        }
    };

    auto drain = [&]()
    {
        while (!work.empty() && leaders.size() < max_blocks * 2)
        {
            const CfgSeed seed = work.front();
            work.pop();
            decode_from(seed.linear, seed.frame);
        }
    };

    auto queue_new = [&](const std::set<CfgLin>& before)
    {
        for (CfgLin L : leaders)
        {
            if (before.count(L))
            {
                continue;
            }
            if (!cfg_ip_in_image(L, image.size()))
            {
                continue;
            }
            if (cfg_ip_inside_owned(owner, L))
            {
                continue;
            }
            const int32_t sb = leader_seg.count(L) ? leader_seg[L] : entry_frame;
            work.push(CfgSeed{L, sb});
        }
    };

    // --- Pass 1a: trusted flow from the entry, then call/jmp/jcc targets ---
    enqueue(entry_ip, entry_frame);
    drain();

    // Jump tables only where the E9 is not an immediate inside owned code.
    {
        std::set<CfgLin> snap = leaders;
        const CfgLin scan_hi = static_cast<CfgLin>(std::min(image.size(), size_t{0x200}));
        cfg_find_near_jmp_tables(image, 0, scan_hi, leaders, table_slots, 4, &owner,
                                 0, leader_seg, seg_frames);
        queue_new(snap);
        snap = leaders;
        if (static_cast<size_t>(entry_ip) < image.size())
        {
            const CfgLin lo = entry_ip;
            const size_t entry_plus = static_cast<size_t>(entry_ip) + 0x100u;
            const CfgLin hi = static_cast<CfgLin>(std::min(image.size(), entry_plus));
            cfg_find_near_jmp_tables(image, lo, hi, leaders, table_slots, 6, &owner,
                                     entry_frame, leader_seg, seg_frames);
            queue_new(snap);
        }
        drain();
    }

    // INT seeds: only an opcode CD. A CD that trusted decode already consumed
    // as an immediate or displacement is not a leader. Uncovered CD bytes are
    // leaders only when a decode that starts there executes `int`.
    auto decode_is_int = [&](CfgLin at, int32_t frame) -> bool
    {
        if (!cfg_in_frame(at, frame))
        {
            return false;
        }
        if (static_cast<size_t>(at) + 2 > image.size())
        {
            return false;
        }
        const uint16_t ip16 = cfg_ip16(at, frame);
        const size_t room = static_cast<size_t>(0x10000u - ip16);
        const size_t avail = std::min({
            image.size() - static_cast<size_t>(at), room, size_t{16}});
        if (avail < 2)
        {
            return false;
        }
        const uint8_t* ptr = image.data() + static_cast<size_t>(at);
        size_t sz = avail;
        uint64_t addr = at;
        if (!cs_disasm_iter(handle, &ptr, &sz, &addr, insn) || !insn->detail)
        {
            return false;
        }
        if (insn->size > room)
        {
            return false;
        }
        return std::string_view(insn->mnemonic) == "int" && insn->size >= 2 &&
               insn->bytes[0] == 0xCD;
    };

    // Greatest frame <= lin, then the cover test. Not a scan of leader_seg.
    auto seg_covering = [&](CfgLin lin, int32_t& frame_out) -> bool
    {
        if (lin > static_cast<CfgLin>(INT32_MAX))
        {
            return false;
        }
        // Flat frame 0: a tighter frame in the first 64 KiB must not win.
        if (lin <= 0xFFFFu)
        {
            frame_out = 0;
            return true;
        }
        auto it = seg_frames.upper_bound(static_cast<int32_t>(lin));
        if (it == seg_frames.begin())
        {
            return false;
        }
        --it;
        const int32_t frame = *it;
        if (frame < 0)
        {
            const int64_t dist = cfg_frame_dist(lin, frame);
            if (dist >= 0 && dist <= static_cast<int64_t>(0xFFFF))
            {
                frame_out = frame;
                return true;
            }
            return false;
        }
        const CfgLin base = static_cast<CfgLin>(frame);
        if (lin >= base && (lin - base) <= 0xFFFFu)
        {
            frame_out = frame;
            return true;
        }
        return false;
    };

    for (size_t i = 0; i + 1 < image.size(); ++i)
    {
        if (image[i] != 0xCD)
        {
            continue;
        }
        const uint8_t inum = image[i + 1];
        if (!cfg_is_tracked_int(inum))
        {
            continue;
        }
        const CfgLin ip = static_cast<CfgLin>(i);
        int32_t sb = 0;
        if (!seg_covering(ip, sb))
        {
            continue;
        }
        if (cfg_ip_inside_owned(owner, ip))
        {
            continue; // CD is inside an instruction we already own
        }
        bool opcode_int = false;
        if (owner[static_cast<size_t>(ip)] == ip)
        {
            opcode_int = true; // trusted decode executed this byte as insn start
        }
        else if (owner[static_cast<size_t>(ip)] == kCfgUnowned)
        {
            opcode_int = decode_is_int(ip, sb);
        }
        if (!opcode_int)
        {
            continue;
        }
        enqueue(ip, sb);
        // Nearby seeds only when they are not strictly inside an owned insn,
        // so mov ah / mov dx can still open a block ahead of an uncovered INT.
        // Skip 00 bytes: they are padding (and the fake PSP hole), and decoding
        // them plants a block of "add [bx+si], al" ahead of the real entry.
        // Stay inside this frame: add the IP, do not subtract across it.
        auto enqueue_nearby = [&](uint16_t ip16_at)
        {
            const int64_t at64 =
                static_cast<int64_t>(sb) + static_cast<int64_t>(ip16_at);
            if (at64 < 0)
            {
                return;
            }
            const CfgLin at = static_cast<CfgLin>(at64);
            if (!cfg_ip_in_image(at, image.size()))
            {
                return;
            }
            if (image[static_cast<size_t>(at)] == 0x00)
            {
                return;
            }
            enqueue_spec(at, sb);
        };
        const uint16_t ip16 = cfg_ip16(ip, sb);
        if (ip16 >= 16)
        {
            enqueue_nearby(static_cast<uint16_t>(ip16 - 16));
        }
        if (ip16 >= 8)
        {
            enqueue_nearby(static_cast<uint16_t>(ip16 - 8));
        }
    }
    drain();

    // Drop leaders that landed strictly inside an owned instruction.
    for (auto it = leaders.begin(); it != leaders.end(); )
    {
        if (cfg_ip_in_image(*it, image.size()) && cfg_ip_inside_owned(owner, *it))
        {
            it = leaders.erase(it);
        }
        else
        {
            ++it;
        }
    }
    for (auto it = table_slots.begin(); it != table_slots.end(); )
    {
        if (cfg_ip_inside_owned(owner, *it))
        {
            it = table_slots.erase(it);
        }
        else
        {
            ++it;
        }
    }

    // --- Pass 2: form blocks from each leader ---
    std::vector<CfgLin> leader_list(leaders.begin(), leaders.end());
    std::sort(leader_list.begin(), leader_list.end());

    auto next_leader_after = [&](CfgLin ip) -> CfgLin
    {
        auto it = std::upper_bound(leader_list.begin(), leader_list.end(), ip);
        if (it == leader_list.end())
        {
            const size_t cap = std::min(image.size(), size_t{0xFFFFFFFFu});
            return static_cast<CfgLin>(cap);
        }
        return *it;
    };

    for (CfgLin L : leader_list)
    {
        if (g.blocks.size() >= max_blocks)
        {
            break;
        }
        if (!cfg_ip_in_image(L, image.size()))
        {
            continue;
        }
        // Do not disassemble from the middle of an owned instruction.
        if (cfg_ip_inside_owned(owner, L))
        {
            continue;
        }

        const int32_t sb = leader_seg.count(L) ? leader_seg[L] : int32_t{0};
        if (!cfg_in_frame(L, sb))
        {
            continue;
        }

        CfgBlock blk;
        blk.start_ip = L;
        blk.seg_base = sb;
        blk.file_off = file_base + static_cast<size_t>(L);
        blk.is_entry = (L == entry_ip);
        blk.is_table_entry = table_slots.count(L) != 0;

        CfgLin limit = next_leader_after(L);
        CfgLin linear = L;
        CfgLin end_cursor = L;
        bool stop = false;
        // AH from the start of this block only. Unknown until B4 or B8.
        uint16_t block_ah = 0x100;

        while (!stop && linear < limit && cfg_ip_in_image(linear, image.size()))
        {
            if (!cfg_in_frame(linear, sb))
            {
                break;
            }
            const uint16_t ip16 = cfg_ip16(linear, sb);
            const size_t room = static_cast<size_t>(0x10000u - ip16);
            const size_t avail = std::min({
                image.size() - static_cast<size_t>(linear), room, size_t{16}});
            if (avail == 0)
            {
                break;
            }
            const uint8_t* ptr = image.data() + static_cast<size_t>(linear);
            size_t sz = avail;
            uint64_t addr = linear;
            if (!cs_disasm_iter(handle, &ptr, &sz, &addr, insn) || !insn->detail)
            {
                break;
            }
            if (insn->size == 0 || insn->size > room)
            {
                break;
            }
            if (static_cast<size_t>(linear) + insn->size > image.size())
            {
                break;
            }

            // Same as the trusted walk. The block's first instruction may
            // cover an interior target (linear != L). Only a later
            // instruction stops, and only when the opcode after prefixes
            // is 00 (detail->x86.opcode[0], not bytes[0], so 2E 00 still
            // stops). The covered address must be in leaders and not in
            // spec_leaders. An INT-nearby seed does not end the walk
            // (RG6). Other opcodes do not stop.
            if (linear != L && insn->size > 1 &&
                insn->detail != nullptr &&
                insn->detail->x86.opcode[0] == 0x00)
            {
                bool covers_leader = false;
                for (uint16_t k = 1; k < insn->size; ++k)
                {
                    const CfgLin at = static_cast<CfgLin>(linear + k);
                    if (leaders.count(at) != 0 && spec_leaders.count(at) == 0)
                    {
                        covers_leader = true;
                        break;
                    }
                }
                if (covers_leader)
                {
                    break;
                }
            }

            // Refuse an insn that would cover a byte owned by a different start.
            bool clash = false;
            for (uint16_t k = 0; k < insn->size; ++k)
            {
                const uint32_t own = owner[static_cast<size_t>(linear) + k];
                if (own != kCfgUnowned && own != linear)
                {
                    clash = true;
                    break;
                }
            }
            if (clash)
            {
                break;
            }
            for (uint16_t k = 0; k < insn->size; ++k)
            {
                const size_t idx = static_cast<size_t>(linear) + k;
                if (owner[idx] == kCfgUnowned)
                {
                    owner[idx] = linear;
                }
            }

            CfgInsn ci;
            ci.ip = linear;
            ci.seg_base = sb;
            ci.file_off = file_base + static_cast<size_t>(linear);
            ci.size = static_cast<uint8_t>(std::min(insn->size, static_cast<uint16_t>(16)));
            std::memcpy(ci.bytes, insn->bytes, ci.size);
            ci.text = insn->mnemonic;
            if (insn->op_str[0])
            {
                ci.text.push_back(' ');
                ci.text += insn->op_str;
            }
            blk.insns.push_back(ci);
            end_cursor = linear + insn->size;

            const cs_x86& x86 = insn->detail->x86;
            std::string mnem = insn->mnemonic;
            const uint16_t next16 = static_cast<uint16_t>(ip16 + insn->size);
            CfgLin next = 0;
            const bool next_ok = cfg_fall_next(linear, sb,
                                              static_cast<uint16_t>(insn->size), next);
            const bool wrapped = cfg_ip16_wrapped(ip16, next16);
            // A leader strictly inside this insn is not a block boundary.
            if (!wrapped && insn->size > 0 && (linear + insn->size) > limit)
            {
                const CfgLin advanced = next_leader_after(linear + insn->size - 1);
                if (advanced > limit)
                {
                    limit = advanced;
                }
            }

            // Stop decoding through obvious data (00 00 → "add [bx+si], al")
            if ((insn->size == 2 && insn->bytes[0] == 0x00 && insn->bytes[1] == 0x00) ||
                (insn->size == 1 && insn->bytes[0] == 0x00) ||
                (mnem == "add" && ci.text.find("[bx + si], al") != std::string::npos &&
                 insn->bytes[0] == 0x00))
            {
                size_t nullish = 0;
                for (auto it = blk.insns.rbegin();
                     it != blk.insns.rend() && nullish < 8; ++it)
                {
                    if (it->text.find("add byte ptr [bx + si], al") != std::string::npos ||
                        it->text == "add byte ptr [bx + si], al")
                    {
                        nullish++;
                    }
                    else
                    {
                        break;
                    }
                }
                if (nullish >= 4)
                {
                    while (!blk.insns.empty() &&
                           blk.insns.back().text.find("[bx + si], al") != std::string::npos)
                    {
                        blk.insns.pop_back();
                    }
                    if (!blk.insns.empty())
                    {
                        end_cursor = blk.insns.back().ip + blk.insns.back().size;
                    }
                    else
                    {
                        end_cursor = L;
                    }
                    stop = true;
                    break;
                }
            }

            auto edge_imm = [&](CfgEdgeKind kind)
            {
                if (x86.op_count < 1 || x86.operands[0].type != X86_OP_IMM)
                {
                    return false;
                }
                CfgEdge e;
                e.kind = kind;
                const uint64_t imm = static_cast<uint64_t>(x86.operands[0].imm);
                CfgLin tgt = 0;
                if (!cfg_near_target(imm, sb, tgt))
                {
                    return false;
                }
                e.to_ip = tgt;
                e.has_target = cfg_ip_in_image(e.to_ip, image.size());
                if (!e.has_target)
                {
                    g.unresolved.insert(e.to_ip);
                }
                blk.outs.push_back(e);
                if (e.has_target && e.to_ip <= linear)
                {
                    g.n_loops_back++;
                }
                return true;
            };

            // Direct far transfer. A relocated segment word is the target.
            // Pinned outside returns false so the caller keeps today's
            // targetless edge and does not apply M1. Not pinned: M1
            // (operand 1 when operand 0 equals the file CS), enqueued at
            // that offset with segment base 0. Operand 0 is never the target.
            auto edge_far_same = [&](CfgEdgeKind kind) -> bool
            {
                const CfgFarReloc pin =
                    cfg_far_reloc_site(image, linear, insn->size, reloc_at);
                if (pin.kind == CfgFarRelocKind::Outside)
                {
                    return false;
                }
                CfgLin off = 0;
                if (pin.kind == CfgFarRelocKind::InImage)
                {
                    off = pin.ip;
                }
                else
                {
                    uint16_t m1 = 0;
                    if (!cfg_far_same_seg_off(x86, file_cs, m1))
                    {
                        return false;
                    }
                    off = m1;
                }
                CfgEdge e;
                e.kind = kind;
                e.to_ip = off;
                e.has_target = cfg_ip_in_image(off, image.size());
                if (!e.has_target)
                {
                    g.unresolved.insert(off);
                }
                blk.outs.push_back(e);
                if (e.has_target && e.to_ip <= linear)
                {
                    g.n_loops_back++;
                }
                return true;
            };

            if (ci.size >= 2 && ci.bytes[0] == 0xB4)
            {
                block_ah = ci.bytes[1];
            }
            else if (ci.size >= 3 && ci.bytes[0] == 0xB8)
            {
                block_ah = ci.bytes[2];
            }
            const bool cd = ci.size >= 2 && ci.bytes[0] == 0xCD;
            const uint8_t inum = cd ? ci.bytes[1] : 0;
            // The set covers a tracked int whose mov ah lives in the previous
            // block. Bytes cover an int that stayed in this block (INT 27h).
            const bool insn_noreturn =
                noreturn_ips.count(linear) != 0 ||
                (cd && cfg_int_noreturn(inum, block_ah));
            if (!insn_noreturn && cd && inum == 0x21)
            {
                block_ah = 0x100;
            }

            if (cfg_is_uncond_jmp(mnem))
            {
                // Far jump: reloc pin or M1. No fall-through.
                const CfgEdgeKind jk = table_slots.count(L) ? CfgEdgeKind::Table
                                                            : CfgEdgeKind::Jump;
                const bool edged = cfg_is_far_xfer(mnem) ? edge_far_same(jk) : edge_imm(jk);
                if (!edged)
                {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::Jump;
                    e.has_target = false;
                    blk.outs.push_back(e);
                }
                stop = true;
            }
            else if (cfg_is_jcc(mnem) || mnem == "jcxz" || mnem == "loop" ||
                     mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
                     mnem == "loopnz")
            {
                edge_imm(CfgEdgeKind::CondTrue);
                CfgEdge f;
                f.kind = CfgEdgeKind::CondFalse;
                f.to_ip = next_ok ? next : CfgLin{0};
                f.has_target = next_ok && cfg_ip_in_image(next, image.size());
                blk.outs.push_back(f);
                stop = true;
            }
            else if (cfg_is_call(mnem))
            {
                // Far call keeps the fall-through edge below. The target is
                // the reloc pin or, when the segment word is not relocated, M1.
                const bool edged = cfg_is_far_xfer(mnem) ? edge_far_same(CfgEdgeKind::Call)
                                                         : edge_imm(CfgEdgeKind::Call);
                if (!edged)
                {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::Call;
                    e.has_target = false;
                    blk.outs.push_back(e);
                }
                // Fall-through edge for the one instruction after CALL. A zero
                // run does not suppress it. Still skip an 80/b0 segment table
                // or a jump-table slot. ret does not fall through.
                bool cont_ok = next_ok && cfg_ip_in_image(next, image.size());
                if (cont_ok)
                {
                    // Segment table after ICON entry: 80 0c b0 08 ... then zeros
                    if (static_cast<size_t>(next) + 4 < image.size() &&
                        image[static_cast<size_t>(next)] == 0x80 &&
                        image[static_cast<size_t>(next) + 2] == 0xb0)
                    {
                        cont_ok = false;
                    }
                    if (table_slots.count(next))
                    {
                        cont_ok = false;
                    }
                }
                if (cont_ok && leaders.count(next))
                {
                    CfgEdge cont;
                    cont.kind = CfgEdgeKind::FallThrough;
                    cont.to_ip = next;
                    cont.has_target = true;
                    blk.outs.push_back(cont);
                }
                stop = true;
            }
            else if (cfg_is_ret(mnem) || mnem == "hlt" || insn_noreturn)
            {
                CfgEdge e;
                e.kind = CfgEdgeKind::Ret;
                e.has_target = false;
                blk.outs.push_back(e);
                stop = true;
            }
            else if (!next_ok)
            {
                stop = true;
            }
            else if (wrapped)
            {
                // Same frame, IP 0. Not frame + 0x10000, and not a negative linear.
                if (cfg_ip_in_image(next, image.size()) && leaders.count(next))
                {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::FallThrough;
                    e.to_ip = next;
                    e.has_target = true;
                    blk.outs.push_back(e);
                }
                stop = true;
            }
            else if (next >= limit)
            {
                // fall into next leader
                if (cfg_ip_in_image(next, image.size()) && leaders.count(next))
                {
                    CfgEdge e;
                    e.kind = CfgEdgeKind::FallThrough;
                    e.to_ip = next;
                    e.has_target = true;
                    blk.outs.push_back(e);
                }
                stop = true;
            }
            else
            {
                linear = next;
            }
            if (insn->size == 0)
            {
                break;
            }
        }

        blk.end_ip = end_cursor;
        if (blk.insns.empty())
        {
            continue;
        }
        g.blocks[L] = std::move(blk);
    }

    // Mark call targets + preds + edge count
    for (auto& [sip, blk] : g.blocks)
    {
        for (const auto& e : blk.outs)
        {
            g.n_edges++;
            if (!e.has_target)
            {
                continue;
            }
            auto it = g.blocks.find(e.to_ip);
            if (it == g.blocks.end())
            {
                continue;
            }
            it->second.preds.push_back(sip);
            if (e.kind == CfgEdgeKind::Call)
            {
                it->second.is_call_target = true;
            }
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
                lit.off = static_cast<CfgLin>(i);
                lit.text.assign(reinterpret_cast<const char*>(&image[i]), len);
                // Classification is filled once, after cfg_string_interesting.
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
                lit.off = static_cast<CfgLin>(i + 1);
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

/**
 * @brief Scan a block's instruction bytes for register immediates.
 *
 * @param blk        Block to scan.
 * @param before_ip  Stop before this linear address. 0xFFFFFFFF scans the
 *                   whole block. 0xFFFF is a real address, not the sentinel.
 * @return Last AH/AL/DX/BX/SI/DI immediates seen before @p before_ip.
 */
static inline CfgRegHint cfg_scan_block_regs(const CfgBlock& blk,
                                             CfgLin before_ip = 0xFFFFFFFFu)
{
    CfgRegHint h;
    for (const auto& in : blk.insns)
    {
        if (before_ip != 0xFFFFFFFFu && in.ip >= before_ip)
        {
            break;
        }
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
static inline CfgRegHint cfg_regs_from_preds(const CfgGraph& g, CfgLin blk_ip,
                                             int max_depth = 6) {
    CfgRegHint best;
    std::queue<std::pair<CfgLin, int>> q;
    std::set<CfgLin> seen;
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
        for (CfgLin p : it->second.preds) {
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
static inline CfgBlock* cfg_block_at(CfgGraph& g, CfgLin ip) {
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
        const CfgLin call_ip = static_cast<CfgLin>(i);
        CfgBlock* blk = cfg_block_at(g, call_ip);
        if (!blk) {
            // create soft xref on nearest block start if any
            continue;
        }
        CfgStringXref xr;
        xr.at_ip = call_ip;
        xr.str_ip = static_cast<CfgLin>(str_at + 1);
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

/**
 * @brief True when @p text is a branch, call, or jump.
 *
 * Those operands are code targets. They are not string immediates.
 * `mov`, `push`, and memory displacements stay eligible.
 *
 * @param text Capstone "mnemonic op_str".
 * @return true for jmp, jcc, jcxz, loop*, call, and the far forms.
 */
static inline bool cfg_text_is_flow(std::string_view text)
{
    const size_t sp = text.find(' ');
    const std::string_view mnem =
        (sp == std::string_view::npos) ? text : text.substr(0, sp);
    if (cfg_is_uncond_jmp(mnem) || cfg_is_call(mnem) || cfg_is_jcc(mnem))
    {
        return true;
    }
    return mnem == "jcxz" || mnem == "jecxz" || mnem == "loop" ||
           mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
           mnem == "loopnz";
}

/// Annotate blocks with INT sites, string xrefs, pred AH/DX, FCB paths, tags.
static inline void cfg_annotate(CfgGraph& g, const std::vector<uint8_t>& image) {
    cfg_collect_strings(image, g.strings, 4);
    // Lowercase and classify each literal once, before any operand lookup.
    for (CfgStringLit& lit : g.strings)
    {
        lit.interesting = cfg_string_interesting(lit.text);
    }

    std::map<CfgLin, const CfgStringLit*> by_off;
    for (const auto& s : g.strings)
        by_off[s.off] = &s;

    // Greatest literal start <= off, then a covering check. Not a linear scan.
    auto find_string_at = [&](CfgLin off) -> const CfgStringLit*
    {
        auto it = by_off.upper_bound(off);
        if (it == by_off.begin())
        {
            return nullptr;
        }
        --it;
        const CfgStringLit* lit = it->second;
        if (lit == nullptr)
        {
            return nullptr;
        }
        const size_t begin = static_cast<size_t>(lit->off);
        const size_t end = begin + lit->text.size();
        if (static_cast<size_t>(off) < begin || static_cast<size_t>(off) >= end)
        {
            return nullptr;
        }
        return lit;
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
        std::set<CfgLin> seen_str;

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

            // Branch, call, and jump operands are code targets, not strings.
            // The mnemonic itself is not an immediate ("add" is 0xADD).
            if (cfg_text_is_flow(in.text))
            {
                continue;
            }
            const size_t op_at = in.text.find(' ');
            if (op_at == std::string::npos)
            {
                continue;
            }
            std::string ops = in.text.substr(op_at + 1);
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
                    const CfgStringLit* lit = find_string_at(static_cast<CfgLin>(imm));
                    // Dedup before using the precomputed class or tagging.
                    if (lit != nullptr && seen_str.insert(lit->off).second &&
                        (lit->interesting || lit->text.size() >= 6))
                    {
                        CfgStringXref xr;
                        xr.at_ip = in.ip;
                        xr.str_ip = lit->off;
                        xr.str = lit->text.size() > 48 ? lit->text.substr(0, 48) + "..."
                                                       : lit->text;
                        blk.str_xrefs.push_back(std::move(xr));
                        g.n_str_xrefs++;
                        if (lit->text.size() <= 16 &&
                            lit->text.find('.') != std::string::npos)
                            cfg_tag_filename(blk, lit->text);
                        else
                            cfg_tag_message(blk, lit->text);
                    }
                }
                pos = rest + (tlen ? tlen : 1);
            }
        }

        // LE16 in block → interesting strings (mov dx/bx/si, offset …)
        if (blk.start_ip < blk.end_ip && blk.end_ip <= image.size()) {
            for (CfgLin off = blk.start_ip; off + 1 < blk.end_ip; ++off) {
                bool is_imm_load = false;
                if (off >= 1) {
                    uint8_t op = image[off - 1];
                    if (op == 0xBA || op == 0xBB || op == 0xBE || op == 0xBF ||
                        op == 0xB8 || op == 0xB9)
                        is_imm_load = true;
                }
                if (!is_imm_load) continue;
                uint16_t val = static_cast<uint16_t>(image[off] | (image[off + 1] << 8));
                const CfgStringLit* lit = find_string_at(val);
                if (lit == nullptr || !seen_str.insert(lit->off).second || !lit->interesting)
                    continue;
                CfgStringXref xr;
                xr.at_ip = off - 1;
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
    std::cout << std::format("BB {}..{}  file {:08X}h  insns={}  preds={}",
                             cfg_lin_hex(b.start_ip), cfg_lin_hex(b.end_ip),
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
        std::cout << std::format("  INT {:02X}h @ {}", site.int_num, cfg_lin_hex(site.ip));
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
        std::cout << std::format("  str xref @ {} -> image:{}  \"{}\"\n",
                                 cfg_lin_hex(xr.at_ip), cfg_lin_hex(xr.str_ip), xr.str);
    }

    if (!b.preds.empty() && b.preds.size() <= 12) {
        std::cout << "  preds:";
        for (CfgLin p : b.preds)
            std::cout << std::format(" {}", cfg_lin_hex(p));
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
            std::cout << std::format("    {}:  {}\n", cfg_lin_hex(in.ip), in.text);
        }
        if (b.insns.size() > lim)
            std::cout << std::format("    ... {} more insns\n", b.insns.size() - lim);
    }

    for (const auto& e : b.outs) {
        if (e.has_target)
            std::cout << std::format("  -> {}  [{}]\n", cfg_lin_hex(e.to_ip), cfg_edge_name(e.kind));
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
    std::map<CfgLin, std::vector<std::pair<CfgLin, CfgEdgeKind>>> rev;
    for (const auto& [sip, blk] : g.blocks) {
        for (const auto& e : blk.outs) {
            if (!e.has_target) continue;
            rev[e.to_ip].push_back({sip, e.kind});
        }
        // preds may include fall-through-only; ensure listed
        for (CfgLin p : blk.preds)
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

        std::cout << std::format("SEED {}  {}\n", cfg_lin_hex(seed->start_ip),
                                 cfg_seed_label(*seed));

        // BFS reverse: who reaches this seed
        std::queue<std::pair<CfgLin, int>> q;
        std::map<CfgLin, std::pair<CfgLin, CfgEdgeKind>> parent; // child -> (parent, edge)
        std::set<CfgLin> seen;
        q.push({seed->start_ip, 0});
        seen.insert(seed->start_ip);

        std::vector<CfgLin> callers; // depth-1 call parents
        std::vector<CfgLin> frontier;

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
            for (CfgLin p : seed->preds) {
                if (n++ >= 12) {
                    std::cout << " ...";
                    break;
                }
                std::cout << std::format(" {}", cfg_lin_hex(p));
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
            for (CfgLin c : callers) {
                std::cout << std::format(" {}", cfg_lin_hex(c));
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
        CfgLin tip = seed->start_ip;
        int tip_depth = 0;
        for (const auto& [node, pr] : parent) {
            // compute depth by walking
            int d = 0;
            CfgLin x = node;
            std::set<CfgLin> guard;
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
            std::vector<std::pair<CfgLin, CfgEdgeKind>> chain;
            CfgLin x = tip;
            std::set<CfgLin> guard;
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
                std::cout << cfg_lin_hex(chain[i].first);
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
                std::cout << std::format(" {}:{}", cfg_edge_name(e.kind),
                                         cfg_lin_hex(e.to_ip));
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
            std::cout << std::format("  {}  {}\n", cfg_lin_hex(seed->start_ip), name);
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
            std::cout << std::format("{}     ", cfg_lin_hex(bp->start_ip));
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

//=============================================================================
// Graphviz DOT export (--cfg-dot=FILE)
//=============================================================================

static inline std::string cfg_dot_escape(std::string_view s)
{
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s)
    {
        if (c == '\\' || c == '"')
        {
            o.push_back('\\');
            o.push_back(c);
        }
        else if (c == '\n' || c == '\r')
            o += "\\n";
        else if (static_cast<unsigned char>(c) < 32)
            continue;
        else
            o.push_back(c);
    }
    return o;
}

static inline const char* cfg_dot_edge_color(CfgEdgeKind k)
{
    switch (k)
    {
    case CfgEdgeKind::FallThrough: return "#666666";
    case CfgEdgeKind::Jump:        return "#1a5276";
    case CfgEdgeKind::CondTrue:    return "#196f3d";
    case CfgEdgeKind::CondFalse:   return "#b7950b";
    case CfgEdgeKind::Call:        return "#6c3483";
    case CfgEdgeKind::Ret:         return "#922b21";
    case CfgEdgeKind::Table:       return "#b9770e";
    }
    return "#000000";
}

static inline std::string cfg_dot_node_fill(const CfgBlock& b)
{
    if (b.is_entry)
        return "#abebc6"; // green — entry
    if (b.is_table_entry)
        return "#d7bde2"; // purple — jump-table slot
    if (b.is_interesting)
        return "#f5cba7"; // orange — INT/string/tags
    if (b.is_call_target)
        return "#aed6f1"; // blue — call target
    return "#f8f9f9";
}

/// Write Graphviz digraph for CFG. Returns false on I/O error.
static inline bool cfg_write_dot(const CfgGraph& g,
                                 const std::string& path,
                                 const Options& opts)
{
    std::ofstream out(path);
    if (!out)
    {
        std::cerr << "Error: cannot write CFG DOT to '" << path << "'\n";
        return false;
    }

    out << "// dumpexe CFG — Graphviz digraph\n";
    out << "// CS=" << std::format("{:04X}h", g.cs_seg)
        << " blocks=" << g.blocks.size()
        << " edges=" << g.n_edges << "\n";
    out << "digraph cfg {\n";
    out << "  graph [rankdir=TB, fontsize=10, fontname=\"Helvetica\","
           " label=\"dumpexe CFG  CS="
        << std::format("{:04X}h", g.cs_seg)
        << "  blocks=" << g.blocks.size()
        << "  edges=" << g.n_edges << "\","
           " labelloc=t];\n";
    out << "  node  [shape=box, style=\"rounded,filled\", fontname=\"Courier\","
           " fontsize=9];\n";
    out << "  edge  [fontname=\"Helvetica\", fontsize=8];\n\n";

    // Legend (subgraph)
    out << "  subgraph cluster_legend {\n";
    out << "    label=\"legend\"; style=dashed; color=gray;\n";
    out << "    leg_entry [label=\"entry\", fillcolor=\"#abebc6\"];\n";
    out << "    leg_int   [label=\"interesting\", fillcolor=\"#f5cba7\"];\n";
    out << "    leg_tab   [label=\"jmp-table\", fillcolor=\"#d7bde2\"];\n";
    out << "    leg_call  [label=\"call-tgt\", fillcolor=\"#aed6f1\"];\n";
    out << "    leg_entry -> leg_int -> leg_tab -> leg_call [style=invis];\n";
    out << "  }\n\n";

    const size_t max_nodes = opts.cfgMaxBlocks ? opts.cfgMaxBlocks : 500;
    std::vector<const CfgBlock*> order;
    order.reserve(g.blocks.size());
    for (const auto& kv : g.blocks)
        order.push_back(&kv.second);
    std::sort(order.begin(), order.end(),
              [](const CfgBlock* a, const CfgBlock* b)
              { return a->start_ip < b->start_ip; });

    // Prefer interesting + entry when truncating
    std::set<CfgLin> emit;
    for (const CfgBlock* bp : order)
    {
        if (bp->is_entry || bp->is_interesting || bp->is_table_entry)
            emit.insert(bp->start_ip);
    }
    for (const CfgBlock* bp : order)
    {
        if (emit.size() >= max_nodes)
            break;
        emit.insert(bp->start_ip);
    }

    for (const CfgBlock* bp : order)
    {
        if (!emit.count(bp->start_ip))
            continue;
        const CfgBlock& b = *bp;
        std::string label = cfg_lin_hex(b.start_ip);
        if (b.is_entry)
            label += "\\nENTRY";
        if (!b.tags.empty())
        {
            label += "\\n";
            for (size_t i = 0; i < b.tags.size() && i < 4; ++i)
            {
                if (i)
                    label += ", ";
                label += cfg_dot_escape(b.tags[i]);
            }
            if (b.tags.size() > 4)
                label += std::format(" +{}", b.tags.size() - 4);
        }
        if (!opts.cfgNoInsns && !b.insns.empty())
        {
            size_t n = opts.cfgInsnsPerBlock ? opts.cfgInsnsPerBlock : 12;
            if (n > 6)
                n = 6; // keep DOT readable
            for (size_t i = 0; i < b.insns.size() && i < n; ++i)
                label += "\\n" + cfg_dot_escape(b.insns[i].text);
            if (b.insns.size() > n)
                label += "\\n…";
        }
        out << std::format("  n{} [label=\"{}\", fillcolor=\"{}\"];\n",
                           cfg_lin_hex(b.start_ip), label, cfg_dot_node_fill(b));
    }
    out << "\n";

    size_t edges_out = 0;
    for (const CfgBlock* bp : order)
    {
        if (!emit.count(bp->start_ip))
            continue;
        for (const CfgEdge& e : bp->outs)
        {
            if (!e.has_target)
            {
                // ret / unknown: dangling note node optional — skip
                continue;
            }
            if (!emit.count(e.to_ip) && !g.blocks.count(e.to_ip))
                continue;
            // If target not emitted but exists, still draw if both ends in emit
            if (!emit.count(e.to_ip))
                continue;
            out << std::format(
                "  n{} -> n{} [label=\"{}\", color=\"{}\"];\n",
                cfg_lin_hex(bp->start_ip), cfg_lin_hex(e.to_ip), cfg_edge_name(e.kind),
                cfg_dot_edge_color(e.kind));
            ++edges_out;
        }
    }

    out << "}\n";
    out.flush();
    if (!out)
    {
        std::cerr << "Error: failed writing CFG DOT '" << path << "'\n";
        return false;
    }
    if (!opts.jsonOut)
    {
        std::cerr << std::format(
            "CFG DOT: wrote {} ({} nodes emitted, {} edges, graph has {} blocks)\n",
            path, emit.size(), edges_out, g.blocks.size());
    }
    return true;
}

/**
 * @brief Build and annotate a CFG for a loaded image region. Does not print.
 *
 * @param fileData        Whole file.
 * @param image_file_off  File offset of image[0].
 * @param image_len       Load-image length.
 * @param entry_ip        Entry linear address. image[0] is linear 0.
 * @param cs_seg          Load base stored on the graph. Not a flow segment.
 * @param file_cs         MZ header CS for unpinned far transfers.
 * @param opts            Follow-calls and annotation flags.
 * @param relocs          MZ fixups into the image. Empty for COM.
 * @param entry_frame  Paragraph frame of @p entry_ip (`cs * 16`). 0 for COM
 *                      and for an entry that is not inside the image.
 *                      May be negative.
 * @return Annotated graph. Empty when the slice is outside the file.
 */
static inline CfgGraph cfg_build_annotated(const std::vector<uint8_t>& fileData,
                                           size_t image_file_off,
                                           size_t image_len,
                                           CfgLin entry_ip,
                                           uint16_t cs_seg,
                                           uint16_t file_cs,
                                           const Options& opts,
                                           std::span<const RelocEntry> relocs = {},
                                           int32_t entry_frame = 0)
{
    CfgGraph empty;
    if (image_file_off >= fileData.size())
        return empty;
    size_t len = std::min(image_len, fileData.size() - image_file_off);
    std::vector<uint8_t> image(
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off),
        fileData.begin() + static_cast<std::ptrdiff_t>(image_file_off + len));

    CfgGraph g = cfg_build(image, entry_ip, cs_seg, file_cs, image_file_off,
                           opts.cfgFollowCalls, 20000, relocs, entry_frame);
    cfg_annotate(g, image);
    return g;
}

/**
 * @brief Present an already-built CFG. Does not build another graph.
 *
 * Writes DOT when @p opts.cfgDotPath is set. Prints the human dump when
 * @p opts.showCfg is set and JSON output is off.
 *
 * @param g    Annotated control-flow graph.
 * @param opts Presentation flags (@c cfgDotPath, @c showCfg, @c jsonOut).
 */
static inline void cfg_emit_views(const CfgGraph& g, const Options& opts)
{
    if (!opts.cfgDotPath.empty())
    {
        cfg_write_dot(g, opts.cfgDotPath, opts);
    }
    // Human CFG dump when --cfg (or cfg-* that set showCfg), not in pure JSON mode
    if (opts.showCfg && !opts.jsonOut)
    {
        cfg_print(g, opts);
    }
}

/**
 * @brief Build one annotated CFG, then optional DOT export and human print.
 *
 * @param fileData        Whole file.
 * @param image_file_off  File offset of image[0].
 * @param image_len       Load-image length.
 * @param entry_ip        Entry linear address. Pass 0 when the MZ entry is
 *                        outside the image.
 * @param cs_seg          Load base stored on the graph. Not a flow segment.
 * @param file_cs         MZ header CS for unpinned far transfers.
 * @param opts            Presentation and follow-calls flags.
 * @param relocs          MZ fixups into the image. Empty for COM.
 * @param entry_frame  Paragraph frame of @p entry_ip (`cs * 16`). 0 for COM.
 *                      May be negative.
 * @return The annotated graph.
 */
static inline CfgGraph cfg_analyze_image(const std::vector<uint8_t>& fileData,
                                         size_t image_file_off,
                                         size_t image_len,
                                         CfgLin entry_ip,
                                         uint16_t cs_seg,
                                         uint16_t file_cs,
                                         const Options& opts,
                                         std::span<const RelocEntry> relocs = {},
                                         int32_t entry_frame = 0)
{
    if (image_file_off >= fileData.size())
    {
        if (!opts.jsonOut)
            std::cout << "\nCFG: image offset outside file.\n";
        return {};
    }

    CfgGraph g = cfg_build_annotated(fileData, image_file_off, image_len,
                                     entry_ip, cs_seg, file_cs, opts, relocs,
                                     entry_frame);
    cfg_emit_views(g, opts);
    return g;
}

#endif // CFG_H
