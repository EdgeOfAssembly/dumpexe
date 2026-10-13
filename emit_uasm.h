/**
 * @file emit_uasm.h
 * @brief P2 verified UASM emitter: units, rules R3–R12, pins, symbolic db.
 *
 * A printer over the decoded instructions and the relocation set. It
 * writes the most readable spelling the rules allow; verify.h assembles the
 * whole listing and demotes lines that do not reproduce the original bytes
 * (mnemonic → pin → symbolic db → raw db). Layout is flat: one para use16
 * segment holding the load image (org 100h for COM, org 0 for EXE). Labels
 * are named by image linear (`L%05X`). Every reference field the model knows
 * (near branch targets, relocated segment words, far offsets) stays an
 * expression in every rung except raw db, so a demotion keeps edit safety.
 */
#ifndef DX_EMIT_UASM_H
#define DX_EMIT_UASM_H

#include <algorithm>
#include <cstdint>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <capstone/capstone.h>

#include "cfg.h"

namespace dx
{

/** @brief Kind of a symbolic reference field inside an instruction. */
enum class RefKind : uint8_t
{
    Rel,    ///< near branch displacement (rel8 or rel16)
    Seg,    ///< relocated segment word
    FarOff, ///< offset word of a relocated far pointer
    Off     ///< P4: proven near offset (jump-table base, string pointer)
};

/** @brief P4: one word in data that holds a near offset. */
struct OffWord
{
    uint32_t target = 0;
    uint32_t frame = 0;
};

/** @brief One reference field of an instruction. */
struct InsnRef
{
    RefKind kind = RefKind::Rel;
    uint8_t off = 0;     ///< field offset inside the instruction
    uint8_t size = 0;    ///< 1 or 2
    uint32_t target = 0; ///< linear target (Rel, FarOff)
    uint32_t frame = 0;  ///< frame linear = paragraph * 16 (Seg, FarOff)
};

/** @brief How a code unit is printed this round. */
enum class Rung : uint8_t
{
    Mnemonic = 0,
    Pin = 1,
    SymDb = 2,
    RawDb = 3
};

/** @brief One emitted unit: an instruction or a data run. */
struct EmitUnit
{
    uint32_t lin = 0;
    uint32_t size = 0;
    bool code = false;
    Rung rung = Rung::RawDb;
    std::vector<InsnRef> refs;
    std::string decoded;       ///< Capstone text, for comments
    std::string reason;        ///< last demotion reason
    bool tentative = false;    ///< demoted for a range error only
};

/** @brief Emitter options and inputs. */
struct EmitInput
{
    const std::vector<uint8_t>* image = nullptr; ///< image[0] is linear 0
    uint32_t emit_lo = 0;      ///< first emitted linear (0x100 for a pure COM)
    uint32_t entry = 0;        ///< entry linear
    bool com = false;          ///< pure COM: org 100h
    std::set<uint32_t> reloc_at; ///< in-image relocated words
    std::string source_name;
    bool negative_control = false; ///< every code unit raw db (shift must break)
    /// Strategy C (P3): the listing carries the MZ header and the file tail,
    /// so `uasm -bin` rebuilds the whole EXE. Needs @c file and @c hdr_len.
    bool mz_header = false;
    const std::vector<uint8_t>* file = nullptr; ///< whole file (strategy C)
    uint32_t hdr_len = 0;                       ///< header bytes (e_cparhdr * 16)
    std::vector<RelocEntry> reloc_entries;      ///< relocation table, original order
    uint32_t entry_frame = 0;                   ///< CS * 16 of the entry
    /// P5 hints: label names, forced data ranges [lo, hi), heads not to
    /// print as code (--strict: no Derived-or-stronger fact).
    std::map<uint32_t, std::string> label_names;
    std::vector<std::pair<uint32_t, uint32_t>> force_data;
    std::set<uint32_t> weak_heads;
};

/** @brief MASM hex: 0NNh with a leading 0 before A–F. */
inline std::string uasm_hex(uint32_t v)
{
    std::string h = std::format("{:X}", v);
    if (!h.empty() && h[0] >= 'A' && h[0] <= 'F')
    {
        h.insert(h.begin(), '0');
    }
    return h + "h";
}

/** @brief Label name of a linear. */
inline std::string uasm_label(uint32_t lin)
{
    return std::format("L{:05X}", lin);
}

/**
 * @brief Builds the units and renders the listing for one image.
 *
 * Construction decodes every CFG instruction once with Capstone detail and
 * records its reference fields. @c render produces the source for the
 * current rungs; verify.h changes rungs and calls it again.
 */
class UasmEmitter
{
public:
    UasmEmitter(const CfgGraph& g, EmitInput in);
    ~UasmEmitter();
    UasmEmitter(const UasmEmitter&) = delete;
    UasmEmitter& operator=(const UasmEmitter&) = delete;

    /**
     * @brief Render the listing.
     *
     * @param header   Comment lines placed first (each without the ';').
     * @param shift_at Linear before which @p shift_text is inserted (before
     *                 its label and align guard), or -1.
     * @param shift_text One source line inserted by a shift test.
     * @return Source text. @c line_unit maps 1-based source lines to units.
     */
    std::string render(const std::vector<std::string>& header, int64_t shift_at = -1,
                       std::string_view shift_text = {});

    std::vector<EmitUnit>& units() { return units_; }
    const std::vector<EmitUnit>& units() const { return units_; }
    const std::map<int, size_t>& line_unit() const { return line_unit_; }
    uint32_t emit_lo() const { return in_.emit_lo; }
    uint32_t org() const { return in_.com ? 0x100u : 0u; }
    /// Listing address of image linear 0 minus the linear: header bytes in strategy C.
    uint32_t bias() const { return in_.mz_header ? in_.hdr_len : 0u; }
    /// Bytes `uasm -bin` must produce.
    const std::vector<uint8_t>& expected() const { return expected_; }
    /// Tail bytes after the load image (strategy C).
    uint32_t tail_len() const { return tail_len_; }
    /// Header fields printed as literals because no expression reproduces them.
    const std::vector<std::string>& header_literals() const { return hdr_literal_; }
    /// Relocated words printed in data units as segment expressions.
    size_t data_seg_words() const { return data_seg_words_; }
    /// Relocation-derived frames that sit inside a printed instruction.
    std::set<uint32_t> all_bases() const { return bases_; }
    const EmitInput& input() const { return in_; }

    /** @brief Pin text for unit @p u, or empty when no pin family fits. */
    std::string pin_text(const EmitUnit& u);

    /** @brief Relocated words printed as segment expressions in the last render. */
    const std::set<uint32_t>& symbolic_relocs() const { return sym_relocs_; }

    /** @brief Index of the unit starting at @p lin, or -1. */
    int unit_at(uint32_t lin) const;

    /** @brief Index of the unit covering @p lin, or -1. */
    int unit_covering(uint32_t lin) const;

    /** @brief True when the last render put an `align 16` guard before @p lin. */
    bool align_before(uint32_t lin) const
    {
        return labels_.count(lin) && frame_bases_.count(lin) && lin > in_.emit_lo && lin % 16 == 0;
    }

    /** @brief Labels the last render defined (linear → equ head or itself). */
    const std::set<uint32_t>& labels() const { return labels_; }

private:
    std::string mnemonic_text(const EmitUnit& u, const cs_insn* ci);
    std::vector<std::string> symdb_lines(const EmitUnit& u, bool raw);
    std::string seg_expr(uint32_t frame);
    std::string off_expr(uint32_t target, uint32_t frame);
    void collect_labels();
    void add_value_refs();
    std::string data_lines(uint32_t lin, uint32_t len);
    const cs_insn* decode(const EmitUnit& u);

    const CfgGraph& g_;
    EmitInput in_;
    csh cs_ = 0;
    cs_insn* insn_ = nullptr;
    std::vector<EmitUnit> units_;
    std::vector<uint32_t> starts_;
    std::map<uint32_t, int32_t> frame_of_;
    std::set<uint32_t> labels_;
    std::map<uint32_t, std::pair<uint32_t, uint32_t>> equs_;
    std::set<uint32_t> frame_bases_;
    std::set<std::string> used_macros_;
    std::map<int, size_t> line_unit_;
    std::set<uint32_t> sym_relocs_;
    std::set<uint32_t> straddled_;
    std::map<uint32_t, OffWord> off_words_;  ///< P4 table words
    int64_t dgroup_ = -1;
    std::vector<uint32_t> want_roots_;   ///< P5: table targets still in data
    size_t n_tables_ = 0;
    size_t n_strings_ = 0;
    std::set<uint32_t> bases_;
    std::vector<uint8_t> expected_;
    uint32_t tail_len_ = 0;
    std::vector<std::string> hdr_literal_;
    size_t data_seg_words_ = 0;
    std::string header_lines();
    std::string data_word(uint32_t at);

public:
    /** @brief Decoded instructions dropped because they straddle a segment base. */
    size_t straddled() const { return straddled_.size(); }
    /// Label text: a hinted name, else L%05X.
    std::string lbl(uint32_t lin) const
    {
        auto it = in_.label_names.find(lin);
        return it != in_.label_names.end() ? it->second : uasm_label(lin);
    }
    /// P4: words in data printed as near offsets (jump-table entries).
    const std::map<uint32_t, OffWord>& off_words() const { return off_words_; }
    /// Inferred DGROUP base (mov r16, seg X; mov ds, r16), or -1.
    int64_t dgroup() const { return dgroup_; }
    /// P5: bounded-table targets that the graph did not decode.
    const std::vector<uint32_t>& want_roots() const { return want_roots_; }
    size_t value_tables() const { return n_tables_; }
    size_t value_strings() const { return n_strings_; }
};

// ---------------------------------------------------------------------------

inline UasmEmitter::UasmEmitter(const CfgGraph& g, EmitInput in)
    : g_(g)
    , in_(std::move(in))
{
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &cs_) == CS_ERR_OK)
    {
        cs_option(cs_, CS_OPT_DETAIL, CS_OPT_ON);
        insn_ = cs_malloc(cs_);
    }
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());

    // Unique instruction heads that match the image bytes.
    std::map<uint32_t, const CfgInsn*> heads;
    for (const auto& kv : g_.blocks)
    {
        for (const CfgInsn& ci : kv.second.insns)
        {
            if (ci.ip < in_.emit_lo || ci.size == 0 || ci.ip + ci.size > n)
            {
                continue;
            }
            if (std::memcmp(img.data() + ci.ip, ci.bytes, ci.size) != 0)
            {
                continue;
            }
            bool forced = in_.weak_heads.count(ci.ip) != 0;
            for (const auto& [lo, hi] : in_.force_data)
                if (ci.ip < hi && ci.ip + ci.size > lo)
                    forced = true;
            if (forced)
                continue;
            heads.emplace(ci.ip, &ci);
            frame_of_.emplace(ci.ip, ci.seg_base);
        }
    }

    // Relocation-derived segment bases are hard boundaries: an instruction
    // that straddles one is not printed as code (it is data the CFG ran
    // into), so every base can carry a label and an align 16 guard.
    {
        std::set<uint32_t> bases;
        for (uint32_t at : in_.reloc_at)
        {
            if (at + 1 < n)
                bases.insert((img[at] | (img[at + 1] << 8)) * 16u);
        }
        for (const RelocEntry& r : in_.reloc_entries)
        {
            if (static_cast<uint32_t>(r.segment) * 16u < n)
                bases.insert(static_cast<uint32_t>(r.segment) * 16u);
        }
        if (!in_.com && in_.entry_frame < n)
            bases.insert(in_.entry_frame);
        bases_ = bases;
        for (auto it = heads.begin(); it != heads.end();)
        {
            const uint32_t h = it->first;
            const uint32_t end = h + it->second->size;
            auto b = bases.upper_bound(h);
            if (b != bases.end() && *b < end)
            {
                straddled_.insert(h);
                it = heads.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    if (in_.mz_header && in_.file != nullptr)
    {
        expected_ = *in_.file;
        tail_len_ = static_cast<uint32_t>(in_.file->size() - std::min<size_t>(in_.file->size(), in_.hdr_len + n));
    }
    else
    {
        expected_.assign(img.begin() + in_.emit_lo, img.end());
    }

    uint32_t a = in_.emit_lo;
    auto next_head = heads.lower_bound(a);
    while (a < n)
    {
        while (next_head != heads.end() && next_head->first < a)
        {
            ++next_head;
        }
        if (next_head != heads.end() && next_head->first == a)
        {
            const CfgInsn& ci = *next_head->second;
            EmitUnit u;
            u.lin = a;
            u.size = ci.size;
            u.code = true;
            u.rung = in_.negative_control ? Rung::RawDb : Rung::Mnemonic;
            u.decoded = ci.text;
            units_.push_back(std::move(u));
            a += ci.size;
            continue;
        }
        const uint32_t stop = (next_head != heads.end()) ? next_head->first : n;
        EmitUnit u;
        u.lin = a;
        u.size = stop - a;
        u.code = false;
        units_.push_back(std::move(u));
        a = stop;
    }
    for (const EmitUnit& u : units_)
    {
        starts_.push_back(u.lin);
    }

    // Reference fields.
    for (EmitUnit& u : units_)
    {
        if (!u.code)
        {
            continue;
        }
        const cs_insn* ci = decode(u);
        if (ci == nullptr)
        {
            u.rung = Rung::RawDb;
            u.reason = "capstone did not decode";
            continue;
        }
        const cs_x86& x = ci->detail->x86;
        const int32_t frame = frame_of_[u.lin];
        // Near branches: E8 E9 EB 7x E0-E3 0F 8x.
        const uint8_t imm_off = x.encoding.imm_offset;
        const uint8_t imm_size = x.encoding.imm_size;
        const uint8_t op0 = x.opcode[0];
        const bool near_br = (op0 == 0xE8 || op0 == 0xE9 || op0 == 0xEB ||
                              (op0 >= 0x70 && op0 <= 0x7F) || (op0 >= 0xE0 && op0 <= 0xE3) ||
                              (op0 == 0x0F && x.opcode[1] >= 0x80 && x.opcode[1] <= 0x8F));
        if (near_br && x.op_count >= 1 && x.operands[0].type == X86_OP_IMM && imm_size != 0 &&
            imm_off + imm_size == u.size)
        {
            const uint32_t tgt16 = static_cast<uint32_t>(x.operands[0].imm) & 0xFFFFu;
            const int64_t t = static_cast<int64_t>(frame) + tgt16;
            if (t >= static_cast<int64_t>(in_.emit_lo) && t < static_cast<int64_t>(n))
            {
                InsnRef r;
                r.kind = RefKind::Rel;
                r.off = imm_off;
                r.size = imm_size;
                r.target = static_cast<uint32_t>(t);
                u.refs.push_back(r);
            }
        }
        // Relocated words inside this instruction.
        for (uint32_t k = 0; k + 1 < u.size; ++k)
        {
            if (in_.reloc_at.count(u.lin + k) == 0)
            {
                continue;
            }
            const uint32_t seg = img[u.lin + k] | (img[u.lin + k + 1] << 8);
            const uint32_t fr = seg * 16u;
            InsnRef r;
            r.kind = RefKind::Seg;
            r.off = static_cast<uint8_t>(k);
            r.size = 2;
            r.frame = fr;
            u.refs.push_back(r);
            if ((op0 == 0x9A || op0 == 0xEA) && u.size == 5 && k == 3)
            {
                const uint32_t off = img[u.lin + 1] | (img[u.lin + 2] << 8);
                InsnRef f;
                f.kind = RefKind::FarOff;
                f.off = 1;
                f.size = 2;
                f.frame = fr;
                f.target = fr + off;
                u.refs.push_back(f);
            }
        }
    }
    add_value_refs();
}

/**
 * @brief P4 value references (valueprop-lite).
 *
 * Two proven patterns, each all-or-nothing:
 *  - bounded jump table: `cmp r, N` / `ja|jae|jbe|jb` within the eight
 *    instructions before `jmp word ptr cs:[bx+T]` (or `[bx+T]` in a COM).
 *    Every one of the N entries must name a decoded instruction head in the
 *    same frame and the table must lie in data; then T and each entry are
 *    offsets.
 *  - `$`-string for DOS 09h: `mov dx, imm` next to `mov ah, 9` and `int 21h`,
 *    DS known (COM: 0; MZ: the inferred DGROUP), and a `$` within 4 KiB.
 * The frame must be 0 in a COM or a relocation-derived base, so the
 * paragraph shift keeps the expression honest.
 */
inline void UasmEmitter::add_value_refs()
{
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    std::vector<size_t> code;
    for (size_t i = 0; i < units_.size(); ++i)
        if (units_[i].code && units_[i].rung != Rung::RawDb)
            code.push_back(i);
    // DGROUP.
    if (!in_.com && in_.emit_lo == 0)
    {
        std::map<uint32_t, size_t> votes;
        for (size_t j = 0; j + 1 < code.size(); ++j)
        {
            const EmitUnit& a = units_[code[j]];
            const EmitUnit& b = units_[code[j + 1]];
            if (a.lin + a.size != b.lin || a.size != 3 || b.size != 2)
                continue;
            const uint8_t op = img[a.lin];
            if (op < 0xB8 || op > 0xBF || img[b.lin] != 0x8E ||
                img[b.lin + 1] != static_cast<uint8_t>(0xD8 + (op - 0xB8)))
                continue;
            for (const InsnRef& r : a.refs)
                if (r.kind == RefKind::Seg && r.frame < n)
                    ++votes[r.frame];
        }
        size_t bestv = 0;
        for (const auto& [fr, c] : votes)
            if (c > bestv)
            {
                bestv = c;
                dgroup_ = fr;
            }
    }
    const bool pure_com = in_.com;
    auto frame_ok = [&](int64_t fr) -> bool
    {
        if (pure_com)
            return fr == 0;
        return fr >= 0 && fr < n && bases_.count(static_cast<uint32_t>(fr)) != 0;
    };
    auto in_data = [&](uint32_t a, uint32_t len) -> bool
    {
        if (a < in_.emit_lo || a + len > n)
            return false;
        const int ui = unit_covering(a);
        if (ui < 0 || units_[static_cast<size_t>(ui)].code)
            return false;
        const EmitUnit& d = units_[static_cast<size_t>(ui)];
        return a + len <= d.lin + d.size;
    };
    auto has_off_ref = [](const EmitUnit& u)
    {
        for (const InsnRef& r : u.refs)
            if (r.kind != RefKind::Rel)
                return true;
        return false;
    };
    for (size_t j = 0; j < code.size(); ++j)
    {
        EmitUnit& u = units_[code[j]];
        const uint8_t* b = img.data() + u.lin;
        if (has_off_ref(u))
            continue;
        // Jump table: [2E] FF A7 lo hi.
        const bool csp = u.size == 5 && b[0] == 0x2E && b[1] == 0xFF && b[2] == 0xA7;
        const bool nop = u.size == 4 && b[0] == 0xFF && b[1] == 0xA7;
        if ((csp && (pure_com || frame_ok(frame_of_[u.lin]))) || (nop && pure_com))
        {
            const uint32_t k = csp ? 3 : 2;
            const int64_t fr = pure_com ? 0 : frame_of_[u.lin];
            const uint32_t disp = b[k] | (b[k + 1] << 8);
            // Bound: cmp r, imm followed by an unsigned jcc, all contiguous.
            int64_t count = -1;
            bool doubled_after_cmp = false;
            for (size_t back = 1; back <= 8 && back <= j; ++back)
            {
                const EmitUnit& c = units_[code[j - back]];
                const EmitUnit& nx = units_[code[j - back + 1]];
                if (c.lin + c.size != nx.lin)
                    break;
                const uint8_t* cb = img.data() + c.lin;
                // shl bx,1 (D1 E3) or add bx,bx (03 DB / 01 DB) between the
                // compare and the jump: the compare saw the undoubled index.
                if (c.size == 2 && ((cb[0] == 0xD1 && cb[1] == 0xE3) ||
                                    ((cb[0] == 0x03 || cb[0] == 0x01) && cb[1] == 0xDB)))
                {
                    doubled_after_cmp = true;
                    continue;
                }
                int64_t imm = -1;
                if (c.size == 3 && cb[0] == 0x83 && (cb[1] & 0xF8) == 0xF8)
                    imm = cb[2];
                else if (c.size == 4 && cb[0] == 0x81 && (cb[1] & 0xF8) == 0xF8)
                    imm = cb[2] | (cb[3] << 8);
                else if (c.size == 3 && cb[0] == 0x80 && (cb[1] & 0xF8) == 0xF8)
                    imm = cb[2];
                else if (c.size == 2 && cb[0] == 0x3C)
                    imm = cb[1];
                else if (c.size == 3 && cb[0] == 0x3D)
                    imm = cb[1] | (cb[2] << 8);
                if (imm < 0)
                    continue;
                const uint8_t jo = img[nx.lin];
                if (jo == 0x77 || jo == 0x76) // ja / jbe: 0..imm
                    count = imm + 1;
                else if (jo == 0x73 || jo == 0x72) // jae / jb: 0..imm-1
                    count = imm;
                // Review R9: a compare on the already doubled index bounds
                // the byte offset, so the entry count is half.
                if (count > 0 && !doubled_after_cmp)
                    count = (count + 1) / 2;
                break;
            }
            if (count > 0 && count <= 256)
            {
                const uint32_t T = static_cast<uint32_t>(fr + disp);
                bool ok = in_data(T, static_cast<uint32_t>(count * 2));
                std::vector<uint32_t> tg;
                std::vector<uint32_t> undecoded;
                for (int64_t e = 0; ok && e < count; ++e)
                {
                    const uint32_t at = T + static_cast<uint32_t>(e * 2);
                    if (in_.reloc_at.count(at) || in_.reloc_at.count(at + 1) ||
                        (at > 0 && in_.reloc_at.count(at - 1)))
                        ok = false;
                    const uint32_t t = static_cast<uint32_t>(fr + (img[at] | (img[at + 1] << 8)));
                    const int ti = unit_at(t);
                    if (t < n && t >= in_.emit_lo && ti < 0)
                    {
                        // Not a unit start: fine only if inside data (P5
                        // fixpoint seeds it), never mid-instruction.
                        const int ci = unit_covering(t);
                        if (ci >= 0 && !units_[static_cast<size_t>(ci)].code)
                            undecoded.push_back(t);
                        else
                            ok = false;
                    }
                    else if (t < n && ti >= 0 && !units_[static_cast<size_t>(ti)].code)
                    {
                        undecoded.push_back(t);
                    }
                    else if (t >= n || ti < 0 || frame_of_[t] != fr)
                    {
                        ok = false;
                    }
                    tg.push_back(t);
                }
                if (ok && !undecoded.empty())
                {
                    // Bounded table with entries in data: ask for a rebuild
                    // with these as entries (same frame as the entry only).
                    const auto ef = frame_of_.find(in_.entry);
                    if (ef != frame_of_.end() && ef->second == fr)
                        want_roots_.insert(want_roots_.end(), undecoded.begin(), undecoded.end());
                    ok = false;
                }
                if (ok)
                {
                    InsnRef r;
                    r.kind = RefKind::Off;
                    r.off = static_cast<uint8_t>(k);
                    r.size = 2;
                    r.target = T;
                    r.frame = static_cast<uint32_t>(fr);
                    u.refs.push_back(r);
                    for (size_t e = 0; e < tg.size(); ++e)
                        off_words_[T + static_cast<uint32_t>(e * 2)] = {tg[e], static_cast<uint32_t>(fr)};
                    ++n_tables_;
                }
            }
            continue;
        }
        // $-string: BA iw with B4 09 and CD 21 in the same contiguous run.
        if (u.size == 3 && b[0] == 0xBA)
        {
            const int64_t ds = pure_com ? 0 : dgroup_;
            if (ds < 0 || !frame_ok(ds))
                continue;
            bool ah9 = false;
            bool i21 = false;
            for (size_t d = (j >= 3 ? j - 3 : 0); d <= j + 3 && d < code.size(); ++d)
            {
                const EmitUnit& c = units_[code[d]];
                const uint8_t* cb = img.data() + c.lin;
                if (c.size == 2 && cb[0] == 0xB4 && cb[1] == 0x09)
                    ah9 = true;
                if (c.size == 2 && cb[0] == 0xCD && cb[1] == 0x21 && d > j)
                    i21 = true;
            }
            if (!ah9 || !i21)
                continue;
            for (size_t d = j + 1; d < code.size() && units_[code[d]].lin < u.lin + 16; ++d)
                if (units_[code[d - 1]].lin + units_[code[d - 1]].size != units_[code[d]].lin)
                    i21 = false;
            if (!i21)
                continue;
            const uint32_t t = static_cast<uint32_t>(ds + (b[1] | (b[2] << 8)));
            if (!in_data(t, 1))
                continue;
            bool dollar = false;
            for (uint32_t q = t; q < n && q < t + 4096; ++q)
                if (img[q] == '$')
                {
                    dollar = true;
                    break;
                }
            if (!dollar)
                continue;
            InsnRef r;
            r.kind = RefKind::Off;
            r.off = 1;
            r.size = 2;
            r.target = t;
            r.frame = static_cast<uint32_t>(ds);
            u.refs.push_back(r);
            ++n_strings_;
        }
    }
}

inline UasmEmitter::~UasmEmitter()
{
    if (insn_ != nullptr)
    {
        cs_free(insn_, 1);
    }
    if (cs_ != 0)
    {
        cs_close(&cs_);
    }
}

inline const cs_insn* UasmEmitter::decode(const EmitUnit& u)
{
    if (insn_ == nullptr)
    {
        return nullptr;
    }
    const std::vector<uint8_t>& img = *in_.image;
    const int32_t frame = frame_of_.count(u.lin) ? frame_of_.at(u.lin) : 0;
    const uint8_t* p = img.data() + u.lin;
    size_t sz = u.size;
    uint64_t addr = static_cast<uint16_t>(static_cast<int64_t>(u.lin) - frame);
    if (!cs_disasm_iter(cs_, &p, &sz, &addr, insn_) || insn_->detail == nullptr ||
        insn_->size != u.size)
    {
        return nullptr;
    }
    return insn_;
}

inline int UasmEmitter::unit_at(uint32_t lin) const
{
    auto it = std::lower_bound(starts_.begin(), starts_.end(), lin);
    if (it == starts_.end() || *it != lin)
    {
        return -1;
    }
    return static_cast<int>(it - starts_.begin());
}

inline int UasmEmitter::unit_covering(uint32_t lin) const
{
    auto it = std::upper_bound(starts_.begin(), starts_.end(), lin);
    if (it == starts_.begin())
    {
        return -1;
    }
    const int i = static_cast<int>(it - starts_.begin()) - 1;
    const EmitUnit& u = units_[static_cast<size_t>(i)];
    return (lin < u.lin + u.size) ? i : -1;
}

inline std::string UasmEmitter::seg_expr(uint32_t frame)
{
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    labels_.insert(in_.emit_lo);
    if (frame >= n)
    {
        // A segment past the load image (BSS, stack) follows the image:
        // paragraphs after the rounded-up image end.
        labels_.insert(n);
        const uint32_t k = frame / 16u - (n + 15u) / 16u;
        return std::format("((({} - {} + 15) shr 4) + {})", lbl(n), lbl(in_.emit_lo),
                           uasm_hex(k));
    }
    labels_.insert(frame);
    return std::format("(({} - {}) shr 4)", lbl(frame), lbl(in_.emit_lo));
}

inline std::string UasmEmitter::off_expr(uint32_t target, uint32_t frame)
{
    if (in_.com && frame == 0)
    {
        labels_.insert(target);
        return "offset " + lbl(target);
    }
    labels_.insert(target);
    labels_.insert(frame);
    return std::format("({} - {})", lbl(target), lbl(frame));
}

inline void UasmEmitter::collect_labels()
{
    labels_.clear();
    frame_bases_.clear();
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    labels_.insert(in_.entry);
    for (const auto& [lin, name] : in_.label_names)
        if (lin >= in_.emit_lo && lin < n)
            labels_.insert(lin);
    // P3: every relocation-derived base is a label with an align 16 guard.
    for (uint32_t b : bases_)
    {
        if (b >= in_.emit_lo && b < n && unit_covering(b) >= 0 &&
            !units_[static_cast<size_t>(unit_covering(b))].code)
        {
            labels_.insert(b);
            frame_bases_.insert(b);
        }
        else if (b < n && unit_at(b) >= 0)
        {
            labels_.insert(b);
            frame_bases_.insert(b);
        }
    }
    // P4 table words: targets and frames are labels.
    for (const auto& [at, w] : off_words_)
    {
        labels_.insert(w.target);
        if (!(in_.com && w.frame == 0))
            labels_.insert(w.frame);
    }
    // Relocated words in data: their frames (or the image end) are labels.
    for (uint32_t at : in_.reloc_at)
    {
        const int ui = unit_covering(at);
        if (ui < 0 || units_[static_cast<size_t>(ui)].code || at + 1 >= n)
            continue;
        const uint32_t fr = ((*in_.image)[at] | ((*in_.image)[at + 1] << 8)) * 16u;
        labels_.insert(in_.emit_lo);
        labels_.insert(fr < n ? fr : n);
    }
    if (in_.mz_header)
    {
        labels_.insert(in_.emit_lo);
        labels_.insert(n);
        if (in_.entry_frame < n)
            labels_.insert(in_.entry_frame);
        for (const RelocEntry& r : in_.reloc_entries)
        {
            const uint32_t s = static_cast<uint32_t>(r.segment) * 16u;
            const uint32_t at = s + r.offset;
            if (s < n && at < n)
            {
                labels_.insert(s);
                labels_.insert(at);
            }
        }
    }
    for (const EmitUnit& u : units_)
    {
        if (!u.code || u.rung == Rung::RawDb)
        {
            continue;
        }
        for (const InsnRef& r : u.refs)
        {
            if (r.kind == RefKind::Rel)
            {
                labels_.insert(r.target);
            }
            else if (r.kind == RefKind::Off)
            {
                labels_.insert(r.target);
            }
            else if (r.kind == RefKind::Seg && r.frame >= n)
            {
                labels_.insert(n);
                labels_.insert(in_.emit_lo);
            }
            else if (r.frame >= in_.emit_lo && r.frame < n &&
                     (r.kind != RefKind::FarOff || r.target < n))
            {
                labels_.insert(r.frame);
                labels_.insert(in_.emit_lo);
                if (r.kind == RefKind::FarOff)
                {
                    labels_.insert(r.target);
                }
                frame_bases_.insert(r.frame);
            }
        }
    }
    // Labels inside an unsplittable unit become equates.
    equs_.clear();
    for (uint32_t lb : labels_)
    {
        const int ui = unit_covering(lb);
        if (ui < 0)
        {
            continue;
        }
        const EmitUnit& u = units_[static_cast<size_t>(ui)];
        if (u.lin != lb && u.code)
        {
            equs_[lb] = {u.lin, lb - u.lin};
        }
    }
    for (const auto& kv : equs_)
    {
        labels_.insert(kv.second.first);
    }
}

inline std::string UasmEmitter::pin_text(const EmitUnit& u)
{
    const cs_insn* ci = decode(u);
    if (ci == nullptr || !u.refs.empty())
    {
        return {};
    }
    const cs_x86& x = ci->detail->x86;
    if (x.prefix[0] || x.prefix[1] || x.prefix[2] || x.prefix[3])
    {
        return {};
    }
    static const char* r16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    static const char* r8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
    static const char* grp1[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
    const uint8_t op = x.opcode[0];
    const uint8_t* b = in_.image->data() + u.lin;
    // reg,reg ALU/mov with mod=11.
    const uint8_t base = op & 0xFC;
    const bool alu = base <= 0x38 && (base & 0x07) == 0;
    if ((alu || base == 0x88) && u.size == 2 && (b[1] >> 6) == 3)
    {
        const char* nm = (base == 0x88) ? "mov" : grp1[base >> 3];
        const bool w = op & 1;
        const bool d = (op >> 1) & 1;
        const char** R = w ? r16 : r8;
        const char* reg = R[(b[1] >> 3) & 7];
        const char* rm = R[b[1] & 7];
        used_macros_.insert("rr");
        return std::format("{}_{} {}, {}", nm, d ? "r" : "rm", d ? reg : rm, d ? rm : reg);
    }
    // Accumulator imm16: 05 0D ... 3D iw.
    if ((op & 0xC7) == 0x05 && op <= 0x3D && u.size == 3)
    {
        const char* nm = grp1[op >> 3];
        used_macros_.insert(std::string("aw:") + nm);
        return std::format("{}_aw {}", nm, uasm_hex(b[1] | (b[2] << 8)));
    }
    // 81 /n iw, register destination.
    if (op == 0x81 && u.size == 4 && (b[1] >> 6) == 3)
    {
        const char* nm = grp1[(b[1] >> 3) & 7];
        used_macros_.insert(std::string("iw:") + nm);
        return std::format("{}_iw {}, {}", nm, r16[b[1] & 7], uasm_hex(b[2] | (b[3] << 8)));
    }
    return {};
}

inline std::string UasmEmitter::mnemonic_text(const EmitUnit& u, const cs_insn* ci)
{
    const cs_x86& x = ci->detail->x86;
    std::string mn = ci->mnemonic;
    const uint8_t op0 = x.opcode[0];
    const bool any_prefix = x.prefix[0] || x.prefix[1] || x.prefix[2] || x.prefix[3];
    const InsnRef* rel = nullptr;
    const InsnRef* seg = nullptr;
    const InsnRef* offr = nullptr;
    for (const InsnRef& r : u.refs)
    {
        if (r.kind == RefKind::Rel)
            rel = &r;
        else if (r.kind == RefKind::Seg)
            seg = &r;
        else if (r.kind == RefKind::Off)
            offr = &r;
        else
            return {};
    }
    if (seg != nullptr)
    {
        // mov r16, seg X (B8-BF iw) is the only mnemonic form with a segment word.
        if (u.refs.size() == 1 && op0 >= 0xB8 && op0 <= 0xBF && u.size == 3 && !any_prefix &&
            seg->frame >= in_.emit_lo)
        {
            sym_relocs_.insert(u.lin + seg->off);
            return std::format("mov {}, {}", cs_reg_name(cs_, x.operands[0].reg),
                               seg_expr(seg->frame));
        }
        return {};
    }
    if (mn == "lcall" || mn == "ljmp")
    {
        if (op0 == 0x9A || op0 == 0xEA)
            return {};
        mn = (mn == "lcall") ? "call" : "jmp";
    }
    if (x.prefix[0] == 0xF0)
        return {};
    // Branches (R4).
    const bool is_branch = (op0 == 0xE8 || op0 == 0xE9 || op0 == 0xEB ||
                            (op0 >= 0x70 && op0 <= 0x7F) || (op0 >= 0xE0 && op0 <= 0xE3) ||
                            (op0 == 0x0F && x.opcode[1] >= 0x80 && x.opcode[1] <= 0x8F));
    if (is_branch)
    {
        if (rel == nullptr || any_prefix)
            return {};
        const std::string T = lbl(rel->target);
        if (op0 == 0xEB)
            return "jmp short " + T;
        if (op0 == 0xE9)
            return "jmp near ptr " + T;
        if (op0 == 0xE8)
            return "call near ptr " + T;
        if (op0 >= 0x70 && op0 <= 0x7F)
            return mn + " short " + T;
        if (op0 == 0x0F)
            return mn + " near ptr " + T;
        return mn + " " + T;
    }
    // String ops.
    {
        std::string base = mn;
        std::string rep;
        const size_t sp = mn.find(' ');
        if (sp != std::string::npos)
        {
            rep = mn.substr(0, sp);
            base = mn.substr(sp + 1);
        }
        static const char* strops[] = {"movs", "cmps", "lods", "stos", "scas", "ins", "outs"};
        for (const char* s : strops)
        {
            const size_t L = std::strlen(s);
            if (base.size() == L + 1 && base.compare(0, L, s) == 0 &&
                (base[L] == 'b' || base[L] == 'w' || base[L] == 'd'))
            {
                if (x.prefix[1] != 0)
                    return {};
                if (x.prefix[0] == 0xF2 && std::string_view(s) != "cmps" &&
                    std::string_view(s) != "scas")
                    return {};
                if (base[L] == 'd')
                    return {};
                return mn;
            }
        }
    }
    if (mn == "xlatb")
        return x.prefix[1] ? std::string{} : mn;
    if (mn == "int3")
        return "int 3";
    if (mn.starts_with("rep") && (mn.find("ret") != std::string::npos || mn.find("iret") != std::string::npos))
        return {};
    if ((mn == "cwde" || mn == "cdq") && x.prefix[2] == 0)
        return mn == "cwde" ? "cbw" : "cwd";
    if (mn == "pushaw" || mn == "popaw")
        mn.pop_back();
    if (mn == "aam" || mn == "aad")
        return (x.op_count >= 1 && (x.operands[0].imm & 0xFF) == 10) ? mn : std::string{};
    if (mn.find(' ') != std::string::npos)
        return {}; // other prefixed mnemonic (rep on a non-string op)

    std::vector<std::string> ops;
    for (int i = 0; i < x.op_count; ++i)
    {
        const cs_x86_op& o = x.operands[i];
        if (o.type == X86_OP_REG)
        {
            ops.emplace_back(cs_reg_name(cs_, o.reg));
        }
        else if (o.type == X86_OP_IMM)
        {
            const unsigned sz = o.size ? o.size : 2;
            if (x.encoding.imm_size == 1 && sz > 1)
            {
                int v = static_cast<int>(o.imm & 0xFF);
                if (v >= 128)
                    v -= 256;
                ops.push_back(std::to_string(v));
            }
            else if (offr != nullptr && x.encoding.imm_size == 2 && x.encoding.imm_offset == offr->off)
            {
                ops.push_back(off_expr(offr->target, offr->frame));
            }
            else
            {
                const uint64_t mask = (sz >= 8) ? ~0ull : ((1ull << (8 * sz)) - 1);
                ops.push_back(uasm_hex(static_cast<uint32_t>(static_cast<uint64_t>(o.imm) & mask)));
            }
        }
        else if (o.type == X86_OP_MEM)
        {
            std::string segn = o.mem.segment != X86_REG_INVALID ? cs_reg_name(cs_, o.mem.segment) : "";
            std::vector<std::string> parts;
            if (o.mem.base != X86_REG_INVALID)
                parts.emplace_back(cs_reg_name(cs_, o.mem.base));
            if (o.mem.index != X86_REG_INVALID)
                parts.emplace_back(cs_reg_name(cs_, o.mem.index));
            const bool has_reg = !parts.empty();
            const uint8_t ds = x.encoding.disp_size;
            if (ds != 0)
            {
                if (has_reg)
                {
                    if (ds == 1)
                    {
                        int v = static_cast<int>(o.mem.disp & 0xFF);
                        if (v >= 128)
                            v -= 256;
                        parts.push_back(std::to_string(v));
                    }
                    else if (offr != nullptr && x.encoding.disp_offset == offr->off)
                    {
                        std::string ex = off_expr(offr->target, offr->frame);
                        if (ex.starts_with("offset "))
                        {
                            // A bare label in [] carries its segment: UASM
                            // would add a CS override. Use a constant.
                            labels_.insert(in_.emit_lo);
                            ex = std::format("({} - {} + {})", ex.substr(7), lbl(in_.emit_lo),
                                             uasm_hex(in_.emit_lo));
                        }
                        parts.push_back(ex);
                    }
                    else
                    {
                        parts.push_back(uasm_hex(static_cast<uint32_t>(o.mem.disp) & 0xFFFFu));
                    }
                }
                else
                {
                    parts.push_back(uasm_hex(static_cast<uint32_t>(o.mem.disp) & 0xFFFFu));
                }
            }
            if (!has_reg && segn.empty())
                segn = "ds";
            std::string inner;
            for (size_t k = 0; k < parts.size(); ++k)
            {
                if (k && !(parts[k][0] == '-'))
                    inner += "+";
                inner += parts[k];
            }
            std::string ptr;
            switch (o.size)
            {
            case 1: ptr = "byte ptr "; break;
            case 2: ptr = "word ptr "; break;
            case 4: ptr = "dword ptr "; break;
            case 6: ptr = "fword ptr "; break;
            case 8: ptr = "qword ptr "; break;
            case 10: ptr = "tbyte ptr "; break;
            default: break;
            }
            static const std::set<std::string> noptr = {"lea", "fnstenv", "fldenv", "fnsave",
                                                        "frstor", "fsave", "fstenv"};
            if (noptr.count(mn))
                ptr.clear();
            if (mn == "lds" || mn == "les")
                ptr = "dword ptr ";
            ops.push_back(ptr + (segn.empty() ? "" : segn + ":") + "[" + inner + "]");
        }
        else
        {
            return {};
        }
    }
    static const std::set<std::string> fpu2 = {"fadd", "fmul", "fsub", "fsubr", "fdiv", "fdivr",
                                               "faddp", "fmulp", "fsubp", "fsubrp", "fdivp", "fdivrp"};
    if (fpu2.count(mn) && ops.size() == 1 && ops[0].starts_with("st("))
    {
        ops = (op0 == 0xD8) ? std::vector<std::string>{"st", ops[0]}
                            : std::vector<std::string>{ops[0], "st"};
    }
    if ((mn == "xchg" || mn == "test") && ops.size() == 2 && x.operands[0].type == X86_OP_REG &&
        x.operands[1].type == X86_OP_REG && op0 >= 0x84 && op0 <= 0x87)
    {
        std::swap(ops[0], ops[1]);
    }
    std::string out = mn;
    for (size_t k = 0; k < ops.size(); ++k)
    {
        out += (k ? ", " : " ") + ops[k];
    }
    return out;
}

inline std::vector<std::string> UasmEmitter::symdb_lines(const EmitUnit& u, bool raw)
{
    const uint8_t* b = in_.image->data() + u.lin;
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    std::map<uint8_t, std::pair<uint8_t, std::string>> f;
    if (!raw)
    {
        for (const InsnRef& r : u.refs)
        {
            if (r.kind == RefKind::Rel)
            {
                labels_.insert(r.target);
                const uint32_t rest = u.size - r.off - r.size;
                f[r.off] = {r.size, std::format("{} - ($ + {})", lbl(r.target), r.size + rest)};
            }
            else if (r.kind == RefKind::Off && in_.com && r.frame == 0)
            {
                f[r.off] = {2, off_expr(r.target, 0)};
            }
            else if (r.kind == RefKind::Seg && r.frame >= n)
            {
                f[r.off] = {2, seg_expr(r.frame)};
                sym_relocs_.insert(u.lin + r.off);
            }
            else if (r.frame >= in_.emit_lo && r.frame < n)
            {
                if (r.kind == RefKind::Seg)
                {
                    f[r.off] = {2, seg_expr(r.frame)};
                    sym_relocs_.insert(u.lin + r.off);
                }
                else if (r.target < n)
                {
                    f[r.off] = {2, off_expr(r.target, r.frame)};
                }
            }
        }
    }
    std::vector<std::string> lines;
    std::string cur;
    for (uint32_t k = 0; k < u.size;)
    {
        auto it = f.find(static_cast<uint8_t>(k));
        if (it != f.end())
        {
            if (!cur.empty())
            {
                lines.push_back("db " + cur);
                cur.clear();
            }
            lines.push_back((it->second.first == 2 ? "dw " : "db ") + it->second.second);
            k += it->second.first;
            continue;
        }
        if (!cur.empty())
            cur += ", ";
        cur += uasm_hex(b[k]);
        ++k;
    }
    if (!cur.empty())
        lines.push_back("db " + cur);
    return lines;
}

inline std::string UasmEmitter::data_lines(uint32_t lin, uint32_t len)
{
    const uint8_t* b = in_.image->data();
    std::string out;
    uint32_t p = lin;
    const uint32_t end = lin + len;
    while (p < end)
    {
        uint32_t q = p;
        while (q < end && b[q] == b[p])
            ++q;
        if (q - p >= 8)
        {
            out += std::format("    db {} dup({})\n", q - p, uasm_hex(b[p]));
            p = q;
            continue;
        }
        // Up to 16 bytes, stopping before a run of 8 equal bytes.
        uint32_t r = p;
        std::string row;
        while (r < end && r - p < 16)
        {
            uint32_t s = r;
            while (s < end && b[s] == b[r] && s - r < 8)
                ++s;
            if (s - r >= 8 && r != p)
                break;
            if (!row.empty())
                row += ", ";
            row += uasm_hex(b[r]);
            ++r;
        }
        out += "    db " + row + "\n";
        p = r;
    }
    return out;
}

inline std::string UasmEmitter::data_word(uint32_t at)
{
    const uint32_t seg = (*in_.image)[at] | ((*in_.image)[at + 1] << 8);
    sym_relocs_.insert(at);
    ++data_seg_words_;
    return std::format("    dw {}\t; {:05X}: segment word", seg_expr(seg * 16u), at);
}

inline std::string UasmEmitter::header_lines()
{
    // Strategy C: the MZ header as source. A field is an expression only
    // when that expression reproduces the original value; otherwise it is
    // the literal and is listed in header_literals().
    hdr_literal_.clear();
    const std::vector<uint8_t>& f = *in_.file;
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    const uint32_t H = in_.hdr_len;
    auto w = [&](uint32_t o) -> uint32_t { return o + 1 < f.size() ? (f[o] | (f[o + 1] << 8)) : 0; };
    const std::string L0 = lbl(in_.emit_lo);
    const std::string LE = lbl(n);
    std::string out;
    auto line = [&](const std::string& s) { out += "    " + s + "\n"; };
    auto field = [&](uint32_t o, const char* name, bool ok, const std::string& expr)
    {
        if (ok)
            line(std::format("dw {}\t\t; {}", expr, name));
        else
        {
            hdr_literal_.push_back(name);
            line(std::format("dw {}\t\t; {} (literal)", uasm_hex(w(o)), name));
        }
    };
    const uint32_t lfarlc = w(0x18);
    const uint32_t crlc = w(0x06);
    const bool table_ok = lfarlc >= 0x1C && lfarlc + crlc * 4 <= H;
    out += "DXHDR:\n";
    line(std::format("db {}, {}\t\t; signature", uasm_hex(f[0]), uasm_hex(f[1])));
    const uint32_t fsz = H + n;
    field(0x02, "e_cblp", w(0x02) == fsz % 512, std::format("(({} - DXHDR) mod 512)", LE));
    field(0x04, "e_cp", w(0x04) == (fsz + 511) / 512, std::format("((({} - DXHDR) + 511) shr 9)", LE));
    field(0x06, "e_crlc", table_ok, "((DXRELEND - DXRELTAB) shr 2)");
    field(0x08, "e_cparhdr", w(0x08) * 16 == H, std::format("(({} - DXHDR) shr 4)", L0));
    field(0x0A, "e_minalloc", false, "");
    field(0x0C, "e_maxalloc", false, "");
    field(0x0E, "e_ss", false, "");
    field(0x10, "e_sp", false, "");
    field(0x12, "e_csum", false, "");
    const uint32_t ef = in_.entry_frame;
    const bool entry_ok = ef < n && in_.entry < n && w(0x16) * 16u == ef && ef + w(0x14) == in_.entry;
    field(0x14, "e_ip", entry_ok, std::format("({} - {})", lbl(in_.entry), lbl(ef)));
    field(0x16, "e_cs", entry_ok, std::format("(({} - {}) shr 4)", lbl(ef), L0));
    field(0x18, "e_lfarlc", table_ok, "(DXRELTAB - DXHDR)");
    field(0x1A, "e_ovno", false, "");
    // The literal fields above are expected: drop them from the report.
    hdr_literal_.erase(std::remove_if(hdr_literal_.begin(), hdr_literal_.end(),
                                      [](const std::string& s)
                                      {
                                          return s == "e_minalloc" || s == "e_maxalloc" ||
                                                 s == "e_ss" || s == "e_sp" || s == "e_csum" ||
                                                 s == "e_ovno";
                                      }),
                       hdr_literal_.end());
    auto raw = [&](uint32_t from, uint32_t to)
    {
        for (uint32_t p = from; p < to;)
        {
            uint32_t q = p;
            while (q < to && f[q] == f[p])
                ++q;
            if (q - p >= 8)
            {
                line(std::format("db {} dup({})", q - p, uasm_hex(f[p])));
                p = q;
                continue;
            }
            std::string row;
            const uint32_t r = std::min(to, p + 16);
            for (uint32_t k = p; k < r; ++k)
                row += (k > p ? ", " : "") + uasm_hex(f[k]);
            line("db " + row);
            p = r;
        }
    };
    const uint32_t tab = table_ok ? lfarlc : 0x1C;
    raw(0x1C, tab);
    out += "DXRELTAB:\n";
    if (table_ok)
    {
        for (uint32_t i = 0; i < crlc; ++i)
        {
            const uint32_t off = w(lfarlc + 4 * i);
            const uint32_t seg = w(lfarlc + 4 * i + 2);
            const uint32_t s = seg * 16u;
            const uint32_t at = s + off;
            if (s < n && at < n)
                line(std::format("dw ({} - {}), (({} - {}) shr 4)", lbl(at), lbl(s),
                                 lbl(s), L0));
            else
            {
                hdr_literal_.push_back(std::format("relocation {}", i));
                line(std::format("dw {}, {}", uasm_hex(off), uasm_hex(seg)));
            }
        }
    }
    out += "DXRELEND:\n";
    raw(table_ok ? lfarlc + crlc * 4 : 0x1C, H);
    out += "align 16\n";
    return out;
}

inline std::string UasmEmitter::render(const std::vector<std::string>& header, int64_t shift_at,
                                       std::string_view shift_text)
{
    used_macros_.clear();
    sym_relocs_.clear();
    data_seg_words_ = 0;
    collect_labels();
    const uint32_t n = static_cast<uint32_t>(in_.image->size());

    // Pass 1: text per code unit for the current rung, and the CPU level.
    std::vector<std::vector<std::string>> text(units_.size());
    int cpu = 0;
    bool fpu = false;
    for (size_t i = 0; i < units_.size(); ++i)
    {
        EmitUnit& u = units_[i];
        if (!u.code)
            continue;
        if (u.rung == Rung::Mnemonic)
        {
            const cs_insn* ci = decode(u);
            std::string t = ci ? mnemonic_text(u, ci) : std::string{};
            if (t.empty())
            {
                u.rung = u.refs.empty() ? Rung::Pin : Rung::SymDb;
                u.reason = "no safe mnemonic form";
            }
            else
            {
                text[i] = {t};
            }
        }
        if (u.rung == Rung::Pin)
        {
            std::string t = pin_text(u);
            if (t.empty())
            {
                u.rung = Rung::SymDb;
            }
            else
            {
                text[i] = {t};
            }
        }
        if (u.rung == Rung::SymDb || u.rung == Rung::RawDb)
        {
            text[i] = symdb_lines(u, u.rung == Rung::RawDb);
        }
        if (u.rung == Rung::Mnemonic)
        {
            CfgInsn tmp;
            tmp.size = static_cast<uint8_t>(u.size);
            std::memcpy(tmp.bytes, in_.image->data() + u.lin, std::min<uint32_t>(u.size, 16));
            int lvl = 0;
            {
                // Inline of listing_uasm_cpu_level (prefix skip, 0F/66/67 → 386).
                size_t k = 0;
                while (k < tmp.size && (tmp.bytes[k] == 0x26 || tmp.bytes[k] == 0x2E ||
                                        tmp.bytes[k] == 0x36 || tmp.bytes[k] == 0x3E ||
                                        tmp.bytes[k] == 0xF0 || tmp.bytes[k] == 0xF2 ||
                                        tmp.bytes[k] == 0xF3))
                    ++k;
                const uint8_t op = k < tmp.size ? tmp.bytes[k] : 0;
                const uint8_t reg = (k + 1 < tmp.size) ? ((tmp.bytes[k + 1] >> 3) & 7) : 0;
                if (op == 0x66 || op == 0x67 || op == 0x0F ||
                    ((op == 0x8C || op == 0x8E) && (reg == 4 || reg == 5)))
                    lvl = 3;
                else if (op == 0x63)
                    lvl = 2;
                else if (op == 0x60 || op == 0x61 || op == 0x62 || op == 0x68 || op == 0x69 ||
                         op == 0x6A || op == 0x6B || (op >= 0x6C && op <= 0x6F) || op == 0xC0 ||
                         op == 0xC1 || op == 0xC8 || op == 0xC9)
                    lvl = 1;
                if (op >= 0xD8 && op <= 0xDF)
                    fpu = true;
            }
            cpu = std::max(cpu, lvl);
        }
    }
    // Symbolic db and pins may have added labels; recompute equates.
    {
        std::set<uint32_t> extra = labels_;
        collect_labels();
        labels_.insert(extra.begin(), extra.end());
        for (uint32_t lb : extra)
        {
            const int ui = unit_covering(lb);
            if (ui >= 0 && units_[static_cast<size_t>(ui)].code &&
                units_[static_cast<size_t>(ui)].lin != lb)
            {
                equs_[lb] = {units_[static_cast<size_t>(ui)].lin,
                             lb - units_[static_cast<size_t>(ui)].lin};
                labels_.insert(units_[static_cast<size_t>(ui)].lin);
            }
        }
    }

    std::string out;
    int line = 0;
    auto put = [&](std::string_view s)
    {
        out += s;
        out += '\n';
        ++line;
    };
    for (const std::string& h : header)
        put("; " + h);
    for (const auto& kv : equs_)
        put(std::format("{} equ <({}+{})>", lbl(kv.first), lbl(kv.second.first),
                        kv.second.second));
    // Pin macros actually used.
    if (!used_macros_.empty())
    {
        static const char* r16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
        static const char* r8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
        put("; ---- encoding-pin macros (forms UASM would encode differently)");
        put("@regnum macro r");
        for (int k = 0; k < 16; ++k)
        {
            put(std::format("  {} <r>,<{}>", k == 0 ? "IFIDNI" : "ELSEIFIDNI",
                            k < 8 ? r16[k] : r8[k - 8]));
            put(std::format("    exitm <{}>", k & 7));
        }
        put("  ENDIF");
        put("  .err <bad register>");
        put("  exitm <0>");
        put("endm");
        put("@regw macro r");
        for (int k = 0; k < 8; ++k)
        {
            put(std::format("  {} <r>,<{}>", k == 0 ? "IFIDNI" : "ELSEIFIDNI", r8[k]));
            put("    exitm <0>");
        }
        put("  ENDIF");
        put("  exitm <1>");
        put("endm");
        static const std::pair<const char*, unsigned> alu[] = {
            {"add", 0x00}, {"or", 0x08}, {"adc", 0x10}, {"sbb", 0x18}, {"and", 0x20},
            {"sub", 0x28}, {"xor", 0x30}, {"cmp", 0x38}, {"mov", 0x88}};
        if (used_macros_.count("rr"))
        {
            for (const auto& [nm, base] : alu)
            {
                put(std::format("{}_rm macro d, s", nm));
                put(std::format("  db {} + @regw(d), 0C0h + (@regnum(s) shl 3) + @regnum(d)",
                                uasm_hex(base)));
                put("endm");
                put(std::format("{}_r macro d, s", nm));
                put(std::format("  db {} + @regw(d), 0C0h + (@regnum(d) shl 3) + @regnum(s)",
                                uasm_hex(base + 2)));
                put("endm");
            }
        }
        for (const auto& [nm, base] : alu)
        {
            if (used_macros_.count(std::string("aw:") + nm))
            {
                put(std::format("{}_aw macro v", nm));
                put(std::format("  db {}", uasm_hex(base + 5)));
                put("  dw v");
                put("endm");
            }
            if (used_macros_.count(std::string("iw:") + nm))
            {
                put(std::format("{}_iw macro d, v", nm));
                put(std::format("  db 81h, 0C0h + ({} shl 3) + @regnum(d)", base >> 3));
                put("  dw v");
                put("endm");
            }
        }
    }
    put("_TEXT segment para public use16 'CODE'");
    put("assume cs:_TEXT, ds:nothing, es:nothing, ss:nothing");
    static const char* lvl[] = {".8086", ".186", ".286", ".386"};
    put(fpu ? (cpu >= 2 ? std::string(lvl[cpu]) : std::string(".286")) : std::string(lvl[cpu]));
    if (fpu)
        put(cpu >= 3 ? ".387" : ".287");
    put(in_.com ? "org 100h" : "org 0");
    if (in_.emit_lo != (in_.com ? 0x100u : 0u))
        put(std::format("org {}", uasm_hex(in_.emit_lo)));
    if (in_.mz_header && in_.file != nullptr)
    {
        const std::string h = header_lines();
        for (char c : h)
            if (c == '\n')
                ++line;
        out += h;
    }

    line_unit_.clear();
    for (size_t i = 0; i < units_.size(); ++i)
    {
        const EmitUnit& u = units_[i];
        if (u.code && static_cast<int64_t>(u.lin) == shift_at)
            put("    " + std::string(shift_text) + "\t; inserted by shift test");
        if (!u.code)
        {
            // Split data at labels and at relocated words.
            uint32_t p = u.lin;
            const uint32_t end = u.lin + u.size;
            while (p < end)
            {
                auto it = labels_.upper_bound(p);
                uint32_t q = end;
                if (it != labels_.end() && *it < end)
                    q = *it;
                auto rt = in_.reloc_at.upper_bound(p);
                if (rt != in_.reloc_at.end() && *rt < q)
                    q = *rt;
                auto ot = off_words_.upper_bound(p);
                if (ot != off_words_.end() && ot->first < q)
                    q = ot->first;
                if (shift_at > static_cast<int64_t>(p) && shift_at < static_cast<int64_t>(q))
                    q = static_cast<uint32_t>(shift_at);
                if (static_cast<int64_t>(p) == shift_at)
                    put("    " + std::string(shift_text) + "\t; inserted by shift test");
                if (labels_.count(p))
                {
                    if (frame_bases_.count(p) && p > in_.emit_lo && p % 16 == 0)
                        put("align 16");
                    put(lbl(p) + ":");
                }
                if (auto ow = off_words_.find(p);
                    ow != off_words_.end() && p + 2 <= end && labels_.count(p + 1) == 0)
                {
                    put(std::format("    dw {}\t; {:05X}: table word",
                                    off_expr(ow->second.target, ow->second.frame), p));
                    p += 2;
                    continue;
                }
                if (in_.reloc_at.count(p) && p + 2 <= end && labels_.count(p + 1) == 0)
                {
                    put(data_word(p));
                    p += 2;
                    continue;
                }
                std::string d = data_lines(p, q - p);
                // Tag the first line so the verifier can map this chunk.
                if (const size_t nl = d.find('\n'); nl != std::string::npos)
                    d.insert(nl, std::format("\t; {:05X}:", p));
                for (char c : d)
                    if (c == '\n')
                        ++line;
                out += d;
                p = q;
            }
            continue;
        }
        if (labels_.count(u.lin))
        {
            if (frame_bases_.count(u.lin) && u.lin > in_.emit_lo && u.lin % 16 == 0)
                put("align 16");
            put(lbl(u.lin) + ":");
        }
        const uint8_t* b = in_.image->data() + u.lin;
        std::string bytes;
        for (uint32_t k = 0; k < u.size; ++k)
            bytes += std::format("{}{:02X}", k ? " " : "", b[k]);
        const std::string dec = u.decoded;
        for (size_t j = 0; j < text[i].size(); ++j)
        {
            std::string ln = "    " + text[i][j];
            if (j == 0)
            {
                ln += std::format("\t; {:05X}: {}", u.lin, bytes);
                if (u.rung != Rung::Mnemonic)
                    ln += "  " + dec;
            }
            line_unit_[line + 1] = i;
            put(ln);
        }
    }
    if (labels_.count(n))
        put(lbl(n) + ":");
    if (in_.mz_header && in_.file != nullptr && tail_len_ != 0)
    {
        // File tail past the load image (overlay, debug info), verbatim.
        const std::vector<uint8_t>& f = *in_.file;
        const uint32_t from = in_.hdr_len + n;
        bool first = true;
        for (uint32_t p = from; p < f.size();)
        {
            uint32_t q = p;
            while (q < f.size() && f[q] == f[p])
                ++q;
            std::string ln;
            if (q - p >= 8)
            {
                ln = std::format("    db {} dup({})", q - p, uasm_hex(f[p]));
                p = q;
            }
            else
            {
                const uint32_t r = std::min<uint32_t>(static_cast<uint32_t>(f.size()), p + 16);
                std::string row;
                for (uint32_t k = p; k < r; ++k)
                    row += (k > p ? ", " : "") + uasm_hex(f[k]);
                ln = "    db " + row;
                p = r;
            }
            if (first)
            {
                ln += std::format("\t; {:05X}: file tail", n);
                first = false;
            }
            put(ln);
        }
    }
    put("_TEXT ends");
    if (labels_.count(in_.entry) && in_.entry >= in_.emit_lo && in_.entry < n)
        put("end " + lbl(in_.entry));
    else
        put("end");
    return out;
}

} // namespace dx

#endif // DX_EMIT_UASM_H
