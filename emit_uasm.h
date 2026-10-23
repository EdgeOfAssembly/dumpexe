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

#include "int_annotate.h"
#include <algorithm>
#include <array>
#include <cctype>
#include "pair_table.h"
#include <cstdint>
#include <format>
#include <functional>
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
    /// U2: label NUL-terminated printable runs found in data as cstr_.
    bool scan_cstrings = false;
    /// Generic jump tables: hint `table ADDR N [near|far]` (linear, count, far).
    struct TableHint
    {
        uint32_t lin = 0;
        uint32_t count = 0;
        bool far = false;
    };
    std::vector<TableHint> table_hints;
    /// Generic jump tables: roots the previous round seeded (non-sticky).
    std::set<uint32_t> jt_prev;
    /// Targets of non-tentative entries of the previous round -> table bases.
    std::map<uint32_t, std::set<uint32_t>> jt_prev_firm;
    /// Segment layout: when set, the U2 scan only looks at [cstr_lo, cstr_hi).
    uint32_t cstr_lo = 0;
    uint32_t cstr_hi = UINT32_MAX;
    /// Extra ranges [lo, hi) the scan also covers (far data segments).
    std::vector<std::pair<uint32_t, uint32_t>> cstr_extra;
    /// U3: look for the C startup `call X; push ax; call exit` and comment
    /// X as a possible _main (a hint only; the label is not renamed).
    bool hint_main = false;
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

    /**
     * @brief Shape key for the verified-pair table (§10.10): fixed bytes in hex,
     *        displacement and immediate replaced by a size and a value class.
     *        Empty for units with references or that do not decode.
     */
    std::string pair_key(const EmitUnit& u);
    /** @brief True when @p u may keep its mnemonic without an assembler. */
    bool pair_verified(const EmitUnit& u);
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
    void scan_cstrings();
    void find_main_hint();
    int64_t mask_bound(const std::vector<size_t>& code, size_t j, uint8_t rm);
    // Generic jump/call tables (see add_generic_table).
    void jt_prepare();
    bool jt_clean(uint32_t t, uint32_t fr, int* insns = nullptr, int* known_hits = nullptr,
                  bool* anchored = nullptr) const;
    bool add_generic_table(const std::vector<size_t>& code, size_t j);
    /** @brief Index range facts for an indexed jmp/call (see jt_index_range). */
    struct JtIndexRange
    {
        int64_t count = -1;   ///< entries a dominating compare guard allows, or -1
        int64_t mask = -1;    ///< entries-1 an `and` mask allows, or -1
        bool byte_idx = false; ///< the index register holds a zero-extended byte
        bool doubled = false;  ///< scaled by 2 between the guard (or source) and the jump
        bool rescaled = false; ///< scaled more than once (stride above one slot): only slot 0 is proven
        int64_t first = 0;     ///< first reachable slot (add bias, inverted guard)
        bool legacy = false;   ///< count is the pre-n8 cap (voided guard fallback)
        bool zero_only = false; ///< ja/jne on an `and`'s flags: only index 0 reaches the jump
    };
    int64_t jt_legacy_count(const std::vector<size_t>& code, size_t j) const;
    JtIndexRange jt_index_range(const std::vector<size_t>& code, size_t j, uint8_t r0, uint8_t r1, int unit_shift = 1) const;
    void jt_table(uint32_t T, int64_t fr, int64_t count, bool far, bool hinted, size_t unit_idx, uint8_t disp_off,
                  bool guarded = false, int64_t first = 0);
    void jt_direct_targets(const std::vector<size_t>& code);
    bool jt_ready_ = false;
    std::set<uint32_t> jt_bounds_;   ///< code starts, labels, data-load addresses
    std::set<uint32_t> jt_loads_;    ///< addresses read by direct-address loads
    std::set<uint32_t> jt_imm_;      ///< addresses named by pointer-register immediate loads
    std::set<uint32_t> jt_called_;   ///< targets of direct near calls (function heads)
    std::set<uint32_t> jt_xref_;     ///< entry point, direct branch/call and far-pointer targets in code
    std::map<uint32_t, std::set<uint32_t>> jt_firm_; ///< non-tentative entry target -> table bases
    bool jt_imm_is_pointer(size_t i, uint8_t reg) const;
    std::set<uint32_t> jt_weak_;     ///< instructions whose block head is below Derived
    bool jt_is_code(uint32_t lin) const;
    std::set<uint32_t> jt_roots_;    ///< valid table entries / promoted targets
    size_t n_jt_ = 0, n_jt_entries_ = 0, n_jt_holes_ = 0, n_jt_far_unres_ = 0, n_jt_direct_ = 0;
    std::vector<std::string> jt_notes_;
    bool contiguous_units(size_t a, size_t b) const { return units_[a].lin + units_[a].size == units_[b].lin; }
    bool exit_like(uint32_t y) const;
    std::set<uint32_t> cstr_scanned_;
    int64_t main_hint_ = -1;
    int64_t main_hint_exit_ = -1;
    void type_string(uint32_t lin, uint32_t len, const char* prefix);
    template <class InData>
    void add_startup_roots(const std::vector<size_t>& code, InData&& in_data);
    size_t n_init_roots_ = 0;
    size_t n_vector_roots_ = 0;
    size_t n_ptr_roots_ = 0;
    size_t n_far_vec_roots_ = 0;
    size_t n_cb_roots_ = 0;
    std::vector<std::pair<uint32_t, int32_t>> cb_seeds_; // (target, frame) seeded by add_callback_args
    void add_callback_args(const std::vector<size_t>& code);
    std::vector<std::pair<uint32_t, int32_t>> want_far_roots_;
    template <class FrameOk, class InData>
    void add_pointer_refs(const std::vector<size_t>& code, FrameOk&& frame_ok, InData&& in_data);
    std::map<uint32_t, uint32_t> str_len_;          ///< P4 typed strings
    std::map<uint32_t, std::string> auto_names_;    ///< P4 names (hints win)
    size_t n_pointers_ = 0;
    std::string data_lines(uint32_t lin, uint32_t len);
    std::string hex_lines(uint32_t lin, uint32_t len);
    std::set<uint32_t> call_targets_;   ///< R4: near call targets (func_ labels)
    void name_call_targets();
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
public:
    /// Readability counters of the last render (R1..R4).
    size_t r_ascii_ = 0, r_hibit_ = 0, r_int21_ = 0, r_funcs_ = 0;
private:
    std::string header_lines();
    std::string data_word(uint32_t at);
    std::string string_text(uint32_t lin, uint32_t len) const;

public:
    /** @brief Decoded instructions dropped because they straddle a segment base. */
    size_t straddled() const { return straddled_.size(); }
    /// Label text: a hinted name, else L%05X.
    std::string lbl(uint32_t lin) const
    {
        auto it = in_.label_names.find(lin);
        if (it != in_.label_names.end())
            return it->second;
        auto a = auto_names_.find(lin);
        return a != auto_names_.end() ? a->second : uasm_label(lin);
    }
    /// P4: words in data printed as near offsets (jump-table entries).
    const std::map<uint32_t, OffWord>& off_words() const { return off_words_; }
    /// Inferred DGROUP base (mov r16, seg X; mov ds, r16), or -1.
    int64_t dgroup() const { return dgroup_; }
    /// P5: bounded-table targets that the graph did not decode.
    const std::vector<uint32_t>& want_roots() const { return want_roots_; }
    size_t value_tables() const { return n_tables_; }
    /// Generic jump tables: all currently valid entries (decoded or not).
    const std::set<uint32_t>& jt_roots() const { return jt_roots_; }
    const std::map<uint32_t, std::set<uint32_t>>& jt_firm() const { return jt_firm_; }
    size_t jt_tables() const { return n_jt_; }
    size_t jt_entries() const { return n_jt_entries_; }
    size_t jt_holes() const { return n_jt_holes_; }
    size_t jt_far_unresolved() const { return n_jt_far_unres_; }
    size_t jt_direct() const { return n_jt_direct_; }
    const std::vector<std::string>& jt_notes() const { return jt_notes_; }
    size_t value_strings() const { return n_strings_; }
    size_t value_pointers() const { return n_pointers_; }
    /// Coverage: entries asked for from Borland init/exit tables and from
    /// INT 21h/25h handlers set with DS = CS (see add_startup_roots).
    size_t init_roots() const { return n_init_roots_; }
    size_t vector_roots() const { return n_vector_roots_; }
    size_t ptr_roots() const { return n_ptr_roots_; }
    /// FP emulator coverage: INT 21h/25h handlers whose DS is a relocated
    /// segment (linear, frame), still in data.
    size_t far_vector_roots() const { return n_far_vec_roots_; }
    /// Code pointers passed to a callee that calls through that parameter.
    size_t callback_roots() const { return n_cb_roots_; }
    const std::vector<std::pair<uint32_t, int32_t>>& callback_seeds() const { return cb_seeds_; }
    const std::vector<std::pair<uint32_t, int32_t>>& want_far_roots() const { return want_far_roots_; }
    size_t typed_strings() const { return str_len_.size() - cstr_scanned_.size(); }
    /// U2: NUL-terminated strings found by the data scan (not by a reference).
    size_t scanned_cstrings() const { return cstr_scanned_.size(); }
    /// U3: possible _main (linear) and the exit call after it, or -1.
    int64_t main_hint() const { return main_hint_; }
    int64_t main_hint_exit() const { return main_hint_exit_; }
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
    {
        std::vector<size_t> jc;
        for (size_t i = 0; i < units_.size(); ++i)
            if (units_[i].code && units_[i].rung != Rung::RawDb)
                jc.push_back(i);
        jt_direct_targets(jc);
    }
    if (in_.scan_cstrings)
        scan_cstrings();
    if (in_.hint_main)
        find_main_hint();
}

/**
 * @brief F5: reject short runs that look like code or table bytes.
 *
 * Runs of 8 bytes or more pass. A shorter run passes only if:
 *  - every byte is a letter, digit, blank (space, TAB, CR, LF) or text
 *    punctuation `.,:;!?'"-%()/\_+=*#&@<>[]$^`;
 *  - each maximal letter run is all upper case, or CamelCase: split before
 *    each upper-case letter that follows a lower-case one, every part is one
 *    capital followed by lower case, except that the first part may be all
 *    lower case of two or more letters (`ChDir`, `getDate`, `error`); a
 *    lone letter is fine (`-w-`);
 *  - it is not a period-2 repetition (`dJdJdJ`, `tMtMtM`, `r0r0r0`).
 * printf conversions (`%s`, `%-5.2lf`, `%*d`, `%%`) are read as one blank
 * each before these tests, and a run with one skips the repetition test,
 * so `%s%s%s` passes.
 * `$RPj`, `6kIj`, `}SDH`, `pNzK` fail; `TEMP`, `(null)`, `ChDir`, `READ$`,
 * `^PgUp` and `XXXXXX` pass.
 */
inline bool cstr_plausible(const uint8_t* s, size_t len)
{
    if (len >= 8)
        return true;
    // printf conversions (`%s`, `%-08.3lX`, `%*d`, `%%`) count as one
    // blank each; a run with one passes the period-2 test (`%s%s%s`).
    uint8_t buf[8];
    size_t bl = 0;
    bool spec = false;
    for (size_t i = 0; i < len;)
    {
        if (s[i] == '%')
        {
            size_t k = i + 1;
            if (k < len && s[k] == '%')
            {
                buf[bl++] = ' ';
                spec = true;
                i = k + 1;
                continue;
            }
            while (k < len && std::string_view("-+ #0").find(static_cast<char>(s[k])) != std::string_view::npos)
                ++k;
            if (k < len && s[k] == '*')
                ++k;
            else
                while (k < len && std::isdigit(s[k]))
                    ++k;
            if (k < len && s[k] == '.')
            {
                ++k;
                if (k < len && s[k] == '*')
                    ++k;
                else
                    while (k < len && std::isdigit(s[k]))
                        ++k;
            }
            if (k < len && std::string_view("hlLNF").find(static_cast<char>(s[k])) != std::string_view::npos)
                ++k;
            if (k < len && std::string_view("diouxXcsfeEgGpn").find(static_cast<char>(s[k])) != std::string_view::npos)
            {
                buf[bl++] = ' ';
                spec = true;
                i = k + 1;
                continue;
            }
        }
        buf[bl++] = s[i++];
    }
    s = buf;
    len = bl;
    static constexpr std::string_view punct = ".,:;!?'\"-%()/\\_+=*#&@<>[]$^";
    for (size_t i = 0; i < len; ++i)
    {
        const uint8_t c = s[i];
        if (std::isalnum(c) || c == ' ' || c == 9 || c == 10 || c == 13)
            continue;
        if (punct.find(static_cast<char>(c)) == std::string_view::npos)
            return false;
    }
    for (size_t i = 0; i < len;)
    {
        if (!std::isalpha(s[i]))
        {
            ++i;
            continue;
        }
        size_t j = i;
        bool any_lower = false;
        while (j < len && std::isalpha(s[j]))
            any_lower |= std::islower(s[j++]) != 0;
        if (any_lower && j - i > 1)
        {
            // Parts: [i, k) split before an upper case letter after a lower one.
            size_t k = i;
            bool first = true;
            while (k < j)
            {
                size_t e = k + 1;
                while (e < j && !(std::isupper(s[e]) && std::islower(s[e - 1])))
                    ++e;
                const size_t plen = e - k;
                bool lower_tail = true;
                for (size_t m = k + 1; m < e; ++m)
                    lower_tail &= std::islower(s[m]) != 0;
                const bool cap = std::isupper(s[k]) && plen >= 2 && lower_tail;
                const bool low = first && std::islower(s[k]) && plen >= 2 && lower_tail;
                if (!cap && !low)
                    return false;
                first = false;
                k = e;
            }
        }
        i = j;
    }
    if (len >= 6 && !spec)
    {
        bool rep = true;
        for (size_t i = 2; i < len && rep; ++i)
            rep = s[i] == s[i - 2];
        if (rep && s[0] != s[1])
            return false;
    }
    return true;
}

/**
 * @brief U2: type NUL-terminated text in data as `cstr_` strings.
 *
 * A run of at least 4 printable bytes (or TAB/LF/CR), starting at a data
 * unit start or after a non-text byte and ending in a 0 byte, with at least
 * 3 letters. Runs already typed by a reference, or crossing a relocated or
 * table word, are left alone (type_string checks the latter).
 */
inline void UasmEmitter::scan_cstrings()
{
    const std::vector<uint8_t>& img = *in_.image;
    auto text = [](uint8_t c) { return (c >= 0x20 && c < 0x7F) || c == 9 || c == 10 || c == 13; };
    for (const EmitUnit& u : units_)
    {
        if (u.code)
            continue;
        std::vector<std::pair<uint32_t, uint32_t>> wins = in_.cstr_extra;
        wins.emplace_back(in_.cstr_lo, in_.cstr_hi);
        for (const auto& [wlo, whi] : wins)
        {
        if (u.lin + u.size <= wlo || u.lin >= whi)
            continue;
        const uint32_t end = std::min(u.lin + u.size, whi);
        uint32_t p = std::max(u.lin, wlo);
        while (p < end)
        {
            if (!text(img[p]) || (p > u.lin && text(img[p - 1])))
            {
                ++p;
                continue;
            }
            uint32_t q = p;
            size_t alpha = 0;
            while (q < end && text(img[q]))
            {
                if (std::isalpha(img[q]))
                    ++alpha;
                ++q;
            }
            if (q < end && img[q] == 0 && q - p >= 4 && alpha >= 3 && cstr_plausible(img.data() + p, q - p))
            {
                // F1: no byte of a relocated (or table) word may lie in the
                // run or its NUL; a word starting at p-1 covers p.
                bool clash = false;
                for (uint32_t k = (p > 0 ? p - 1 : p); k <= q; ++k)
                    if (in_.reloc_at.count(k) || off_words_.count(k))
                        clash = true;
                for (const auto& [sl, len] : str_len_)
                    if (sl < q + 1 && sl + len > p)
                        clash = true;
                if (!clash)
                {
                    type_string(p, q + 1 - p, "cstr");
                    if (str_len_.count(p))
                        cstr_scanned_.insert(p);
                }
            }
            p = q;
        }
        }
    }
}

/**
 * @brief U3: the C startup calls main, then passes its return value to exit:
 *        `call X` / `push ax` / `call Y` (near or far). The first such run
 *        within 512 bytes after the entry, with X a decoded head and Y a
 *        known exit (see exit_like), makes X a possible _main. Only a
 *        comment is printed; nothing is asserted.
 */
/**
 * @brief F2: Y is a known exit when no path from Y reaches a return, or a
 *        path reaches DOS terminate (`mov ah, 4Ch` or `mov ax, 4Cxxh`, then
 *        `int 21h` in the same straight run). Walks decoded units through
 *        fall-through, rel jumps, both jcc arms and near calls, three call
 *        levels deep. A unit outside the decoded code, an indirect jump or a
 *        walk budget overrun counts as "may return" with no terminate seen.
 */
inline bool UasmEmitter::exit_like(uint32_t y) const
{
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    bool terminate = false;
    size_t budget = 4096;
    // Returns true when some path from @p h may return to its caller.
    std::function<bool(uint32_t, int)> may_return = [&](uint32_t h, int depth) -> bool {
        std::set<uint32_t> seen;
        std::vector<uint32_t> work{h};
        bool ret = false;
        while (!work.empty())
        {
            uint32_t p = work.back();
            work.pop_back();
            bool ah4c = false;
            while (true)
            {
                if (budget == 0 || p >= n)
                    return true;
                --budget;
                if (!seen.insert(p).second)
                    break;
                const int ui = unit_at(p);
                if (ui < 0 || !units_[static_cast<size_t>(ui)].code)
                    return true;
                const EmitUnit& u = units_[static_cast<size_t>(ui)];
                const uint8_t* b = img.data() + u.lin;
                const uint32_t nx = u.lin + u.size;
                // Near targets wrap inside the unit's 64 KiB frame.
                const auto fit = frame_of_.find(u.lin);
                const uint32_t fr = fit != frame_of_.end() && fit->second >= 0 && static_cast<uint32_t>(fit->second) <= u.lin
                                        ? static_cast<uint32_t>(fit->second)
                                        : (u.lin & ~0xFFFFu);
                auto near = [&](int32_t rel) { return fr + ((nx - fr + static_cast<uint32_t>(rel)) & 0xFFFFu); };
                if ((u.size == 2 && b[0] == 0xB4 && b[1] == 0x4C) || (u.size == 3 && b[0] == 0xB8 && b[2] == 0x4C))
                {
                    ah4c = true;
                    p = nx;
                    continue;
                }
                if (u.size == 2 && b[0] == 0xCD && b[1] == 0x21 && ah4c)
                {
                    terminate = true;
                    break;
                }
                const uint8_t op = b[0];
                if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA || op == 0xCF)
                {
                    ret = true;
                    break;
                }
                if (op == 0xEB && u.size == 2)
                {
                    p = near(static_cast<int8_t>(b[1]));
                    continue;
                }
                if (op == 0xE9 && u.size == 3)
                {
                    p = near(static_cast<int16_t>(b[1] | (b[2] << 8)));
                    continue;
                }
                if (((op >= 0x70 && op <= 0x7F) || (op >= 0xE0 && op <= 0xE3)) && u.size == 2)
                {
                    work.push_back(near(static_cast<int8_t>(b[1])));
                    p = nx;
                    continue;
                }
                if (op == 0xE8 && u.size == 3)
                {
                    const uint32_t t = near(static_cast<int16_t>(b[1] | (b[2] << 8)));
                    if (depth < 3 && !may_return(t, depth + 1))
                        break; // the callee never comes back: path ends
                    if (terminate)
                        return true;
                    p = nx;
                    continue;
                }
                if (op == 0x9A && u.size == 5 && in_.reloc_at.count(u.lin + 3))
                {
                    const uint32_t t = (static_cast<uint32_t>(b[3] | (b[4] << 8)) << 4) + (b[1] | (b[2] << 8));
                    if (depth < 3 && !may_return(t, depth + 1))
                        break;
                    if (terminate)
                        return true;
                    p = nx;
                    continue;
                }
                if (op == 0xFF && u.size >= 2 && (((b[1] >> 3) & 7) == 4 || ((b[1] >> 3) & 7) == 5))
                    return true; // indirect jump: unknown
                if (u.size == 2 && b[0] == 0xCD)
                    ah4c = false;
                p = nx;
            }
            if (terminate)
                return true;
        }
        return ret;
    };
    const bool r = may_return(y, 0);
    return terminate || !r;
}

inline void UasmEmitter::find_main_hint()
{
    const std::vector<uint8_t>& img = *in_.image;
    for (size_t i = 0; i + 2 < units_.size(); ++i)
    {
        const EmitUnit& a = units_[i];
        const EmitUnit& b = units_[i + 1];
        const EmitUnit& c = units_[i + 2];
        // F2: the startup's main call sits near the entry.
        if (!a.code || !b.code || !c.code || a.lin < in_.entry || a.lin >= in_.entry + 0x200)
            continue;
        if (a.size != 3 || img[a.lin] != 0xE8 || b.lin != a.lin + 3 || b.size != 1 || img[b.lin] != 0x50 ||
            c.lin != b.lin + 1)
            continue;
        if (!((c.size == 3 && img[c.lin] == 0xE8) || (c.size == 5 && img[c.lin] == 0x9A)))
            continue;
        const int16_t rel = static_cast<int16_t>(img[a.lin + 1] | (img[a.lin + 2] << 8));
        const int64_t x = static_cast<int64_t>(a.lin) + 3 + rel;
        if (x < 0 || unit_at(static_cast<uint32_t>(x)) < 0 || !units_[static_cast<size_t>(unit_at(static_cast<uint32_t>(x)))].code)
            continue;
        // F2: the exit call must not return (or must reach DOS terminate).
        uint32_t y = 0;
        if (img[c.lin] == 0xE8)
        {
            const auto fit = frame_of_.find(c.lin);
            const uint32_t fr = fit != frame_of_.end() && fit->second >= 0 && static_cast<uint32_t>(fit->second) <= c.lin
                                    ? static_cast<uint32_t>(fit->second)
                                    : (c.lin & ~0xFFFFu);
            y = fr + ((c.lin + 3 - fr + static_cast<uint32_t>(static_cast<int16_t>(img[c.lin + 1] | (img[c.lin + 2] << 8)))) & 0xFFFFu);
        }
        else if (in_.reloc_at.count(c.lin + 3))
            y = (static_cast<uint32_t>(img[c.lin + 3] | (img[c.lin + 4] << 8)) << 4) + (img[c.lin + 1] | (img[c.lin + 2] << 8));
        else
            continue;
        if (!exit_like(y))
            continue;
        main_hint_ = x;
        main_hint_exit_ = c.lin;
        return;
    }
}

/**
 * @brief P4 value references (valueprop-lite).
 *
 * Two proven patterns, each all-or-nothing:
 *  - bounded jump table: a range guard on the index (`cmp bx|bl|al.., N`
 *    with ja/jae/jg/jge falling through or jbe/jb/jle/jl taken, dominating
 *    the jump; see jt_index_range) before `jmp word ptr cs:[bx+T]` (or
 *    `[bx+T]` in a COM).
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
        // Jump table: [2E] FF A7 lo hi (also a call table, FF 97, with CS).
        const bool csp = u.size == 5 && b[0] == 0x2E && b[1] == 0xFF &&
                         (b[2] == 0xA7 || b[2] == 0x97 || b[2] == 0xA4 || b[2] == 0xA5 || b[2] == 0xA6 ||
                          b[2] == 0x94 || b[2] == 0x95 || b[2] == 0x96);
        const bool nop = u.size == 4 && b[0] == 0xFF && b[1] == 0xA7;
        const size_t jt_n0 = n_tables_, jt_w0 = want_roots_.size(), jt_f0 = want_far_roots_.size();
        if ((csp && (pure_com || frame_ok(frame_of_[u.lin]))) || (nop && pure_com))
        {
            const uint32_t k = csp ? 3 : 2;
            const int64_t fr = pure_com ? 0 : frame_of_[u.lin];
            const uint32_t disp = b[k] | (b[k + 1] << 8);
            // Bound: a dominating range guard on the index register (n8;
            // see jt_index_range). Only the [bx+T] form is scanned here.
            int64_t count = -1, first = 0;
            if (!csp || (b[2] & 7) == 7)
            {
                jt_prepare();
                const JtIndexRange ir = jt_index_range(code, j, 3, 0xFF);
                count = ir.count;
                first = ir.first;
            }
            // Value-mask bound (FP emulator; see mask_bound). It is a proven
            // upper bound, so with a compare bound too the smaller one wins.
            if (csp)
            {
                const int64_t mb = mask_bound(code, j, static_cast<uint8_t>(b[2] & 7));
                if (mb > 0 && (count < 0 || mb < count))
                    count = mb;
            }
            if (count > 0 && count <= 256)
            {
                const uint32_t T = static_cast<uint32_t>(fr + disp);
                bool ok = in_data(T, static_cast<uint32_t>(count * 2));
                std::vector<uint32_t> tg;
                std::vector<uint32_t> undecoded;
                if (first >= count)
                    ok = false;
                for (int64_t e = first; ok && e < count; ++e)
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
                if (ok)
                    for (uint32_t t : tg)
                        jt_firm_[t].insert(T); // a bounded table's entries are non-tentative
                if (ok && !undecoded.empty())
                {
                    // Bounded table with entries in data: ask for a rebuild
                    // with these as entries (same frame as the entry only).
                    const auto ef = frame_of_.find(in_.entry);
                    if (ef != frame_of_.end() && ef->second == fr)
                        want_roots_.insert(want_roots_.end(), undecoded.begin(), undecoded.end());
                    else if (!pure_com && fr >= 0)
                        // Another code segment: seeded in its own frame.
                        for (uint32_t t : undecoded)
                        {
                            const std::pair<uint32_t, int32_t> fs{t, static_cast<int32_t>(fr)};
                            if (std::find(want_far_roots_.begin(), want_far_roots_.end(), fs) == want_far_roots_.end())
                                want_far_roots_.push_back(fs);
                        }
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
                        off_words_[T + static_cast<uint32_t>((e + first) * 2)] = {tg[e], static_cast<uint32_t>(fr)};
                    auto_names_.emplace(T, std::format("jt_{:05X}", T));
                    ++n_tables_;
                }
            }
            if (n_tables_ == jt_n0 && want_roots_.size() == jt_w0 && want_far_roots_.size() == jt_f0)
                (void)add_generic_table(code, j);
            continue;
        }
        if (add_generic_table(code, j))
            continue;
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
            uint32_t dpos = t;
            for (uint32_t q = t; q < n && q < t + 4096; ++q)
                if (img[q] == '$')
                {
                    dollar = true;
                    dpos = q;
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
            type_string(t, dpos + 1 - t, "str");
        }
    }
    add_pointer_refs(code, frame_ok, in_data);
    add_startup_roots(code, in_data);
    add_callback_args(code);
}

/**
 * @brief Type [@p lin, lin+len) as a string and name it, when it lies in one
 *        data unit and has no relocated word.
 */
inline void UasmEmitter::type_string(uint32_t lin, uint32_t len, const char* prefix)
{
    const int ui = unit_covering(lin);
    if (ui < 0 || units_[static_cast<size_t>(ui)].code)
        return;
    const EmitUnit& d = units_[static_cast<size_t>(ui)];
    if (lin + len > d.lin + d.size)
        return;
    for (uint32_t k = 0; k < len; ++k)
        if (in_.reloc_at.count(lin + k) || off_words_.count(lin + k))
            return;
    str_len_[lin] = len;
    auto_names_.emplace(lin, std::format("{}_{:05X}", prefix, lin));
}

/**
 * @brief P4 pointer cases.
 *
 * S06: `mov si|di|bx, T` then `mov R, [base+d]` then `call|jmp R`, all in one
 * contiguous run: the word at T+d is a code pointer. When its target is a
 * decoded head, T becomes an offset and the word a `dw` offset (named
 * ptrtab_); when the target is still data it is seeded (P5 fixpoint).
 *
 * S09 (consumer rule): `mov ax, T` / `push ax` / `call near F` where F
 * dereferences its first stack argument (`mov bx, [bp+4]` within its first
 * eight instructions) and T is a NUL-terminated printable string of at
 * least three characters in data: T becomes an offset (named cstr_).
 *
 * COM only (DS = CS = frame 0), like the other value rules without a proven
 * DS in an MZ.
 */
template <class FrameOk, class InData>
inline void UasmEmitter::add_pointer_refs(const std::vector<size_t>& code, FrameOk&& frame_ok, InData&& in_data)
{
    if (!in_.com)
        return;
    (void)frame_ok;
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    auto contiguous = [&](size_t a, size_t b) {
        for (size_t k = a; k < b; ++k)
            if (units_[code[k]].lin + units_[code[k]].size != units_[code[k + 1]].lin)
                return false;
        return true;
    };
    auto has_ref = [](const EmitUnit& u) { return !u.refs.empty(); };
    for (size_t j = 0; j < code.size(); ++j)
    {
        EmitUnit& u = units_[code[j]];
        const uint8_t* b = img.data() + u.lin;
        // S06.
        if (u.size == 3 && (b[0] == 0xBE || b[0] == 0xBF || b[0] == 0xBB) && !has_ref(u))
        {
            const uint8_t base_rm = b[0] == 0xBE ? 4 : (b[0] == 0xBF ? 5 : 7);
            const uint32_t T = b[1] | (b[2] << 8);
            for (size_t k = j + 1; k < code.size() && k <= j + 4; ++k)
            {
                const EmitUnit& ld = units_[code[k]];
                const uint8_t* lb = img.data() + ld.lin;
                if (!contiguous(j, k))
                    break;
                if (!(ld.size == 3 && lb[0] == 0x8B && (lb[1] >> 6) == 1 && (lb[1] & 7) == base_rm) &&
                    !(ld.size == 2 && lb[0] == 0x8B && (lb[1] >> 6) == 0 && (lb[1] & 7) == base_rm &&
                      base_rm != 6))
                    continue;
                const uint32_t d = ld.size == 3 ? lb[2] : 0;
                const uint8_t R = (lb[1] >> 3) & 7;
                bool used = false;
                for (size_t c = k + 1; c < code.size() && c <= k + 3 && !used; ++c)
                {
                    if (!contiguous(k, c))
                        break;
                    const EmitUnit& cu = units_[code[c]];
                    const uint8_t* cb = img.data() + cu.lin;
                    if (cu.size == 2 && cb[0] == 0xFF && cb[1] == static_cast<uint8_t>(0xC0 | (2 << 3) | R))
                        used = true;
                    else if (cu.size == 2 && cb[0] == 0xFF && cb[1] == static_cast<uint8_t>(0xC0 | (4 << 3) | R))
                        used = true;
                }
                if (!used)
                    break;
                const uint32_t at = T + d;
                if (!in_data(T, 1) || !in_data(at, 2) || in_.reloc_at.count(at))
                    break;
                const uint32_t tgt = img[at] | (img[at + 1] << 8);
                if (tgt < in_.emit_lo || tgt >= n)
                    break;
                const int ti = unit_at(tgt);
                if (ti >= 0 && units_[static_cast<size_t>(ti)].code)
                {
                    InsnRef r;
                    r.kind = RefKind::Off;
                    r.off = 1;
                    r.size = 2;
                    r.target = T;
                    r.frame = 0;
                    u.refs.push_back(r);
                    off_words_[at] = {tgt, 0};
                    auto_names_.emplace(T, std::format("ptrtab_{:05X}", T));
                    ++n_pointers_;
                }
                else if (unit_covering(tgt) >= 0 && !units_[static_cast<size_t>(unit_covering(tgt))].code)
                {
                    want_roots_.push_back(tgt);
                }
                break;
            }
            continue;
        }
        // S09: B8 iw / 50 / E8 rel16.
        if (u.size == 3 && b[0] == 0xB8 && !has_ref(u) && j + 2 < code.size() && contiguous(j, j + 2))
        {
            const EmitUnit& p = units_[code[j + 1]];
            const EmitUnit& c = units_[code[j + 2]];
            if (!(p.size == 1 && img[p.lin] == 0x50 && c.size == 3 && img[c.lin] == 0xE8))
                continue;
            const uint32_t F = static_cast<uint32_t>(c.lin + 3 + static_cast<int16_t>(img[c.lin + 1] | (img[c.lin + 2] << 8))) & 0xFFFFu;
            const int fi = unit_at(F);
            if (fi < 0 || !units_[static_cast<size_t>(fi)].code)
                continue;
            bool deref = false;
            for (size_t q = static_cast<size_t>(fi), cnt = 0; q < units_.size() && cnt < 8 && units_[q].code; ++q, ++cnt)
            {
                const uint8_t* qb = img.data() + units_[q].lin;
                // mov bx|si|di, [bp+4]
                if (units_[q].size == 3 && qb[0] == 0x8B && qb[2] == 0x04 &&
                    (qb[1] == 0x5E || qb[1] == 0x76 || qb[1] == 0x7E))
                    deref = true;
            }
            if (!deref)
                continue;
            const uint32_t T = b[1] | (b[2] << 8);
            if (!in_data(T, 1))
                continue;
            uint32_t q = T;
            while (q < n && q < T + 256 && img[q] >= 0x20 && img[q] < 0x7F)
                ++q;
            if (q >= n || img[q] != 0 || q - T < 3)
                continue;
            InsnRef r;
            r.kind = RefKind::Off;
            r.off = 1;
            r.size = 2;
            r.target = T;
            r.frame = 0;
            u.refs.push_back(r);
            ++n_strings_;
            type_string(T, q + 1 - T, "cstr");
        }
    }
}

/**
 * @brief Coverage: proven entries the static graph cannot see.
 *
 *  - Borland C startup init/exit tables. Decoded `mov si, S` / `mov di, E` /
 *    `call P`, where P walks 6-byte records (`add bx, 6` within its first 24
 *    instructions and an `es:[bx]` operand). DS is known (COM: 0; MZ: the
 *    inferred DGROUP) and [S, E) lies in data. Each record is
 *    {type, priority, offset, segment}: type 0 is a near offset in the
 *    entry frame; type 1 is far, and its segment word must be relocated and
 *    equal to the entry frame. Any other type rejects the whole table.
 *  - INT 21h AH=25h (set vector) with DS = CS: within the contiguous run of
 *    at most 6 instructions ending in `int 21h`, `mov ax, 25xxh` or
 *    `mov ah, 25h`, `push cs`/`pop ds` or `mov r, cs`/`mov ds, r`, and
 *    `mov dx, imm` after the DS load, with nothing else in the run. The
 *    handler is the run's frame plus imm.
 *  - code pointer cells: `mov word ptr ds:[X], imm` stores into a cell
 *    called by `call word ptr ds:[X]`, all in one code frame (see below).
 * Targets that sit in undecoded data are asked for as fixpoint entries
 * (want_roots); entries outside the entry frame are not used.
 */
template <class InData>
inline void UasmEmitter::add_startup_roots(const std::vector<size_t>& code, InData&& in_data)
{
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    const auto efit = frame_of_.find(in_.entry);
    if (efit == frame_of_.end() || efit->second < 0)
        return;
    const uint32_t ef = static_cast<uint32_t>(efit->second);
    auto want = [&](uint32_t t) -> bool {
        if (t < in_.emit_lo || t >= n || t < ef || t - ef > 0xFFFFu)
            return false;
        const int ci = unit_covering(t);
        if (ci < 0 || units_[static_cast<size_t>(ci)].code)
            return false;
        for (const auto& [lo, hi] : in_.force_data)
            if (t >= lo && t < hi)
                return false;
        want_roots_.push_back(t);
        return true;
    };
    auto contiguous = [&](size_t a, size_t b) {
        for (size_t k = a; k < b; ++k)
            if (units_[code[k]].lin + units_[code[k]].size != units_[code[k + 1]].lin)
                return false;
        return true;
    };
    // DS: COM 0; MZ the inferred DGROUP, else the Borland c0 entry
    // `mov dx, DGROUP` (relocated word at entry+1; ES = DS for the walker).
    int64_t ds = in_.com ? 0 : dgroup_;
    if (ds < 0 && !in_.com && in_.entry + 3 <= n && img[in_.entry] == 0xBA && in_.reloc_at.count(in_.entry + 1))
    {
        const int eu = unit_at(in_.entry);
        if (eu >= 0 && units_[static_cast<size_t>(eu)].code)
            ds = static_cast<int64_t>(img[in_.entry + 1] | (img[in_.entry + 2] << 8)) * 16;
    }
    for (size_t j = 0; j + 2 < code.size(); ++j)
    {
        const EmitUnit& a = units_[code[j]];
        const EmitUnit& b = units_[code[j + 1]];
        const EmitUnit& c = units_[code[j + 2]];
        const uint8_t* ab = img.data() + a.lin;
        const uint8_t* bb = img.data() + b.lin;
        const uint8_t* cb = img.data() + c.lin;
        if (ds < 0 || !contiguous(j, j + 2) || a.size != 3 || ab[0] != 0xBE || b.size != 3 || bb[0] != 0xBF ||
            c.size != 3 || cb[0] != 0xE8)
            continue;
        const uint32_t cfr = static_cast<uint32_t>(frame_of_[c.lin]);
        const uint32_t P = cfr + ((c.lin + 3 - cfr + static_cast<uint32_t>(static_cast<int16_t>(cb[1] | (cb[2] << 8)))) & 0xFFFFu);
        const int pi = unit_at(P);
        if (pi < 0 || !units_[static_cast<size_t>(pi)].code)
            continue;
        bool step6 = false;
        bool esbx = false;
        for (size_t q = static_cast<size_t>(pi), cnt = 0; q < units_.size() && cnt < 24 && units_[q].code; ++q, ++cnt)
        {
            const uint8_t* qb = img.data() + units_[q].lin;
            if (units_[q].size == 3 && qb[0] == 0x83 && qb[1] == 0xC3 && qb[2] == 0x06)
                step6 = true;
            if (units_[q].size >= 3 && qb[0] == 0x26 && (qb[1] == 0x80 || qb[1] == 0x8A) && (qb[2] & 0xC7) == 0x07)
                esbx = true;
            if (units_[q].size >= 4 && qb[0] == 0x26 && (qb[1] == 0x80 || qb[1] == 0x8A) && (qb[2] & 0xC7) == 0x47)
                esbx = true;
        }
        if (!step6 || !esbx)
            continue;
        const uint32_t S = static_cast<uint32_t>(ds) + (ab[1] | (ab[2] << 8));
        const uint32_t E = static_cast<uint32_t>(ds) + (bb[1] | (bb[2] << 8));
        if (E <= S || (E - S) % 6 != 0 || E - S > 6 * 256 || !in_data(S, E - S))
            continue;
        std::vector<uint32_t> tg;
        bool ok = true;
        for (uint32_t r = S; r < E && ok; r += 6)
        {
            const uint32_t off = img[r + 2] | (img[r + 3] << 8);
            if (img[r] == 0)
                tg.push_back(ef + off);
            else if (img[r] == 1 && in_.reloc_at.count(r + 4) && static_cast<uint32_t>(img[r + 4] | (img[r + 5] << 8)) * 16u == ef)
                tg.push_back(ef + off);
            else if (img[r] != 1)
                ok = false;
        }
        if (!ok)
            continue;
        for (uint32_t t : tg)
            if (want(t))
                ++n_init_roots_;
    }
    // Code pointer cells: `call word ptr ds:[X]` (FF 16 X) and
    // `mov word ptr ds:[X], imm` (C7 06 X imm) both in decoded code, no
    // segment override, X not relocated. A near call goes to CS:imm, so the
    // target frame is the frame of the calling code: every call through X
    // and every store to X must sit in one code frame F (one segment, so in
    // the multi-segment models also one module and one DS), DS known (a COM,
    // or a known DGROUP). Targets are seeded only when F is the entry frame
    // (the rebuild walks extra entries in the entry frame only).
    if (ds >= 0)
    {
        std::map<uint32_t, std::set<int64_t>> cell_frames;
        std::vector<std::pair<uint32_t, uint32_t>> stores;
        std::set<uint32_t> called;
        for (size_t j = 0; j < code.size(); ++j)
        {
            const EmitUnit& u = units_[code[j]];
            const uint8_t* b = img.data() + u.lin;
            const auto fit = frame_of_.find(u.lin);
            const int64_t fr = fit != frame_of_.end() ? fit->second : -1;
            if (u.size == 4 && b[0] == 0xFF && b[1] == 0x16)
            {
                called.insert(b[2] | (b[3] << 8));
                cell_frames[b[2] | (b[3] << 8)].insert(fr);
            }
            else if (u.size == 6 && b[0] == 0xC7 && b[1] == 0x06)
            {
                stores.emplace_back(b[2] | (b[3] << 8), b[4] | (b[5] << 8));
                cell_frames[b[2] | (b[3] << 8)].insert(fr);
            }
        }
        for (const auto& [x, v] : stores)
        {
            if (!called.count(x) || in_.reloc_at.count(static_cast<uint32_t>(ds) + x))
                continue;
            const std::set<int64_t>& fs = cell_frames[x];
            if (fs.size() != 1 || *fs.begin() != static_cast<int64_t>(ef))
                continue;
            if (want(ef + v))
                ++n_ptr_roots_;
        }
    }
    // INT 21h / AH=25h with DS = CS.
    for (size_t j = 0; j < code.size(); ++j)
    {
        const EmitUnit& u = units_[code[j]];
        if (u.size != 2 || img[u.lin] != 0xCD || img[u.lin + 1] != 0x21)
            continue;
        int64_t found = -1;
        for (size_t k0 = j; k0 > 0 && k0 + 6 > j && found < 0;)
        {
        --k0;
        if (!contiguous(k0, j))
            break;
        bool ah25 = false;
        bool dscs = false;
        int64_t dx = -1;
        bool bad = false;
        for (size_t k = k0; k < j && !bad; ++k)
        {
            const EmitUnit& w = units_[code[k]];
            const uint8_t* wb = img.data() + w.lin;
            if (w.size == 3 && wb[0] == 0xB8 && wb[2] == 0x25)
                ah25 = true;
            else if (w.size == 2 && wb[0] == 0xB4 && wb[1] == 0x25)
                ah25 = true;
            else if (w.size == 2 && wb[0] == 0xB0)
                ;
            else if (w.size == 1 && wb[0] == 0x0E && k + 1 < j && units_[code[k + 1]].size == 1 && img[units_[code[k + 1]].lin] == 0x1F)
            {
                dscs = true;
                dx = -1;
                ++k;
            }
            else if (w.size == 2 && wb[0] == 0x8C && (wb[1] & 0xF8) == 0xC8 && k + 1 < j && units_[code[k + 1]].size == 2 &&
                     img[units_[code[k + 1]].lin] == 0x8E && img[units_[code[k + 1]].lin + 1] == static_cast<uint8_t>(0xD8 | (wb[1] & 7)))
            {
                dscs = true;
                dx = -1;
                ++k;
            }
            else if (w.size == 3 && wb[0] == 0xBA)
                dx = wb[1] | (wb[2] << 8);
            else
                bad = true;
        }
        if (!bad && ah25 && dscs && dx >= 0)
            found = dx;
        }
        const int64_t fr = frame_of_[u.lin];
        if (found < 0 || fr < 0)
            continue;
        if (want(static_cast<uint32_t>(fr + found)))
            ++n_vector_roots_;
    }
    // INT 21h / AH=25h with DS = a relocated segment (the Borland FP
    // emulator hooks INT 34h-3Eh this way). In the contiguous run of at most
    // 32 instructions before `int 21h`:
    //  - `mov r16, seg` (relocated word) then `mov ds, r16`, and a later
    //    `mov dx, imm`: the handler is seg:imm;
    //  - `lds dx, [bp+d]`: each `mov word ptr [bp+d], imm` paired with the
    //    next `mov word ptr [bp+d+2], seg` (relocated word) in the run is a
    //    handler seg:imm. Any other write to [bp+d] or [bp+d+2], or a call,
    //    rejects the run.
    // AH must be 25h at the `int 21h` (set by `mov ax, 25xxh` or
    // `mov ah, 25h` after the last other write to AX/AH in the run).
    auto far_want = [&](uint32_t seg, uint32_t off) -> bool {
        const uint32_t fr = seg * 16u;
        const uint32_t t = fr + off;
        if (t >= n || t < in_.emit_lo || fr == ef)
            return false;
        const int ci = unit_covering(t);
        if (ci < 0 || units_[static_cast<size_t>(ci)].code)
            return false;
        for (const auto& [lo, hi] : in_.force_data)
            if (t >= lo && t < hi)
                return false;
        const std::pair<uint32_t, int32_t> fs{t, static_cast<int32_t>(fr)};
        if (std::find(want_far_roots_.begin(), want_far_roots_.end(), fs) != want_far_roots_.end())
            return false;
        want_far_roots_.push_back(fs);
        return true;
    };
    for (size_t j = 0; j < code.size(); ++j)
    {
        const EmitUnit& u = units_[code[j]];
        if (u.size != 2 || img[u.lin] != 0xCD || img[u.lin + 1] != 0x21)
            continue;
        // The handler's frame comes from the relocated segment value, so
        // the run's own frame does not matter (a far-call target can be
        // decoded partly from another frame).
        size_t k0 = j;
        while (k0 > 0 && j - k0 < 32 && contiguous(k0 - 1, j))
            --k0;
        bool ah25 = false;
        int64_t ds_seg = -1;     // from mov r, seg / mov ds, r
        int64_t dx = -1;
        int lds_d = 1000;        // [bp+d] of the last lds dx
        std::map<int, std::vector<std::pair<uint32_t, bool>>> st; // d -> (value, seg relocated)
        std::set<int> bad_d;
        bool bad = false;
        for (size_t k = k0; k < j && !bad; ++k)
        {
            const EmitUnit& w = units_[code[k]];
            const uint8_t* wb = img.data() + w.lin;
            if (w.size == 3 && wb[0] == 0xB8)
                ah25 = wb[2] == 0x25;
            else if (w.size == 2 && wb[0] == 0xB4)
                ah25 = wb[1] == 0x25;
            else if (w.size == 1 && wb[0] == 0x40)
                ah25 = false;
            if (w.size == 3 && wb[0] >= 0xB8 && wb[0] <= 0xBF && in_.reloc_at.count(w.lin + 1) && k + 1 < j)
            {
                const EmitUnit& m = units_[code[k + 1]];
                if (m.size == 2 && img[m.lin] == 0x8E && img[m.lin + 1] == static_cast<uint8_t>(0xD8 | (wb[0] - 0xB8)))
                {
                    ds_seg = wb[1] | (wb[2] << 8);
                    dx = -1;
                    lds_d = 1000;
                    ++k;
                    continue;
                }
            }
            if (w.size == 2 && wb[0] == 0x8E && (wb[1] & 0xF8) == 0xD8)
            {
                ds_seg = -1; // mov ds, r from elsewhere
                lds_d = 1000;
            }
            else if (w.size == 1 && wb[0] == 0x1F)
            {
                ds_seg = -1;
                lds_d = 1000;
            }
            else if (w.size == 3 && wb[0] == 0xBA)
            {
                dx = wb[1] | (wb[2] << 8);
                lds_d = 1000;
            }
            else if (w.size == 3 && wb[0] == 0xC5 && wb[1] == 0x56)
            {
                lds_d = static_cast<int8_t>(wb[2]);
                ds_seg = -1;
                dx = -1;
            }
            else if (w.size == 5 && wb[0] == 0xC7 && wb[1] == 0x46)
            {
                const int d = static_cast<int8_t>(wb[2]);
                st[d].emplace_back(static_cast<uint32_t>(wb[3] | (wb[4] << 8)), in_.reloc_at.count(w.lin + 3) != 0);
            }
            else if (wb[0] == 0xE8 || wb[0] == 0x9A || (wb[0] == 0xFF && w.size >= 2 && (((wb[1] >> 3) & 7) == 2 || ((wb[1] >> 3) & 7) == 3)))
                bad = true;
            else if (w.size == 3 && (wb[0] == 0x88 || wb[0] == 0x89 || wb[0] == 0xC6 || wb[0] == 0xFF || wb[0] == 0x8F ||
                                     wb[0] == 0xD1 || wb[0] == 0x01 || wb[0] == 0x29 || wb[0] == 0x31 || wb[0] == 0x09 ||
                                     wb[0] == 0x21) && (wb[1] & 0xC7) == 0x46)
                bad_d.insert(static_cast<int8_t>(wb[2])); // other write to [bp+d]
        }
        if (bad || !ah25)
            continue;
        if (ds_seg >= 0 && dx >= 0)
        {
            if (far_want(static_cast<uint32_t>(ds_seg), static_cast<uint32_t>(dx)))
                ++n_far_vec_roots_;
            continue;
        }
        if (lds_d == 1000 || bad_d.count(lds_d) || bad_d.count(lds_d + 1) || bad_d.count(lds_d + 2) || bad_d.count(lds_d + 3))
            continue;
        const auto& offs = st[lds_d];
        const auto& segs = st[lds_d + 2];
        if (offs.empty() || offs.size() != segs.size())
            continue;
        bool all_reloc = true;
        for (const auto& [v, r] : segs)
            all_reloc &= r;
        if (!all_reloc)
            continue;
        for (size_t q = 0; q < offs.size(); ++q)
            if (far_want(segs[q].first, offs[q].first))
                ++n_far_vec_roots_;
    }
}

/**
 * @brief Code pointers passed as arguments (Borland printf passes __FPUTN).
 *
 * For a near `call F` (E8) in decoded code, frame fr:
 *  - F starts with `push bp / mov bp, sp` and, in its body (units in frame
 *    fr from F up to the next near-call target, at most 4 KB), BP is written
 *    only by that prologue and `pop bp`;
 *  - F does `call word ptr [bp+d]` (FF 56 d), d = 4 + 2 * slot, and every
 *    other use of [bp+d] in the body is a read (push, mov r, cmp);
 *  - the caller's contiguous run before the call, with no branch or table
 *    entry into it after its start and no other SP write, pushes the slot-th
 *    word (counting back from the call) as `push imm` or `push r` where the
 *    last write to r in the run is `mov r, imm` (not relocated).
 * Then CS:imm (frame fr) is a code entry: it is seeded when it lies in data,
 * and the immediate becomes a symbolic offset when it starts an instruction.
 */
inline void UasmEmitter::add_callback_args(const std::vector<size_t>& code)
{
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    const auto efit = frame_of_.find(in_.entry);
    if (efit == frame_of_.end() || efit->second < 0)
        return;
    const int64_t ef = efit->second;
    auto frame = [&](uint32_t lin) -> int64_t {
        const auto it = frame_of_.find(lin);
        return it == frame_of_.end() ? -1 : it->second;
    };
    auto rel_target = [&](const EmitUnit& w) -> int64_t {
        const uint8_t* bb = img.data() + w.lin;
        const int64_t fr = frame(w.lin);
        if (fr < 0)
            return -1;
        const uint32_t nx = w.lin + w.size;
        if (w.size == 2 && (bb[0] == 0xEB || (bb[0] >= 0x70 && bb[0] <= 0x7F) || (bb[0] >= 0xE0 && bb[0] <= 0xE3)))
            return fr + ((nx - fr + static_cast<int8_t>(bb[1])) & 0xFFFF);
        if (w.size == 3 && (bb[0] == 0xE9 || bb[0] == 0xE8))
            return fr + ((nx - fr + static_cast<int16_t>(bb[1] | (bb[2] << 8))) & 0xFFFF);
        return -1;
    };
    auto reg_written = [&](const EmitUnit& w, int want) -> int {
        const cs_insn* ci = decode(w);
        if (ci == nullptr)
            return -1;
        cs_regs rd, wr;
        uint8_t nr = 0, nw = 0;
        if (cs_regs_access(cs_, ci, rd, &nr, wr, &nw) != CS_ERR_OK)
            return -1;
        static constexpr unsigned regs[8][4] = {
            {X86_REG_AX, X86_REG_AL, X86_REG_AH, X86_REG_EAX}, {X86_REG_CX, X86_REG_CL, X86_REG_CH, X86_REG_ECX},
            {X86_REG_DX, X86_REG_DL, X86_REG_DH, X86_REG_EDX}, {X86_REG_BX, X86_REG_BL, X86_REG_BH, X86_REG_EBX},
            {X86_REG_SP, X86_REG_ESP, X86_REG_SP, X86_REG_ESP}, {X86_REG_BP, X86_REG_EBP, X86_REG_BP, X86_REG_EBP},
            {X86_REG_SI, X86_REG_ESI, X86_REG_SI, X86_REG_ESI}, {X86_REG_DI, X86_REG_EDI, X86_REG_DI, X86_REG_EDI}};
        for (uint8_t q = 0; q < nw; ++q)
            for (unsigned r : regs[want])
                if (wr[q] == r)
                    return 1;
        return 0;
    };
    std::set<uint32_t> entries, callees;
    for (size_t q = 0; q < code.size(); ++q)
    {
        const EmitUnit& w = units_[code[q]];
        const int64_t t = rel_target(w);
        if (t < 0)
            continue;
        entries.insert(static_cast<uint32_t>(t));
        if (img[w.lin] == 0xE8)
            callees.insert(static_cast<uint32_t>(t));
    }
    for (const auto& [at, ow] : off_words_)
        entries.insert(ow.target);
    std::map<uint32_t, size_t> pos;
    for (size_t q = 0; q < code.size(); ++q)
        pos[units_[code[q]].lin] = q;
    // Callee analysis, cached: slot -> ok.
    std::map<uint32_t, std::set<int>> callee_slots;
    auto analyse = [&](uint32_t P, int64_t fr) -> const std::set<int>& {
        auto [it, fresh] = callee_slots.emplace(P, std::set<int>{});
        if (!fresh)
            return it->second;
        std::set<int>& out = it->second;
        const auto pit = pos.find(P);
        if (pit == pos.end() || pit->second + 1 >= code.size())
            return out;
        const EmitUnit& a = units_[code[pit->second]];
        const EmitUnit& b = units_[code[pit->second + 1]];
        if (a.size != 1 || img[a.lin] != 0x55 || b.lin != a.lin + 1 || b.size != 2 ||
            !((img[b.lin] == 0x8B && img[b.lin + 1] == 0xEC) || (img[b.lin] == 0x89 && img[b.lin + 1] == 0xE5)))
            return out;
        // Body: units reachable from F without entering callees (jumps,
        // branches, fall-through, resolved cs: jump tables). An unresolved
        // indirect jump or a unit outside frame fr rejects F.
        std::set<int> calls;
        std::map<int, bool> other_use; // d -> written or used otherwise
        std::set<uint32_t> seen, helpers;
        std::vector<uint32_t> work{b.lin + 2};
        seen.insert(b.lin + 2);
        while (!work.empty())
        {
            if (seen.size() > 4096)
                return out;
            const uint32_t at = work.back();
            work.pop_back();
            const int wi = unit_at(at);
            if (wi < 0 || !units_[static_cast<size_t>(wi)].code || frame(at) != fr)
                return out;
            const EmitUnit& w = units_[static_cast<size_t>(wi)];
            const uint8_t* wb = img.data() + w.lin;
            auto go = [&](uint32_t t) {
                if (seen.insert(t).second)
                    work.push_back(t);
            };
            // pop bp only as the epilogue (directly before a ret); any other
            // BP write rebases the frame (push si / pop bp, mov bp,..).
            if (w.size == 1 && wb[0] == 0x5D)
            {
                const uint32_t r = w.lin + 1;
                if (r >= n || !(img[r] == 0xC2 || img[r] == 0xC3 || img[r] == 0xCA || img[r] == 0xCB))
                    return out;
            }
            else if (reg_written(w, 5) != 0)
                return out; // BP rewritten (or undecodable)
            const cs_insn* ci = decode(w);
            if (ci == nullptr || ci->detail == nullptr)
                return out;
            const cs_x86& x = ci->detail->x86;
            // [bp+d] operands of any displacement size, prefix or index.
            // Only the plain read forms below leave slot d intact; BP
            // used as a register value (mov si,bp, push bp to a nested
            // routine, ...) lets the slot be written elsewhere: reject.
            const bool is_call = wb[0] == 0xFF && w.size == 3 && (wb[1] & 0xC7) == 0x46 && ((wb[1] >> 3) & 7) == 2;
            const bool pop_bp = w.size == 1 && wb[0] == 0x5D; // epilogue, checked above
            const bool sp_from_bp = w.size == 2 && ((wb[0] == 0x8B && wb[1] == 0xE5) || (wb[0] == 0x89 && wb[1] == 0xEC));
            for (uint8_t oi = 0; oi < x.op_count; ++oi)
            {
                const cs_x86_op& o = x.operands[oi];
                if (o.type == X86_OP_REG && (o.reg == X86_REG_BP || o.reg == X86_REG_EBP) && !sp_from_bp && !pop_bp)
                    return out;
                if (o.type != X86_OP_MEM || (o.mem.base != X86_REG_BP && o.mem.base != X86_REG_EBP &&
                                             o.mem.index != X86_REG_BP && o.mem.index != X86_REG_EBP))
                    continue;
                const int d = static_cast<int>(o.mem.disp);
                const bool idx = o.mem.index != X86_REG_INVALID || o.mem.base != X86_REG_BP;
                const bool wr = (o.access & CS_AC_WRITE) != 0 || ci->id == X86_INS_LEA;
                if (idx)
                {
                    // [bp+si+d]: a local array when d < 0; otherwise it may
                    // reach any parameter slot.
                    if (d >= 0 && wr)
                        return out;
                    continue;
                }
                if (is_call)
                {
                    calls.insert(d);
                    continue;
                }
                const bool rd_only = !wr && (ci->id == X86_INS_PUSH || ci->id == X86_INS_MOV || ci->id == X86_INS_CMP);
                if (!rd_only)
                    for (int b = 0; b < std::max<int>(1, o.size); ++b)
                        other_use[d + b] = true;
            }
            const uint8_t op = wb[0];
            const int64_t t = rel_target(w);
            const uint32_t nx = w.lin + w.size;
            if (op == 0xC2 || op == 0xC3 || op == 0xCA || op == 0xCB || op == 0xCF)
                continue;
            if (op == 0xEB || op == 0xE9)
            {
                if (t < 0)
                    return out;
                go(static_cast<uint32_t>(t));
                continue;
            }
            if (op == 0xE8)
            {
                // A local helper without its own frame (no push bp / mov
                // bp, sp) shares F's BP: it is part of the body, and every
                // call to it must come from the body (checked below).
                if (t >= static_cast<int64_t>(n))
                    return out; // call past the end of the image
                if (t >= 0 && !(static_cast<size_t>(t) + 2 < img.size() && img[static_cast<size_t>(t)] == 0x55 &&
                                ((img[t + 1] == 0x8B && img[t + 2] == 0xEC) || (img[t + 1] == 0x89 && img[t + 2] == 0xE5))))
                {
                    helpers.insert(static_cast<uint32_t>(t));
                    go(static_cast<uint32_t>(t));
                }
                go(nx);
                continue;
            }
            if (t >= 0)
            {
                go(static_cast<uint32_t>(t));
                go(nx);
                continue;
            }
            if (op == 0xEA)
                return out;
            // jmp word ptr ds:[X]: a tail call through a cell (a thunk);
            // the callee keeps BP like any C function.
            if (op == 0xFF && w.size == 4 && wb[1] == 0x26)
                continue;
            const bool csx = op == 0x2E && w.size == 5 && wb[1] == 0xFF;
            const uint8_t* mb = csx ? wb + 1 : wb;
            if (mb[0] == 0xFF && ((mb[1] >> 3) & 7) >= 4 && ((mb[1] >> 3) & 7) <= 5)
            {
                // Jump through a cs: table resolved as a bounded jump table.
                if (!csx || ((mb[1] >> 3) & 7) != 4)
                    return out;
                const uint32_t T = static_cast<uint32_t>(fr) + (wb[3] | (wb[4] << 8));
                bool any = false;
                for (uint32_t e = T; off_words_.count(e); e += 2)
                {
                    go(off_words_.at(e).target);
                    any = true;
                }
                if (!any)
                    return out;
                continue;
            }
            if (op == 0xCD && w.size == 2 && cfg_int_noreturn(wb[1], 0x100))
                continue;
            go(nx);
        }
        for (size_t q = 0; q < code.size(); ++q)
        {
            const EmitUnit& w = units_[code[q]];
            if (img[w.lin] != 0xE8)
                continue;
            const int64_t t = rel_target(w);
            if (t >= 0 && helpers.count(static_cast<uint32_t>(t)) && !seen.count(w.lin))
                return out;
        }
        for (int d : calls)
            if (d >= 4 && d % 2 == 0 && !other_use.count(d) && !other_use.count(d + 1) && !other_use.count(d - 1))
                out.insert((d - 4) / 2);
        return out;
    };
    for (size_t j = 0; j < code.size(); ++j)
    {
        const EmitUnit& u = units_[code[j]];
        if (u.size != 3 || img[u.lin] != 0xE8)
            continue;
        const int64_t fr = frame(u.lin);
        const int64_t P = rel_target(u);
        if (fr < 0 || P < 0 || frame(static_cast<uint32_t>(P)) != fr)
            continue;
        const std::set<int>& slots = analyse(static_cast<uint32_t>(P), fr);
        if (slots.empty())
            continue;
        // Pushes before the call, nearest first.
        std::vector<size_t> pushes;
        size_t k = j;
        while (k > 0 && pushes.size() < 16 && contiguous_units(code[k - 1], code[k]))
        {
            if (k != j && entries.count(units_[code[k]].lin))
                break;
            const EmitUnit& w = units_[code[k - 1]];
            const uint8_t* wb = img.data() + w.lin;
            const bool push = (w.size == 1 && ((wb[0] >= 0x50 && wb[0] <= 0x57) || wb[0] == 0x06 || wb[0] == 0x0E ||
                                               wb[0] == 0x16 || wb[0] == 0x1E)) ||
                              (w.size == 3 && wb[0] == 0x68) || (w.size == 2 && wb[0] == 0x6A) ||
                              (wb[0] == 0xFF && w.size >= 2 && ((wb[1] >> 3) & 7) == 6);
            if (push)
            {
                pushes.push_back(k - 1);
                --k;
                continue;
            }
            if (rel_target(w) >= 0 || wb[0] == 0xC2 || wb[0] == 0xC3 || wb[0] == 0xCA || wb[0] == 0xCB ||
                wb[0] == 0xCC || wb[0] == 0xCD || wb[0] == 0xCF || wb[0] == 0x9A || wb[0] == 0xEA || wb[0] == 0x9D ||
                (wb[0] == 0xFF && w.size >= 2 && ((wb[1] >> 3) & 7) >= 2) || reg_written(w, 4) != 0)
                break;
            --k;
        }
        for (int slot : slots)
        {
            if (static_cast<size_t>(slot) >= pushes.size())
                continue;
            const size_t pj = pushes[static_cast<size_t>(slot)];
            const EmitUnit& pu = units_[code[pj]];
            const uint8_t* pb = img.data() + pu.lin;
            size_t mj = pj;
            uint32_t imm = 0;
            if (pu.size == 3 && pb[0] == 0x68)
                imm = pb[1] | (pb[2] << 8);
            else if (pu.size == 1 && pb[0] >= 0x50 && pb[0] <= 0x57 && pb[0] != 0x54)
            {
                const int r = pb[0] - 0x50;
                bool found = false;
                for (size_t q = pj; q > k && !found;)
                {
                    --q;
                    const EmitUnit& w = units_[code[q]];
                    const int wr = reg_written(w, r);
                    if (wr == 0)
                        continue;
                    if (wr < 0 || w.size != 3 || img[w.lin] != 0xB8 + r)
                        break;
                    imm = img[w.lin + 1] | (img[w.lin + 2] << 8);
                    mj = q;
                    found = true;
                }
                if (!found)
                    continue;
            }
            else
                continue;
            EmitUnit& mu = units_[code[mj]];
            if (in_.reloc_at.count(mu.lin + 1) || !mu.refs.empty())
                continue;
            const uint32_t t = static_cast<uint32_t>(fr) + imm;
            // imm 0 is a NULL callback; DGROUP (above the code) is data.
            if (imm == 0 || t >= n || t < in_.emit_lo || imm >= 0x10000)
                continue;
            if (dgroup_ > fr && static_cast<int64_t>(t) >= dgroup_)
                continue;
            const int ti = unit_at(t);
            if (ti >= 0 && units_[static_cast<size_t>(ti)].code)
            {
                if (frame(t) != fr)
                    continue;
                InsnRef r;
                r.kind = RefKind::Off;
                r.off = 1;
                r.size = 2;
                r.target = t;
                r.frame = static_cast<uint32_t>(fr);
                mu.refs.push_back(r);
                continue;
            }
            const int ci = unit_covering(t);
            if (ci < 0 || units_[static_cast<size_t>(ci)].code)
                continue;
            bool forced = false;
            for (const auto& [lo, hi] : in_.force_data)
                forced |= t >= lo && t < hi;
            if (forced)
                continue;
            if (fr == ef)
            {
                if (std::find(want_roots_.begin(), want_roots_.end(), t) == want_roots_.end())
                {
                    want_roots_.push_back(t);
                    cb_seeds_.emplace_back(t, static_cast<int32_t>(fr));
                    ++n_cb_roots_;
                }
            }
            else
            {
                const std::pair<uint32_t, int32_t> fs{t, static_cast<int32_t>(fr)};
                if (std::find(want_far_roots_.begin(), want_far_roots_.end(), fs) == want_far_roots_.end())
                {
                    want_far_roots_.push_back(fs);
                    cb_seeds_.push_back(fs);
                    ++n_cb_roots_;
                }
            }
        }
    }
}

/**
 * @brief FP emulator jump tables: entry count for `jmp|call cs:[R+T]` at
 *        code[j] (R = BX, BP, SI or DI by @p rm), or -1.
 *
 * Bit-mask abstract interpretation over the contiguous run of at most 48
 * instructions before the jump. The run starts after the last call or
 * backward branch, and no branch from outside the run may land inside it.
 * Each 16-bit register holds a mask of bits that may be set (unknown =
 * FFFFh): mov imm sets it, and/xor-self/shifts/xchg/mov reg-reg follow it,
 * any other write (Capstone register access) makes it unknown. Forward
 * branches inside the run join their state (OR) at the target. At the jump
 * the index mask must be 2^k - 2 (k >= 2): the index is an even value
 * 0..mask, so the word entries are 0..mask/2.
 */
/**
 * @brief Generic jump/call tables: collect the addresses that end a table.
 *
 * A table never runs into a decoded instruction, a branch target, a word
 * another reference already names, or an address an ordinary direct-address
 * load reads as data.
 */
inline void UasmEmitter::jt_prepare()
{
    if (jt_ready_)
        return;
    jt_ready_ = true;
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    // Heuristic heads (below Derived, e.g. an E9-run slot inside data) do
    // not bound a table and do not block an entry: a seed overrides them.
    if (g_.flow.has_value())
        for (const auto& [ip, blk] : g_.blocks)
        {
            if (blk.insns.empty())
                continue;
            // A head is weak when its best fact is below Derived, or when
            // nothing but its own decode explains it (a heuristic leader:
            // only `flow` facts from itself, no entry or branch to it).
            dx::Strength best = dx::Strength::Hint;
            bool explained = false;
            for (const dx::Fact& f : g_.flow->facts().at(dx::Lin{blk.insns.front().ip}))
            {
                if (f.strength > best)
                    best = f.strength;
                if (f.why != dx::Why::DirectFlow || f.source.v != f.subject.v)
                    explained = true;
            }
            if (best < dx::Strength::Derived || !explained)
                for (const CfgInsn& ci : blk.insns)
                    jt_weak_.insert(static_cast<uint32_t>(ci.ip));
        }
    jt_xref_.insert(in_.entry);
    // Targets of the graph's own (bounded) jump-table edges from proven code.
    for (const auto& [ip, blk] : g_.blocks)
        if (!blk.insns.empty() && !jt_weak_.count(static_cast<uint32_t>(blk.insns.back().ip)))
            for (const CfgEdge& e : blk.outs)
                if (e.kind == CfgEdgeKind::Table && e.has_target)
                    jt_xref_.insert(static_cast<uint32_t>(e.to_ip));
    for (size_t ui = 0; ui < units_.size(); ++ui)
    {
        const EmitUnit& u = units_[ui];
        if (!u.code || jt_weak_.count(u.lin))
            continue;
        jt_bounds_.insert(u.lin);
        for (const InsnRef& r : u.refs)
        {
            if (r.kind == RefKind::Rel || r.kind == RefKind::FarOff || r.kind == RefKind::Off)
                jt_bounds_.insert(r.target);
            if (r.kind == RefKind::Rel && img[u.lin] == 0xE8)
                jt_called_.insert(r.target);
            if (r.kind == RefKind::Rel || r.kind == RefKind::FarOff)
                jt_xref_.insert(r.target);
        }
        // Direct-address memory operands (mod=00 rm=110 or A0-A3 moffs).
        const uint8_t* b = img.data() + u.lin;
        uint32_t k = 0;
        int seg = -1;
        while (k < u.size && (b[k] == 0x26 || b[k] == 0x2E || b[k] == 0x36 || b[k] == 0x3E || b[k] == 0xF2 ||
                              b[k] == 0xF3 || b[k] == 0xF0))
        {
            if (b[k] == 0x2E)
                seg = 1;
            else if (b[k] == 0x3E)
                seg = 3;
            else if (b[k] == 0x26 || b[k] == 0x36)
                seg = 0;
            ++k;
        }
        if (k >= u.size)
            continue;
        // Immediate address loads: the word list a `mov si, offset X` points
        // at is data, so X ends a table before it. Only bx/si/di/bp loads
        // whose value is then used as a memory base or string pointer count;
        // a loop count or other constant (mov cx, N) is not an address.
        if (k == 0 && u.size == 3 && b[0] >= 0xB8 && b[0] <= 0xBF && b[0] != 0xBC)
        {
            const uint8_t reg = b[0] - 0xB8;
            if ((reg != 3 && reg != 5 && reg != 6 && reg != 7) || !jt_imm_is_pointer(ui, reg))
                continue;
            const uint32_t imm = b[1] | (b[2] << 8);
            const int32_t ifr = frame_of_.count(u.lin) ? frame_of_.at(u.lin) : 0;
            for (int64_t ib : {in_.com ? int64_t{0} : int64_t{ifr}, in_.com ? int64_t{-1} : int64_t{dgroup_}})
                if (ib >= 0 && ib + imm < n && ib + imm > in_.emit_lo)
                    jt_imm_.insert(static_cast<uint32_t>(ib + imm));
            continue;
        }
        int64_t disp = -1;
        const uint8_t op = b[k];
        if (op >= 0xA0 && op <= 0xA3 && k + 3 <= u.size)
            disp = b[k + 1] | (b[k + 2] << 8);
        else if (k + 4 <= u.size && op != 0xFF && op != 0x0F)
        {
            // Opcodes with a ModRM byte: 00-3F (not segment/BCD/prefix rows),
            // 80-8F, C0-C7, D0-D3, F6/F7, FE.
            const bool modrm = (op < 0x40 && (op & 7) < 4) || (op >= 0x80 && op <= 0x8F && op != 0x8D) ||
                               op == 0xC4 || op == 0xC5 || op == 0xC6 || op == 0xC7 || (op >= 0xD0 && op <= 0xD3) ||
                               op == 0xF6 || op == 0xF7 || op == 0xFE;
            if (modrm && (b[k + 1] & 0xC7) == 0x06)
                disp = b[k + 2] | (b[k + 3] << 8);
        }
        if (disp < 0)
            continue;
        int64_t base = -1;
        const int32_t fr = frame_of_.count(u.lin) ? frame_of_.at(u.lin) : 0;
        if (in_.com)
            base = 0;
        else if (seg == 1)
            base = fr;
        else if (seg != 0 && dgroup_ >= 0)
            base = dgroup_;
        if (base >= 0 && base + disp < n)
        {
            jt_loads_.insert(static_cast<uint32_t>(base + disp));
            jt_bounds_.insert(static_cast<uint32_t>(base + disp));
        }
    }
}

/**
 * @brief True when decoding from @p t by fall-through stays valid until a
 *        terminator (ret, retf, iret, jmp) or known code.
 *
 * Rejected: a Capstone failure, a run into the middle of a decoded
 * instruction, two `add [bx+si], al` (00 00) in a row, int3/into/hlt/bound/
 * arpl/lock, a near branch or call out of the image, or no terminator within
 * 400 instructions.
 */
/**
 * @brief True when the value a `mov reg, imm16` (unit @p i) loads into
 *        bx/bp/si/di is used as a memory base/index or a string pointer by
 *        the straight-line code after it, before the register is rewritten,
 *        or is still live at a call or indirect jump (handed on as an argument).
 */
inline bool UasmEmitter::jt_imm_is_pointer(size_t i, uint8_t reg) const
{
    static const x86_reg cs_regs[8] = {X86_REG_AX, X86_REG_CX, X86_REG_DX, X86_REG_BX,
                                       X86_REG_SP, X86_REG_BP, X86_REG_SI, X86_REG_DI};
    const x86_reg r = cs_regs[reg];
    const std::vector<uint8_t>& img = *in_.image;
    csh h = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &h) != CS_ERR_OK)
        return false;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* ci = cs_malloc(h);
    bool used = false;
    for (size_t j = i + 1; j < units_.size() && j <= i + 12 && ci != nullptr; ++j)
    {
        const EmitUnit& u = units_[j];
        const EmitUnit& pv = units_[j - 1];
        if (!u.code || pv.lin + pv.size != u.lin)
            break;
        const uint8_t* ptr = img.data() + u.lin;
        size_t sz = u.size;
        uint64_t addr = 0;
        if (!cs_disasm_iter(h, &ptr, &sz, &addr, ci) || ci->detail == nullptr)
            break;
        const cs_x86& x = ci->detail->x86;
        bool writes = false;
        for (uint8_t o = 0; o < x.op_count; ++o)
        {
            const cs_x86_op& op = x.operands[o];
            if (op.type == X86_OP_MEM && (op.mem.base == r || op.mem.index == r) && ci->id != X86_INS_LEA)
                used = true;
            // Any write (mov, add, sub, inc, xchg, pop, lea, ...) changes the
            // value: it is no longer the loaded immediate.
            if (op.type == X86_OP_REG && (op.access & CS_AC_WRITE) &&
                (op.reg == r ||
                 (reg == 3 && (op.reg == X86_REG_BL || op.reg == X86_REG_BH))))
                writes = true;
        }
        for (uint8_t q = 0; q < ci->detail->regs_write_count; ++q)
            if (ci->detail->regs_write[q] == r)
                writes = true;

        // String ops and xlat read si/di/bx implicitly.
        const std::string_view m(ci->mnemonic);
        const bool str = m.starts_with("lods") || m.starts_with("movs") || m.starts_with("stos") ||
                         m.starts_with("scas") || m.starts_with("cmps") || m.starts_with("outs") ||
                         m.starts_with("ins") || m.starts_with("xlat");
        if (str)
            for (uint8_t q = 0; q < ci->detail->regs_read_count; ++q)
                if (ci->detail->regs_read[q] == r)
                    used = true;
        if (str && ((reg == 6 && (m.starts_with("lods") || m.starts_with("movs") || m.starts_with("cmps") ||
                                  m.starts_with("outs"))) ||
                    (reg == 7 && (m.starts_with("stos") || m.starts_with("movs") || m.starts_with("scas") ||
                                  m.starts_with("cmps") || m.starts_with("ins"))) ||
                    (reg == 3 && m.starts_with("xlat"))))
            used = true;
        if (used || writes)
            break; // a use in the same instruction as a write comes first (mov bx, [bx]; lodsb)
        // Still live at a call or an indirect jump: the value is handed to
        // the callee or the dispatched handler (an argument pointer).
        if (m == "call" || m == "lcall" || (m == "jmp" && x.op_count >= 1 && x.operands[0].type != X86_OP_IMM))
        {
            used = true;
            break;
        }
        const uint8_t o0 = img[u.lin];
        if (o0 == 0xC3 || o0 == 0xCB || o0 == 0xC2 || o0 == 0xCA || o0 == 0xCF || o0 == 0xE9 || o0 == 0xEB ||
            o0 == 0xEA || (o0 >= 0x70 && o0 <= 0x7F) || (o0 >= 0xE0 && o0 <= 0xE3))
            break; // end of straight-line code
    }
    if (ci != nullptr)
        cs_free(ci, 1);
    cs_close(&h);
    return used;
}

/** @brief A decoded instruction starts at @p lin and its head is Derived or stronger. */
inline bool UasmEmitter::jt_is_code(uint32_t lin) const
{
    const int ui = unit_at(lin);
    return ui >= 0 && units_[static_cast<size_t>(ui)].code && !jt_weak_.count(lin);
}

inline bool UasmEmitter::jt_clean(uint32_t t, uint32_t fr, int* insns, int* known_hits, bool* anchored) const
{
    bool anch = false;
    int n_ins = 0, hits = 0;
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    csh h = 0;
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &h) != CS_ERR_OK)
        return false;
    cs_option(h, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn* ci = cs_malloc(h);
    bool ok = false;
    uint32_t p = t;
    int zeros = 0;
    for (int i = 0; i < 400 && ci != nullptr; ++i)
    {
        if (p < in_.emit_lo || p >= n)
            break;
        const int ui = unit_at(p);
        if (ui >= 0 && jt_is_code(p))
        {
            ok = anch = true; // runs into known code
            break;
        }
        const int cv = unit_covering(p);
        if (cv >= 0 && units_[static_cast<size_t>(cv)].code && !jt_weak_.count(units_[static_cast<size_t>(cv)].lin))
            break;
        const uint8_t* ptr = img.data() + p;
        size_t sz = std::min<size_t>(15, n - p);
        uint64_t addr = static_cast<uint16_t>(p - fr);
        if (!cs_disasm_iter(h, &ptr, &sz, &addr, ci))
            break;
        bool overlap = false;
        for (uint32_t q = p + 1; q < p + ci->size; ++q)
        {
            if (jt_is_code(q))
                overlap = true;
        }
        if (overlap)
            break;
        const std::string_view m(ci->mnemonic);
        if (img[p] == 0 && p + 1 < n && img[p + 1] == 0)
        {
            if (++zeros >= 2)
                break;
        }
        else
            zeros = 0;
        if (m == "int3" || m == "into" || m == "hlt" || m == "bound" || m == "arpl" || m == "lock" ||
            m == "int1" || m == "ud2" || m == "salc")
            break;
        ++n_ins;
        if (m == "ret" || m == "retf" || m == "iret" || m == "jmp" || m == "ljmp")
        {
            ok = true;
            // A direct near jmp into known code anchors the run.
            const uint8_t j0 = ci->detail ? ci->detail->x86.opcode[0] : 0;
            if ((j0 == 0xE9 || j0 == 0xEB) && ci->detail->x86.op_count >= 1 &&
                ci->detail->x86.operands[0].type == X86_OP_IMM &&
                jt_is_code(fr + (static_cast<uint32_t>(ci->detail->x86.operands[0].imm) & 0xFFFFu)))
                anch = true;
            break;
        }
        const uint8_t op0 = ci->detail ? ci->detail->x86.opcode[0] : 0;
        if ((op0 == 0xE8 || (op0 >= 0x70 && op0 <= 0x7F) || (op0 >= 0xE0 && op0 <= 0xE3)) && ci->detail &&
            ci->detail->x86.op_count >= 1 && ci->detail->x86.operands[0].type == X86_OP_IMM)
        {
            const uint32_t tg = fr + (static_cast<uint32_t>(ci->detail->x86.operands[0].imm) & 0xFFFFu);
            if (tg < in_.emit_lo || tg >= n)
                break;
            if (jt_is_code(tg))
                ++hits;
        }
        p += ci->size;
    }
    if (ci != nullptr)
        cs_free(ci, 1);
    cs_close(&h);
    if (insns != nullptr)
        *insns = n_ins;
    if (known_hits != nullptr)
        *known_hits = hits;
    if (anchored != nullptr)
        *anchored = ok && (anch || hits > 0);
    return ok;
}

/**
 * @brief One generic table at @p T: walk entries up to @p count, ending at
 *        the next boundary; 0000 or out-of-image words are holes; two
 *        invalid entries in a row end the table.
 */
inline void UasmEmitter::jt_table(uint32_t T, int64_t fr, int64_t count, bool far, bool hinted, size_t unit_idx,
                                  uint8_t disp_off, bool guarded, int64_t first)
{
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    const uint32_t esz = far ? 4u : 2u;
    uint32_t end = n;
    if (auto it = jt_bounds_.upper_bound(T); it != jt_bounds_.end())
        end = std::min(end, *it);
    if (!hinted)
    {
        // A table never runs past the end of its segment (the next
        // relocation-derived segment base) ...
        if (auto it = bases_.upper_bound(T); it != bases_.end())
            end = std::min(end, *it);
        // ... nor into a word list an immediate address load names.
        if (auto it = jt_imm_.upper_bound(T); it != jt_imm_.end())
            end = std::min(end, *it);
    }
    // The table must sit in data: stop at the first code byte.
    for (uint32_t a = T; a < end; ++a)
    {
        const int ci = unit_covering(a);
        if (ci < 0 || units_[static_cast<size_t>(ci)].code)
        {
            end = a;
            break;
        }
        a = units_[static_cast<size_t>(ci)].lin + units_[static_cast<size_t>(ci)].size - 1;
    }
    // A hard end: the next code start, label, known table start, data-load
    // address, segment base or named word list. The image end, and a count
    // from a byte-sized index, are not independent of the table's contents.
    bool hard_end = end < n;
    if (count > 0 && T + static_cast<uint64_t>(count) * esz < end)
    {
        end = static_cast<uint32_t>(T + static_cast<uint64_t>(count) * esz);
        hard_end = false;
    }
    struct Ent
    {
        uint32_t at, target, frame;
        int state; // 0 hole, 1 valid, 2 invalid
        bool tent = false; // after a hole in an unguarded table
    };
    std::vector<Ent> ents;
    int bad_run = 0;
    // Holes (0000 or out-of-image words):
    //  - guarded (compare or mask) or hinted: holes are skipped;
    //  - otherwise a hole ends the table, unless the slots run up to a hard
    //    end (see above) and every slot up to it is a 0000 hole or a valid
    //    entry. Every slot after the first hole also needs an independent
    //    reference to its target (see below).
    const bool hole_rule = !guarded && !hinted && !far;
    bool after_hole = false, any_hole = false, filled = true;
    size_t first_hole = 0;
    for (uint32_t at = T + static_cast<uint32_t>(first) * esz; at + esz <= end; at += esz)
    {
        if (!in_.com && (in_.reloc_at.count(at) || (!far && in_.reloc_at.count(at + 1))))
        {
            ents.push_back({at, 0, 0, 2});
            filled = false;
            if (++bad_run >= 2)
                break;
            continue;
        }
        const uint32_t w = img[at] | (img[at + 1] << 8);
        uint32_t tf = static_cast<uint32_t>(fr);
        if (far)
        {
            if (in_.com || !in_.reloc_at.count(at + 2))
            {
                ents.push_back({at, 0, 0, 2});
                if (++bad_run >= 2)
                    break;
                continue;
            }
            tf = (img[at + 2] | (img[at + 3] << 8)) * 16u;
        }
        const uint64_t t = static_cast<uint64_t>(tf) + w;
        if ((w == 0 && !far) || t < in_.emit_lo || t >= n)
        {
            if (w != 0)
                filled = false; // only 0000 is a hole in a hard-bounded table
            if (!any_hole)
                first_hole = ents.size();
            any_hole = after_hole = true;
            ents.push_back({at, 0, 0, 0});
            if (hole_rule && !filled)
                break;
            continue;
        }
        const uint32_t tt = static_cast<uint32_t>(t);
        bool valid;
        if (tt >= T && tt < at + esz)
            valid = false; // into the table itself
        else if (hole_rule && after_hole)
        {
            // A slot after a hole needs an independent reference to its
            // target from outside this table: proven code there that the
            // entry point, a direct branch or a far pointer in code, or a
            // non-tentative entry of another table reaches. Decoding
            // cleanly or joining known code is not evidence. A directly
            // called function is never a dispatch entry here.
            bool other = false;
            for (const auto* m : {&jt_firm_, &in_.jt_prev_firm})
                if (auto it = m->find(tt); it != m->end())
                    for (uint32_t b : it->second)
                        other = other || b != T;
            valid = jt_is_code(tt) && frame_of_.count(tt) && static_cast<uint32_t>(frame_of_.at(tt)) == tf &&
                    !jt_called_.count(tt) && (jt_xref_.count(tt) || other);
        }
        else if (const int ui = unit_at(tt); ui >= 0 && units_[static_cast<size_t>(ui)].code)
            valid = frame_of_.count(tt) && static_cast<uint32_t>(frame_of_.at(tt)) == tf;
        else if (const int cv = unit_covering(tt); cv >= 0 && units_[static_cast<size_t>(cv)].code)
            valid = false; // mid-instruction
        else
        {
            valid = hinted || jt_clean(tt, tf);
        }
        if (!valid)
            filled = false;
        if (hole_rule && any_hole && !valid)
            break;
        ents.push_back({at, tt, tf, valid ? 1 : 2, hole_rule && after_hole});
        bad_run = valid ? 0 : bad_run + 1;
        if (bad_run >= 2)
            break;
    }
    // Unguarded with a hole: keep the slots past it only when they fill the
    // table exactly up to a hard end; otherwise the table ends at the hole.
    if (hole_rule && any_hole)
    {
        const bool reached = !ents.empty() && ents.back().at + esz >= end;
        if (!(filled && hard_end && reached))
            ents.resize(first_hole);
    }
    // Trim trailing holes and invalid entries.
    while (!ents.empty() && ents.back().state != 1)
        ents.pop_back();
    size_t valid = 0, holes = 0;
    for (const Ent& e : ents)
        valid += e.state == 1, holes += e.state == 0;
    if (valid < (hinted ? 1u : 2u) || (!hinted && ents.front().state != 1))
        return;
    bool all_code = true;
    for (const Ent& e : ents)
        if (e.state == 1)
        {
            if (far)
            {
                const std::pair<uint32_t, int32_t> fs{e.target, static_cast<int32_t>(e.frame)};
                const int fi = unit_at(e.target);
                if ((fi < 0 || !units_[static_cast<size_t>(fi)].code) &&
                    std::find(want_far_roots_.begin(), want_far_roots_.end(), fs) == want_far_roots_.end())
                    want_far_roots_.push_back(fs);
            }
            else if (!in_.com && e.frame != in_.entry_frame)
            {
                // Another code segment: seeded in its own frame (sticky).
                const std::pair<uint32_t, int32_t> fs{e.target, static_cast<int32_t>(e.frame)};
                if (!jt_is_code(e.target) &&
                    std::find(want_far_roots_.begin(), want_far_roots_.end(), fs) == want_far_roots_.end())
                    want_far_roots_.push_back(fs);
            }
            else if (!jt_is_code(e.target) || in_.jt_prev.count(e.target))
                // Seed only what the graph left in data, and keep what an
                // earlier round seeded; decoded code is not re-seeded (a new
                // entry would change the graph around it).
                jt_roots_.insert(e.target);
            const int ui = unit_at(e.target);
            if (ui < 0 || !units_[static_cast<size_t>(ui)].code)
                all_code = false;
        }
    for (const Ent& e : ents)
        if (e.state == 1 && !e.tent)
            jt_firm_[e.target].insert(T);
    ++n_jt_;
    n_jt_entries_ += valid;
    n_jt_holes_ += holes;
    if (!all_code)
        return;
    // Every valid entry decoded: print the words as `dw label` (holes and
    // invalid words stay plain data) and the table base symbolically.
    // A word another table already printed with the same target is not a
    // clash (two views of one table, e.g. a hint and the generic rule).
    bool clash = false;
    for (const Ent& e : ents)
        if (auto it = off_words_.find(e.at);
            e.state == 1 && it != off_words_.end() && (it->second.target != e.target || it->second.frame != e.frame))
            clash = true;
    if (clash)
        return;
    for (const Ent& e : ents)
        if (e.state == 1 && !far)
            off_words_[e.at] = {e.target, e.frame};
    if (unit_idx != SIZE_MAX && !far)
    {
        EmitUnit& u = units_[unit_idx];
        InsnRef r;
        r.kind = RefKind::Off;
        r.off = disp_off;
        r.size = 2;
        r.target = T;
        r.frame = static_cast<uint32_t>(fr);
        u.refs.push_back(r);
    }
    auto_names_.emplace(T, std::format("jt_{:05X}", T));
}


namespace jtx
{
/// GPR write of one instruction: kind 0 none, 1 @c reg (16-bit number;
/// part 0 word, 1 low byte, 2 high byte), 2 unknown or several.
struct GprWrite
{
    int kind = 2;
    uint8_t reg = 0;
    uint8_t part = 0;
};

inline GprWrite gpr_write(const uint8_t* b, uint32_t n)
{
    GprWrite w;
    uint32_t k = 0;
    while (k < n && (b[k] == 0x26 || b[k] == 0x2E || b[k] == 0x36 || b[k] == 0x3E))
        ++k;
    if (k >= n)
        return w;
    const uint8_t op = b[k];
    const uint8_t m = k + 1 < n ? b[k + 1] : 0;
    const bool mreg = k + 1 < n && (m >> 6) == 3;
    const uint8_t mr = (m >> 3) & 7;
    auto r16 = [&w](uint8_t r) { w.kind = 1, w.reg = r & 7, w.part = 0; return w; };
    auto r8 = [&w](uint8_t r) { w.kind = 1, w.reg = r & 3, w.part = (r & 7) < 4 ? 1 : 2; return w; };
    auto none = [&w]() { w.kind = 0; return w; };
    auto rm_w = [&](bool word) { return !mreg ? none() : (word ? r16(m & 7) : r8(m & 7)); };
    if (op < 0x40 && (op & 7) <= 5)
    {
        if ((op >> 3) == 7)
            return none(); // cmp
        switch (op & 7)
        {
        case 0: return rm_w(false);
        case 1: return rm_w(true);
        case 2: return r8(mr);
        case 3: return r16(mr);
        case 4: return r8(0);
        default: return r16(0);
        }
    }
    if (op == 0x0F && k + 2 < n && (b[k + 1] & 0xF0) == 0x80)
        return none();
    if (op == 0x0F && k + 2 < n && (b[k + 1] == 0xB6 || b[k + 1] == 0xB7))
        return r16((b[k + 2] >> 3) & 7);
    if (op >= 0x40 && op <= 0x4F)
        return r16(op & 7);
    if ((op >= 0x50 && op <= 0x57) || (op >= 0x70 && op <= 0x7F) || op == 0x84 || op == 0x85 || op == 0x8E ||
        op == 0x90 || op == 0x9C || op == 0x9D || op == 0x9E || op == 0xA2 || op == 0xA3 || op == 0xA8 ||
        op == 0xA9 || (op >= 0xF8 && op <= 0xFD))
        return none();
    if (op >= 0x58 && op <= 0x5F)
        return r16(op & 7);
    if (op >= 0x80 && op <= 0x83)
        return mr == 7 ? none() : rm_w(op & 1);
    switch (op)
    {
    case 0x88: return rm_w(false);
    case 0x89: return rm_w(true);
    case 0x8A: return r8(mr);
    case 0x8B: return r16(mr);
    case 0x8C: return rm_w(true);
    case 0x8D: return r16(mr);
    case 0x8F: return rm_w(true);
    case 0x98: return r16(0);
    case 0x99: return r16(2);
    case 0x9F: return r8(4);
    case 0xA0: return r8(0);
    case 0xA1: return r16(0);
    default: break;
    }
    if (op >= 0xB0 && op <= 0xB7)
        return r8(op & 7);
    if (op >= 0xB8 && op <= 0xBF)
        return r16(op & 7);
    if (op == 0xC0 || op == 0xC1 || (op >= 0xD0 && op <= 0xD3))
        return rm_w(op & 1);
    if (op == 0xF6 || op == 0xF7)
        return mr <= 1 ? none() : (mr <= 3 ? rm_w(op & 1) : w);
    if (op == 0xFE && mr <= 1)
        return rm_w(false);
    if (op == 0xFF && mr <= 1)
        return rm_w(true);
    if (op == 0xFF && mr == 6)
        return none();
    return w;
}
} // namespace jtx

/**
 * @brief Index range of the indexed jump/call at code[@p j] (n8).
 *
 * Walks the straight-line code before the jump and tracks the index
 * register through `mov` copies (word and low byte) and `xchg`. A range guard counts
 * only when it compares that register (word, or its low byte when the high
 * byte is proven zero) with an immediate and the following jcc leaves the
 * table only for in-range values:
 *  - unsigned: ja/jae fall through, jbe/jb taken forward to the jump path;
 *  - signed: jg/jge fall through, jle/jl taken, word compares only
 *    (upper bound only; a negative bound gives none). A signed compare on
 *    the low byte gives no bound: bytes 80..FF are negative and pass;
 *  - unsigned jbe/jb taken away from the jump keeps the old cap (imm+1 or
 *    imm): nothing proves the slots past it.
 * Bound = imm+1 (inclusive forms) or imm, minus any sub/add bias between the
 * guard and the jump, scaled by the left shifts between the compare and the
 * jump and divided by the entry size (2 near, 4 far). An `and` mask between
 * the guard and the jump only clears bits: an upper guard still holds and
 * the caller takes min(guard, mask+1); an inverted guard's first slot is lost. A word inc/dec/add/sub
 * nearer the jump than `xor r8h,r8h` cancels the zero high byte.
 * The guard must dominate the jump: no instruction between them (other than
 * the guard's own taken target) is a direct branch target, the register is
 * not rewritten in between, and no call/int intervenes. Without a guard the
 * byte-source and `and` mask facts are still reported (old behavior).
 */
inline UasmEmitter::JtIndexRange UasmEmitter::jt_index_range(const std::vector<size_t>& code, size_t j, uint8_t r0,
                                                             uint8_t r1, int unit_shift) const
{
    JtIndexRange out;
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t jlin = units_[code[j]].lin;
    bool alias[8] = {};
    alias[r0 & 7] = true;
    if (r1 < 8)
        alias[r1] = true;
    int64_t bias_e = 0, bias_b = 0; // in element units / in byte-offset units
    bool mask_byte = false;
    bool need_set = false, need_ok = false; // fall-through broken at an unconditional transfer
    uint32_t need = 0;
    std::vector<uint32_t> seen{jlin};
    bool guard = false, gbyte = false;
    uint32_t guard_cmp = 0;    // linear address of the guard's compare
    bool masks_only = false;   // a compare whose flags were overwritten: later (earlier-in-code) guards are not trusted, masks still are
    int64_t mask_bias_e = 0, mask_bias_b = 0, mask_bias_off = 0; // biases seen when the nearest mask was recorded
    int scales = 0;            // left scalings of the index since the last value reset (mask)
    bool scale_frozen = false; // a mask nearer the jump fixed the value range
    int64_t inv_first = -1;    // inverted guard: lowest index the path can carry
    int shifts = 0;            // left scalings seen so far between this point and the jump
    int64_t bias_off = 0;      // total bias in byte-offset units (each bias scaled by the shifts after it)
    bool masked = false;       // a mask nearer the jump rewrote the index: earlier guards no longer hold (M-a)
    bool word_arith = false;   // inc/dec/add/sub on the word index nearer the jump: may carry into the high byte (L-c)
    const int64_t unit = int64_t{1} << unit_shift; // entry size in bytes (2 near, 4 far)
    auto sx8 = [](uint8_t v) { return static_cast<int64_t>(static_cast<int8_t>(v)); };
    for (size_t back = 1; back <= 12 && back <= j; ++back)
    {
        const EmitUnit& c = units_[code[j - back]];
        const EmitUnit& nx = units_[code[j - back + 1]];
        if (c.lin + c.size != nx.lin)
            break;
        const uint8_t* cb = img.data() + c.lin;
        const uint32_t sz = c.size;
        uint32_t p = 0;
        while (p < sz && (cb[p] == 0x26 || cb[p] == 0x2E || cb[p] == 0x36 || cb[p] == 0x3E))
            ++p;
        if (p >= sz)
            break;
        const uint8_t op = cb[p];
        const uint8_t m = p + 1 < sz ? cb[p + 1] : 0;
        const bool mreg = p + 1 < sz && (m >> 6) == 3;
        const uint8_t mr = (m >> 3) & 7;
        // Control transfers.
        const bool uncond = op == 0xEB || op == 0xE9 || op == 0xEA || op == 0xC3 || op == 0xCB || op == 0xC2 ||
                            op == 0xCA || op == 0xCF || (op == 0xFF && p + 1 < sz && (mr == 4 || mr == 5));
        if (uncond)
        {
            if (need_set || guard)
                break;
            need_set = true;
            need = nx.lin;
            continue;
        }
        if (op == 0xE8 || op == 0x9A || op == 0xCC || op == 0xCD || op == 0xCE ||
            (op == 0xFF && p + 1 < sz && (mr == 2 || mr == 3)))
            break;
        const bool jcc8 = op >= 0x70 && op <= 0x7F && sz == p + 2;
        const bool jcc16 = op == 0x0F && sz == p + 4 && (cb[p + 1] & 0xF0) == 0x80;
        if (jcc8 || jcc16)
        {
            const uint32_t tgt = jcc8 ? c.lin + sz + static_cast<uint32_t>(sx8(cb[p + 1]))
                                      : c.lin + sz + static_cast<uint32_t>(static_cast<int16_t>(cb[p + 2] | (cb[p + 3] << 8)));
            if (need_set && !need_ok)
            {
                if ((tgt & 0xFFFF) != (need & 0xFFFF))
                    break;
                need_ok = true;
            }
            if (!guard)
                seen.push_back(c.lin);
            continue;
        }
        if (need_set && !need_ok)
            break; // the block before an unconditional transfer is not on the path
        const bool add_self = (op == 0x03 || op == 0x01) && mreg && mr == (m & 7);
        // shl r,1 / add r,r on the index: scaled by 2.
        // Any further left scaling (a second shl/add self, before or after
        // the compare) gives a stride above one slot (M1): only slot 0 is
        // proven. shl r,imm8 counts imm8 times; shl r,cl is unknown.
        if (sz == p + 2 && ((op == 0xD1 && (m & 0xF8) == 0xE0 && alias[m & 7]) || (add_self && alias[m & 7])))
        {
            if (!scale_frozen && ++scales > unit_shift)
                out.rescaled = true;
            if (!guard)
            {
                ++shifts;
                out.doubled = true;
                seen.push_back(c.lin);
            }
            continue;
        }
        if (mreg && alias[m & 7] && (m & 0x38) == 0x20 && ((op == 0xC1 && sz == p + 3) || (op == 0xD3 && sz == p + 2)))
        {
            if (!scale_frozen)
                out.rescaled = true;
            break;
        }
        // High byte cleared: xor/sub r8h,r8h, mov r8h,0.
        if (sz == p + 2 && (op == 0x32 || op == 0x30 || op == 0x2A || op == 0x28) && mreg && mr == (m & 7) && mr >= 4 &&
            alias[mr & 3])
        {
            out.byte_idx = out.byte_idx || !word_arith;
            if (!guard)
                seen.push_back(c.lin);
            continue;
        }
        if (sz == p + 2 && op >= 0xB4 && op <= 0xB7 && m == 0 && alias[op & 3])
        {
            out.byte_idx = out.byte_idx || !word_arith;
            if (!guard)
                seen.push_back(c.lin);
            continue;
        }
        // Sources: lodsb leaves AH as it was (L4): the value source, but a
        // byte only when the high byte is cleared nearer the jump. cbw is
        // kept byte-sized as before.
        if (op == 0xAC && sz == p + 1 && alias[0])
            break;
        if (op == 0x98 && sz == p + 1 && alias[0])
        {
            out.byte_idx = true;
            break;
        }
        if (op == 0x0F && p + 2 < sz && cb[p + 1] == 0xB6 && alias[(cb[p + 2] >> 3) & 7])
        {
            out.byte_idx = true;
            break;
        }
        // xchg r16, r16 (90+r with ax, or 87 /r): the registers swap roles.
        if ((op >= 0x91 && op <= 0x97 && sz == p + 1) || (op == 0x87 && mreg && sz == p + 2))
        {
            const uint8_t ra = op == 0x87 ? mr : 0;
            const uint8_t rb = op == 0x87 ? (m & 7) : (op & 7);
            std::swap(alias[ra], alias[rb]);
            if (!guard)
                seen.push_back(c.lin);
            continue;
        }
        // Register copies (word, or low byte to low byte).
        if (mreg && sz == p + 2 && (op == 0x8B || op == 0x89 || op == 0x8A || op == 0x88))
        {
            const bool word = op & 1;
            const uint8_t dst = (op & 2) ? mr : (m & 7);
            const uint8_t src = (op & 2) ? (m & 7) : mr;
            if (word ? alias[dst] : (dst < 4 && alias[dst]))
            {
                if (!word && src >= 4)
                    break;
                alias[dst] = false;
                alias[src & 7] = true;
                if (!guard)
                    seen.push_back(c.lin);
                continue;
            }
            if (!word && dst >= 4 && alias[dst & 3])
                break; // high byte written
        }
        // z4d: an `and` directly before the guard's compare (no bias between
        // them or after) also limits the guarded index: record its mask.
        const bool and_before_guard = guard && nx.lin == guard_cmp && bias_e == 0 && bias_b == 0 && bias_off == 0;
        if (!guard || and_before_guard)
        {
            // and r, imm: mask.
            int64_t mk = -1;
            bool mb = false;
            if (op == 0x24 && sz == p + 2 && alias[0])
                mk = cb[p + 1], mb = true;
            else if (op == 0x25 && sz == p + 3 && alias[0])
                mk = cb[p + 1] | (cb[p + 2] << 8);
            else if (op == 0x80 && mreg && mr == 4 && sz == p + 3 && (m & 7) < 4 && alias[m & 7])
                mk = cb[p + 2], mb = true;
            else if (op == 0x83 && mreg && mr == 4 && sz == p + 3 && alias[m & 7])
                mk = sx8(cb[p + 2]) & 0xFFFF;
            else if (op == 0x81 && mreg && mr == 4 && sz == p + 4 && alias[m & 7])
                mk = cb[p + 2] | (cb[p + 3] << 8);
            if (mk >= 0 && guard)
            {
                if (out.mask < 0)
                {
                    out.mask = (mk << shifts) >> unit_shift;
                    mask_byte = mb;
                }
                seen.push_back(c.lin);
                continue;
            }
            if (mk >= 0)
            {
                if (out.mask < 0)
                {
                    // Highest byte offset (mask << shifts after it) over the entry size (M-b).
                    out.mask = (mk << shifts) >> unit_shift;
                    mask_byte = mb;
                    mask_bias_e = bias_e, mask_bias_b = bias_b, mask_bias_off = bias_off;
                }
                else if (mb == mask_byte && bias_e == mask_bias_e && bias_b == mask_bias_b && bias_off == mask_bias_off)
                {
                    // Round 6: an `and` only clears bits, so two masks with no
                    // bias between them intersect (a1: 0Ah & 05h).
                    out.mask &= (mk << shifts) >> unit_shift;
                }
                scale_frozen = true;
                masked = true;
                // z1: a ja/jne right after the `and` tests the and's flags
                // (CF=0): its fall-through carries a zero index only.
                {
                    const uint8_t* nb = img.data() + nx.lin;
                    if (nx.size == 2 && (nb[0] == 0x77 || nb[0] == 0x75) && !need_set)
                    {
                        const uint32_t jt = nx.lin + 2 + static_cast<uint32_t>(sx8(nb[1]));
                        bool dom = jt <= nx.lin || jt > jlin;
                        for (uint32_t l : seen)
                            if (l >= nx.lin + nx.size && jt_xref_.count(l))
                                dom = false;
                        if (dom)
                        {
                            out.count = 1, out.first = 0, out.mask = -1, out.zero_only = true;
                            return out;
                        }
                    }
                }
                seen.push_back(c.lin);
                continue;
            }
            if (guard)
                goto jt_after_mask; // only the `and` is read before the guard's compare
            // sub/add r, imm and inc/dec r: bias.
            int64_t bi = 0;
            bool isb = false;
            if (op >= 0x40 && op <= 0x4F && sz == p + 1 && alias[op & 7])
            {
                (out.doubled ? bias_e : bias_b) += op < 0x48 ? -1 : 1;
                bias_off += (op < 0x48 ? -1 : 1) * (int64_t{1} << shifts);
                word_arith = true;
                seen.push_back(c.lin);
                continue;
            }
            if ((op == 0x2C || op == 0x04) && sz == p + 2 && alias[0])
                bi = cb[p + 1], isb = true;
            else if ((op == 0x2D || op == 0x05) && sz == p + 3 && alias[0])
                bi = static_cast<int16_t>(cb[p + 1] | (cb[p + 2] << 8)), isb = true;
            else if (op == 0x83 && mreg && (mr == 5 || mr == 0) && sz == p + 3 && alias[m & 7])
                bi = sx8(cb[p + 2]), isb = true;
            else if (op == 0x81 && mreg && (mr == 5 || mr == 0) && sz == p + 4 && alias[m & 7])
                bi = static_cast<int16_t>(cb[p + 2] | (cb[p + 3] << 8)), isb = true;
            else if (op == 0x80 && mreg && (mr == 5 || mr == 0) && sz == p + 3 && (m & 7) < 4 && alias[m & 7])
                bi = cb[p + 2], isb = true;
            if (isb)
            {
                const bool is_add = op == 0x04 || op == 0x05 || ((op & 0xFC) == 0x80 && mr == 0);
                (out.doubled ? bias_e : bias_b) += is_add ? -bi : bi;
                bias_off += (is_add ? -bi : bi) * (int64_t{1} << shifts);
                if (op != 0x04 && op != 0x2C && op != 0x80)
                    word_arith = true; // a word add/sub can carry into the high byte
                seen.push_back(c.lin);
                continue;
            }
            // cmp r, imm followed by a range jcc.
            int64_t imm = -1;
            bool cbyte = false, ours = false;
            if (op == 0x3C && sz == p + 2)
                imm = cb[p + 1], cbyte = true, ours = alias[0];
            else if (op == 0x3D && sz == p + 3)
                imm = cb[p + 1] | (cb[p + 2] << 8), ours = alias[0];
            else if (op == 0x80 && mreg && mr == 7 && sz == p + 3)
                imm = cb[p + 2], cbyte = true, ours = (m & 7) < 4 && alias[m & 7];
            else if (op == 0x83 && mreg && mr == 7 && sz == p + 3)
                imm = sx8(cb[p + 2]) & 0xFFFF, ours = alias[m & 7];
            else if (op == 0x81 && mreg && mr == 7 && sz == p + 4)
                imm = cb[p + 2] | (cb[p + 3] << 8), ours = alias[m & 7];
            if (imm >= 0 && ours)
            {
                // Round 6: instructions that write no flags (mov, lea, push/pop,
                // xchg, nop) may sit between the compare and its jcc. The walk
                // already checked they do not write the index (alias) registers;
                // none of them may be a branch target.
                size_t jk = j - back + 1;
                bool gap_ok = true, idx_touch = false;
                while (jk < j)
                {
                    const EmitUnit& u = units_[code[jk]];
                    const uint8_t* ub = img.data() + u.lin;
                    uint32_t q = 0;
                    while (q < u.size && (ub[q] == 0x26 || ub[q] == 0x2E || ub[q] == 0x36 || ub[q] == 0x3E))
                        ++q;
                    if (q >= u.size)
                        break;
                    const uint8_t o = ub[q];
                    const bool nonflag = (o >= 0x88 && o <= 0x8E) || (o >= 0xB0 && o <= 0xBF) || o == 0xC6 || o == 0xC7 ||
                                         (o >= 0x50 && o <= 0x5F) || (o >= 0x90 && o <= 0x97) || o == 0x86 || o == 0x87 ||
                                         o == 0x06 || o == 0x07 || o == 0x0E || o == 0x16 || o == 0x17 || o == 0x1E || o == 0x1F ||
                                         o == 0x9C;
                    if (!nonflag)
                        break;
                    if (jt_xref_.count(u.lin))
                        gap_ok = false;
                    // A non-flag writer that touches the index (any part, or
                    // either xchg operand) voids the guard and every earlier mask.
                    bool touch = false;
                    if (o == 0x87 || o == 0x86)
                    {
                        const uint8_t xm = q + 1 < u.size ? ub[q + 1] : 0;
                        const auto r16 = [&](uint8_t r) { return o == 0x86 ? static_cast<uint8_t>(r & 3) : r; };
                        touch = alias[r16((xm >> 3) & 7)] || ((xm >> 6) == 3 && alias[r16(xm & 7)]) || (xm >> 6) != 3;
                    }
                    else if (o >= 0x91 && o <= 0x97)
                        touch = alias[0] || alias[o & 7];
                    else
                    {
                        const jtx::GprWrite gw = jtx::gpr_write(ub, u.size);
                        touch = gw.kind == 2 || (gw.kind == 1 && alias[gw.reg]);
                    }
                    if (touch)
                    {
                        idx_touch = true;
                        break;
                    }
                    ++jk;
                }
                if (idx_touch)
                    break; // stop the walk: no guard, no mask from here on
                const EmitUnit& jx = units_[code[jk]];
                const uint8_t* nb = img.data() + jx.lin;
                uint8_t jo = 0;
                uint32_t jt = 0;
                if (!gap_ok || masks_only)
                    ; // not a guard
                else if (jx.size == 2 && nb[0] >= 0x70 && nb[0] <= 0x7F)
                    jo = nb[0], jt = jx.lin + 2 + static_cast<uint32_t>(sx8(nb[1]));
                else if (jx.size == 4 && nb[0] == 0x0F && (nb[1] & 0xF0) == 0x80)
                    jo = static_cast<uint8_t>(nb[1] - 0x10),
                    jt = jx.lin + 4 + static_cast<uint32_t>(static_cast<int16_t>(nb[2] | (nb[3] << 8)));
                const bool sgn = jo == 0x7F || jo == 0x7D || jo == 0x7E || jo == 0x7C;
                const int64_t v = sgn ? (cbyte ? sx8(static_cast<uint8_t>(imm)) : static_cast<int16_t>(imm)) : imm;
                // L2: a taken guard needs an unconditional transfer before its
                // target, else the fall-through reaches the jump too.
                const bool taken_ok = jt > jx.lin && jt <= jlin && need_set && jt == need;
                const bool away = jt <= jx.lin || jt > jlin;
                int64_t bound = -1;
                uint32_t taken = 0;
                if (sgn && cbyte)
                    ; // L-a: a signed byte compare never bounds a zero-extended byte index (80..FF pass)
                else if ((jo == 0x77 || jo == 0x7F) && !need_set)
                    bound = v + 1;
                else if ((jo == 0x73 || jo == 0x7D) && !need_set)
                    bound = v;
                else if ((jo == 0x76 || jo == 0x7E || jo == 0x72 || jo == 0x7C) && taken_ok)
                    bound = (jo == 0x76 || jo == 0x7E) ? v + 1 : v, taken = jt;
                else if ((jo == 0x76 || jo == 0x72) && !need_set && away && bias_e == 0 && bias_b == 0)
                {
                    // M3: jbe/jb taken away from the jump: the path carries an
                    // index above (jbe) or at least (jb) imm. Slots below are
                    // unreachable; no upper bound.
                    const int64_t lo = jo == 0x76 ? v + 1 : v;
                    bool dom = true;
                    for (uint32_t l : seen)
                        if (l >= jx.lin + jx.size && jt_xref_.count(l))
                            dom = false;
                    // M-a: a mask nearer the jump (x & m) can clear the bits
                    // that made the index large: the lower bound is lost.
                    if (dom && !masked)
                        inv_first = ((lo << shifts) + unit - 1) >> unit_shift;
                    break;
                }
                if (jo == 0)
                {
                    // A compare whose flags are overwritten (or with no jcc):
                    // not a guard. A compare changes no register, so keep
                    // walking for masks only (a10f: `and 7; cmp 3; add cx,1; ja`).
                    masks_only = true;
                    seen.push_back(c.lin);
                    continue;
                }
                if (bound < 0 && (jo == 0x77 || jo == 0x73 || jo == 0x76 || jo == 0x72 || sgn))
                    break; // a range jcc we cannot use: stop, keep no guard
                if (bound >= 0)
                {
                    // Dominance: nothing after the jcc on the path is a direct branch target.
                    const uint32_t from = taken ? taken : jx.lin + jx.size;
                    bool dom = true;
                    for (uint32_t l : seen)
                        if (l >= from && l != taken && jt_xref_.count(l))
                            dom = false;
                    if (!dom)
                        break;
                    // M-b: the compare sees the offset scaled by `shifts`; the
                    // table step is `unit` bytes. Near tables keep the round-1 arithmetic.
                    int64_t c0;
                    if (unit_shift == 1)
                        c0 = out.doubled ? bound - bias_e - bias_b / 2 : (bound - bias_b + 1) / 2;
                    else
                    {
                        const int64_t top = (bound << shifts) - bias_off; // byte offsets below top
                        c0 = top > 0 ? (top + unit - 1) >> unit_shift : 0;
                    }
                    if (c0 > 0)
                    {
                        out.count = c0;
                        // L1: an add (negative bias) after the guard skips the low slots.
                        const int64_t nb = unit_shift == 1 ? (out.doubled ? bias_e * 2 + bias_b : bias_b) : bias_off; // in bytes
                        if (nb < 0)
                            out.first = std::min<int64_t>((-nb) >> unit_shift, c0);
                        guard = true;
                        guard_cmp = c.lin;
                        gbyte = cbyte;
                        // Keep walking: an earlier scaling (M1) or a cleared high byte.
                        continue;
                    }
                    break;
                }
                // Another jcc (je/jne...): not a range guard; keep looking.
                seen.push_back(c.lin);
                continue;
            }
        }
        jt_after_mask:;
        const jtx::GprWrite w = jtx::gpr_write(cb, sz);
        if (w.kind == 2 || (w.kind == 1 && alias[w.reg]))
            break;
        if (!guard)
            seen.push_back(c.lin);
    }
    if (guard && gbyte && !out.byte_idx)
        out.count = -1, out.first = 0; // a byte compare bounds a word index only with the high byte zero
    if (mask_byte && !out.byte_idx)
        out.mask = -1;
    if (out.rescaled)
    {
        // Stride above one slot: only slot 0 (index 0) is proven reachable.
        out.count = 1, out.first = 0, out.mask = -1;
        return out;
    }
    if (out.count < 0 && inv_first > 0)
    {
        // M3: unguarded from the first reachable slot. M2 still holds: never
        // more than the pre-n8 cap; at or below the first slot, no table (a9c).
        out.first = inv_first;
        const int64_t lc = jt_legacy_count(code, j);
        if (lc > 0)
        {
            if (lc > inv_first)
                out.count = lc, out.legacy = true;
            else
                out.count = 0, out.first = 0; // every slot under main's cap is unreachable: no table
        }
        return out;
    }
    if (out.count < 0 && !(masked && out.mask >= 0))
    {
        // M-a: with a mask and no upper guard the mask is the bound; no legacy cap.
        // M2: a voided or missing guard never yields more than the pre-n8
        // cap (register-blind compare scan), so no slot main left as data
        // becomes an entry.
        const int64_t lc = jt_legacy_count(code, j);
        if (lc > 0)
            out.count = lc, out.legacy = true;
    }
    if (out.count < 0 && out.mask == 0)
        out.count = 1, out.first = 0; // masks with no common bit: only index 0 (a1); one slot, as z1
    if (out.count > 0 && out.mask >= 0)
    {
        // A bound and a mask: the index is at most count-1 and has only mask
        // bits, so the count is the highest such value + 1 (tight for masks
        // with gaps: guard 9 and 0Ah gives 9, not 10). Biases after the mask
        // (`and 3; inc bx`) are not added: an under-count, never false code.
        const int64_t lim = out.count - 1;
        int64_t hi = 0;
        for (int b = 15; b >= 0; --b)
        {
            const int64_t bit = int64_t{1} << b;
            if ((out.mask & bit) && (hi | bit) <= lim)
                hi |= bit;
        }
        out.count = hi + 1;
        if (out.first > hi)
            out.first = 0;
    }
    return out;
}

/**
 * @brief Pre-n8 cap (main c552a32), the smallest of the generic and P4
 *        compare scans (the first `cmp r, imm` + ja/jae/jbe/jb within 12 (8)
 *        contiguous instructions, any register) and main's register-blind
 *        `and` mask scan (mask+1, halved on the byte offset). Only a ceiling for a
 *        voided guard (see jt_index_range); -1 when none.
 */
inline int64_t UasmEmitter::jt_legacy_count(const std::vector<size_t>& code, size_t j) const
{
    const std::vector<uint8_t>& img = *in_.image;
    auto imm_of = [](const EmitUnit& c, const uint8_t* cb) -> int64_t
    {
        if (c.size == 3 && cb[0] == 0x83 && (cb[1] & 0xF8) == 0xF8)
            return cb[2];
        if (c.size == 4 && cb[0] == 0x81 && (cb[1] & 0xF8) == 0xF8)
            return cb[2] | (cb[3] << 8);
        if (c.size == 3 && cb[0] == 0x80 && (cb[1] & 0xF8) == 0xF8)
            return cb[2];
        if (c.size == 2 && cb[0] == 0x3C)
            return cb[1];
        if (c.size == 3 && cb[0] == 0x3D)
            return cb[1] | (cb[2] << 8);
        return -1;
    };
    const uint32_t jlin = units_[code[j]].lin;
    // Old generic scan (compare and `and` mask, as main add_generic_table).
    int64_t g = -1, mcap = -1;
    {
        bool doubled = false;
        int64_t bias = 0;
        for (size_t back = 1; back <= 12 && back <= j; ++back)
        {
            const EmitUnit& c = units_[code[j - back]];
            const EmitUnit& nx = units_[code[j - back + 1]];
            if (c.lin + c.size != nx.lin)
                break;
            const uint8_t* cb = img.data() + c.lin;
            if (c.size == 2 && cb[0] == 0xD1 && (cb[1] & 0xF8) == 0xE0)
            {
                doubled = true;
                continue;
            }
            if (c.size == 2 && (cb[0] == 0x03 || cb[0] == 0x01) && (cb[1] >> 6) == 3 && ((cb[1] >> 3) & 7) == (cb[1] & 7))
            {
                doubled = true;
                continue;
            }
            if (mcap < 0)
            {
                int64_t mk = -1;
                if (c.size == 2 && cb[0] == 0x24)
                    mk = cb[1];
                else if (c.size == 3 && cb[0] == 0x25)
                    mk = cb[1] | (cb[2] << 8);
                else if (c.size == 3 && cb[0] == 0x83 && (cb[1] & 0xF8) == 0xE0)
                    mk = cb[2];
                else if (c.size == 4 && cb[0] == 0x81 && (cb[1] & 0xF8) == 0xE0)
                    mk = cb[2] | (cb[3] << 8);
                if (mk >= 0)
                    mcap = (doubled ? mk : (mk >> 1)) + 1;
            }
            if ((c.size == 3 && cb[0] == 0x83 && (cb[1] & 0xF8) == 0xE8) || (c.size == 2 && cb[0] == 0x2C))
                bias += c.size == 2 ? cb[1] : cb[2];
            else if (c.size == 3 && cb[0] == 0x2D)
                bias += cb[1] | (cb[2] << 8);
            const int64_t imm = imm_of(c, cb);
            if (imm < 0)
                continue;
            const uint8_t jo = img[nx.lin];
            const uint32_t jt = nx.size == 2 ? nx.lin + 2 + static_cast<uint32_t>(static_cast<int8_t>(img[nx.lin + 1])) : 0;
            int64_t c0 = -1;
            if (jo == 0x77)
                c0 = imm + 1;
            else if (jo == 0x73)
                c0 = imm;
            else if ((jo == 0x76 || jo == 0x72) && jt > nx.lin && jt <= jlin)
                c0 = jo == 0x76 ? imm + 1 : imm;
            if (c0 > 0)
            {
                c0 -= bias;
                if (!doubled)
                    c0 = (c0 + 1) / 2;
                if (c0 > 0)
                    g = c0;
            }
            break;
        }
    }
    // Old P4 scan ([bx+T] only).
    int64_t q = -1;
    {
        const uint8_t* b = img.data() + units_[code[j]].lin;
        const uint32_t usz = units_[code[j]].size;
        const bool bx = (usz == 4 && b[0] == 0xFF && b[1] == 0xA7) || (usz == 5 && b[0] == 0x2E && b[1] == 0xFF && (b[2] & 7) == 7);
        bool dbl = false;
        for (size_t back = 1; bx && q < 0 && back <= 8 && back <= j; ++back)
        {
            const EmitUnit& c = units_[code[j - back]];
            const EmitUnit& nx = units_[code[j - back + 1]];
            if (c.lin + c.size != nx.lin)
                break;
            const uint8_t* cb = img.data() + c.lin;
            if (c.size == 2 && ((cb[0] == 0xD1 && cb[1] == 0xE3) || ((cb[0] == 0x03 || cb[0] == 0x01) && cb[1] == 0xDB)))
            {
                dbl = true;
                continue;
            }
            const int64_t imm = imm_of(c, cb);
            if (imm < 0)
                continue;
            const uint8_t jo = img[nx.lin];
            if (jo == 0x77 || jo == 0x76)
                q = imm + 1;
            else if (jo == 0x73 || jo == 0x72)
                q = imm;
            if (q > 0 && !dbl)
                q = (q + 1) / 2;
            break;
        }
    }
    int64_t best = -1;
    for (int64_t v : {g, q, mcap})
        if (v > 0 && (best < 0 || v < best))
            best = v;
    return best;
}

/**
 * @brief Generic rule for `jmp|call [base+index+disp16]` (FF /2 /3 /4 /5,
 *        mod=10). `[disp16]` alone is a variable, not a table.
 *
 * Bound, smallest wins: an unsigned compare guard (bias from a later
 * sub/add), an `and` mask, a byte-sized index (at most 256), the next
 * boundary (jt_prepare), two invalid entries in a row.
 * @return true when @p j was an indirect jump/call through memory.
 */
inline bool UasmEmitter::add_generic_table(const std::vector<size_t>& code, size_t j)
{
    jt_prepare();
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    const size_t ui = code[j];
    const EmitUnit& u = units_[ui];
    const uint8_t* b = img.data() + u.lin;
    uint32_t k = 0;
    int seg = -1; // -1 none, 0 es/ss, 1 cs, 3 ds
    while (k < u.size && (b[k] == 0x26 || b[k] == 0x2E || b[k] == 0x36 || b[k] == 0x3E))
    {
        seg = b[k] == 0x2E ? 1 : (b[k] == 0x3E ? 3 : 0);
        ++k;
    }
    if (k + 4 != u.size || b[k] != 0xFF)
        return false;
    const uint8_t modrm = b[k + 1];
    const uint8_t reg = (modrm >> 3) & 7;
    if (reg < 2 || reg > 5 || (modrm >> 6) != 2)
        return false;
    const bool far = reg == 3 || reg == 5;
    const uint8_t rm = modrm & 7;
    const uint32_t disp = b[k + 2] | (b[k + 3] << 8);
    const int32_t fr = frame_of_.count(u.lin) ? frame_of_.at(u.lin) : 0;
    int64_t tbase = -1;
    const bool bp_based = rm == 2 || rm == 3 || rm == 6;
    if (in_.com)
        tbase = (seg == 0 || (bp_based && seg < 0)) ? -1 : 0;
    else if (seg == 1)
        tbase = fr;
    else if ((seg == 3 || (seg < 0 && !bp_based)) && dgroup_ >= 0)
        tbase = dgroup_;
    if (tbase < 0 || tbase + disp >= n)
    {
        if (far)
            ++n_jt_far_unres_, jt_notes_.push_back(std::format("{:05X}: far table, segment unresolved", u.lin));
        return true;
    }
    if (far && in_.com)
    {
        ++n_jt_far_unres_;
        jt_notes_.push_back(std::format("{:05X}: far table in a COM (segment is the load segment), not followed", u.lin));
        return true;
    }
    // Index register(s) of the ModRM form. reg numbers: ax0 cx1 dx2 bx3 sp4 bp5 si6 di7
    static const uint8_t idx_regs[8][2] = {{3, 6}, {3, 7}, {5, 6}, {5, 7}, {6, 0xFF}, {7, 0xFF}, {5, 0xFF}, {3, 0xFF}};
    const JtIndexRange ir = jt_index_range(code, j, idx_regs[rm][0], idx_regs[rm][1], far ? 2 : 1);
    int64_t count = ir.count;
    if (count == 0)
        return true; // no reachable slot (an inverted guard at or above the cap): leave it as data
    const bool byte_idx = ir.byte_idx;
    if (ir.mask >= 0)
    {
        const int64_t mb = ir.mask + 1;
        if (count < 0 || mb < count)
            count = mb;
    }
    const bool guarded = count > 0 || ir.mask >= 0;
    if (count < 0 && byte_idx)
        count = ir.doubled ? 256 : 128;
    if (count < 0 || count > 256)
        count = 256;
    const uint8_t disp_off = static_cast<uint8_t>(k + 2);
    jt_table(static_cast<uint32_t>(tbase + disp), fr, count, far, false, ui, disp_off, guarded, ir.first);
    return true;
}

/**
 * @brief Table hints, and direct near branch targets the graph left in data
 *        that decode cleanly to a terminator (guards: not a typed string, not
 *        a zero run, not an address only loads read, and a call or jump into
 *        known code within the run, or a terminator in at most 32 instructions).
 */
inline void UasmEmitter::jt_direct_targets(const std::vector<size_t>& code)
{
    jt_prepare();
    const std::vector<uint8_t>& img = *in_.image;
    const uint32_t n = static_cast<uint32_t>(img.size());
    for (const EmitInput::TableHint& h : in_.table_hints)
    {
        const uint32_t fr = in_.com ? 0u : in_.entry_frame;
        jt_table(h.lin, fr, h.count, h.far, true, SIZE_MAX, 0);
    }
    for (size_t ci : code)
    {
        const EmitUnit& u = units_[ci];
        for (const InsnRef& r : u.refs)
        {
            if (r.kind != RefKind::Rel)
                continue;
            const uint32_t t = r.target;
            if (t < in_.emit_lo || t + 2 > n)
                continue;
            const int ui = unit_at(t);
            const bool was = in_.jt_prev.count(t) != 0;
            if (ui >= 0 && units_[static_cast<size_t>(ui)].code)
            {
                if (was && jt_roots_.insert(t).second)
                    ++n_jt_direct_; // keep what an earlier round seeded
                continue;
            }
            const int cv = unit_covering(t);
            if (cv < 0 || units_[static_cast<size_t>(cv)].code)
                continue;
            if (str_len_.count(t) || (img[t] == 0 && img[t + 1] == 0) || jt_loads_.count(t))
                continue;
            const uint32_t fr = frame_of_.count(u.lin) ? static_cast<uint32_t>(frame_of_.at(u.lin)) : 0u;
            // Text guard: eight printable bytes in a row are not code.
            bool text = t + 8 <= n;
            for (uint32_t q = t; text && q < t + 8; ++q)
                text = img[q] >= 0x20 && img[q] < 0x7F;
            int ni = 0, kh = 0;
            if (text || (!in_.com && fr != in_.entry_frame) || !jt_clean(t, fr, &ni, &kh))
                continue;
            // Call density: a branch into known code, or a short run.
            if (kh == 0 && ni > 32)
                continue;
            if (jt_roots_.insert(t).second)
                ++n_jt_direct_;
        }
    }
}

inline int64_t UasmEmitter::mask_bound(const std::vector<size_t>& code, size_t j, uint8_t rm)
{
    const std::vector<uint8_t>& img = *in_.image;
    size_t s0 = j;
    while (s0 > 0 && j - s0 < 48 && contiguous_units(code[s0 - 1], code[s0]))
    {
        const EmitUnit& w = units_[code[s0 - 1]];
        const uint8_t* wb = img.data() + w.lin;
        if (wb[0] == 0xE8 || wb[0] == 0x9A || (wb[0] == 0xFF && w.size >= 2 && (((wb[1] >> 3) & 7) == 2 || ((wb[1] >> 3) & 7) == 3)))
            break;
        --s0;
    }
    if (s0 == j)
        return -1;
    const uint32_t lo = units_[code[s0]].lin;
    const uint32_t hi = units_[code[j]].lin;
    auto br_target = [&](const EmitUnit& b) -> int64_t {
        const uint8_t* bb = img.data() + b.lin;
        const auto fit = frame_of_.find(b.lin);
        const int64_t fr = fit != frame_of_.end() ? fit->second : 0;
        const uint32_t nx = b.lin + b.size;
        if (b.size == 2 && (bb[0] == 0xEB || (bb[0] >= 0x70 && bb[0] <= 0x7F) || (bb[0] >= 0xE0 && bb[0] <= 0xE3)))
            return fr + ((nx - fr + static_cast<int8_t>(bb[1])) & 0xFFFF);
        if (b.size == 3 && (bb[0] == 0xE9 || bb[0] == 0xE8))
            return fr + ((nx - fr + static_cast<int16_t>(bb[1] | (bb[2] << 8))) & 0xFFFF);
        return -1;
    };
    // Entry points inside (lo, hi]: a branch from outside the run, any
    // backward branch, or a table entry. The analysis starts at the last
    // one, where nothing is known about the registers.
    std::set<uint32_t> entries;
    for (size_t q = 0; q < code.size(); ++q)
    {
        const EmitUnit& b = units_[code[q]];
        const int64_t t = br_target(b);
        if (t <= static_cast<int64_t>(lo) || t > static_cast<int64_t>(hi))
            continue;
        if (b.lin < lo || b.lin > hi || t <= static_cast<int64_t>(b.lin))
            entries.insert(static_cast<uint32_t>(t));
    }
    for (const auto& [at, ow] : off_words_)
        if (ow.target > lo && ow.target <= hi)
            entries.insert(ow.target);
    if (!entries.empty())
    {
        const uint32_t last = *entries.rbegin();
        if (last == hi)
            return -1;
        while (units_[code[s0]].lin < last)
            ++s0;
        if (units_[code[s0]].lin != last || s0 >= j)
            return -1;
    }
    const uint32_t lo2 = units_[code[s0]].lin;
    using St = std::array<uint32_t, 8>; // ax cx dx bx sp bp si di
    const St unknown{0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF};
    St st = unknown;
    bool live = true;
    std::map<uint32_t, St> pend;
    auto join = [](St& a, const St& b) { for (size_t i = 0; i < 8; ++i) a[i] |= b[i]; };
    auto get8 = [&](const St& x, uint8_t r) -> uint32_t { return r < 4 ? (x[r] & 0xFF) : ((x[r - 4] >> 8) & 0xFF); };
    auto set8 = [&](St& x, uint8_t r, uint32_t v) {
        if (r < 4)
            x[r] = (x[r] & 0xFF00) | (v & 0xFF);
        else
            x[r - 4] = (x[r - 4] & 0x00FF) | ((v & 0xFF) << 8);
    };
    auto reg16 = [](unsigned cr) -> int {
        switch (cr)
        {
        case X86_REG_AX: case X86_REG_AL: case X86_REG_AH: case X86_REG_EAX: return 0;
        case X86_REG_CX: case X86_REG_CL: case X86_REG_CH: case X86_REG_ECX: return 1;
        case X86_REG_DX: case X86_REG_DL: case X86_REG_DH: case X86_REG_EDX: return 2;
        case X86_REG_BX: case X86_REG_BL: case X86_REG_BH: case X86_REG_EBX: return 3;
        case X86_REG_SP: case X86_REG_ESP: return 4;
        case X86_REG_BP: case X86_REG_EBP: return 5;
        case X86_REG_SI: case X86_REG_ESI: return 6;
        case X86_REG_DI: case X86_REG_EDI: return 7;
        default: return -1;
        }
    };
    for (size_t k = s0; k < j; ++k)
    {
        const EmitUnit& w = units_[code[k]];
        if (auto it = pend.find(w.lin); it != pend.end())
        {
            if (live)
                join(st, it->second);
            else
                st = it->second;
            live = true;
        }
        if (!live)
            continue;
        const uint8_t* wb = img.data() + w.lin;
        const uint8_t op = wb[0];
        const uint8_t md = w.size >= 2 ? wb[1] : 0;
        const bool rr = w.size == 2 && (md >> 6) == 3;
        const int64_t t = br_target(w);
        if (t >= 0)
        {
            if (t <= static_cast<int64_t>(w.lin) && t >= static_cast<int64_t>(lo2))
                return -1; // loop inside the run
            if (t > static_cast<int64_t>(w.lin) && t <= static_cast<int64_t>(hi))
            {
                auto [it, fresh] = pend.emplace(static_cast<uint32_t>(t), st);
                if (!fresh)
                    join(it->second, st);
            }
            if (op == 0xEB || op == 0xE9)
                live = false;
            continue;
        }
        if (w.size == 3 && op >= 0xB8 && op <= 0xBF)
            st[op - 0xB8] = wb[1] | (wb[2] << 8);
        else if (w.size == 2 && op >= 0xB0 && op <= 0xB7)
            set8(st, op - 0xB0, wb[1]);
        else if (rr && (op == 0x22 || op == 0x20))
        {
            const uint8_t d = op == 0x22 ? (md >> 3) & 7 : md & 7, sr = op == 0x22 ? md & 7 : (md >> 3) & 7;
            set8(st, d, get8(st, d) & get8(st, sr));
        }
        else if (rr && (op == 0x23 || op == 0x21))
        {
            const uint8_t d = op == 0x23 ? (md >> 3) & 7 : md & 7, sr = op == 0x23 ? md & 7 : (md >> 3) & 7;
            st[d] &= st[sr];
        }
        else if (w.size == 3 && op == 0x80 && (md & 0xF8) == 0xE0)
            set8(st, md & 7, get8(st, md & 7) & wb[2]);
        else if (w.size == 3 && op == 0x83 && (md & 0xF8) == 0xE0)
            st[md & 7] &= static_cast<uint32_t>(static_cast<int16_t>(static_cast<int8_t>(wb[2]))) & 0xFFFF;
        else if (w.size == 4 && op == 0x81 && (md & 0xF8) == 0xE0)
            st[md & 7] &= static_cast<uint32_t>(wb[2] | (wb[3] << 8));
        else if (w.size == 2 && op == 0x24)
            set8(st, 0, get8(st, 0) & wb[1]);
        else if (w.size == 3 && op == 0x25)
            st[0] &= static_cast<uint32_t>(wb[1] | (wb[2] << 8));
        else if (rr && op == 0xD1 && ((md >> 3) & 7) == 5)
            st[md & 7] >>= 1;
        else if (rr && op == 0xD1 && ((md >> 3) & 7) == 4)
            st[md & 7] = (st[md & 7] << 1) & 0xFFFF;
        else if (w.size == 1 && op >= 0x91 && op <= 0x97)
            std::swap(st[0], st[op - 0x90]);
        else if (rr && op == 0x87)
            std::swap(st[(md >> 3) & 7], st[md & 7]);
        else if (rr && op == 0x8B)
            st[(md >> 3) & 7] = st[md & 7];
        else if (rr && op == 0x8A)
            set8(st, (md >> 3) & 7, get8(st, md & 7));
        else if (rr && (op == 0x33 || op == 0x31 || op == 0x2B || op == 0x29) && ((md >> 3) & 7) == (md & 7))
            st[md & 7] = 0;
        else
        {
            const cs_insn* ci = decode(w);
            if (ci == nullptr)
                return -1;
            cs_regs rd, wr;
            uint8_t nr = 0, nw = 0;
            if (cs_regs_access(cs_, ci, rd, &nr, wr, &nw) != CS_ERR_OK)
                return -1;
            for (uint8_t q = 0; q < nw; ++q)
                if (const int r = reg16(wr[q]); r >= 0)
                    st[static_cast<size_t>(r)] = 0xFFFF;
        }
    }
    if (auto it = pend.find(hi); it != pend.end())
    {
        if (live)
            join(st, it->second);
        else
            st = it->second;
        live = true;
    }
    if (!live)
        return -1;
    static constexpr uint8_t idx[8] = {0, 0, 0, 0, 6, 7, 5, 3}; // rm -> reg
    if (rm < 4)
        return -1;
    const uint32_t m = st[idx[rm]];
    if (m < 2 || m > 0x1FE || (m & 1) != 0 || ((m + 2) & m) != 0) // at most 256 entries
        return -1;
    return m / 2 + 1;
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

inline std::string UasmEmitter::pair_key(const EmitUnit& u)
{
    if (!u.refs.empty())
        return {};
    const cs_insn* ci = decode(u);
    if (ci == nullptr)
        return {};
    const cs_x86& x = ci->detail->x86;
    const uint8_t* b = in_.image->data() + u.lin;
    const uint32_t dofs = x.encoding.disp_offset, dsz = x.encoding.disp_size;
    const uint32_t iofs = x.encoding.imm_offset, isz = x.encoding.imm_size;
    auto cls = [&](uint32_t at, uint32_t sz)
    {
        int64_t v = 0;
        for (uint32_t k = 0; k < sz; ++k)
            v |= static_cast<int64_t>(b[at + k]) << (8 * k);
        const int64_t sv = sz == 1 ? static_cast<int8_t>(v) : (sz == 2 ? static_cast<int16_t>(v) : v);
        if (v == 0)
            return std::string("z");
        if (v == 1)
            return std::string("1");
        return std::string(sv >= -128 && sv <= 127 ? "s" : (v <= 0xFF ? "u" : "w"));
    };
    std::string k;
    for (uint32_t j = 0; j < u.size;)
    {
        if (dsz != 0 && j == dofs)
        {
            k += std::format("D{}{}", dsz, cls(j, dsz));
            j += dsz;
        }
        else if (isz != 0 && j == iofs)
        {
            k += std::format("I{}{}", isz, cls(j, isz));
            j += isz;
        }
        else
        {
            k += std::format("{:02X}", b[j]);
            ++j;
        }
    }
    return k;
}

inline bool UasmEmitter::pair_verified(const EmitUnit& u)
{
    const uint8_t* b = in_.image->data() + u.lin;
    // Sized branches (R4) spell their encoding explicitly.
    if (u.refs.size() == 1 && u.refs[0].kind == RefKind::Rel &&
        (b[0] == 0xE8 || b[0] == 0xE9 || b[0] == 0xEB || (b[0] >= 0x70 && b[0] <= 0x7F)))
        return true;
    const std::string k = pair_key(u);
    return !k.empty() && std::binary_search(std::begin(kVerifiedPairs), std::end(kVerifiedPairs),
                                            std::string_view(k));
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
    // U2 scanned strings carry their cstr_ label.
    for (uint32_t s : cstr_scanned_)
        labels_.insert(s);
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
    if (ci == nullptr)
    {
        return {};
    }
    {
        const uint8_t* pb = in_.image->data() + u.lin;
        uint32_t k = 0;
        while (k < u.size && (pb[k] == 0x26 || pb[k] == 0x2E || pb[k] == 0x36 || pb[k] == 0x3E ||
                              pb[k] == 0xF2 || pb[k] == 0xF3))
            ++k;
        auto hexlist = [&](uint32_t from, uint32_t to)
        {
            std::string t;
            for (uint32_t j = from; j < to; ++j)
                t += (j > from ? ", " : "") + uasm_hex(pb[j]);
            return t;
        };
        // JS8: exact short branch (any prefixes) as data, edit-tracking via the label.
        if (k + 2 == u.size && u.refs.size() == 1 && u.refs[0].kind == RefKind::Rel &&
            ((pb[k] >= 0x70 && pb[k] <= 0x7F) || pb[k] == 0xEB || (pb[k] >= 0xE0 && pb[k] <= 0xE3)))
        {
            used_macros_.insert("js8");
            return std::format("JS8 {}, {}", lbl(u.refs[0].target), hexlist(0, k + 1));
        }
        // @m16: ModRM memory form with a literal disp16 (mod=10, or mod=00 rm=110).
        if (u.refs.empty() && k + 4 <= u.size && pb[k] != 0x0F && pb[k] != 0x66 && pb[k] != 0x67 &&
            pb[k] != 0xF0)
        {
            const uint8_t m = pb[k + 1];
            const bool d16 = (m >> 6) == 2 || ((m >> 6) == 0 && (m & 7) == 6);
            static const uint8_t modrm_ops[] = {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
                                                0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
                                                0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
                                                0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B,
                                                0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
                                                0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
                                                0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3,
                                                0xF6, 0xF7, 0xFE, 0xFF};
            const bool known = std::find(std::begin(modrm_ops), std::end(modrm_ops), pb[k]) !=
                               std::end(modrm_ops);
            if (d16 && known && ci->size == u.size)
            {
                used_macros_.insert("m16");
                std::string t = std::format("@m16 <{}>, {}", hexlist(0, k + 2),
                                            uasm_hex(pb[k + 2] | (pb[k + 3] << 8)));
                if (k + 4 < u.size)
                    t += ", " + hexlist(k + 4, u.size);
                return t;
            }
        }
    }
    if (!u.refs.empty())
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

inline std::string UasmEmitter::hex_lines(uint32_t lin, uint32_t len)
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

/** @brief R1/R2: true for a printable ASCII byte (0x20..0x7E). */
inline bool rd_print(uint8_t c) { return c >= 0x20 && c < 0x7F; }

/**
 * @brief R1/R2 text score on 7-bit chars: >= 60% letters/space, >= 3 distinct
 * letters, a run of >= 3 letters, no char above half the run, and not
 * mostly a period-2 pattern or a constant-stride table; >= 15% vowels.
 */
inline bool rd_texty(const uint8_t* b, uint32_t n, uint8_t mask)
{
    uint32_t letters = 0, spaces = 0, run = 0, best = 0, cnt[128] = {};
    std::set<uint8_t> dl;
    uint32_t pr = 0;
    for (uint32_t k = 0; k < n; ++k)
    {
        const uint8_t c = b[k] & mask;
        if (!rd_print(c))
        {
            run = 0;
            continue;
        }
        ++pr;
        ++cnt[c];
        const bool l = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
        if (l)
        {
            ++letters;
            dl.insert(c);
            best = std::max(best, ++run);
        }
        else
        {
            spaces += c == ' ';
            run = 0;
        }
    }
    if (pr == 0 || dl.size() < 3 || best < 3 || (letters + spaces) * 10 < pr * 6)
        return false;
    for (uint32_t c = 0; c < 128; ++c)
        if (cnt[c] * 2 > pr)
            return false;
    // Period-2 patterns (AbAbAb) and ascending tables (abcdef) are not text.
    uint32_t per2 = 0, asc = 0, vowels = 0;
    for (uint32_t k = 0; k < n; ++k)
        if (std::strchr("aeiouyAEIOUY", b[k] & mask) && (b[k] & mask))
            ++vowels;
    if (vowels * 100 < letters * 15)
        return false;
    for (uint32_t k = 0; k + 1 < n; ++k)
    {
        if (k + 2 < n && (b[k] & mask) == (b[k + 2] & mask))
            ++per2;
        // Constant stride (ascending tables, 16-step key maps).
        if (k + 2 < n && ((b[k + 1] & mask) - (b[k] & mask)) == ((b[k + 2] & mask) - (b[k + 1] & mask)))
            ++asc;
    }
    if (n >= 4 && (per2 * 2 > n || asc * 2 > n))
        return false;
    return true;
}

/**
 * @brief Data bytes as db lines, with two game-agnostic readability rules.
 *
 * R1: a run of printable ASCII (CR, LF and TAB allowed inside) whose longest
 * printable stretch is >= 6 bytes (>= 4 when followed by NUL, '$' or CRLF) and
 * that has at least two distinct bytes is quoted; a following NUL is kept on
 * the same line. Quote and macro-sensitive chars stay numeric (string_text).
 * R2: >= 8 bytes all with bit 7 set whose low 7 bits are printable (plus at
 * most one trailing printable byte with bit 7 clear) stay hex, preceded by a
 * comment with the decoded text. Bytes are unchanged either way.
 */
inline std::string UasmEmitter::data_lines(uint32_t lin, uint32_t len)
{
    const uint8_t* b = in_.image->data();
    const uint32_t end = lin + len;
    std::string out;
    uint32_t p = lin, flushed = lin;
    auto flush = [&](uint32_t to) {
        if (to > flushed)
            out += hex_lines(flushed, to - flushed);
        flushed = to;
    };
    auto inner = [](uint8_t c) { return rd_print(c) || c == 0x09 || c == 0x0A || c == 0x0D; };
    while (p < end)
    {
        // R2: high-bit text.
        if ((b[p] & 0x80) && rd_print(b[p] & 0x7F))
        {
            uint32_t q = p;
            while (q < end && (b[q] & 0x80) && rd_print(b[q] & 0x7F))
                ++q;
            uint32_t te = q;
            if (te < end && rd_print(b[te]))
                ++te;
            if (q - p >= 8 && rd_texty(b + p, te - p, 0x7F))
            {
                flush(p);
                std::string t;
                for (uint32_t k = p; k < te; ++k)
                {
                    const char c = static_cast<char>(b[k] & 0x7F);
                    if (c == '"' || c == '\\')
                        t += '\\';
                    t += c;
                }
                out += std::format("    ; hi-bit text: \"{}\"\n", t);
                ++r_hibit_;
                flush(te);
                p = te;
                continue;
            }
            p = q;
            continue;
        }
        if (!rd_print(b[p]))
        {
            ++p;
            continue;
        }
        // R1: ASCII run.
        uint32_t q = p, best = 0, cur = 0;
        std::set<uint8_t> distinct;
        while (q < end && inner(b[q]))
        {
            if (rd_print(b[q]))
            {
                best = std::max(best, ++cur);
                distinct.insert(b[q]);
            }
            else
                cur = 0;
            ++q;
        }
        while (q > p && !rd_print(b[q - 1]) && !(b[q - 1] == 0x0A && q - p >= 2 && b[q - 2] == 0x0D))
            --q;
        const bool term = (q < end && (b[q] == 0)) || b[q - 1] == '$' ||
                          (q - p >= 2 && b[q - 2] == 0x0D && b[q - 1] == 0x0A);
        if ((best >= 6 || (term && best >= 4)) && distinct.size() >= 2 && rd_texty(b + p, q - p, 0xFF))
        {
            flush(p);
            uint32_t se = q;
            if (se < end && b[se] == 0)
                ++se;
            for (uint32_t c = p; c < se; c += 64)
                out += "    db " + string_text(c, std::min<uint32_t>(64, se - c)) + "\n";
            ++r_ascii_;
            flushed = se;
            p = se;
            continue;
        }
        p = q > p ? q : p + 1;
    }
    flush(end);
    return out;
}

/** @brief Bytes as a db operand list: printable runs quoted, the rest hex. */
inline std::string UasmEmitter::string_text(uint32_t lin, uint32_t len) const
{
    const uint8_t* b = in_.image->data() + lin;
    std::string out;
    std::string run;
    auto flush = [&]() {
        if (run.empty())
            return;
        out += (out.empty() ? "" : ", ") + std::string("'") + run + "'";
        run.clear();
    };
    for (uint32_t k = 0; k < len; ++k)
    {
        const uint8_t c = b[k];
        if (c >= 0x20 && c < 0x7F && c != '\'' && c != '<' && c != '>' && c != '!' && c != '&' && c != '%' && c != ';')
        {
            run += static_cast<char>(c);
            continue;
        }
        flush();
        out += (out.empty() ? "" : ", ") + uasm_hex(c);
    }
    flush();
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

/**
 * @brief R3: true when a 1-unit instruction surely leaves AX alone and does
 * not end the block (conservative whitelist on raw bytes).
 */
inline bool rd_keeps_ax(const EmitUnit& u, const uint8_t* b)
{
    if (u.size == 0)
        return false;
    const uint8_t op = b[0];
    // mov r16/r8 imm other than AX/AH/AL
    if ((op >= 0xB1 && op <= 0xB3) || (op >= 0xB5 && op <= 0xB7) || (op >= 0xB9 && op <= 0xBF))
        return true;
    // push r16 / push seg / clc stc cld std cli sti
    if ((op >= 0x50 && op <= 0x57) || op == 0x06 || op == 0x0E || op == 0x16 || op == 0x1E ||
        op == 0xF8 || op == 0xF9 || op == 0xFC || op == 0xFD || op == 0xFA || op == 0xFB)
        return true;
    // pop r16 except AX; pop es/ds
    if ((op >= 0x59 && op <= 0x5F) || op == 0x07 || op == 0x1F)
        return true;
    // mov r/m, r and mov r, r/m (88-8B) with destination not AX/AH/AL
    if ((op >= 0x88 && op <= 0x8B) && u.size >= 2)
    {
        const uint8_t m = b[1];
        const uint8_t reg = (m >> 3) & 7, rm = m & 7, mod = m >> 6;
        if (op == 0x88 || op == 0x89)   // dest r/m
            return !(mod == 3 && (rm == 0 || (op == 0x88 && rm == 4)));
        return !(reg == 0 || (op == 0x8A && reg == 4)); // dest reg
    }
    // mov sreg, r/m (8E) and lea (8D) to a non-AX register
    if (op == 0x8E)
        return true;
    if (op == 0x8D && u.size >= 2)
        return ((b[1] >> 3) & 7) != 0;
    // inc/dec r16 other than AX
    if ((op >= 0x41 && op <= 0x47) || (op >= 0x49 && op <= 0x4F))
        return true;
    // xor/sub r16, r16 on a non-AX register (31/33/29/2B C0+..)
    if ((op == 0x31 || op == 0x33 || op == 0x29 || op == 0x2B) && u.size == 2 && (b[1] >> 6) == 3)
        return (b[1] & 7) != 0 && ((b[1] >> 3) & 7) != 0;
    return false;
}

/** @brief R4: near call (E8) targets get func_ names unless already named. */
inline void UasmEmitter::name_call_targets()
{
    call_targets_.clear();
    for (const EmitUnit& u : units_)
    {
        if (!u.code || u.size != 3 || (*in_.image)[u.lin] != 0xE8)
            continue;
        for (const InsnRef& r : u.refs)
            if (r.kind == RefKind::Rel)
                call_targets_.insert(r.target);
    }
    std::set<std::string> taken;
    for (const auto& [k, v] : in_.label_names)
        taken.insert(v);
    for (const auto& [k, v] : auto_names_)
        taken.insert(v);
    for (uint32_t t : call_targets_)
    {
        if (in_.label_names.count(t) || auto_names_.count(t))
            continue;
        // Never reuse a name already taken (hinted or auto): suffix until free.
        std::string name = std::format("func_{:05X}", t);
        for (int i = 1; taken.count(name); ++i)
            name = std::format("func_{:05X}_{}", t, i);
        taken.insert(name);
        auto_names_.emplace(t, name);
    }
}

inline std::string UasmEmitter::render(const std::vector<std::string>& header, int64_t shift_at,
                                       std::string_view shift_text)
{
    used_macros_.clear();
    sym_relocs_.clear();
    data_seg_words_ = 0;
    r_ascii_ = r_hibit_ = r_int21_ = r_funcs_ = 0;
    name_call_targets();
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
                u.rung = pin_text(u).empty() ? Rung::SymDb : Rung::Pin;
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
    if (used_macros_.count("js8"))
    {
        put("JS8 macro tgt:req, ops:vararg");
        put("  local here");
        put("  db ops");
        put("here label byte");
        put("  db (tgt)-(here+1)");
        put("  .erre ((tgt)-(here+1)+128) le 255, <rel8 out of range>");
        put("endm");
    }
    if (used_macros_.count("m16"))
    {
        put("@m16 macro pre:req, d:req, post:vararg");
        put("  db pre");
        put("  dw d");
        put("  IFNB <post>");
        put("    db post");
        put("  ENDIF");
        put("endm");
    }
    if (std::any_of(used_macros_.begin(), used_macros_.end(),
                    [](const std::string& m) { return m != "js8" && m != "m16"; }))
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
    int ah_known = -1, al_known = -1;
    for (size_t i = 0; i < units_.size(); ++i)
    {
        const EmitUnit& u = units_[i];
        if (u.code && static_cast<int64_t>(u.lin) == shift_at)
            put("    " + std::string(shift_text) + "\t; inserted by shift test");
        if (!u.code)
        {
            ah_known = al_known = -1;
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
                auto sit = str_len_.upper_bound(p);
                if (sit != str_len_.end() && sit->first < q)
                    q = sit->first;
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
                if (auto s = str_len_.find(p); s != str_len_.end() && p + s->second <= end &&
                                                  static_cast<int64_t>(p) != shift_at)
                {
                    // Stop at the next label or relocated/table word inside it.
                    uint32_t se = p + s->second;
                    if (auto nl = labels_.upper_bound(p); nl != labels_.end() && *nl < se)
                        se = *nl;
                    if (shift_at > static_cast<int64_t>(p) && shift_at < static_cast<int64_t>(se))
                        se = static_cast<uint32_t>(shift_at);
                    // Chunked: UASM rejects very long source lines.
                    const char* kind = cstr_scanned_.count(p) ? "string (NUL-terminated, data scan)" : "string";
                    for (uint32_t c = p; c < se; c += 64)
                        put(std::format("    db {}\t; {:05X}: {}", string_text(c, std::min<uint32_t>(64, se - c)), c, kind));
                    p = se;
                    continue;
                }
                std::string d = data_lines(p, q - p);
                // Tag the first line so the verifier can map this chunk.
                {
                    size_t ls = 0;
                    while (d.compare(ls, 5, "    ;") == 0 && d.find('\n', ls) != std::string::npos)
                        ls = d.find('\n', ls) + 1;
                    if (const size_t nl = d.find('\n', ls); nl != std::string::npos)
                        d.insert(nl, std::format("\t; {:05X}:", p));
                }
                for (char c : d)
                    if (c == '\n')
                        ++line;
                out += d;
                p = q;
            }
            continue;
        }
        if (labels_.count(u.lin) && call_targets_.count(u.lin))
        {
            put("; ------------------------------------------------------------");
            ++r_funcs_;
        }
        if (static_cast<int64_t>(u.lin) == main_hint_)
            put(std::format("; hint: possibly _main (C startup calls it, then passes AX to the call at {:05X}); "
                            "not verified", static_cast<uint32_t>(main_hint_exit_)));
        if (labels_.count(u.lin))
        {
            if (frame_bases_.count(u.lin) && u.lin > in_.emit_lo && u.lin % 16 == 0)
                put("align 16");
            put(lbl(u.lin) + ":");
            ah_known = -1;
        }
        const uint8_t* b = in_.image->data() + u.lin;
        // R3: AH from an immediate mov earlier in the same block.
        std::string int21;
        {
            size_t k = 0;
            while (k < u.size && (b[k] == 0x26 || b[k] == 0x2E || b[k] == 0x36 || b[k] == 0x3E))
                ++k;
            const uint8_t op = k < u.size ? b[k] : 0;
            if (op == 0xCD && k + 1 < u.size && b[k + 1] == 0x21)
            {
                if (ah_known >= 0)
                {
                    auto d = annotate_int(0x21, static_cast<uint8_t>(ah_known), 0xFF);
                    int21 = std::format("  DOS AH={}{}", uasm_hex(static_cast<uint32_t>(ah_known)),
                                        d ? std::string(": ") + std::string(*d) : std::string());
                    ++r_int21_;
                }
                ah_known = al_known = -1;
            }
            else if (op == 0xB4 && k == 0 && u.size == 2)
                ah_known = b[1];
            else if (op == 0xB0 && k == 0 && u.size == 2)
                al_known = b[1];
            else if (op == 0xB8 && k == 0 && u.size == 3)
            {
                al_known = b[1];
                ah_known = b[2];
            }
            else if (rd_keeps_ax(u, b))
            {
            }
            else
                ah_known = al_known = -1;
        }
        for (auto& c : int21)
            if (c == '\n' || c == '\r' || c == ';')
                c = ' ';
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
                ln += int21;
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
