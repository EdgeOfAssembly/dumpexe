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
    std::vector<std::pair<uint32_t, int32_t>> want_far_roots_;
    template <class FrameOk, class InData>
    void add_pointer_refs(const std::vector<size_t>& code, FrameOk&& frame_ok, InData&& in_data);
    std::map<uint32_t, uint32_t> str_len_;          ///< P4 typed strings
    std::map<uint32_t, std::string> auto_names_;    ///< P4 names (hints win)
    size_t n_pointers_ = 0;
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
        // Jump table: [2E] FF A7 lo hi (also a call table, FF 97, with CS).
        const bool csp = u.size == 5 && b[0] == 0x2E && b[1] == 0xFF &&
                         (b[2] == 0xA7 || b[2] == 0x97 || b[2] == 0xA4 || b[2] == 0xA5 || b[2] == 0xA6 ||
                          b[2] == 0x94 || b[2] == 0x95 || b[2] == 0x96);
        const bool nop = u.size == 4 && b[0] == 0xFF && b[1] == 0xA7;
        if ((csp && (pure_com || frame_ok(frame_of_[u.lin]))) || (nop && pure_com))
        {
            const uint32_t k = csp ? 3 : 2;
            const int64_t fr = pure_com ? 0 : frame_of_[u.lin];
            const uint32_t disp = b[k] | (b[k + 1] << 8);
            // Bound: cmp r, imm followed by an unsigned jcc, all contiguous.
            int64_t count = -1;
            bool doubled_after_cmp = false;
            // Value-mask bound (FP emulator): see mask_bound.
            if (csp && count < 0)
                count = mask_bound(code, j, static_cast<uint8_t>(b[2] & 7));
            for (size_t back = 1; count < 0 && (!csp || (b[2] & 7) == 7) && back <= 8 && back <= j; ++back)
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
                        off_words_[T + static_cast<uint32_t>(e * 2)] = {tg[e], static_cast<uint32_t>(fr)};
                    auto_names_.emplace(T, std::format("jt_{:05X}", T));
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
        if (static_cast<int64_t>(u.lin) == main_hint_)
            put(std::format("; hint: possibly _main (C startup calls it, then passes AX to the call at {:05X}); "
                            "not verified", static_cast<uint32_t>(main_hint_exit_)));
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
