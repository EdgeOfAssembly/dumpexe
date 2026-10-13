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
    FarOff  ///< offset word of a relocated far pointer
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
     * @param shift_at Unit index before which @p shift_text is inserted, or -1.
     * @param shift_text One source line inserted by a shift test.
     * @return Source text. @c line_unit maps 1-based source lines to units.
     */
    std::string render(const std::vector<std::string>& header, int shift_at = -1,
                       std::string_view shift_text = {});

    std::vector<EmitUnit>& units() { return units_; }
    const std::vector<EmitUnit>& units() const { return units_; }
    const std::map<int, size_t>& line_unit() const { return line_unit_; }
    uint32_t emit_lo() const { return in_.emit_lo; }
    uint32_t org() const { return in_.com ? 0x100u : 0u; }
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

public:
    /** @brief Decoded instructions dropped because they straddle a segment base. */
    size_t straddled() const { return straddled_.size(); }
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
    labels_.insert(frame);
    labels_.insert(in_.emit_lo);
    return std::format("(({} - {}) shr 4)", uasm_label(frame), uasm_label(in_.emit_lo));
}

inline std::string UasmEmitter::off_expr(uint32_t target, uint32_t frame)
{
    labels_.insert(target);
    labels_.insert(frame);
    return std::format("({} - {})", uasm_label(target), uasm_label(frame));
}

inline void UasmEmitter::collect_labels()
{
    labels_.clear();
    frame_bases_.clear();
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    labels_.insert(in_.entry);
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
    for (const InsnRef& r : u.refs)
    {
        if (r.kind == RefKind::Rel)
            rel = &r;
        else if (r.kind == RefKind::Seg)
            seg = &r;
        else
            return {};
    }
    const uint32_t n = static_cast<uint32_t>(in_.image->size());
    if (seg != nullptr)
    {
        // mov r16, seg X (B8-BF iw) is the only mnemonic form with a segment word.
        if (u.refs.size() == 1 && op0 >= 0xB8 && op0 <= 0xBF && u.size == 3 && !any_prefix &&
            seg->frame >= in_.emit_lo && seg->frame < n)
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
        const std::string T = uasm_label(rel->target);
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
                f[r.off] = {r.size, std::format("{} - ($ + {})", uasm_label(r.target), r.size + rest)};
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

inline std::string UasmEmitter::render(const std::vector<std::string>& header, int shift_at,
                                       std::string_view shift_text)
{
    used_macros_.clear();
    sym_relocs_.clear();
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
        put(std::format("{} equ <({}+{})>", uasm_label(kv.first), uasm_label(kv.second.first),
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

    line_unit_.clear();
    for (size_t i = 0; i < units_.size(); ++i)
    {
        const EmitUnit& u = units_[i];
        if (static_cast<int>(i) == shift_at)
            put("    " + std::string(shift_text) + "\t; inserted by shift test");
        if (!u.code)
        {
            // Split data at labels.
            uint32_t p = u.lin;
            const uint32_t end = u.lin + u.size;
            while (p < end)
            {
                auto it = labels_.upper_bound(p);
                uint32_t q = end;
                if (it != labels_.end() && *it < end)
                    q = *it;
                if (labels_.count(p))
                {
                    if (frame_bases_.count(p) && p > in_.emit_lo && p % 16 == 0)
                        put("align 16");
                    put(uasm_label(p) + ":");
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
            put(uasm_label(u.lin) + ":");
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
        put(uasm_label(n) + ":");
    put("_TEXT ends");
    if (labels_.count(in_.entry) && in_.entry >= in_.emit_lo && in_.entry < n)
        put("end " + uasm_label(in_.entry));
    else
        put("end");
    return out;
}

} // namespace dx

#endif // DX_EMIT_UASM_H
