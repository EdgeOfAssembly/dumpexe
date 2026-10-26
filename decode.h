// decode.h - One 16-bit Capstone decoder for P1.
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// The handle is not cfg_build's handle. This header does not include cfg.h.
// Listing text is untouched. The quirk table changes Insn::mnem only.

#ifndef DECODE_H
#define DECODE_H

#include "image_model.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string_view>

namespace dx
{

/**
 * @brief Control-flow class of one decoded instruction.
 *
 * The first seven values are the P1 set. The rest are the design classes
 * this decoder actually assigns.
 */
enum class Flow : uint8_t
{
    Fall,
    Jmp,
    Jcc,
    Call,
    Ret,
    Int,
    Invalid,
    Loop,
    RetN,
    RetF,
    Iret,
    JmpFar,
    CallFar,
    JmpInd,
    CallInd,
    JmpFarInd,
    CallFarInd,
    Into,
    Hlt
};

/**
 * @brief Canonical mnemonic after the 16-bit quirk table.
 */
enum class Mnem : uint16_t
{
    Unknown,
    Add,
    Call,
    Ret,
    Cbw,
    Cwd,
    Int,
    Jmp,
    JmpShort
};

/**
 * @brief One decoded instruction. @c opcode0 is the byte after prefixes.
 */
struct Insn
{
    Lin at{};
    uint8_t len = 0;
    uint8_t bytes[15]{};
    uint8_t opcode0 = 0;
    Flow flow = Flow::Invalid;
    Mnem mnem = Mnem::Unknown;
};

/**
 * @brief Opcode byte after prefixes.
 *
 * False when @p insn is null or its detail is null. A missing detail is not
 * reported as opcode 00. On failure @p opcode0 is left unchanged.
 *
 * @param insn     Capstone instruction. Detail must be on for a true result.
 * @param opcode0  Receives @c detail->x86.opcode[0] on success.
 *                 For @c 2E 00 this is 0x00, not 0x2E.
 * @return false when the opcode byte cannot be read.
 */
inline bool opcode_after_prefixes(const cs_insn* insn, uint8_t& opcode0)
{
    if (insn == nullptr || insn->detail == nullptr)
    {
        return false;
    }
    opcode0 = insn->detail->x86.opcode[0];
    return true;
}

/**
 * @brief 16-bit x86 decoder. One Capstone handle, detail on, not copyable.
 */
class Decoder
{
public:
    /**
     * @brief Open a CS_ARCH_X86 / CS_MODE_16 handle with detail on.
     *
     * A failed open leaves @c at unable to decode. It does not throw.
     */
    Decoder();

    /**
     * @brief Close the Capstone handle.
     */
    ~Decoder();

    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    /**
     * @brief Decode the instruction at @p lin.
     *
     * @param image Load-image bytes.
     * @param lin   Image-linear address of the first byte.
     * @param out   Filled only on success. @c opcode0 is the byte after prefixes.
     *              Opcode 0x98 is @c Mnem::Cbw. Opcode 0x99 is @c Mnem::Cwd.
     * @return false when the address is outside @p image or Capstone fails.
     */
    bool at(std::span<const uint8_t> image, Lin lin, Insn& out);

private:
    csh handle_ = 0;
    cs_insn* insn_ = nullptr;

    static Flow flow_of(const cs_insn* insn);
    static Mnem mnem_of(const cs_insn* insn, uint8_t opcode0);
};

inline Decoder::Decoder()
{
    if (cs_open(CS_ARCH_X86, CS_MODE_16, &handle_) != CS_ERR_OK)
    {
        handle_ = 0;
        return;
    }
    cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);
    insn_ = cs_malloc(handle_);
    if (insn_ == nullptr)
    {
        cs_close(&handle_);
        handle_ = 0;
    }
}

inline Decoder::~Decoder()
{
    if (insn_ != nullptr)
    {
        cs_free(insn_, 1);
        insn_ = nullptr;
    }
    if (handle_ != 0)
    {
        cs_close(&handle_);
        handle_ = 0;
    }
}

inline Flow Decoder::flow_of(const cs_insn* insn)
{
    const std::string_view mnem(insn->mnemonic);
    const cs_x86& x86 = insn->detail->x86;
    const bool imm = x86.op_count >= 1 && x86.operands[0].type == X86_OP_IMM;
    if (mnem == "jmp")
    {
        return imm ? Flow::Jmp : Flow::JmpInd;
    }
    if (mnem == "ljmp" || mnem == "jmpf")
    {
        return imm ? Flow::JmpFar : Flow::JmpFarInd;
    }
    if (mnem == "call")
    {
        return imm ? Flow::Call : Flow::CallInd;
    }
    if (mnem == "lcall" || mnem == "callf")
    {
        return imm ? Flow::CallFar : Flow::CallFarInd;
    }
    if (mnem == "retn")
    {
        return Flow::RetN;
    }
    if (mnem == "ret")
    {
        return Flow::Ret;
    }
    if (mnem == "retf" || mnem == "retfq")
    {
        return Flow::RetF;
    }
    if (mnem == "iret" || mnem == "iretd")
    {
        return Flow::Iret;
    }
    if (mnem == "int")
    {
        return Flow::Int;
    }
    if (mnem == "into")
    {
        return Flow::Into;
    }
    if (mnem == "hlt")
    {
        return Flow::Hlt;
    }
    if (mnem == "loop" || mnem == "loope" || mnem == "loopz" || mnem == "loopne" ||
        mnem == "loopnz" || mnem == "jcxz" || mnem == "jecxz")
    {
        return Flow::Loop;
    }
    if (mnem.size() >= 2 && mnem[0] == 'j')
    {
        return Flow::Jcc;
    }
    return Flow::Fall;
}

inline Mnem Decoder::mnem_of(const cs_insn* insn, uint8_t opcode0)
{
    // Capstone 6 prints cwde/cdq for 98/99 in CS_MODE_16. The mnemonic id
    // is the 8086 form. Listing text is not produced here.
    if (opcode0 == 0x98)
    {
        return Mnem::Cbw;
    }
    if (opcode0 == 0x99)
    {
        return Mnem::Cwd;
    }
    const std::string_view mnem(insn->mnemonic);
    if (mnem == "add")
    {
        return Mnem::Add;
    }
    if (mnem == "call" || mnem == "lcall" || mnem == "callf")
    {
        return Mnem::Call;
    }
    if (mnem == "ret" || mnem == "retn" || mnem == "retf" || mnem == "retfq" ||
        mnem == "iret" || mnem == "iretd")
    {
        return Mnem::Ret;
    }
    if (mnem == "int" || mnem == "into")
    {
        return Mnem::Int;
    }
    if (mnem == "jmp" || mnem == "ljmp" || mnem == "jmpf")
    {
        if (opcode0 == 0xEB)
        {
            return Mnem::JmpShort;
        }
        return Mnem::Jmp;
    }
    return Mnem::Unknown;
}

inline bool Decoder::at(std::span<const uint8_t> image, Lin lin, Insn& out)
{
    if (insn_ == nullptr || handle_ == 0)
    {
        return false;
    }
    if (static_cast<size_t>(lin.v) >= image.size())
    {
        return false;
    }
    const size_t avail = std::min<size_t>(image.size() - static_cast<size_t>(lin.v), 15u);
    if (avail == 0)
    {
        return false;
    }
    const uint8_t* ptr = image.data() + static_cast<size_t>(lin.v);
    size_t size = avail;
    uint64_t addr = lin.v;
    if (!cs_disasm_iter(handle_, &ptr, &size, &addr, insn_) || insn_->detail == nullptr)
    {
        return false;
    }
    if (insn_->size == 0 || insn_->size > 15)
    {
        return false;
    }
    if (static_cast<size_t>(lin.v) + insn_->size > image.size())
    {
        return false;
    }

    uint8_t opcode0 = 0;
    if (!opcode_after_prefixes(insn_, opcode0))
    {
        return false;
    }

    Insn decoded;
    decoded.at = lin;
    decoded.len = static_cast<uint8_t>(insn_->size);
    std::memcpy(decoded.bytes, insn_->bytes, decoded.len);
    decoded.opcode0 = opcode0;
    decoded.flow = flow_of(insn_);
    decoded.mnem = mnem_of(insn_, opcode0);
    out = decoded;
    return true;
}

} // namespace dx

#endif // DECODE_H
