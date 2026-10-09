// flow.h - Record the 2.25 walk. The walk still decides.
// Author: EdgeOfAssembly <haxbox2000@gmail.com>
// License: GPLv2 | Commercial (contact author)
//
// Does not include cfg.h. A false claim_code is not reported to the walk.

#ifndef FLOW_H
#define FLOW_H

#include "bytemap.h"
#include "facts.h"
#include "image_model.h"

#include <cstdint>
#include <set>
#include <span>

namespace dx
{

/**
 * @brief True when a later opcode-00 instruction must stop the walk.
 *
 * False when @p linear is the first instruction of the walk
 * (@p linear == @p walk_start), when @p size is 0 or 1, or when @p opcode0
 * is not 0x00. Otherwise true when some interior byte @c linear+k
 * (k in 1..size-1) is in @p leaders and not in @p spec. An INT-nearby seed
 * stays in @p spec and does not stop the walk (RG6). The caller passes the
 * opcode after prefixes, so a CS prefix in front of 00 still stops.
 *
 * @param linear      Address of this instruction.
 * @param walk_start  Address of the first instruction of this walk.
 * @param size        Decoded length.
 * @param opcode0     Opcode byte after prefixes. Not the raw first byte.
 * @param leaders     Real and speculative leaders.
 * @param spec        Speculative leaders. A hit here does not stop.
 * @return true only when the walk must stop before this instruction.
 */
inline bool stop_opcode00(uint32_t linear, uint32_t walk_start, uint8_t size,
                          uint8_t opcode0, const std::set<uint32_t>& leaders,
                          const std::set<uint32_t>& spec)
{
    if (linear == walk_start || size <= 1 || opcode0 != 0x00)
    {
        return false;
    }
    for (uint8_t k = 1; k < size; ++k)
    {
        const uint64_t at64 = static_cast<uint64_t>(linear) + static_cast<uint64_t>(k);
        if (at64 > 0xFFFFFFFFu)
        {
            break;
        }
        const uint32_t at = static_cast<uint32_t>(at64);
        if (leaders.count(at) != 0 && spec.count(at) == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Drop a speculative mark. A non-nearby enqueue uses this.
 *
 * @param spec Speculative leader set.
 * @param at   Leader to erase. Absent is a no-op.
 */
inline void promote_real(std::set<uint32_t>& spec, uint32_t at)
{
    spec.erase(at);
}

/**
 * @brief Insert a speculative leader.
 *
 * A second call leaves @p at speculative. cfg_build calls this only when
 * the leader was just created. A later Present enqueue does not call it,
 * so the mark survives a second nearby seed. @c promote_real clears it.
 *
 * @param spec Speculative leader set.
 * @param at   Leader to insert.
 */
inline void mark_spec_created(std::set<uint32_t>& spec, uint32_t at)
{
    spec.insert(at);
}

/**
 * @brief Facts and byte claims recorded for one cfg_build.
 *
 * The image classification is stored here only. It does not change enqueue.
 * @c note_insn never tells the walk that a claim failed.
 */
class FlowTrace
{
public:
    /**
     * @brief Record an image of @p n_bytes and copy @p image_bytes into it.
     *
     * @param n_bytes          Byte-map length. The caller passes the image size.
     * @param fmt              Format the caller already decided. Not guessed.
     * @param image_file_base  File offset of the first image byte.
     * @param entry            Entry linear.
     * @param entry_frame      Paragraph frame. May be negative.
     * @param image_bytes      Load-image slice. Copied. Not a new PSP prefix.
     * @param psp_in_bytes     True when @p image_bytes already includes the
     *                         256-byte PSP or the zero hole. Forwarded to
     *                         @c image_from_load. No default: @c cfg_build
     *                         is the only production caller and must say.
     */
    explicit FlowTrace(uint32_t n_bytes, Fmt fmt, FileOff image_file_base, Lin entry,
                       int32_t entry_frame, std::span<const uint8_t> image_bytes,
                       bool psp_in_bytes);

    /**
     * @brief Record a leader. Does not claim bytes.
     *
     * @param at        Leader linear.
     * @param why       Why the walk enqueued it.
     * @param strength  Strength of that enqueue. Hint is stored and not promoted.
     * @param source    Instruction or entry that produced the leader.
     */
    void note_leader(uint32_t at, Why why, Strength strength, uint32_t source);

    /**
     * @brief Record an instruction the walk already accepted.
     *
     * Adds a fact whose @c why is the argument (the walk passes DirectFlow)
     * and claims the bytes when @p strength is at least @c kPromote. A false
     * claim is ignored. The walk is not told to drop the instruction.
     *
     * @param at        Instruction linear.
     * @param len       Instruction length.
     * @param why       Stored on the fact.
     * @param strength  Proven when the walk start is not speculative, else Likely.
     * @param source    Walk start.
     */
    void note_insn(uint32_t at, uint8_t len, Why why, Strength strength, uint32_t source);

    /**
     * @brief Byte map filled by successful claims.
     *
     * @return The map. A rejected claim leaves the previous item in place.
     */
    const ByteMap& bytes() const;

    /**
     * @brief Facts in insertion order.
     *
     * @return The store.
     */
    const FactStore& facts() const;

    /**
     * @brief Image copied at construction.
     *
     * @return The load image, including the stored format.
     */
    const Image& image() const;

private:
    ByteMap bytes_;
    FactStore facts_;
    Image image_;
};

inline FlowTrace::FlowTrace(uint32_t n_bytes, Fmt fmt, FileOff image_file_base, Lin entry,
                            int32_t entry_frame, std::span<const uint8_t> image_bytes,
                            bool psp_in_bytes)
    : bytes_(n_bytes)
    , image_(image_from_load(fmt, image_bytes, image_file_base, entry, entry_frame,
                             psp_in_bytes))
{
}

inline void FlowTrace::note_leader(uint32_t at, Why why, Strength strength, uint32_t source)
{
    Fact fact;
    fact.why = why;
    fact.strength = strength;
    fact.subject = Lin{at};
    fact.source = Lin{source};
    facts_.add(fact);
}

inline void FlowTrace::note_insn(uint32_t at, uint8_t len, Why why, Strength strength,
                                 uint32_t source)
{
    Fact fact;
    fact.why = why;
    fact.strength = strength;
    fact.subject = Lin{at};
    fact.source = Lin{source};
    fact.unit = (strength == Strength::Likely) ? 1u : 0u;
    facts_.add(fact);
    if (static_cast<uint8_t>(strength) >= static_cast<uint8_t>(kPromote) &&
        lin_in_image(image_, Lin{at}))
    {
        (void)bytes_.claim_code(Lin{at}, len, at, fact);
    }
}

inline const ByteMap& FlowTrace::bytes() const
{
    return bytes_;
}

inline const FactStore& FlowTrace::facts() const
{
    return facts_;
}

inline const Image& FlowTrace::image() const
{
    return image_;
}

} // namespace dx

#endif // FLOW_H
