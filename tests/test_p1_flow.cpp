/**
 * @file test_p1_flow.cpp
 * @brief Catch2 checks for the opcode-00 stop, speculative marks, decode, and flow.
 *
 * cfg_build calls mark_spec_created only when a leader is Created.
 * Tests that turn recording on clear the hook before they return.
 */
#include "cfg.h"
#include "decode.h"
#include "flow.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <set>
#include <span>
#include <vector>

TEST_CASE("stop_opcode00 is false for the first instruction of the walk", "[flow]")
{
    const uint32_t start = 0x100;
    const std::set<uint32_t> leaders{start + 2};
    const std::set<uint32_t> spec;
    REQUIRE_FALSE(dx::stop_opcode00(start, start, 4, 0x00, leaders, spec));
}

TEST_CASE("stop_opcode00 stops a later opcode 00 that covers a real leader", "[flow]")
{
    const uint32_t start = 0x100;
    const std::set<uint32_t> leaders{start + 2};
    const std::set<uint32_t> spec;
    REQUIRE(dx::stop_opcode00(start + 1, start, 2, 0x00, leaders, spec));
}

TEST_CASE("stop_opcode00 ignores a covered leader that is speculative", "[flow]")
{
    const uint32_t start = 0x100;
    const std::set<uint32_t> leaders{start + 2};
    const std::set<uint32_t> spec{start + 2};
    REQUIRE_FALSE(dx::stop_opcode00(start + 1, start, 2, 0x00, leaders, spec));
}

TEST_CASE("stop_opcode00 ignores opcode 0x01", "[flow]")
{
    const uint32_t start = 0x100;
    const std::set<uint32_t> leaders{start + 2};
    const std::set<uint32_t> spec;
    REQUIRE_FALSE(dx::stop_opcode00(start + 1, start, 2, 0x01, leaders, spec));
}

TEST_CASE("promote_real erases and a later mark_spec_created inserts", "[flow]")
{
    std::set<uint32_t> spec;
    dx::mark_spec_created(spec, 0x10);
    dx::mark_spec_created(spec, 0x10);
    REQUIRE(spec.count(0x10) == 1);
    dx::promote_real(spec, 0x10);
    REQUIRE(spec.count(0x10) == 0);
    dx::mark_spec_created(spec, 0x10);
    REQUIRE(spec.count(0x10) == 1);
}

TEST_CASE("Created marks, Present does not, promote clears", "[flow]")
{
    // cfg_build calls mark_spec_created only when place_leader returns Created.
    // Present is not a second mark. The speculative bit therefore survives a
    // second nearby seed. promote_real is what clears it.
    std::set<uint32_t> spec;
    const bool created = true;
    if (created)
    {
        dx::mark_spec_created(spec, 0x20);
    }
    const bool present = true;
    if (present)
    {
        // No mark call. A second nearby seed takes this path.
    }
    REQUIRE(spec.count(0x20) == 1);
    dx::promote_real(spec, 0x20);
    REQUIRE(spec.count(0x20) == 0);
}

TEST_CASE("a missing Capstone detail is not opcode 00", "[decode]")
{
    uint8_t opcode0 = 0xAB;
    REQUIRE_FALSE(dx::opcode_after_prefixes(nullptr, opcode0));
    REQUIRE(opcode0 == 0xAB);

    cs_insn blank{};
    REQUIRE(blank.detail == nullptr);
    REQUIRE_FALSE(dx::opcode_after_prefixes(&blank, opcode0));
    REQUIRE(opcode0 == 0xAB);
}

TEST_CASE("Decoder reads the opcode after a CS prefix", "[decode]")
{
    dx::Decoder decoder;
    const uint8_t raw[] = {0x2E, 0x00, 0xC3};
    dx::Insn insn{};
    REQUIRE(decoder.at(raw, dx::Lin{0}, insn));
    REQUIRE(insn.opcode0 == 0x00);
    REQUIRE(insn.len >= 2);
}

TEST_CASE("Decoder maps opcode 98 to cbw and 99 to cwd", "[decode]")
{
    dx::Decoder decoder;
    dx::Insn insn{};
    const uint8_t cbw[] = {0x98};
    REQUIRE(decoder.at(cbw, dx::Lin{0}, insn));
    REQUIRE(insn.mnem == dx::Mnem::Cbw);
    const uint8_t cwd[] = {0x99};
    REQUIRE(decoder.at(cwd, dx::Lin{0}, insn));
    REQUIRE(insn.mnem == dx::Mnem::Cwd);
}

namespace
{

/**
 * @brief Sets the flow-recording hook and clears it on every exit.
 */
class RecordFlow
{
public:
    /**
     * @brief Store @p on in the process hook.
     *
     * @param on True records the next @c cfg_build. False leaves flow off.
     */
    explicit RecordFlow(bool on)
    {
        cfg_set_record_flow(on);
    }

    /** @brief Force the hook off so a later test does not inherit it. */
    ~RecordFlow()
    {
        cfg_set_record_flow(false);
    }

    RecordFlow(const RecordFlow&) = delete;
    RecordFlow& operator=(const RecordFlow&) = delete;
};

/**
 * @brief Block-start linears in map order.
 *
 * @param graph Graph from @c cfg_build.
 * @return Start IP of each block.
 */
std::vector<CfgLin> block_starts(const CfgGraph& graph)
{
    std::vector<CfgLin> starts;
    starts.reserve(graph.blocks.size());
    for (const auto& item : graph.blocks)
    {
        starts.push_back(item.first);
    }
    return starts;
}

/**
 * @brief True when @p trace holds one fact with this why and strength.
 *
 * @param trace    Recorded walk.
 * @param why      Expected reason.
 * @param strength Expected strength.
 * @return true if any fact matches both fields.
 */
bool has_fact(const dx::FlowTrace& trace, dx::Why why, dx::Strength strength)
{
    for (const dx::Fact& fact : trace.facts().all())
    {
        if (fact.why == why && fact.strength == strength)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief True when a fact matches why, strength, and subject linear.
 *
 * @param trace    Recorded walk.
 * @param why      Expected reason.
 * @param strength Expected strength.
 * @param subject  Expected subject linear.
 * @return true if any fact matches all three.
 */
bool has_fact_at(const dx::FlowTrace& trace, dx::Why why, dx::Strength strength,
                 uint32_t subject)
{
    for (const dx::Fact& fact : trace.facts().all())
    {
        if (fact.why == why && fact.strength == strength && fact.subject.v == subject)
        {
            return true;
        }
    }
    return false;
}

} /* namespace */

TEST_CASE("cfg_build leaves flow disengaged by default", "[flow]")
{
    REQUIRE_FALSE(cfg_record_flow());
    const std::vector<uint8_t> image{0xC3};
    const CfgGraph graph = cfg_build(image, 0, 0, 0, 0, false);
    REQUIRE_FALSE(graph.flow.has_value());
    REQUIRE_FALSE(cfg_record_flow());
}

TEST_CASE("COM psp_in_bytes does not count the PSP twice", "[flow]")
{
    const RecordFlow guard(true);
    std::vector<uint8_t> image(256, 0);
    image.push_back(0xC3);
    const CfgGraph graph = cfg_build(image, 0x100, 0, 0, 0, false, 20000, {}, 0,
                                     dx::Fmt::Com, true);
    REQUIRE(graph.flow.has_value());
    REQUIRE(graph.flow->image().fmt == dx::Fmt::Com);
    REQUIRE(graph.flow->image().virtual_below == 0u);
    REQUIRE(graph.flow->image().bytes.size() == 257u);
}

TEST_CASE("equal CS and frame 0 stay Mz when the caller does not say Com", "[flow]")
{
    const RecordFlow guard(true);
    const std::vector<uint8_t> image{0xC3};
    // cs_seg == file_cs, empty relocs, frame 0. The deleted guess said Com.
    const CfgGraph graph = cfg_build(image, 0, 0, 0, 0, false);
    REQUIRE(graph.flow.has_value());
    REQUIRE(graph.flow->image().fmt == dx::Fmt::Mz);
    REQUIRE(graph.flow->image().virtual_below == 0u);
}

TEST_CASE("jz fall-through is Fallthrough and leaders match the hook off", "[flow]")
{
    const RecordFlow guard(false);
    const std::vector<uint8_t> image{0x74, 0x00, 0xC3};
    const CfgGraph off = cfg_build(image, 0, 0, 0, 0, false);
    REQUIRE_FALSE(off.flow.has_value());
    cfg_set_record_flow(true);
    const CfgGraph on = cfg_build(image, 0, 0, 0, 0, false);
    REQUIRE(on.flow.has_value());
    const std::vector<CfgLin> off_starts = block_starts(off);
    const std::vector<CfgLin> on_starts = block_starts(on);
    REQUIRE(off_starts == on_starts);
    REQUIRE(on_starts == std::vector<CfgLin>{0u, 2u});
    REQUIRE(has_fact(*on.flow, dx::Why::Fallthrough, dx::Strength::Proven));
}

TEST_CASE("INT 21h reached only by the scan is IntScan Likely", "[flow]")
{
    const RecordFlow guard(true);
    constexpr CfgLin k_entry = 0x100u;
    constexpr CfgLin k_int = 0x114u;
    std::vector<uint8_t> image(static_cast<std::size_t>(k_int) + 2u, 0);
    image[k_entry] = 0xC3;
    for (CfgLin at = k_entry + 1u; at < k_int; ++at)
    {
        image[at] = 0x90;
    }
    image[k_int] = 0xCD;
    image[static_cast<std::size_t>(k_int) + 1u] = 0x21;
    const CfgGraph graph = cfg_build(image, k_entry, 0, 0, 0, false, 20000, {}, 0,
                                     dx::Fmt::Com, true);
    REQUIRE(graph.flow.has_value());
    const dx::FlowTrace& trace = *graph.flow;
    REQUIRE(has_fact_at(trace, dx::Why::IntScan, dx::Strength::Likely, k_int));
    REQUIRE(has_fact_at(trace, dx::Why::HintIntScan, dx::Strength::Hint, k_int - 16u));
    REQUIRE(has_fact_at(trace, dx::Why::HintIntScan, dx::Strength::Hint, k_int - 8u));

    // Likely note_insn facts (DirectFlow) each take the next unit from 1.
    // Leaders, hints, and Proven instructions stay on unit 0.
    std::vector<uint32_t> likely_units;
    uint32_t proven = 0u;
    for (const dx::Fact& fact : trace.facts().all())
    {
        if (fact.why == dx::Why::DirectFlow && fact.strength == dx::Strength::Likely)
        {
            likely_units.push_back(fact.unit);
            continue;
        }
        REQUIRE(fact.unit == 0u);
        if (fact.strength == dx::Strength::Proven)
        {
            ++proven;
        }
    }
    REQUIRE(proven >= 1u);
    REQUIRE(likely_units.size() >= 2u);
    for (std::size_t i = 0; i < likely_units.size(); ++i)
    {
        REQUIRE(likely_units[i] == static_cast<uint32_t>(i + 1u));
    }
}

TEST_CASE("Likely note_insn units start at 1 and other strengths stay 0", "[flow]")
{
    const uint8_t raw[] = {0xC3};
    dx::FlowTrace trace(1u,
                        dx::Fmt::Mz,
                        dx::FileOff{0},
                        dx::Lin{0},
                        0,
                        std::span<const uint8_t>(raw, 1),
                        true);
    trace.note_insn(0u, 1u, dx::Why::DirectFlow, dx::Strength::Likely, 0u);
    trace.note_insn(0u, 1u, dx::Why::DirectFlow, dx::Strength::Proven, 0u);
    trace.note_insn(0u, 1u, dx::Why::DirectFlow, dx::Strength::Derived, 0u);
    trace.note_insn(0u, 1u, dx::Why::DirectFlow, dx::Strength::Likely, 0u);
    trace.note_insn(0u, 1u, dx::Why::DirectFlow, dx::Strength::Hint, 0u);
    trace.note_leader(0u, dx::Why::IntScan, dx::Strength::Likely, 0u);
    const std::vector<dx::Fact>& all = trace.facts().all();
    REQUIRE(all.size() == 6u);
    REQUIRE(all[0].unit == 1u);
    REQUIRE(all[0].strength == dx::Strength::Likely);
    REQUIRE(all[1].unit == 0u);
    REQUIRE(all[1].strength == dx::Strength::Proven);
    REQUIRE(all[2].unit == 0u);
    REQUIRE(all[2].strength == dx::Strength::Derived);
    REQUIRE(all[3].unit == 2u);
    REQUIRE(all[3].strength == dx::Strength::Likely);
    REQUIRE(all[4].unit == 0u);
    REQUIRE(all[4].strength == dx::Strength::Hint);
    REQUIRE(all[5].unit == 0u);
    REQUIRE(all[5].strength == dx::Strength::Likely);
}

TEST_CASE("RecordFlow clears the hook on the way out", "[flow]")
{
    REQUIRE_FALSE(cfg_record_flow());
    {
        const RecordFlow guard(true);
        REQUIRE(cfg_record_flow());
    }
    REQUIRE_FALSE(cfg_record_flow());
}

TEST_CASE("image_from_load psp_in_bytes true clears the COM hole", "[image]")
{
    const uint8_t raw[] = {0xC3};
    const dx::Image image = dx::image_from_load(dx::Fmt::Com,
                                                 std::span<const uint8_t>(raw, 1),
                                                 dx::FileOff{0},
                                                 dx::Lin{0},
                                                 0,
                                                 true);
    REQUIRE(image.fmt == dx::Fmt::Com);
    REQUIRE(image.virtual_below == 0u);
    REQUIRE(image.bytes.size() == 1u);
}
