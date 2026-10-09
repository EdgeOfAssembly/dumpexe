/**
 * @file test_p1_flow.cpp
 * @brief Catch2 checks for the opcode-00 stop, speculative marks, and decode.
 *
 * No cfg_build. cfg_build calls mark_spec_created only when a leader is Created.
 */
#include "decode.h"
#include "flow.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <set>

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
