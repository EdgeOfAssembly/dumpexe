/**
 * @file test_p1_model.cpp
 * @brief Catch2 checks for the P1 image, fact store, and byte map.
 *
 * DX_BYTEMAP_AUDIT turns on the full-map invariant scan. The product
 * build leaves it off so a long walk does not rescan the map per claim.
 */
#define DX_BYTEMAP_AUDIT 1
#include "bytemap.h"
#include "facts.h"
#include "image_model.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace
{

dx::Fact fact_at(dx::Why why,
                 dx::Strength strength,
                 uint32_t unit,
                 uint32_t subject = 0)
{
    dx::Fact fact{};
    fact.why = why;
    fact.strength = strength;
    fact.subject = dx::Lin{subject};
    fact.source = dx::Lin{0};
    fact.unit = unit;
    fact.round = 0;
    fact.aux = 0;
    return fact;
}

} /* namespace */

TEST_CASE("image_from_load COM virtual_below and negative frame", "[image]")
{
    const uint8_t raw[] = {0xC3, 0x90, 0x90};
    const std::span<const uint8_t> bytes(raw, 3);
    const dx::Image image = dx::image_from_load(dx::Fmt::Com,
                                                 bytes,
                                                 dx::FileOff{0},
                                                 dx::Lin{0},
                                                 -16);
    REQUIRE(image.fmt == dx::Fmt::Com);
    REQUIRE(image.virtual_below == 0x100u);
    REQUIRE(image.bytes.size() == 3u);
    REQUIRE(image.bytes[0] == 0xC3);
    REQUIRE(image.bytes[2] == 0x90);
    REQUIRE(image.relocs.empty());
    REQUIRE(image.segments.size() == 1u);
    REQUIRE(image.segments[0].id == 0u);
    REQUIRE(image.segments[0].size == 3u);
    REQUIRE(image.segments[0].kind == dx::SegKind::Code);
    REQUIRE(image.segments[0].below_image);
    REQUIRE(image.segments[0].base_lin.v == 0u);
    REQUIRE(image.segments[0].base_lin.v != 0xffffffffu);
    REQUIRE(image.segments[0].file_para.v == 0u);
    REQUIRE(image.entries.size() == 1u);
    REQUIRE(image.entries[0].kind == dx::EntryPoint::Kind::ComStart);
    REQUIRE(image.entries[0].where.frame == 0u);
    REQUIRE(image.entries[0].where.off == 0u);
    REQUIRE(dx::lin_in_image(image, dx::Lin{0}));
    REQUIRE(dx::lin_in_image(image, dx::Lin{2}));
    REQUIRE_FALSE(dx::lin_in_image(image, dx::Lin{3}));

    const uint8_t one[] = {0x90};
    const dx::Image mz = dx::image_from_load(dx::Fmt::Mz,
                                              std::span<const uint8_t>(one, 1),
                                              dx::FileOff{0x20},
                                              dx::Lin{0},
                                              0);
    REQUIRE(mz.virtual_below == 0u);
    REQUIRE(mz.image_file_base.v == 0x20u);
    REQUIRE_FALSE(mz.segments[0].below_image);
    REQUIRE(mz.segments[0].base_lin.v == 0u);
    REQUIRE(mz.segments[0].kind == dx::SegKind::Code);
    REQUIRE(mz.entries[0].kind == dx::EntryPoint::Kind::MzCsIp);
    REQUIRE(mz.entries[0].where.off == 0u);
    REQUIRE(mz.relocs.empty());
}

TEST_CASE("image_from_load stores a fitting SegOff and truncates otherwise", "[image]")
{
    const uint8_t raw[] = {0x90, 0x90};
    const std::span<const uint8_t> bytes(raw, 2);
    const dx::Image fit = dx::image_from_load(dx::Fmt::Mz,
                                               bytes,
                                               dx::FileOff{0},
                                               dx::Lin{0x0100},
                                               0);
    REQUIRE_FALSE(fit.segments[0].below_image);
    REQUIRE(fit.segments[0].base_lin.v == 0u);
    REQUIRE(fit.entries.size() == 1u);
    REQUIRE(fit.entries[0].where.frame == 0u);
    REQUIRE(fit.entries[0].where.off == 0x0100u);

    const dx::Image huge = dx::image_from_load(dx::Fmt::Mz,
                                                bytes,
                                                dx::FileOff{0},
                                                dx::Lin{0x10001},
                                                0x1000);
    REQUIRE_FALSE(huge.segments[0].below_image);
    REQUIRE(huge.segments[0].base_lin.v == 0u);
    REQUIRE(huge.entries[0].where.off == 0x0001u);

    const dx::Image neg = dx::image_from_load(dx::Fmt::Mz,
                                               bytes,
                                               dx::FileOff{0},
                                               dx::Lin{0x0100},
                                               -1);
    REQUIRE(neg.segments[0].below_image);
    REQUIRE(neg.segments[0].base_lin.v == 0u);
    REQUIRE(neg.entries[0].where.off == 0x0100u);
    REQUIRE(neg.entries[0].where.frame == 0u);
}

TEST_CASE("hint claim_code leaves every cell Unknown", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact hint = fact_at(dx::Why::HintIntScan, dx::Strength::Hint, 7u, 0u);
    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 2, 11u, hint));
    REQUIRE_FALSE(map.claim_data(dx::Lin{0}, 2, dx::DType::Word, 11u, hint));
    REQUIRE_FALSE(map.claim_padding(dx::Lin{0}, 2, dx::PadKind::ZeroFill, hint));
    REQUIRE(map.size() == 4u);
    for (uint32_t i = 0; i < map.size(); ++i)
    {
        const dx::ByteCell& cell = map.at(dx::Lin{i});
        REQUIRE(cell.state == dx::BState::Unknown);
        REQUIRE(cell.strength == 0u);
        REQUIRE(cell.item == 0u);
        REQUIRE(cell.flags == 0u);
    }
    REQUIRE(map.at(dx::Lin{99}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{99}).strength == 0u);
}

TEST_CASE("claim_code of length 2 writes head then tail", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact why = fact_at(dx::Why::DirectFlow, dx::Strength::Proven, 3u, 1u);
    REQUIRE(map.claim_code(dx::Lin{1}, 2, 42u, why));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{2}).state == dx::BState::CodeTail);
    REQUIRE(map.at(dx::Lin{3}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{1}).item == 42u);
    REQUIRE(map.at(dx::Lin{2}).item == 42u);
    REQUIRE(map.at(dx::Lin{1}).strength == static_cast<uint8_t>(dx::Strength::Proven));
    REQUIRE(map.at(dx::Lin{2}).strength == static_cast<uint8_t>(dx::Strength::Proven));
    REQUIRE((map.at(dx::Lin{1}).flags & static_cast<uint16_t>(dx::F_Speculative)) == 0u);

    dx::ByteMap likely_map(2);
    const dx::Fact likely = fact_at(dx::Why::CallFallthroughSpec, dx::Strength::Likely, 1u, 0u);
    REQUIRE(likely_map.claim_code(dx::Lin{0}, 2, 8u, likely));
    const uint16_t spec = static_cast<uint16_t>(dx::F_Speculative);
    REQUIRE((likely_map.at(dx::Lin{0}).flags & spec) == spec);
    REQUIRE((likely_map.at(dx::Lin{1}).flags & spec) == spec);
    REQUIRE(likely_map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(likely_map.at(dx::Lin{1}).state == dx::BState::CodeTail);
}

TEST_CASE("weaker claim_code on the same head is rejected", "[bytemap]")
{
    dx::ByteMap map(2);
    const dx::Fact strong = fact_at(dx::Why::Entry, dx::Strength::Proven, 1u, 0u);
    const dx::Fact weak = fact_at(dx::Why::CallFallthroughSpec, dx::Strength::Likely, 2u, 0u);
    REQUIRE(map.claim_code(dx::Lin{0}, 1, 5u, strong));
    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 1, 9u, weak));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 5u);
    REQUIRE(map.at(dx::Lin{0}).strength == static_cast<uint8_t>(dx::Strength::Proven));
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::Unknown);

    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 2, 9u, weak));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 5u);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::Unknown);
}

TEST_CASE("equal-strength code overlap sets Conflict and keeps the old item", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact first = fact_at(dx::Why::DirectJmp, dx::Strength::Proven, 1u, 0u);
    const dx::Fact second = fact_at(dx::Why::DirectCall, dx::Strength::Proven, 2u, 1u);
    REQUIRE(map.claim_code(dx::Lin{0}, 2, 5u, first));
    REQUIRE_FALSE(map.claim_code(dx::Lin{1}, 2, 8u, second));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 5u);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::Conflict);
    REQUIRE(map.at(dx::Lin{1}).item == 5u);
    REQUIRE(map.at(dx::Lin{1}).sub == static_cast<uint8_t>(dx::ConflictKind::Overlap));
    REQUIRE(map.at(dx::Lin{2}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{2}).item == 0u);

    dx::ByteMap same(1);
    REQUIRE(same.claim_code(dx::Lin{0}, 1, 5u, first));
    REQUIRE_FALSE(same.claim_code(dx::Lin{0}, 1, 8u, second));
    REQUIRE(same.at(dx::Lin{0}).state == dx::BState::Conflict);
    REQUIRE(same.at(dx::Lin{0}).item == 5u);
}

TEST_CASE("stronger code overlap conflicts and does not replace the item", "[bytemap]")
{
    dx::ByteMap map(2);
    const dx::Fact likely = fact_at(dx::Why::CallFallthroughSpec, dx::Strength::Likely, 2u, 0u);
    const dx::Fact proven = fact_at(dx::Why::DirectJmp, dx::Strength::Proven, 3u, 0u);
    REQUIRE(map.claim_code(dx::Lin{0}, 2, 4u, likely));
    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 2, 9u, proven));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::Conflict);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::Conflict);
    REQUIRE(map.at(dx::Lin{0}).item == 4u);
    REQUIRE(map.at(dx::Lin{1}).item == 4u);
}

TEST_CASE("retract(unit) restores Unknown and retract(0) does not", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact anchored = fact_at(dx::Why::Entry, dx::Strength::Proven, 0u, 0u);
    const dx::Fact unit = fact_at(dx::Why::DirectFlow, dx::Strength::Likely, 4u, 1u);
    REQUIRE(map.claim_code(dx::Lin{0}, 1, 1u, anchored));
    REQUIRE(map.claim_code(dx::Lin{1}, 2, 2u, unit));
    REQUIRE((map.at(dx::Lin{1}).flags & static_cast<uint16_t>(dx::F_Speculative))
            == static_cast<uint16_t>(dx::F_Speculative));

    map.retract(0);
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 1u);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{2}).state == dx::BState::CodeTail);

    map.retract(4);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{2}).state == dx::BState::Unknown);
    REQUIRE(map.at(dx::Lin{1}).strength == 0u);
    REQUIRE(map.at(dx::Lin{2}).strength == 0u);
    REQUIRE(map.at(dx::Lin{1}).item == 0u);
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 1u);

    map.retract(4);
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 1u);
}

TEST_CASE("rejected lengths and out-of-range claims change nothing", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact why = fact_at(dx::Why::DirectFlow, dx::Strength::Proven, 1u, 0u);
    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 0, 1u, why));
    REQUIRE_FALSE(map.claim_code(dx::Lin{0}, 16, 1u, why));
    REQUIRE_FALSE(map.claim_code(dx::Lin{3}, 2, 1u, why));
    REQUIRE_FALSE(map.claim_code(dx::Lin{4}, 1, 1u, why));
    REQUIRE_FALSE(map.claim_data(dx::Lin{0}, 0, dx::DType::Byte, 1u, why));
    REQUIRE_FALSE(map.claim_padding(dx::Lin{2}, 4, dx::PadKind::Align, why));
    for (uint32_t i = 0; i < map.size(); ++i)
    {
        REQUIRE(map.at(dx::Lin{i}).state == dx::BState::Unknown);
    }
    REQUIRE(map.claim_code(dx::Lin{0}, 15, 3u, why) == false);
    dx::ByteMap wide(15);
    REQUIRE(wide.claim_code(dx::Lin{0}, 15, 3u, why));
    REQUIRE(wide.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(wide.at(dx::Lin{14}).state == dx::BState::CodeTail);
    REQUIRE(wide.at(dx::Lin{14}).item == 3u);
}

TEST_CASE("data on code and padding replacement", "[bytemap]")
{
    dx::ByteMap map(4);
    const dx::Fact code = fact_at(dx::Why::Entry, dx::Strength::Proven, 1u, 0u);
    REQUIRE(map.claim_code(dx::Lin{0}, 2, 3u, code));
    const dx::Fact weak = fact_at(dx::Why::DirectFlow, dx::Strength::Likely, 2u, 0u);
    REQUIRE_FALSE(map.claim_data(dx::Lin{0}, 2, dx::DType::Word, 9u, weak));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(map.at(dx::Lin{0}).item == 3u);
    REQUIRE(map.at(dx::Lin{1}).state == dx::BState::CodeTail);

    const dx::Fact strong = fact_at(dx::Why::DirectFlow, dx::Strength::Proven, 4u, 0u);
    REQUIRE_FALSE(map.claim_data(dx::Lin{0}, 1, dx::DType::Byte, 9u, strong));
    REQUIRE(map.at(dx::Lin{0}).state == dx::BState::Conflict);
    REQUIRE(map.at(dx::Lin{0}).item == 3u);
    REQUIRE(map.at(dx::Lin{0}).sub == static_cast<uint8_t>(dx::ConflictKind::DataOnCode));

    dx::ByteMap pad_map(3);
    const dx::Fact pad = fact_at(dx::Why::DirectFlow, dx::Strength::Proven, 1u, 0u);
    REQUIRE(pad_map.claim_padding(dx::Lin{0}, 2, dx::PadKind::ZeroFill, pad));
    REQUIRE(pad_map.at(dx::Lin{0}).state == dx::BState::Padding);
    REQUIRE(pad_map.at(dx::Lin{0}).dtype_or_pad == static_cast<uint8_t>(dx::PadKind::ZeroFill));
    const dx::Fact later = fact_at(dx::Why::DirectFlow, dx::Strength::Likely, 2u, 0u);
    REQUIRE(pad_map.claim_code(dx::Lin{0}, 2, 8u, later));
    REQUIRE(pad_map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(pad_map.at(dx::Lin{1}).state == dx::BState::CodeTail);
    REQUIRE(pad_map.at(dx::Lin{0}).item == 8u);
    pad_map.retract(1);
    REQUIRE(pad_map.at(dx::Lin{0}).state == dx::BState::CodeHead);
    REQUIRE(pad_map.at(dx::Lin{1}).state == dx::BState::CodeTail);
    REQUIRE_FALSE(pad_map.claim_padding(dx::Lin{0}, 1, dx::PadKind::Align, strong));
    REQUIRE(pad_map.at(dx::Lin{0}).state == dx::BState::CodeHead);
}

TEST_CASE("FactStore::at is insertion order", "[facts]")
{
    dx::FactStore store;
    dx::Fact first = fact_at(dx::Why::Entry, dx::Strength::Proven, 0u, 5u);
    first.round = 1;
    first.aux = 0;
    dx::Fact other = fact_at(dx::Why::DirectJmp, dx::Strength::Proven, 0u, 9u);
    other.source = dx::Lin{5};
    other.round = 1;
    other.aux = 1;
    dx::Fact third = fact_at(dx::Why::DirectCall, dx::Strength::Derived, 0u, 5u);
    third.source = dx::Lin{1};
    third.round = 2;
    third.aux = 2;
    store.add(first);
    store.add(other);
    store.add(third);

    const std::vector<dx::Fact> got = store.at(dx::Lin{5});
    REQUIRE(got.size() == 2u);
    REQUIRE(got[0].why == dx::Why::Entry);
    REQUIRE(got[0].round == 1u);
    REQUIRE(got[1].why == dx::Why::DirectCall);
    REQUIRE(got[1].aux == 2u);
    REQUIRE(got[1].strength == dx::Strength::Derived);
    REQUIRE(store.all().size() == 3u);
    REQUIRE(store.all()[1].subject.v == 9u);
    const std::vector<dx::Fact> at_nine = store.at(dx::Lin{9});
    REQUIRE(at_nine.size() == 1u);
    REQUIRE(at_nine[0].source.v == 5u);
    REQUIRE(store.at(dx::Lin{4}).empty());
}
