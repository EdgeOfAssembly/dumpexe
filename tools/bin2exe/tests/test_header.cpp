/**
 * @file test_header.cpp
 * @brief Catch2 checks for MZ page fields, the COM wrap, and header copy.
 */
#include "bin2exe/header.hpp"
#include "bin2exe/mz_pages.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

namespace
{

std::uint16_t le16(const std::vector<std::uint8_t> &bytes, std::size_t offset)
{
    return static_cast<std::uint16_t>(
        static_cast<unsigned>(bytes.at(offset)) |
        (static_cast<unsigned>(bytes.at(offset + 1u)) << 8));
}

} /* namespace */

TEST_CASE("page fields use a zero remainder for a full page", "[pages]")
{
    std::uint16_t cblp = 9;
    std::uint16_t cp = 9;
    REQUIRE(mz_page_fields(512u, &cblp, &cp) == 0);
    REQUIRE(cblp == 0);
    REQUIRE(cp == 1);
    REQUIRE(mz_page_fields(37u, &cblp, &cp) == 0);
    REQUIRE(cblp == 37);
    REQUIRE(cp == 1);
    REQUIRE(mz_page_fields(513u, &cblp, &cp) == 0);
    REQUIRE(cblp == 1);
    REQUIRE(cp == 2);
    const std::uint16_t kept_cblp = cblp;
    const std::uint16_t kept_cp = cp;
    REQUIRE(mz_page_fields(0u, &cblp, &cp) == -1);
    REQUIRE(cblp == kept_cblp);
    REQUIRE(cp == kept_cp);
    REQUIRE(mz_page_fields(512u * 65535u, &cblp, &cp) == 0);
    REQUIRE(cblp == 0);
    REQUIRE(cp == 65535);
    REQUIRE(mz_page_fields(512u * 65535u + 1u, &cblp, &cp) == -1);
    REQUIRE(mz_page_fields(10u, nullptr, &cp) == -1);
    REQUIRE(mz_page_fields(10u, &cblp, nullptr) == -1);
}

TEST_CASE("COM wrap enters at PSP:0100", "[wrap]")
{
    const std::uint8_t image[] = {0xB8, 0x00, 0x4C, 0xCD, 0x21};
    const bin2exe::build_result built = bin2exe::wrap_com(image);
    REQUIRE(built.code == bin2exe::status::ok);
    REQUIRE(built.bytes.size() == 37u);
    REQUIRE(built.bytes[0] == static_cast<std::uint8_t>('M'));
    REQUIRE(built.bytes[1] == static_cast<std::uint8_t>('Z'));
    REQUIRE(le16(built.bytes, 2) == 37);
    REQUIRE(le16(built.bytes, 4) == 1);
    REQUIRE(le16(built.bytes, 6) == 0);
    REQUIRE(le16(built.bytes, 8) == 2);
    REQUIRE(le16(built.bytes, 10) == 0);
    REQUIRE(le16(built.bytes, 12) == 0xFFFF);
    REQUIRE(le16(built.bytes, 14) == 0xFFF0);
    REQUIRE(le16(built.bytes, 16) == 0xFFFE);
    REQUIRE(le16(built.bytes, 18) == 0);
    REQUIRE(le16(built.bytes, 20) == 0x0100);
    REQUIRE(le16(built.bytes, 22) == 0xFFF0);
    REQUIRE(le16(built.bytes, 24) == 0x001C);
    REQUIRE(le16(built.bytes, 26) == 0);
    REQUIRE(built.bytes[28] == 0);
    REQUIRE(built.bytes[31] == 0);
    REQUIRE(built.bytes[32] == 0xB8);
    REQUIRE(built.bytes[36] == 0x21);
    REQUIRE_FALSE(built.payload_length_differs);
}

TEST_CASE("COM wrap rejects empty and oversize images", "[wrap]")
{
    const bin2exe::build_result empty = bin2exe::wrap_com({});
    REQUIRE(empty.code == bin2exe::status::empty_image);
    REQUIRE(empty.bytes.empty());

    std::vector<std::uint8_t> big(bin2exe::k_com_image_max + 1u, 0x90);
    REQUIRE(bin2exe::wrap_com(big).code == bin2exe::status::com_too_large);

    std::vector<std::uint8_t> maxed(bin2exe::k_com_image_max, 0x90);
    const bin2exe::build_result ok = bin2exe::wrap_com(maxed);
    REQUIRE(ok.code == bin2exe::status::ok);
    REQUIRE(ok.bytes.size() == bin2exe::k_com_header_bytes + bin2exe::k_com_image_max);
    std::uint16_t cblp = 0;
    std::uint16_t cp = 0;
    REQUIRE(mz_page_fields(static_cast<std::uint32_t>(ok.bytes.size()), &cblp, &cp) == 0);
    REQUIRE(le16(ok.bytes, 2) == cblp);
    REQUIRE(le16(ok.bytes, 4) == cp);
}

TEST_CASE("header copy keeps the original bytes", "[header]")
{
    std::vector<std::uint8_t> exe(64u, 0);
    exe[0] = static_cast<std::uint8_t>('M');
    exe[1] = static_cast<std::uint8_t>('Z');
    exe[2] = 0x99;
    exe[8] = 4;
    exe[14] = 0x84;
    exe[15] = 0x17;
    exe[28] = 0x67;
    exe[63] = 0xAB;
    const std::uint8_t image[] = {1, 2, 3, 4};
    std::vector<std::uint8_t> full = exe;
    full.insert(full.end(), image, image + 4);
    const bin2exe::build_result built = bin2exe::copy_mz_header(full, full.size(), image, true);
    REQUIRE(built.code == bin2exe::status::ok);
    REQUIRE_FALSE(built.tail_appended);
    REQUIRE_FALSE(built.payload_length_differs);
    REQUIRE(built.original_payload_bytes == 4u);
    REQUIRE(built.bytes == full);

    const std::uint8_t shorter[] = {9, 9};
    const bin2exe::build_result mismatch = bin2exe::copy_mz_header(full, full.size(), shorter, true);
    REQUIRE(mismatch.code == bin2exe::status::ok);
    REQUIRE_FALSE(mismatch.tail_appended);
    REQUIRE(mismatch.payload_length_differs);
    REQUIRE(mismatch.original_payload_bytes == 4u);
    REQUIRE(mismatch.bytes.size() == 66u);
    REQUIRE(mismatch.bytes[2] == 0x99);
    REQUIRE(mismatch.bytes[14] == 0x84);
    REQUIRE(mismatch.bytes[15] == 0x17);
    REQUIRE(mismatch.bytes[63] == 0xAB);
    REQUIRE(mismatch.bytes[64] == 9);
    REQUIRE(mismatch.bytes[65] == 9);
}

TEST_CASE("header copy rejects a bad EXE", "[header]")
{
    const std::uint8_t image[] = {1};
    std::vector<std::uint8_t> nope(32u, 1);
    REQUIRE(bin2exe::copy_mz_header(nope, nope.size(), image, true).code == bin2exe::status::not_mz);

    std::vector<std::uint8_t> tiny(32u, 0);
    tiny[0] = static_cast<std::uint8_t>('M');
    tiny[1] = static_cast<std::uint8_t>('Z');
    tiny[8] = 1;
    REQUIRE(bin2exe::copy_mz_header(tiny, tiny.size(), image, true).code ==
            bin2exe::status::header_too_small);

    std::vector<std::uint8_t> zm(32u, 0);
    zm[0] = static_cast<std::uint8_t>('Z');
    zm[1] = static_cast<std::uint8_t>('M');
    zm[8] = 2;
    const bin2exe::build_result zm_built = bin2exe::copy_mz_header(zm, 33u, image, true);
    REQUIRE(zm_built.code == bin2exe::status::ok);
    REQUIRE(zm_built.bytes[0] == static_cast<std::uint8_t>('Z'));
    REQUIRE_FALSE(zm_built.payload_length_differs);

    std::vector<std::uint8_t> short_prefix(32u, 0);
    short_prefix[0] = static_cast<std::uint8_t>('M');
    short_prefix[1] = static_cast<std::uint8_t>('Z');
    short_prefix[8] = 4;
    REQUIRE(bin2exe::copy_mz_header(short_prefix, 100u, image, true).code ==
            bin2exe::status::header_truncated);

    std::vector<std::uint8_t> huge(32u, 0);
    huge[0] = static_cast<std::uint8_t>('M');
    huge[1] = static_cast<std::uint8_t>('Z');
    huge[8] = 0x01;
    huge[9] = 0x10;
    REQUIRE(bin2exe::copy_mz_header(huge, 70000u, image, true).code ==
            bin2exe::status::header_too_large);

    REQUIRE(bin2exe::copy_mz_header(zm, zm.size(), {}, true).code == bin2exe::status::empty_image);
}

TEST_CASE("header copy appends a matching tail and skips a non-prefix", "[header]")
{
    std::vector<std::uint8_t> header(64u, 0);
    header[0] = static_cast<std::uint8_t>('M');
    header[1] = static_cast<std::uint8_t>('Z');
    header[8] = 4;
    const std::vector<std::uint8_t> payload = {1, 2, 3, 4};
    const std::vector<std::uint8_t> tail = {0xAA, 0xBB, 0xCC};
    std::vector<std::uint8_t> full = header;
    full.insert(full.end(), payload.begin(), payload.end());
    full.insert(full.end(), tail.begin(), tail.end());

    const std::vector<std::uint8_t> prefix = {1, 2};
    const bin2exe::build_result appended =
        bin2exe::copy_mz_header(full, full.size(), prefix, true);
    REQUIRE(appended.code == bin2exe::status::ok);
    REQUIRE(appended.tail_appended);
    REQUIRE(appended.payload_length_differs);
    REQUIRE(appended.original_payload_bytes == 7u);
    REQUIRE(appended.bytes == full);

    const bin2exe::build_result omitted =
        bin2exe::copy_mz_header(full, full.size(), prefix, false);
    REQUIRE(omitted.code == bin2exe::status::ok);
    REQUIRE_FALSE(omitted.tail_appended);
    REQUIRE(omitted.payload_length_differs);
    REQUIRE(omitted.bytes.size() == 66u);
    REQUIRE(omitted.bytes[64] == 1);
    REQUIRE(omitted.bytes[65] == 2);

    const std::vector<std::uint8_t> different = {9, 9, 9, 9};
    const bin2exe::build_result mismatch =
        bin2exe::copy_mz_header(full, full.size(), different, true);
    REQUIRE(mismatch.code == bin2exe::status::ok);
    REQUIRE_FALSE(mismatch.tail_appended);
    REQUIRE(mismatch.bytes.size() == 68u);
    REQUIRE(mismatch.bytes[64] == 9);

    std::vector<std::uint8_t> short_file = header;
    short_file.insert(short_file.end(), payload.begin(), payload.end());
    const bin2exe::build_result missing_tail =
        bin2exe::copy_mz_header(short_file, short_file.size() + 10u, payload, true);
    REQUIRE(missing_tail.code == bin2exe::status::ok);
    REQUIRE_FALSE(missing_tail.tail_appended);
    REQUIRE(missing_tail.payload_length_differs);
    REQUIRE(missing_tail.bytes.size() == short_file.size());
}
