// pair_key / pair_verified bounds: a unit past the image (or empty) is
// rejected before any byte is read or handed to Capstone.
#include <catch2/catch_test_macros.hpp>
#include "emit_uasm.h"

using namespace dx;

namespace {
struct Fixture
{
    std::vector<uint8_t> img{0x90, 0xB8, 0x34, 0x12, 0xEB}; // nop; mov ax,1234h; jmp short (cut)
    CfgGraph g;
    UasmEmitter e{g, [this] { EmitInput in; in.image = &img; return in; }()};
};
EmitUnit unit(uint32_t lin, uint32_t size)
{
    EmitUnit u;
    u.lin = lin;
    u.size = size;
    u.code = true;
    return u;
}
} // namespace

TEST_CASE("pair_key rejects units outside the image before decoding")
{
    Fixture f;
    CHECK_FALSE(f.e.pair_key(unit(1, 3)).empty());   // in bounds: mov ax,imm16
    CHECK(f.e.pair_key(unit(4, 2)).empty());         // runs one byte past the end
    CHECK(f.e.pair_key(unit(5, 1)).empty());         // starts at the end
    CHECK(f.e.pair_key(unit(0xFFFFFFF0u, 3)).empty()); // far past, no wrap
    CHECK(f.e.pair_key(unit(0, 0)).empty());         // empty unit
}

TEST_CASE("pair_verified checks the length before reading the first byte")
{
    Fixture f;
    EmitUnit u = unit(5, 2);                         // past the end
    u.refs.push_back(InsnRef{});
    u.refs[0].kind = RefKind::Rel;
    CHECK_FALSE(f.e.pair_verified(u));
    CHECK_FALSE(f.e.pair_verified(unit(0, 0)));
    CHECK_FALSE(f.e.pair_verified(unit(0xFFFFFFF0u, 3)));
}
