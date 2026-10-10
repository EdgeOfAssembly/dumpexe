/**
 * @file harness_bytemap_claim.c
 * @brief Concrete gcc checks and CBMC proofs for the code-claim core.
 *
 * The live map length is 8. Loops in the core are bounded by that length
 * so --unwind 8 is enough.
 */
#include "bytemap_claim.h"

#ifdef __CPROVER__
uint8_t nondet_uint8_t(void);
#else
#include <assert.h>
#define __CPROVER_assert(cond, msg) \
    do                              \
    {                               \
        (void)(msg);                \
        assert(cond);               \
    }                               \
    while (0)
#endif

_Static_assert(BM_CLAIM_LEN == 8, "claim harness map length is 8");

/**
 * @brief True when @p cell is a zero unknown cell.
 *
 * @param[in] cell Cell. Not null.
 * @return true when every field is clear.
 */
static bool bm_is_unknown(const struct BmCell* cell)
{
    return cell->state == (uint8_t)BM_UNKNOWN
        && cell->strength == 0u
        && cell->span == 0u
        && cell->item == 0u
        && cell->unit == 0u;
}

/**
 * @brief True when every live cell is unknown and the length is 8.
 *
 * @param[in] map Map. Not null.
 * @return true when @p map is the post-init state.
 */
static bool bm_map_unknown(const struct BmMap* map)
{
    /* Same reason as bm_init: a loop of all 8 cells trips CBMC --unwind 8. */
    if (map->len != BM_CLAIM_LEN)
    {
        return false;
    }
    return bm_is_unknown(&map->cell[0])
        && bm_is_unknown(&map->cell[1])
        && bm_is_unknown(&map->cell[2])
        && bm_is_unknown(&map->cell[3])
        && bm_is_unknown(&map->cell[4])
        && bm_is_unknown(&map->cell[5])
        && bm_is_unknown(&map->cell[6])
        && bm_is_unknown(&map->cell[7]);
}

#ifdef __CPROVER__
/**
 * @brief Field-wise equality.
 *
 * @param[in] a First cell. Not null.
 * @param[in] b Second cell. Not null.
 * @return true when every field matches.
 */
static bool bm_same(const struct BmCell* a, const struct BmCell* b)
{
    return a->state == b->state
        && a->strength == b->strength
        && a->span == b->span
        && a->item == b->item
        && a->unit == b->unit;
}
#endif

/**
 * @brief Concrete witnesses for every claim rule. Runs under gcc and CBMC.
 */
static void check_examples(void)
{
    struct BmMap map;
    uint32_t i = 0u;
    bool ok = false;

    bm_init(&map);
    __CPROVER_assert(bm_map_unknown(&map), "init is 8 unknown cells");

    ok = bm_claim_code(&map, 0u, 0u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "length 0 refused");
    __CPROVER_assert(bm_map_unknown(&map), "length 0 writes nothing");

    ok = bm_claim_code(&map, 0u, 16u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "length 16 refused");
    __CPROVER_assert(bm_map_unknown(&map), "length 16 writes nothing");

    ok = bm_claim_code(&map, 0u, 255u, 1u, (uint8_t)BM_ST_LIKELY, 1u);
    __CPROVER_assert(!ok, "length 255 refused");
    __CPROVER_assert(bm_map_unknown(&map), "length 255 writes nothing");

    ok = bm_claim_code(&map, 6u, 3u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "6+3 does not fit");
    ok = bm_claim_code(&map, 8u, 1u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "head 8 does not fit");
    ok = bm_claim_code(&map, 0u, 9u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "length 9 does not fit");
    ok = bm_claim_code(&map, 7u, 2u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "7+2 does not fit");
    ok = bm_claim_code(&map, 0u, 15u, 1u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(!ok, "length 15 does not fit in 8");
    __CPROVER_assert(bm_map_unknown(&map), "a range that does not fit writes nothing");

    ok = bm_claim_code(&map, 0u, 2u, 1u, 0u, 1u);
    __CPROVER_assert(!ok, "strength 0 refused");
    __CPROVER_assert(bm_map_unknown(&map), "strength below Likely writes nothing");

    ok = bm_claim_code(&map, 1u, 3u, 42u, (uint8_t)BM_ST_PROVEN, 7u);
    __CPROVER_assert(ok, "first claim at 1 len 3");
    __CPROVER_assert(bm_is_unknown(&map.cell[0]), "byte 0 stays unknown");
    __CPROVER_assert(map.cell[1].state == (uint8_t)BM_CODE_HEAD, "byte 1 is the head");
    __CPROVER_assert(map.cell[2].state == (uint8_t)BM_CODE_TAIL, "byte 2 is a tail");
    __CPROVER_assert(map.cell[3].state == (uint8_t)BM_CODE_TAIL, "byte 3 is a tail");
    for (i = 1u; i <= 3u; ++i)
    {
        __CPROVER_assert(map.cell[i].item == 42u, "first claim item");
        __CPROVER_assert(map.cell[i].strength == (uint8_t)BM_ST_PROVEN, "first claim strength");
        __CPROVER_assert(map.cell[i].span == 3u, "first claim span");
        __CPROVER_assert(map.cell[i].unit == 7u, "first claim unit");
    }
    for (i = 4u; i < BM_CLAIM_LEN; ++i)
    {
        __CPROVER_assert(bm_is_unknown(&map.cell[i]), "bytes past the first claim stay unknown");
    }

    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 1u, 3u, (uint8_t)BM_ST_LIKELY, 1u);
    __CPROVER_assert(ok, "length 1 first claim");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CODE_HEAD, "single byte is a head");
    __CPROVER_assert(map.cell[0].item == 3u, "length 1 item");
    __CPROVER_assert(bm_is_unknown(&map.cell[1]), "no tail on a 1-byte claim");

    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 8u, 3u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(ok, "full-map first claim");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CODE_HEAD, "full map head");
    __CPROVER_assert(map.cell[7].state == (uint8_t)BM_CODE_TAIL, "full map last tail");
    __CPROVER_assert(map.cell[7].item == 3u, "full map item");
    __CPROVER_assert(map.cell[7].span == 8u, "full map span");

    /* Refused claims must not clobber a claim that is already there. */
    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 2u, 5u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(ok, "anchor claim");
    __CPROVER_assert(!bm_claim_code(&map, 0u, 0u, 9u, (uint8_t)BM_ST_PROVEN, 2u),
                     "bad len on a live map");
    __CPROVER_assert(!bm_claim_code(&map, 0u, 16u, 9u, (uint8_t)BM_ST_PROVEN, 2u),
                     "len 16 on a live map");
    __CPROVER_assert(!bm_claim_code(&map, 7u, 2u, 9u, (uint8_t)BM_ST_PROVEN, 2u),
                     "overflow on a live map");
    __CPROVER_assert(!bm_claim_code(&map, 2u, 1u, 9u, 0u, 2u),
                     "hint on a live map");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CODE_HEAD, "anchor head kept");
    __CPROVER_assert(map.cell[0].item == 5u, "anchor item kept");
    __CPROVER_assert(map.cell[1].state == (uint8_t)BM_CODE_TAIL, "anchor tail kept");
    __CPROVER_assert(map.cell[1].item == 5u, "anchor tail item kept");
    __CPROVER_assert(bm_is_unknown(&map.cell[2]), "anchor neighbour stays unknown");

    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 2u, 5u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(ok, "weaker setup");
    ok = bm_claim_code(&map, 0u, 2u, 9u, (uint8_t)BM_ST_LIKELY, 2u);
    __CPROVER_assert(!ok, "weaker second claim");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CODE_HEAD, "weaker leaves the head");
    __CPROVER_assert(map.cell[1].state == (uint8_t)BM_CODE_TAIL, "weaker leaves the tail");
    __CPROVER_assert(map.cell[0].item == 5u, "weaker leaves the old item");
    __CPROVER_assert(map.cell[1].item == 5u, "weaker leaves the tail item");
    __CPROVER_assert(map.cell[0].strength == (uint8_t)BM_ST_PROVEN, "weaker leaves strength");

    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 2u, 5u, (uint8_t)BM_ST_PROVEN, 1u);
    __CPROVER_assert(ok, "equal setup");
    ok = bm_claim_code(&map, 1u, 2u, 8u, (uint8_t)BM_ST_PROVEN, 2u);
    __CPROVER_assert(!ok, "equal overlap");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CODE_HEAD, "equal keeps the unhit head");
    __CPROVER_assert(map.cell[0].item == 5u, "equal keeps the head item");
    __CPROVER_assert(map.cell[1].state == (uint8_t)BM_CONFLICT, "equal marks the overlap");
    __CPROVER_assert(map.cell[1].item == 5u, "equal keeps the old item");
    __CPROVER_assert(bm_is_unknown(&map.cell[2]), "equal does not claim past the old insn");

    bm_init(&map);
    ok = bm_claim_code(&map, 0u, 4u, 100u, (uint8_t)BM_ST_LIKELY, 2u);
    __CPROVER_assert(ok, "likely 4-byte claim");
    ok = bm_claim_code(&map, 3u, 1u, 200u, (uint8_t)BM_ST_PROVEN, 9u);
    __CPROVER_assert(ok, "stronger claim over the tail");
    for (i = 0u; i < 3u; ++i)
    {
        __CPROVER_assert(bm_is_unknown(&map.cell[i]), "old bytes outside the new claim clear");
    }
    __CPROVER_assert(map.cell[3].state == (uint8_t)BM_CODE_HEAD, "new byte is a head");
    __CPROVER_assert(map.cell[3].item == 200u, "new item");
    __CPROVER_assert(map.cell[3].unit == 9u, "new unit");
    __CPROVER_assert(map.cell[3].strength == (uint8_t)BM_ST_PROVEN, "new strength");
    __CPROVER_assert(bm_is_unknown(&map.cell[4]), "byte after the new claim stays unknown");
    bm_retract(&map, 2u);
    __CPROVER_assert(map.cell[3].state == (uint8_t)BM_CODE_HEAD, "retract old leaves the new head");
    __CPROVER_assert(map.cell[3].item == 200u, "retract old leaves the new item");
    bm_retract(&map, 0u);
    __CPROVER_assert(map.cell[3].item == 200u, "retract 0 writes nothing");
    bm_retract(&map, 9u);
    __CPROVER_assert(bm_is_unknown(&map.cell[3]), "retract new clears the new byte");

    bm_init(&map);
    __CPROVER_assert(bm_claim_code(&map, 0u, 2u, 10u, (uint8_t)BM_ST_LIKELY, 1u),
                     "first weaker insn");
    __CPROVER_assert(bm_claim_code(&map, 2u, 2u, 11u, (uint8_t)BM_ST_LIKELY, 2u),
                     "second weaker insn");
    __CPROVER_assert(bm_claim_code(&map, 1u, 2u, 12u, (uint8_t)BM_ST_PROVEN, 3u),
                     "stronger claim covers both");
    __CPROVER_assert(bm_is_unknown(&map.cell[0]), "first head cleared");
    __CPROVER_assert(map.cell[1].state == (uint8_t)BM_CODE_HEAD, "replacement head");
    __CPROVER_assert(map.cell[1].item == 12u, "replacement item");
    __CPROVER_assert(map.cell[2].state == (uint8_t)BM_CODE_TAIL, "replacement tail");
    __CPROVER_assert(map.cell[2].item == 12u, "replacement tail item");
    __CPROVER_assert(bm_is_unknown(&map.cell[3]), "second tail cleared");
    bm_retract(&map, 1u);
    bm_retract(&map, 2u);
    __CPROVER_assert(map.cell[1].item == 12u, "retract of both old units leaves the new item");
    __CPROVER_assert(map.cell[2].state == (uint8_t)BM_CODE_TAIL, "retract of both old units leaves the tail");

    bm_init(&map);
    map.cell[0].state = (uint8_t)BM_DATA;
    map.cell[0].strength = (uint8_t)BM_ST_LIKELY;
    map.cell[0].item = 4u;
    map.cell[0].unit = 1u;
    map.cell[1] = map.cell[0];
    ok = bm_claim_code(&map, 0u, 2u, 9u, (uint8_t)BM_ST_PROVEN, 2u);
    __CPROVER_assert(!ok, "code on data conflicts");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CONFLICT, "data byte marked conflict");
    __CPROVER_assert(map.cell[0].item == 4u, "data item kept");
    __CPROVER_assert(map.cell[1].item == 4u, "second data item kept");

    bm_init(&map);
    map.cell[0].state = (uint8_t)BM_DATA;
    map.cell[0].strength = (uint8_t)BM_ST_PROVEN;
    map.cell[0].item = 4u;
    map.cell[0].unit = 1u;
    ok = bm_claim_code(&map, 0u, 1u, 9u, (uint8_t)BM_ST_LIKELY, 2u);
    __CPROVER_assert(!ok, "weaker code on data writes nothing");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_DATA, "stronger data stays data");
    __CPROVER_assert(map.cell[0].item == 4u, "stronger data item stays");

    bm_init(&map);
    __CPROVER_assert(bm_claim_code(&map, 0u, 2u, 5u, (uint8_t)BM_ST_LIKELY, 1u),
                     "conflict setup");
    __CPROVER_assert(!bm_claim_code(&map, 0u, 2u, 8u, (uint8_t)BM_ST_LIKELY, 2u),
                     "equal full overlap");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CONFLICT, "full overlap is conflict");
    __CPROVER_assert(!bm_claim_code(&map, 0u, 2u, 9u, (uint8_t)BM_ST_PROVEN, 3u),
                     "stronger code does not replace conflict");
    __CPROVER_assert(map.cell[0].state == (uint8_t)BM_CONFLICT, "conflict stays");
    __CPROVER_assert(map.cell[0].item == 5u, "conflict keeps the old item");
    __CPROVER_assert(map.cell[1].item == 5u, "conflict tail item stays");
}

#ifdef __CPROVER__

/**
 * @brief Assume a promoting strength in the Likely..Proven band.
 *
 * @param[in] strength Candidate.
 */
static void assume_promote(uint8_t strength)
{
    __CPROVER_assume(strength >= BM_ST_LIKELY && strength <= BM_ST_PROVEN);
}

/**
 * @brief Assume @p head and @p len form a span inside the 8-byte map.
 *
 * @param[in] head First byte.
 * @param[in] len  Length.
 */
static void assume_fits(uint32_t head, uint8_t len)
{
    __CPROVER_assume(len >= 1u && len <= BM_CLAIM_LEN);
    __CPROVER_assume(head < BM_CLAIM_LEN);
    __CPROVER_assume((uint32_t)len <= (uint32_t)BM_CLAIM_LEN - head);
}

/**
 * @brief Length 0 or greater than 15 is refused and writes nothing.
 */
static void prove_bad_len(void)
{
    struct BmMap map;
    uint8_t len = nondet_uint8_t();
    uint8_t head8 = nondet_uint8_t();
    uint8_t strength = nondet_uint8_t();
    uint8_t item8 = nondet_uint8_t();
    uint8_t unit8 = nondet_uint8_t();
    bool ok = false;

    __CPROVER_assume(len == 0u || len > 15u);
    __CPROVER_assume(head8 <= BM_CLAIM_LEN);
    assume_promote(strength);
    __CPROVER_assume(item8 <= 3u);
    __CPROVER_assume(unit8 <= 3u);
    bm_init(&map);
    ok = bm_claim_code(&map, head8, len, item8, strength, unit8);
    __CPROVER_assert(!ok, "length 0 or greater than 15 is refused");
    __CPROVER_assert(bm_map_unknown(&map), "bad length writes nothing");
}

/**
 * @brief A span that does not fit in the map is refused and writes nothing.
 */
static void prove_bad_range(void)
{
    struct BmMap map;
    uint8_t len = nondet_uint8_t();
    uint8_t head8 = nondet_uint8_t();
    uint8_t strength = nondet_uint8_t();
    bool ok = false;

    __CPROVER_assume(len >= 1u && len <= 15u);
    __CPROVER_assume(head8 <= 16u);
    if (head8 >= BM_CLAIM_LEN)
    {
        __CPROVER_assume(head8 >= BM_CLAIM_LEN);
    }
    else
    {
        __CPROVER_assume((uint32_t)len > (uint32_t)BM_CLAIM_LEN - head8);
    }
    assume_promote(strength);
    bm_init(&map);
    ok = bm_claim_code(&map, head8, len, 1u, strength, 1u);
    __CPROVER_assert(!ok, "a range that does not fit is refused");
    __CPROVER_assert(bm_map_unknown(&map), "a range that does not fit writes nothing");
}

/**
 * @brief Strength below Likely writes nothing on a span that would otherwise fit.
 */
static void prove_weak_strength(void)
{
    struct BmMap map;
    uint8_t len = nondet_uint8_t();
    uint8_t head8 = nondet_uint8_t();
    uint8_t strength = nondet_uint8_t();
    bool ok = false;

    __CPROVER_assume(strength < BM_ST_LIKELY);
    assume_fits(head8, len);
    bm_init(&map);
    ok = bm_claim_code(&map, head8, len, 1u, strength, 1u);
    __CPROVER_assert(!ok, "strength below Likely is refused");
    __CPROVER_assert(bm_map_unknown(&map), "strength below Likely writes nothing");
}

/**
 * @brief Visit all 8 cells without a loop body that runs 8 times.
 *
 * CBMC --unwind 8 rejects an eighth full iteration. The first pass covers
 * 0..6 and the second pass covers cell 7.
 */
#define BM_EACH(i)                                                          \
    for (uint32_t bm_pass_ = 0u; bm_pass_ < 2u; ++bm_pass_)                 \
        for ((i) = (bm_pass_ == 0u) ? 0u : (uint32_t)(BM_CLAIM_LEN - 1);    \
             (i) < ((bm_pass_ == 0u) ? (uint32_t)(BM_CLAIM_LEN - 1)         \
                                     : (uint32_t)BM_CLAIM_LEN);             \
             ++(i))

/**
 * @brief A first claim writes one head and tails of that item.
 */
static void prove_first(void)
{
    struct BmMap map;
    uint8_t len = nondet_uint8_t();
    uint8_t head8 = nondet_uint8_t();
    uint8_t strength = nondet_uint8_t();
    uint8_t item8 = nondet_uint8_t();
    uint8_t unit8 = nondet_uint8_t();
    uint32_t head = 0u;
    uint32_t end = 0u;
    uint32_t i = 0u;
    bool ok = false;

    assume_fits(head8, len);
    assume_promote(strength);
    __CPROVER_assume(item8 <= 3u);
    __CPROVER_assume(unit8 <= 3u);
    head = head8;
    end = head + (uint32_t)len;
    bm_init(&map);
    ok = bm_claim_code(&map, head, len, item8, strength, unit8);
    __CPROVER_assert(ok, "first claim succeeds");
    BM_EACH(i)
    {
        if (i >= head && i < end)
        {
            uint8_t expect = (i == head) ? (uint8_t)BM_CODE_HEAD : (uint8_t)BM_CODE_TAIL;

            __CPROVER_assert(map.cell[i].state == expect, "first claim head then tails");
            __CPROVER_assert(map.cell[i].item == item8, "first claim item");
            __CPROVER_assert(map.cell[i].strength == strength, "first claim strength");
            __CPROVER_assert(map.cell[i].span == len, "first claim span");
            __CPROVER_assert(map.cell[i].unit == unit8, "first claim unit");
        }
        else
        {
            __CPROVER_assert(bm_is_unknown(&map.cell[i]), "first claim leaves the rest unknown");
        }
    }
}

/**
 * @brief Fill two overlapping in-range spans. Strength is chosen by the caller.
 *
 * @param[out] head1 First head.
 * @param[out] len1  First length.
 * @param[out] head2 Second head.
 * @param[out] len2  Second length.
 */
static void assume_overlap(uint32_t* head1, uint8_t* len1, uint32_t* head2, uint8_t* len2)
{
    uint8_t h1 = nondet_uint8_t();
    uint8_t l1 = nondet_uint8_t();
    uint8_t h2 = nondet_uint8_t();
    uint8_t l2 = nondet_uint8_t();
    uint32_t end1 = 0u;
    uint32_t end2 = 0u;

    assume_fits(h1, l1);
    assume_fits(h2, l2);
    end1 = (uint32_t)h1 + (uint32_t)l1;
    end2 = (uint32_t)h2 + (uint32_t)l2;
    __CPROVER_assume(!(end1 <= h2 || end2 <= h1));
    *head1 = h1;
    *len1 = l1;
    *head2 = h2;
    *len2 = l2;
}

/**
 * @brief A weaker second claim returns false and leaves the old item.
 */
static void prove_weaker(void)
{
    struct BmMap map;
    struct BmCell saved[BM_CLAIM_LEN];
    uint32_t head1 = 0u;
    uint32_t head2 = 0u;
    uint8_t len1 = 0u;
    uint8_t len2 = 0u;
    uint8_t strength1 = nondet_uint8_t();
    uint8_t strength2 = nondet_uint8_t();
    uint32_t i = 0u;
    bool ok = false;

    assume_overlap(&head1, &len1, &head2, &len2);
    assume_promote(strength1);
    assume_promote(strength2);
    __CPROVER_assume(strength2 < strength1);
    bm_init(&map);
    ok = bm_claim_code(&map, head1, len1, 1u, strength1, 1u);
    __CPROVER_assert(ok, "weaker proof first claim");
    BM_EACH(i)
    {
        saved[i] = map.cell[i];
    }
    ok = bm_claim_code(&map, head2, len2, 2u, strength2, 2u);
    __CPROVER_assert(!ok, "weaker second claim returns false");
    BM_EACH(i)
    {
        __CPROVER_assert(bm_same(&map.cell[i], &saved[i]), "weaker claim leaves the old item");
    }
}

/**
 * @brief Equal-strength overlap returns false, marks conflict, and keeps the item.
 */
static void prove_equal(void)
{
    struct BmMap map;
    struct BmCell saved[BM_CLAIM_LEN];
    uint32_t head1 = 0u;
    uint32_t head2 = 0u;
    uint8_t len1 = 0u;
    uint8_t len2 = 0u;
    uint8_t strength = nondet_uint8_t();
    uint32_t end1 = 0u;
    uint32_t end2 = 0u;
    uint32_t i = 0u;
    bool ok = false;
    bool marked = false;

    assume_overlap(&head1, &len1, &head2, &len2);
    assume_promote(strength);
    end1 = head1 + (uint32_t)len1;
    end2 = head2 + (uint32_t)len2;
    bm_init(&map);
    ok = bm_claim_code(&map, head1, len1, 1u, strength, 1u);
    __CPROVER_assert(ok, "equal proof first claim");
    BM_EACH(i)
    {
        saved[i] = map.cell[i];
    }
    ok = bm_claim_code(&map, head2, len2, 2u, strength, 2u);
    __CPROVER_assert(!ok, "equal-strength overlap returns false");
    BM_EACH(i)
    {
        const bool in_both = (i >= head1 && i < end1) && (i >= head2 && i < end2);

        if (in_both)
        {
            __CPROVER_assert(map.cell[i].state == (uint8_t)BM_CONFLICT,
                             "equal overlap marks Conflict");
            __CPROVER_assert(map.cell[i].item == saved[i].item, "equal overlap keeps the old item");
            __CPROVER_assert(map.cell[i].item == 1u, "old item is the first claim");
            __CPROVER_assert(map.cell[i].strength == saved[i].strength, "conflict keeps strength");
            __CPROVER_assert(map.cell[i].unit == saved[i].unit, "conflict keeps the old unit");
            marked = true;
        }
        else
        {
            __CPROVER_assert(bm_same(&map.cell[i], &saved[i]),
                             "bytes outside the overlap stay as they were");
        }
    }
    __CPROVER_assert(marked, "the overlap covered at least one byte");
}

/**
 * @brief A strictly stronger code claim replaces the old instruction.
 *
 * Retract of the old unit does not clear the new bytes. The old unit is
 * not zero and differs from the new unit, so the check is not vacuous.
 */
static void prove_stronger(void)
{
    struct BmMap map;
    uint32_t head1 = 0u;
    uint32_t head2 = 0u;
    uint8_t len1 = 0u;
    uint8_t len2 = 0u;
    uint8_t strength1 = nondet_uint8_t();
    uint8_t strength2 = nondet_uint8_t();
    uint8_t unit1 = nondet_uint8_t();
    uint8_t unit2 = nondet_uint8_t();
    uint32_t end2 = 0u;
    uint32_t i = 0u;
    bool ok = false;

    assume_overlap(&head1, &len1, &head2, &len2);
    assume_promote(strength1);
    assume_promote(strength2);
    __CPROVER_assume(strength2 > strength1);
    __CPROVER_assume(unit1 >= 1u && unit1 <= 3u);
    __CPROVER_assume(unit2 <= 3u);
    __CPROVER_assume(unit2 != unit1);
    end2 = head2 + (uint32_t)len2;
    bm_init(&map);
    ok = bm_claim_code(&map, head1, len1, 1u, strength1, unit1);
    __CPROVER_assert(ok, "stronger proof first claim");
    ok = bm_claim_code(&map, head2, len2, 2u, strength2, unit2);
    __CPROVER_assert(ok, "strictly stronger code claim returns true");
    BM_EACH(i)
    {
        if (i >= head2 && i < end2)
        {
            uint8_t expect = (i == head2) ? (uint8_t)BM_CODE_HEAD : (uint8_t)BM_CODE_TAIL;

            __CPROVER_assert(map.cell[i].state == expect, "new claim is head then tails");
            __CPROVER_assert(map.cell[i].item == 2u, "the item is the new one");
            __CPROVER_assert(map.cell[i].unit == unit2, "new bytes carry the new unit");
            __CPROVER_assert(map.cell[i].strength == strength2, "new strength");
            __CPROVER_assert(map.cell[i].span == len2, "new span");
        }
        else
        {
            __CPROVER_assert(bm_is_unknown(&map.cell[i]),
                             "the old instruction outside the new claim is cleared");
        }
    }
    bm_retract(&map, unit1);
    BM_EACH(i)
    {
        if (i >= head2 && i < end2)
        {
            __CPROVER_assert(map.cell[i].item == 2u, "retract of the old unit does not clear it");
            __CPROVER_assert(map.cell[i].unit == unit2, "retract of the old unit keeps the new unit");
        }
        else
        {
            __CPROVER_assert(bm_is_unknown(&map.cell[i]), "cleared bytes stay clear");
        }
    }
}

/**
 * @brief One nondet mode per rule so the cases are not a cross product.
 */
static void prove_rules(void)
{
    uint8_t mode = nondet_uint8_t();

    __CPROVER_assume(mode <= 6u);
    if (mode == 0u)
    {
        prove_bad_len();
    }
    else if (mode == 1u)
    {
        prove_bad_range();
    }
    else if (mode == 2u)
    {
        prove_weak_strength();
    }
    else if (mode == 3u)
    {
        prove_first();
    }
    else if (mode == 4u)
    {
        prove_weaker();
    }
    else if (mode == 5u)
    {
        prove_equal();
    }
    else
    {
        prove_stronger();
    }
}

#endif /* __CPROVER__ */

int main(void)
{
    check_examples();
#ifdef __CPROVER__
    prove_rules();
#endif
    return 0;
}
