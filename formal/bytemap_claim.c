/**
 * @file bytemap_claim.c
 * @brief C23 code-claim core shared by the gcc harness and CBMC.
 */
#include "bytemap_claim.h"

/**
 * @brief Zero one cell.
 *
 * @param[out] cell Cell to clear. Not null.
 */
static void bm_clear_cell(struct BmCell* cell)
{
    cell->state = (uint8_t)BM_UNKNOWN;
    cell->strength = 0u;
    cell->span = 0u;
    cell->item = 0u;
    cell->unit = 0u;
}

/**
 * @brief CodeHead index that owns @p index, or @c BM_CLAIM_LEN if none.
 *
 * A head owns itself. A tail belongs to the nearest head in the previous
 * 14 bytes with the same item whose span covers @p index. @c item is not
 * a linear address.
 *
 * @param[in] map   Map. Not null. @c len is at most @c BM_CLAIM_LEN.
 * @param[in] index Cell index.
 * @return Head index, or @c BM_CLAIM_LEN when @p index is not code.
 */
static uint32_t bm_code_head(const struct BmMap* map, uint32_t index)
{
    uint32_t head = 0u;
    uint32_t found = BM_CLAIM_LEN;
    uint32_t item = 0u;

    if (index >= map->len || index >= BM_CLAIM_LEN)
    {
        return BM_CLAIM_LEN;
    }
    if (map->cell[index].state == (uint8_t)BM_CODE_HEAD)
    {
        return index;
    }
    if (map->cell[index].state != (uint8_t)BM_CODE_TAIL)
    {
        return BM_CLAIM_LEN;
    }
    item = map->cell[index].item;
    for (head = 0u; head + 1u < BM_CLAIM_LEN; ++head)
    {
        uint32_t distance = 0u;
        uint8_t span = 0u;

        if (head >= index)
        {
            break;
        }
        distance = index - head;
        if (distance > 14u)
        {
            continue;
        }
        if (map->cell[head].state != (uint8_t)BM_CODE_HEAD)
        {
            continue;
        }
        if (map->cell[head].item != item)
        {
            continue;
        }
        span = map->cell[head].span;
        if (span < 1u)
        {
            continue;
        }
        if (head + (uint32_t)span > index)
        {
            found = head;
        }
    }
    return found;
}

/**
 * @brief Clear [begin, begin+span), capped at the live map.
 *
 * A zero span still clears the head byte. The writer never stores a zero
 * span on a live head, and a span above 15 is not a real instruction.
 *
 * @param[in,out] map   Map. Not null.
 * @param[in]     begin First byte.
 * @param[in]     span  Head span.
 */
static void bm_clear_span(struct BmMap* map, uint32_t begin, uint8_t span)
{
    uint32_t nclear = span;
    uint32_t k = 0u;

    if (nclear < 1u || nclear > 15u)
    {
        nclear = 1u;
    }
    /* Body runs at most 7 times. CBMC --unwind 8 rejects an 8th full pass. */
    for (k = 0u; k + 1u < BM_CLAIM_LEN; ++k)
    {
        uint32_t index = 0u;

        if (k >= nclear)
        {
            break;
        }
        index = begin + k;
        if (index >= map->len || index >= BM_CLAIM_LEN)
        {
            break;
        }
        bm_clear_cell(&map->cell[index]);
    }
    if (nclear >= BM_CLAIM_LEN)
    {
        const uint32_t index = begin + (BM_CLAIM_LEN - 1u);

        if (index < map->len && index < BM_CLAIM_LEN)
        {
            bm_clear_cell(&map->cell[index]);
        }
    }
}

/**
 * @brief Write head, tails, item, strength, span, and unit.
 *
 * The caller proved the span fits. No overlap scan.
 *
 * @param[in,out] map      Map. Not null.
 * @param[in]     begin    First byte.
 * @param[in]     len      Instruction length, 1..15, in range.
 * @param[in]     item     Item id.
 * @param[in]     strength Promoting strength.
 * @param[in]     unit     Owning unit.
 */
static void bm_write_code(struct BmMap* map, uint32_t begin, uint8_t len,
                          uint32_t item, uint8_t strength, uint32_t unit)
{
    uint32_t k = 0u;

    for (k = 0u; k + 1u < BM_CLAIM_LEN; ++k)
    {
        uint32_t index = 0u;
        struct BmCell* cell = 0;

        if (k >= len)
        {
            break;
        }
        index = begin + k;
        if (index >= map->len || index >= BM_CLAIM_LEN)
        {
            break;
        }
        cell = &map->cell[index];
        cell->state = (k == 0u) ? (uint8_t)BM_CODE_HEAD : (uint8_t)BM_CODE_TAIL;
        cell->strength = strength;
        cell->span = len;
        cell->item = item;
        cell->unit = unit;
    }
    if (len >= BM_CLAIM_LEN)
    {
        const uint32_t index = begin + (BM_CLAIM_LEN - 1u);

        if (index < map->len && index < BM_CLAIM_LEN)
        {
            struct BmCell* cell = &map->cell[index];

            cell->state = (uint8_t)BM_CODE_TAIL;
            cell->strength = strength;
            cell->span = len;
            cell->item = item;
            cell->unit = unit;
        }
    }
}

/**
 * @brief Mark overlapped code and data bytes conflict. Keep the item.
 *
 * Unknown and padding bytes in the span are left alone. This is not the
 * C++ orphan-tail repair.
 *
 * @param[in,out] map   Map. Not null.
 * @param[in]     begin First byte of the rejected span.
 * @param[in]     len   Length of the rejected span.
 */
static void bm_mark_overlap(struct BmMap* map, uint32_t begin, uint8_t len)
{
    uint32_t k = 0u;

    for (k = 0u; k + 1u < BM_CLAIM_LEN; ++k)
    {
        uint32_t index = 0u;
        uint8_t state = 0u;

        if (k >= len)
        {
            break;
        }
        index = begin + k;
        if (index >= map->len || index >= BM_CLAIM_LEN)
        {
            break;
        }
        state = map->cell[index].state;
        if (state == (uint8_t)BM_CODE_HEAD || state == (uint8_t)BM_CODE_TAIL
            || state == (uint8_t)BM_DATA)
        {
            map->cell[index].state = (uint8_t)BM_CONFLICT;
        }
    }
    if (len >= BM_CLAIM_LEN)
    {
        const uint32_t index = begin + (BM_CLAIM_LEN - 1u);

        if (index < map->len && index < BM_CLAIM_LEN)
        {
            const uint8_t state = map->cell[index].state;

            if (state == (uint8_t)BM_CODE_HEAD || state == (uint8_t)BM_CODE_TAIL
                || state == (uint8_t)BM_DATA)
            {
                map->cell[index].state = (uint8_t)BM_CONFLICT;
            }
        }
    }
}

void bm_init(struct BmMap* map)
{
    /* Unrolled on purpose. A loop whose body runs all 8 cells makes CBMC's
     * --unwind 8 unwinding assertion fail: the check is one iteration late.
     */
    map->len = BM_CLAIM_LEN;
    bm_clear_cell(&map->cell[0]);
    bm_clear_cell(&map->cell[1]);
    bm_clear_cell(&map->cell[2]);
    bm_clear_cell(&map->cell[3]);
    bm_clear_cell(&map->cell[4]);
    bm_clear_cell(&map->cell[5]);
    bm_clear_cell(&map->cell[6]);
    bm_clear_cell(&map->cell[7]);
}

bool bm_claim_code(struct BmMap* map, uint32_t head, uint8_t len,
                   uint32_t item, uint8_t strength, uint32_t unit)
{
    bool weaker = false;
    bool code_hit = false;
    bool data_hit = false;
    bool blocked = false;
    bool equal_code = false;
    uint32_t heads[BM_CLAIM_LEN] = {0};
    uint8_t spans[BM_CLAIM_LEN] = {0};
    uint32_t nheads = 0u;
    uint32_t k = 0u;

    if (map == 0 || map->len == 0u || map->len > BM_CLAIM_LEN)
    {
        return false;
    }
    if (strength < BM_ST_LIKELY)
    {
        return false;
    }
    if (len < 1u || len > 15u)
    {
        return false;
    }
    if (head >= map->len || (uint32_t)len > map->len - head)
    {
        return false;
    }

    for (k = 0u; k + 1u < BM_CLAIM_LEN; ++k)
    {
        uint32_t index = 0u;
        const struct BmCell* cell = 0;

        if (k >= len)
        {
            break;
        }
        index = head + k;
        if (index >= map->len || index >= BM_CLAIM_LEN)
        {
            break;
        }
        cell = &map->cell[index];
        if (cell->state == (uint8_t)BM_CODE_HEAD || cell->state == (uint8_t)BM_CODE_TAIL)
        {
            uint32_t owned = 0u;
            uint32_t s = 0u;
            bool seen = false;

            code_hit = true;
            if (strength < cell->strength)
            {
                weaker = true;
            }
            else if (strength == cell->strength)
            {
                equal_code = true;
            }
            owned = bm_code_head(map, index);
            if (owned >= BM_CLAIM_LEN)
            {
                continue;
            }
            for (s = 0u; s + 1u < BM_CLAIM_LEN; ++s)
            {
                if (s >= nheads)
                {
                    break;
                }
                if (heads[s] == owned)
                {
                    seen = true;
                    break;
                }
            }
            if (!seen && nheads >= BM_CLAIM_LEN && heads[BM_CLAIM_LEN - 1u] == owned)
            {
                seen = true;
            }
            if (!seen && nheads < BM_CLAIM_LEN)
            {
                uint8_t span = map->cell[owned].span;

                heads[nheads] = owned;
                if (span < 1u)
                {
                    span = 1u;
                }
                spans[nheads] = span;
                ++nheads;
            }
        }
        else if (cell->state == (uint8_t)BM_DATA)
        {
            data_hit = true;
            if (strength < cell->strength)
            {
                weaker = true;
            }
        }
        else if (cell->state == (uint8_t)BM_CONFLICT)
        {
            blocked = true;
        }
    }
    if (len >= BM_CLAIM_LEN)
    {
        const uint32_t index = head + (BM_CLAIM_LEN - 1u);

        if (index < map->len && index < BM_CLAIM_LEN)
        {
            const struct BmCell* cell = &map->cell[index];

            if (cell->state == (uint8_t)BM_CODE_HEAD || cell->state == (uint8_t)BM_CODE_TAIL)
            {
                uint32_t owned = 0u;
                uint32_t s = 0u;
                bool seen = false;

                code_hit = true;
                if (strength < cell->strength)
                {
                    weaker = true;
                }
                else if (strength == cell->strength)
                {
                    equal_code = true;
                }
                owned = bm_code_head(map, index);
                if (owned < BM_CLAIM_LEN)
                {
                    for (s = 0u; s + 1u < BM_CLAIM_LEN; ++s)
                    {
                        if (s >= nheads)
                        {
                            break;
                        }
                        if (heads[s] == owned)
                        {
                            seen = true;
                            break;
                        }
                    }
                    if (!seen && nheads >= BM_CLAIM_LEN
                        && heads[BM_CLAIM_LEN - 1u] == owned)
                    {
                        seen = true;
                    }
                    if (!seen && nheads < BM_CLAIM_LEN)
                    {
                        uint8_t span = map->cell[owned].span;

                        heads[nheads] = owned;
                        if (span < 1u)
                        {
                            span = 1u;
                        }
                        spans[nheads] = span;
                        ++nheads;
                    }
                }
            }
            else if (cell->state == (uint8_t)BM_DATA)
            {
                data_hit = true;
                if (strength < cell->strength)
                {
                    weaker = true;
                }
            }
            else if (cell->state == (uint8_t)BM_CONFLICT)
            {
                blocked = true;
            }
        }
    }

    if (weaker)
    {
        return false;
    }
    if (code_hit && !data_hit && !blocked && !equal_code)
    {
        uint32_t s = 0u;

        for (s = 0u; s + 1u < BM_CLAIM_LEN; ++s)
        {
            if (s >= nheads)
            {
                break;
            }
            bm_clear_span(map, heads[s], spans[s]);
        }
        if (nheads >= BM_CLAIM_LEN)
        {
            bm_clear_span(map, heads[BM_CLAIM_LEN - 1u], spans[BM_CLAIM_LEN - 1u]);
        }
        bm_write_code(map, head, len, item, strength, unit);
        return true;
    }
    if (code_hit || data_hit || blocked)
    {
        if (code_hit || data_hit)
        {
            bm_mark_overlap(map, head, len);
        }
        return false;
    }

    bm_write_code(map, head, len, item, strength, unit);
    return true;
}

void bm_retract(struct BmMap* map, uint32_t unit)
{
    uint32_t i = 0u;

    if (map == 0 || unit == 0u)
    {
        return;
    }
    for (i = 0u; i + 1u < BM_CLAIM_LEN; ++i)
    {
        if (i >= map->len)
        {
            break;
        }
        if (map->cell[i].unit == unit)
        {
            bm_clear_cell(&map->cell[i]);
        }
    }
    if (map->len >= BM_CLAIM_LEN && map->cell[BM_CLAIM_LEN - 1u].unit == unit)
    {
        bm_clear_cell(&map->cell[BM_CLAIM_LEN - 1u]);
    }
}
