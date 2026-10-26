/**
 * @file bytemap_claim.h
 * @brief C23 code-claim core for the gcc harness and CBMC.
 *
 * No C++ and no Capstone. The map is a fixed array of @c BM_CLAIM_LEN
 * cells. The harness sets the live length to 8. Equal-strength overlap
 * marks those bytes @c BM_CONFLICT and keeps the old item. It does not
 * run the C++ orphan-tail repair. A strictly stronger code claim replaces
 * each overlapped instruction.
 */
#ifndef BYTEMAP_CLAIM_H
#define BYTEMAP_CLAIM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Cell count. The harness keeps the live length equal to this.
 */
#define BM_CLAIM_LEN 8

/**
 * @brief Lowest strength that may write a cell. Matches Likely.
 */
#define BM_ST_LIKELY 1u

/**
 * @brief Derived, between Likely and Proven.
 */
#define BM_ST_DERIVED 2u

/**
 * @brief Witnessed, between Derived and Proven.
 */
#define BM_ST_WITNESSED 3u

/**
 * @brief Highest strength used by the claim rules.
 */
#define BM_ST_PROVEN 4u

/**
 * @brief What one byte currently is. Zero is unknown.
 */
enum BmState
{
    BM_UNKNOWN = 0,
    BM_CODE_HEAD = 1,
    BM_CODE_TAIL = 2,
    BM_DATA = 3,
    BM_PADDING = 4,
    BM_CONFLICT = 5
};

/**
 * @brief One image byte.
 *
 * A zeroed cell is unknown. @c item is the caller id, not a linear address.
 */
struct BmCell
{
    uint8_t state;    /**< @c BmState. */
    uint8_t strength; /**< 0, or at least @c BM_ST_LIKELY. */
    uint8_t span;     /**< Instruction length on code bytes, else 0. */
    uint32_t item;    /**< Claim item. Not a linear address. */
    uint32_t unit;    /**< Owning unit. 0 is not retracted. */
};

/**
 * @brief Fixed map. @c len is the live prefix, at most @c BM_CLAIM_LEN.
 */
struct BmMap
{
    struct BmCell cell[BM_CLAIM_LEN];
    uint32_t len;
};

/**
 * @brief Set @p map to 8 unknown cells.
 *
 * @param[out] map Map to clear. Not null.
 */
void bm_init(struct BmMap* map);

/**
 * @brief Claim @p len bytes of code at @p head.
 *
 * @p len must be 1..15 and the span must lie in the live map. Strength
 * below @c BM_ST_LIKELY returns false and writes nothing. A strictly
 * weaker overlap with code or data returns false and writes nothing.
 * Equal-strength code marks the overlapped code bytes @c BM_CONFLICT,
 * keeps the old item, and returns false. Data or an existing conflict
 * keeps that same refuse path. A strictly stronger code claim, with no
 * data and no conflict in the span, replaces each overlapped instruction
 * and returns true.
 *
 * @param[in,out] map      Map. Null returns false.
 * @param[in]     head     First byte.
 * @param[in]     len      Instruction length.
 * @param[in]     item     Item stored on a successful claim.
 * @param[in]     strength Fact strength.
 * @param[in]     unit     Unit stored on a successful claim.
 * @retval true  The span is now this item.
 * @retval false Rejected, or overlap marked conflict. No new item.
 */
bool bm_claim_code(struct BmMap* map, uint32_t head, uint8_t len,
                   uint32_t item, uint8_t strength, uint32_t unit);

/**
 * @brief Clear every cell whose unit is still @p unit.
 *
 * Unit 0 is not speculative: retracting 0 writes nothing. A cell whose
 * unit was replaced by a later claim is left alone.
 *
 * @param[in,out] map  Map. Null is a no-op.
 * @param[in]     unit Speculative unit. Zero is a no-op.
 */
void bm_retract(struct BmMap* map, uint32_t unit);

#endif /* BYTEMAP_CLAIM_H */
