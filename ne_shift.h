/**
 * @file ne_shift.h
 * @brief NE alignment shift shared by the reporter and the CBMC harness.
 *
 * Real NE linkers use a small shift (commonly 9, a 512-byte sector). A count
 * above 16 is not a sector size this tool applies. `1u << n` is undefined for
 * `n >= 32`, and a `size_t` shift is undefined when the count is at least the
 * width of `size_t`. Callers must use these functions instead of `<<`.
 */
#ifndef NE_SHIFT_H
#define NE_SHIFT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Report whether an NE alignment shift count may be applied.
 *
 * @param[in] shift Alignment shift from @c NEHeader::align or a resource
 *                  table's align shift.
 * @return true when @p shift is usable.
 * @retval true  @p shift is at most 16 and may be applied.
 * @retval false @p shift is out of range.
 */
bool ne_align_shift_ok(uint16_t shift);

/**
 * @brief Shift @p value left by an NE alignment count.
 *
 * @param[in] value Quantity in alignment units (sector, resource offset or
 *                  length, or 1 for the sector size).
 * @param[in] shift Alignment shift count.
 * @return `(size_t)value << shift` when @p shift is at most 16.
 * @retval 0 @p shift is greater than 16.
 */
size_t ne_shift_left(uint32_t value, uint16_t shift);

#ifdef __cplusplus
}
#endif

#endif /* NE_SHIFT_H */
