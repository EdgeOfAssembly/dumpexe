/**
 * @file ne_shift.c
 * @brief NE alignment shift shared by the reporter and the CBMC harness.
 */
#include "ne_shift.h"

bool ne_align_shift_ok(uint16_t shift)
{
    return shift <= 16u;
}

size_t ne_shift_left(uint32_t value, uint16_t shift)
{
    if (!ne_align_shift_ok(shift))
    {
        return 0;
    }
    return (size_t)value << shift;
}
