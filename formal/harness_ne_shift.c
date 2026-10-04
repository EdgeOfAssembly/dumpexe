/**
 * @file harness_ne_shift.c
 * @brief CBMC harness for the NE alignment shift the reporter calls.
 */
#include "../ne_shift.h"

#ifdef __CPROVER__
uint16_t nondet_uint16_t(void);
uint32_t nondet_uint32_t(void);
#else
#include <assert.h>
#define __CPROVER_assert(cond, msg) assert(cond)
#endif

int main(void)
{
    uint16_t shift = 0;
    uint32_t value = 0;

#ifdef __CPROVER__
    shift = nondet_uint16_t();
    value = nondet_uint32_t();
#else
    shift = 9u;
    value = 1u;
#endif

    __CPROVER_assert(ne_align_shift_ok(shift) == (shift <= 16u),
                     "ok iff shift <= 16");
    if (shift > 16u)
    {
        __CPROVER_assert(ne_shift_left(value, shift) == 0,
                         "shift above 16 yields 0");
    }
    else
    {
        __CPROVER_assert(
            ne_shift_left(value, shift) == ((size_t)value << shift),
            "in-range shift matches size_t shift");
    }
    return 0;
}
