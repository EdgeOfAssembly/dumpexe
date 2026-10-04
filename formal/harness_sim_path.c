/**
 * @file harness_sim_path.c
 * @brief CBMC harness for the production guest-path check.
 *
 * Includes ../sim_path.h and links sim_path.c. It does not reimplement
 * sim_guest_path_ok.
 */
#include "../sim_path.h"

#include <stddef.h>

#ifdef __CPROVER__
size_t nondet_size_t(void);
char nondet_char(void);
#else
#include <assert.h>
#define __CPROVER_assert(cond, msg) assert(cond)
#endif

int main(void)
{
    __CPROVER_assert(!sim_guest_path_ok(".."), ".. rejected");
    __CPROVER_assert(!sim_guest_path_ok("/etc/hostname"),
                     "absolute /etc/hostname rejected");
    __CPROVER_assert(!sim_guest_path_ok("../x"), "../x rejected");
    __CPROVER_assert(sim_guest_path_ok("NEWFILE.TXT"), "NEWFILE.TXT accepted");
    __CPROVER_assert(!sim_guest_path_ok(""), "empty rejected");
    __CPROVER_assert(!sim_guest_path_ok("."), ". rejected");
    __CPROVER_assert(!sim_guest_path_ok("a/../b"), "dotdot component rejected");
    __CPROVER_assert(!sim_guest_path_ok("foo..txt"), "two dots rejected");
    __CPROVER_assert(sim_guest_path_ok("A/B.TXT"), "relative with one dot accepted");

#ifdef __CPROVER__
    {
        /* Nondet only under CBMC. A NUL is planted inside the object so the
         * production walker cannot read past this buffer. */
        char raw[81];
        size_t n = nondet_size_t();
        __CPROVER_assume(n < 9);
        raw[0] = nondet_char();
        raw[1] = nondet_char();
        raw[2] = nondet_char();
        raw[3] = nondet_char();
        raw[4] = nondet_char();
        raw[5] = nondet_char();
        raw[6] = nondet_char();
        raw[7] = nondet_char();
        raw[n] = '\0';
        (void)sim_guest_path_ok(raw);
    }
#endif
    return 0;
}
