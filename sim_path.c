/**
 * @file sim_path.c
 * @brief Guest path policy shared by the simulator and the CBMC harness.
 *
 * The walk is chunked so CBMC `--unwind 8` covers the production function.
 * Each chunk consumes 16 bytes with straight-line calls, and there are five
 * chunks (80 bytes). A longer scan would trip `--unwinding-assertions`.
 */
#include "sim_path.h"

#include <stddef.h>

/** Bytes accepted inside one path component, not counting a single '.'. */
static bool sim_path_atom(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
    {
        return true;
    }
    if (c >= 'a' && c <= 'z')
    {
        return true;
    }
    if (c >= '0' && c <= '9')
    {
        return true;
    }
    if (c == '_' || c == '-')
    {
        return true;
    }
    return false;
}

/** Parser state carried across the unrolled chunks. */
typedef struct SimPathState
{
    bool bad;
    bool in_component;
    unsigned len;
    unsigned dots;
    unsigned nondots;
    unsigned total;
} SimPathState;

/**
 * @brief Close the component currently being scanned.
 *
 * Empty components, `.`, and `..` (and any component with more than one
 * dot, or with only dots) are rejected.
 */
static void sim_path_end_component(SimPathState *st)
{
    if (!st->in_component || st->len == 0 || st->nondots == 0 || st->dots > 1)
    {
        st->bad = true;
    }
    st->in_component = false;
    st->len = 0;
    st->dots = 0;
    st->nondots = 0;
}

/** Feed one path byte. A NUL is not a path byte; the caller stops on it. */
static void sim_path_feed(SimPathState *st, unsigned char c)
{
    if (st->bad)
    {
        return;
    }
    if (c == '/')
    {
        sim_path_end_component(st);
        return;
    }
    if (c == '\\' || c == ':' || c < 0x20 || c > 0x7E)
    {
        st->bad = true;
        return;
    }
    st->in_component = true;
    st->len++;
    if (c == '.')
    {
        st->dots++;
        if (st->dots > 1)
        {
            st->bad = true;
        }
        return;
    }
    if (!sim_path_atom(c))
    {
        st->bad = true;
        return;
    }
    st->nondots++;
}

/**
 * @brief Consume one byte if the path has not ended and is still within 80.
 *
 * Stops at the first NUL. Does not read index 80; the caller does that only
 * when 80 non-NUL bytes were already accepted.
 */
static void sim_path_step(const char *path, size_t *pos, bool *ended,
                          SimPathState *st)
{
    unsigned char c;

    if (*ended || *pos >= 80)
    {
        return;
    }
    c = (unsigned char)path[*pos];
    if (c == 0)
    {
        *ended = true;
        return;
    }
    *pos += 1;
    st->total += 1;
    sim_path_feed(st, c);
}

/** Sixteen steps, written out so CBMC does not need an inner unwind. */
static void sim_path_burst(const char *path, size_t *pos, bool *ended,
                           SimPathState *st)
{
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
    sim_path_step(path, pos, ended, st);
}

bool sim_guest_path_ok(const char *path)
{
    SimPathState st;
    size_t pos = 0;
    bool ended = false;
    int chunk;

    if (path == NULL)
    {
        return false;
    }

    st.bad = false;
    st.in_component = false;
    st.len = 0;
    st.dots = 0;
    st.nondots = 0;
    st.total = 0;

    for (chunk = 0; chunk < 5; chunk++)
    {
        sim_path_burst(path, &pos, &ended, &st);
    }

    if (!ended)
    {
        /* Exactly 80 non-NUL bytes. One more byte must be the terminator. */
        if (pos != 80 || path[pos] != '\0')
        {
            return false;
        }
    }

    if (st.bad || st.total == 0 || !st.in_component)
    {
        return false;
    }
    sim_path_end_component(&st);
    return !st.bad;
}
