/**
 * @file sim_path.h
 * @brief Guest path policy for dumpexe --simulate.
 *
 * Names accepted here are keys in the simulator's in-memory file map.
 * They are never joined onto a host directory and never passed to fopen.
 */
#ifndef SIM_PATH_H
#define SIM_PATH_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Report whether @p path may be used as a guest file name.
 *
 * A path is accepted only when it is a non-empty relative string of at most
 * 80 bytes. Components use `A-Z`, `a-z`, `0-9`, `_`, `-`, and at most one
 * `.`, and are separated by `/`. Empty strings, a leading `/` or `\`, any
 * `\`, any `:`, an empty component, a component that is `.` or `..`, and
 * any other byte are rejected.
 *
 * @param[in] path NUL-terminated guest path. May be NULL.
 * @return Whether @p path is safe to store in the guest file map.
 * @retval true  @p path is a non-empty relative name within the rules.
 * @retval false @p path is NULL, empty, too long, or otherwise rejected.
 *
 * @note The simulator uppercases ASCII letters after this check. The map key
 *       uses `/` separators only.
 */
bool sim_guest_path_ok(const char *path);

#ifdef __cplusplus
}
#endif

#endif /* SIM_PATH_H */
