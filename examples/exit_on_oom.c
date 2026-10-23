/*
 * Category: orderly exit on out-of-memory -- correct behaviour, NOT a bug.
 *
 * When an allocation fails, the program frees what it holds, reports the error
 * and exits with status 1 (EXIT_FAILURE). For a command-line tool that is the
 * right way to handle running out of memory, so failstep reports no problem:
 * these runs are listed as info ("exits cleanly with code 1 when allocation
 * #K fails"). Compare abort_on_oom.c, which aborts the process instead.
 *
 *   failstep enumerate -- ./ex_exit_on_oom                 -> 0 problems
 *   failstep enumerate --ok-exit 1 -- ./ex_exit_on_oom     -> 0 problems
 *   failstep enumerate --ok-exit 2 -- ./ex_exit_on_oom     -> problem (status 1 unexpected)
 *   failstep enumerate --strict-exit -- ./ex_exit_on_oom   -> problem
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Returns 0 on success, -1 when memory runs out (having freed everything). */
static int greet(const char *who) {
    size_t len = strlen(who) + 1;
    char *name = malloc(len);
    if (!name) return -1;
    memcpy(name, who, len);

    char *greeting = malloc(len + 16);
    if (!greeting) {
        free(name);
        return -1;
    }
    snprintf(greeting, len + 16, "hello, %s", name);
    puts(greeting);

    free(greeting);
    free(name);
    return 0;
}

int main(void) {
    if (greet("failstep") != 0) {
        fputs("error: out of memory\n", stderr);
        return EXIT_FAILURE;
    }
    return 0;
}
