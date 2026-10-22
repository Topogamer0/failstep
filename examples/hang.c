/*
 * Category: hang.
 *
 * BUG: on allocation failure the program spins forever instead of giving up,
 * so a single failed allocation wedges the process. failstep kills it after the
 * timeout and reports a "hang".
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>

int main(void) {
    char *p = malloc(256);
    if (!p) {
        for (;;) { /* BUG: never terminates on out-of-memory */
        }
    }
    free(p);
    return 0;
}
