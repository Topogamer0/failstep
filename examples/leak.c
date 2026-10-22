/*
 * Category: memory leak on the allocation-failure path.
 *
 * BUG: when the second allocation fails, the function returns without freeing
 * the first buffer. LeakSanitizer reports the leak on exactly the run where the
 * second allocation is the one failstep fails.
 *
 * failstep reports this as "leak".
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *first = malloc(64);
    if (!first) return 0; /* handled: nothing allocated yet */
    memset(first, 1, 64);

    char *second = malloc(64);
    if (!second) {
        /* BUG: `first` is never freed here */
        return 0;
    }

    free(second);
    free(first);
    return 0;
}
