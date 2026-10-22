/*
 * Fixed version of abort_on_oom.c: fail gracefully instead of aborting.
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(256);
    if (!p) return 0; /* handled, no abort */
    memset(p, 0, 256);
    free(p);
    return 0;
}
