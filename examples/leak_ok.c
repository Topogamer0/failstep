/*
 * Fixed version of leak.c: the error path frees what it already holds.
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *first = malloc(64);
    if (!first) return 0;
    memset(first, 1, 64);

    char *second = malloc(64);
    if (!second) {
        free(first); /* clean up before bailing out */
        return 0;
    }

    free(second);
    free(first);
    return 0;
}
