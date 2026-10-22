/*
 * Fixed version of hang.c: give up instead of spinning.
 * SPDX-License-Identifier: MIT
 */
#include <stdlib.h>

int main(void) {
    char *p = malloc(256);
    if (!p) return 0; /* handled */
    free(p);
    return 0;
}
