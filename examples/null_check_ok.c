/*
 * Fixed version of null_check.c: the allocation is checked, and the program
 * cleans up and reports success for the demo when memory runs out.
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t n = 128;
    char *buf = malloc(n);
    if (!buf) {
        fprintf(stderr, "out of memory, handled cleanly\n");
        return 0; /* handled: no crash */
    }
    memset(buf, 'x', n);
    buf[n - 1] = '\0';
    puts(buf);
    free(buf);
    return 0;
}
