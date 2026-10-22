/*
 * Category: abnormal exit.
 *
 * BUG: the program aborts the whole process when an allocation fails (here via
 * assert). Turning a recoverable out-of-memory condition into a crash is a
 * denial of service. failstep reports this as "abnormal-exit" (killed by
 * SIGABRT).
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *p = malloc(256);
    assert(p != NULL); /* BUG: aborts on out-of-memory */
    memset(p, 0, 256);
    free(p);
    return 0;
}
