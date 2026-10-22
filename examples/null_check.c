/*
 * Category: NULL dereference (missing NULL check).
 *
 * BUG: the result of malloc() is used without checking for NULL, so a failed
 * allocation leads straight to a crash (a classic denial of service, and the
 * entry point for worse when the NULL write lands on attacker-influenced data).
 *
 * failstep enumerate/sites reports this as "null-deref".
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    size_t n = 128;
    char *buf = malloc(n);
    memset(buf, 'x', n); /* <-- dereferences buf even when malloc returned NULL */
    buf[n - 1] = '\0';
    puts(buf);
    free(buf);
    return 0;
}
