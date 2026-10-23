/*
 * failstep unit tests -- the public runtime API without the CLI.
 * SPDX-License-Identifier: MIT
 */
#include <failstep/failstep.h>

#include <stdio.h>
#include <string.h>

static int g_failures;

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_failures++;                                                \
        }                                                                \
    } while (0)

static void test_version(void) {
    /* The runtime, the header macros and the CMake project version agree. */
    CHECK(strcmp(failstep_version(), FAILSTEP_VERSION_STRING) == 0);
    CHECK(strcmp(failstep_version(), FAILSTEP_PROJECT_VERSION) == 0);
}

static void test_tag_sites(void) {
    failstep_site_t a = failstep_site_tag("alpha");
    failstep_site_t b = failstep_site_tag("beta");
    failstep_site_t a2 = failstep_site_tag("alpha");
    CHECK(a != 0);
    CHECK(b != 0);
    CHECK(a == a2);  /* deterministic */
    CHECK(a != b);   /* distinct tags -> distinct sites */
}

static void test_inactive_by_default(void) {
    /* No FAILSTEP_MODE in the environment: the oracle must never fail. */
    CHECK(failstep_active() == 0);
    CHECK(failstep_should_fail() == 0);
    CHECK(failstep_should_fail() == 0);
}

static void test_fuzz_oracle(void) {
    /* control byte 0x05 = bits 1,0,1 -> fail allocations 1 and 3, pass 2 */
    unsigned char data[2] = {1, 0x05};
    size_t used = failstep_fuzz_begin(data, sizeof(data));
    CHECK(used == 2);
    CHECK(failstep_active() == 1);

    int r1 = failstep_should_fail();
    int r2 = failstep_should_fail();
    int r3 = failstep_should_fail();
    CHECK(r1 == 1);
    CHECK(r2 == 0);
    CHECK(r3 == 1);

    failstep_fuzz_end();
    CHECK(failstep_active() == 0);
    CHECK(failstep_should_fail() == 0);
}

static void test_fuzz_empty(void) {
    size_t used = failstep_fuzz_begin(NULL, 0);
    CHECK(used == 0);
    /* No control bytes: nothing fails. */
    CHECK(failstep_should_fail() == 0);
    CHECK(failstep_should_fail() == 0);
    failstep_fuzz_end();
}

static void test_alloc_count(void) {
    unsigned long long before = failstep_alloc_count();
    unsigned char data[2] = {1, 0x00};
    failstep_fuzz_begin(data, sizeof(data));
    (void)failstep_should_fail();
    (void)failstep_should_fail();
    failstep_fuzz_end();
    CHECK(failstep_alloc_count() >= before + 2);
}

int main(void) {
    test_version();
    test_tag_sites();
    test_inactive_by_default();
    test_fuzz_oracle();
    test_fuzz_empty();
    test_alloc_count();

    if (g_failures) {
        fprintf(stderr, "%d check(s) failed\n", g_failures);
        return 1;
    }
    printf("all unit tests passed\n");
    return 0;
}
