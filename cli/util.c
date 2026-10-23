/*
 * failstep CLI -- small shared helpers.
 * SPDX-License-Identifier: MIT
 */
#include "cli.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *fs_xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) {
        fprintf(stderr, "failstep: out of memory\n");
        exit(2);
    }
    return p;
}

void *fs_xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) {
        fprintf(stderr, "failstep: out of memory\n");
        exit(2);
    }
    return p;
}

char *fs_xstrdup(const char *s) {
    if (!s) return NULL;
    size_t n = strlen(s) + 1;
    char *p = (char *)fs_xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *fs_read_file(const char *path, size_t *len_out) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    char *buf = (char *)fs_xmalloc((size_t)sz + 1);
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    if (len_out) *len_out = got;
    return buf;
}

void fs_frames_free(fs_frame *f, int n) {
    if (!f) return;
    for (int i = 0; i < n; i++) {
        free(f[i].func);
        free(f[i].file);
        free(f[i].module);
        free(f[i].raw);
    }
    free(f);
}

void fs_job_free(fs_job *j) {
    free(j->key);
    fs_frames_free(j->inj, j->inj_n);
    fs_frames_free(j->err, j->err_n);
    free(j->asan_type);
    free(j->err_path);
    free(j->repro);
}

const char *fs_ptype_name(fs_ptype t) {
    switch (t) {
    case PT_CLEAN: return "clean";
    case PT_ASAN: return "asan-error";
    case PT_LEAK: return "leak";
    case PT_NULLDEREF: return "null-deref";
    case PT_HANG: return "hang";
    case PT_ABNORMAL: return "abnormal-exit";
    case PT_EXIT: return "clean-exit";
    }
    return "unknown";
}

const char *fs_ptype_label(fs_ptype t) {
    switch (t) {
    case PT_CLEAN: return "clean";
    case PT_ASAN: return "ASan error";
    case PT_LEAK: return "memory leak";
    case PT_NULLDEREF: return "NULL dereference (missing NULL check)";
    case PT_HANG: return "hang (timeout)";
    case PT_ABNORMAL: return "abnormal exit";
    case PT_EXIT: return "clean exit";
    }
    return "unknown";
}

int fs_ptype_is_problem(fs_ptype t) {
    return t != PT_CLEAN && t != PT_EXIT;
}
