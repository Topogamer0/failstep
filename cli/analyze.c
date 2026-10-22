#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
/*
 * failstep CLI -- parse failstep report/stats files and the target's ASan /
 * LeakSanitizer output, classify the outcome and symbolize the injected frames.
 *
 * SPDX-License-Identifier: MIT
 */
#include "cli.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- line helpers ------------------------------------------------------ */

static char *next_line(char **p) {
    if (!**p) return NULL;
    char *start = *p;
    char *nl = strchr(start, '\n');
    if (nl) {
        *nl = '\0';
        *p = nl + 1;
    } else {
        *p = start + strlen(start);
    }
    return start;
}

static const char *base_name(const char *path) {
    const char *b = path;
    for (const char *q = path; q && *q; q++)
        if (*q == '/' || *q == '\\') b = q + 1;
    return b;
}

/* ---- report (the injected failure) ------------------------------------- */

int fs_read_report(const char *path, fs_job *job) {
    size_t len;
    char *buf = fs_read_file(path, &len);
    if (!buf) return 0;

    int cap = 0;
    char *p = buf, *line;
    while ((line = next_line(&p)) != NULL) {
        if (strncmp(line, "index ", 6) == 0) {
            job->index = strtoull(line + 6, NULL, 10);
        } else if (strncmp(line, "site ", 5) == 0) {
            job->site = strtoull(line + 5, NULL, 0);
        } else if (strncmp(line, "frame\t", 6) == 0) {
            /* frame<TAB>off<TAB>addr<TAB>module<TAB>symbol */
            char *f = line + 6;
            char *tok[4] = {NULL, NULL, NULL, NULL};
            int ti = 0;
            tok[ti++] = f;
            for (char *q = f; *q && ti < 4; q++) {
                if (*q == '\t') {
                    *q = '\0';
                    tok[ti++] = q + 1;
                }
            }
            if (job->inj_n == cap) {
                cap = cap ? cap * 2 : 8;
                job->inj = (fs_frame *)realloc(job->inj, (size_t)cap * sizeof(fs_frame));
            }
            fs_frame *fr = &job->inj[job->inj_n++];
            memset(fr, 0, sizeof(*fr));
            fr->off = tok[0] ? strtoull(tok[0], NULL, 0) : 0;
            fr->raw = tok[1] ? fs_xstrdup(tok[1]) : NULL;
            fr->module = tok[2] ? fs_xstrdup(tok[2]) : NULL;
            if (tok[3] && *tok[3]) fr->func = fs_xstrdup(tok[3]);
        }
    }
    free(buf);
    return 1;
}

/* ---- stats (count pass) ------------------------------------------------ */

int fs_read_stats(const char *path, unsigned long long *total, unsigned long long **sites,
                  size_t *nsites) {
    size_t len;
    char *buf = fs_read_file(path, &len);
    if (!buf) return 0;

    *total = 0;
    size_t cap = 0, n = 0;
    unsigned long long *arr = NULL;

    char *p = buf, *line;
    while ((line = next_line(&p)) != NULL) {
        if (strncmp(line, "allocs ", 7) == 0) {
            *total = strtoull(line + 7, NULL, 10);
        } else if (strncmp(line, "site ", 5) == 0) {
            unsigned long long h = strtoull(line + 5, NULL, 0);
            if (n == cap) {
                cap = cap ? cap * 2 : 64;
                arr = (unsigned long long *)realloc(arr, cap * sizeof(*arr));
            }
            arr[n++] = h;
        }
    }
    free(buf);
    *sites = arr;
    *nsites = n;
    return 1;
}

/* ---- symbolization of injected frames ---------------------------------- */

#if !defined(_WIN32)
/* Single-quote a string for the shell, escaping embedded single quotes as
 * '\'' so a module path containing a quote cannot break the command. */
static void shell_squote(const char *s, char *out, size_t n) {
    size_t o = 0;
    if (o < n) out[o++] = '\'';
    for (; *s && o + 4 < n; s++) {
        if (*s == '\'') {
            out[o++] = '\'';
            out[o++] = '\\';
            out[o++] = '\'';
            out[o++] = '\'';
        } else {
            out[o++] = *s;
        }
    }
    if (o < n) out[o++] = '\'';
    out[o < n ? o : n - 1] = '\0';
}

static void run_addr2line(fs_frame *fr) {
    if (!fr->module) return;
    char q[1200], cmd[2048];
    shell_squote(fr->module, q, sizeof(q));
    snprintf(cmd, sizeof(cmd), "addr2line -e %s -f -C 0x%llx 2>/dev/null", q, fr->off);
    FILE *pp = popen(cmd, "r");
    if (!pp) return;
    char func[1024] = {0}, loc[1024] = {0};
    if (fgets(func, sizeof(func), pp) && fgets(loc, sizeof(loc), pp)) {
        func[strcspn(func, "\n")] = '\0';
        loc[strcspn(loc, "\n")] = '\0';
        if (func[0] && strcmp(func, "??") != 0) {
            free(fr->func);
            fr->func = fs_xstrdup(func);
        }
        /* loc is file:line, file:line:col, or ??:0 */
        if (loc[0] && strncmp(loc, "??", 2) != 0) {
            /* Strip a trailing ":<digits>" up to twice (column then line). */
            int line_no = 0, have_line = 0;
            for (int pass = 0; pass < 2; pass++) {
                char *c = strrchr(loc, ':');
                if (!c || c[1] == '\0') break;
                int alldig = 1;
                for (char *d = c + 1; *d; d++)
                    if (!isdigit((unsigned char)*d)) alldig = 0;
                if (!alldig) break;
                line_no = atoi(c + 1); /* innermost numeric is the line we keep */
                have_line = 1;
                *c = '\0';
                if (pass == 0) continue; /* could be col; loop once more for line */
            }
            if (have_line) {
                free(fr->file);
                fr->file = fs_xstrdup(loc);
                fr->line = line_no;
            }
        }
    }
    pclose(pp);
}
#endif

static void symbolize_injected(fs_job *job) {
#if !defined(_WIN32)
    for (int i = 0; i < job->inj_n; i++) run_addr2line(&job->inj[i]);
#else
    (void)job;
#endif
}

/* ---- ASan / LSan parsing ----------------------------------------------- */

/* Parse "#0 0x... in func file:line:col" or "#0 0x.. in func (mod+0x..)". */
static int parse_asan_frame(const char *line, fs_frame *fr) {
    const char *h = strstr(line, "#");
    if (!h) return 0;
    const char *in = strstr(line, " in ");
    memset(fr, 0, sizeof(*fr));
    if (!in) {
        fr->raw = fs_xstrdup(line);
        return 1;
    }
    const char *rest = in + 4;
    /* Copy the part after " in ", trimming trailing whitespace. */
    char buf[2048];
    snprintf(buf, sizeof(buf), "%s", rest);
    char *e = buf + strlen(buf);
    while (e > buf && isspace((unsigned char)e[-1])) *--e = '\0';

    /*
     * The source location (or "(module+0xNN)") is the LAST whitespace-delimited
     * token; everything before it is the function name, which may itself
     * contain spaces (C++ signatures like "std::vector<int>::push_back(int)").
     */
    char *lastsp = NULL;
    for (char *p = buf; *p; p++)
        if (*p == ' ') lastsp = p;

    char *loc = NULL;
    if (lastsp) {
        *lastsp = '\0';
        loc = lastsp + 1;
        fr->func = fs_xstrdup(buf);
    } else {
        fr->func = fs_xstrdup(buf); /* no location token */
    }

    if (loc && loc[0] && loc[0] != '(') {
        /* file:line[:col] */
        char *c1 = strchr(loc, ':');
        if (c1) {
            *c1 = '\0';
            fr->file = fs_xstrdup(loc);
            fr->line = atoi(c1 + 1);
        } else {
            fr->file = fs_xstrdup(loc);
        }
    }
    fr->raw = fs_xstrdup(line);
    return 1;
}

static void parse_asan(fs_job *job, const char *text) {
    /*
     * Match the "ERROR:"-prefixed marker only, so the trailing
     * "SUMMARY: AddressSanitizer: N byte(s) leaked" line of a leak report is
     * not mistaken for an AddressSanitizer error.
     */
    const char *err = strstr(text, "ERROR: AddressSanitizer:");
    if (err) err += strlen("ERROR: ");
    const char *leak = strstr(text, "ERROR: LeakSanitizer:");
    if (!leak) leak = strstr(text, "detected memory leaks");

    if (err) {
        /* type follows "AddressSanitizer:" */
        const char *t = err + strlen("AddressSanitizer:");
        while (*t == ' ') t++;
        char type[128] = {0};
        int ti = 0;
        while (*t && *t != ' ' && *t != '\n' && ti < (int)sizeof(type) - 1) type[ti++] = *t++;
        type[ti] = '\0';
        /* ASan phrases some errors as "attempting double-free on ..."; report
         * the defect word, not the verb. */
        if (strcmp(type, "attempting") == 0) {
            while (*t == ' ') t++;
            ti = 0;
            while (*t && *t != ' ' && *t != '\n' && ti < (int)sizeof(type) - 1) type[ti++] = *t++;
            type[ti] = '\0';
        }
        job->asan_type = fs_xstrdup(type);

        /* A SEGV at (or very near) address 0 is a dereference of the NULL the
         * failed allocation returned -- a missing NULL check. */
        const char *segv = strstr(text, "SEGV on unknown address");
        if (!segv) segv = strstr(text, "BUS on unknown address"); /* Darwin */
        if (segv) {
            const char *addr = strstr(segv, "0x");
            unsigned long long a = addr ? strtoull(addr, NULL, 16) : ~0ull;
            job->ptype = (a < 0x1000) ? PT_NULLDEREF : PT_ASAN;
        } else {
            job->ptype = PT_ASAN;
        }
    } else if (leak) {
        job->asan_type = fs_xstrdup("memory-leak");
        job->ptype = PT_LEAK;
    }

    /* Collect the frames of the first stack after the (first) error marker. */
    const char *scan = err ? err : (leak ? leak : NULL);
    if (!scan) return;
    char *dup = fs_xstrdup(scan);
    int cap = 0;
    char *p = dup, *line;
    int started = 0;
    while ((line = next_line(&p)) != NULL) {
        const char *hash = strstr(line, "#");
        int is_frame = 0;
        if (hash && isdigit((unsigned char)hash[1])) {
            /* require the "#N 0x" shape */
            const char *q = hash + 1;
            while (isdigit((unsigned char)*q)) q++;
            if (*q == ' ' && strstr(q, "0x")) is_frame = 1;
        }
        if (is_frame) {
            started = 1;
            if (job->err_n == cap) {
                cap = cap ? cap * 2 : 16;
                job->err = (fs_frame *)realloc(job->err, (size_t)cap * sizeof(fs_frame));
            }
            if (parse_asan_frame(line, &job->err[job->err_n])) job->err_n++;
        } else if (started) {
            break; /* end of the first stack */
        }
    }
    free(dup);
}

/* ---- top-level classification ------------------------------------------ */

void fs_analyze(fs_job *job, const char *target_path) {
    (void)base_name;
    symbolize_injected(job);

    if (job->timed_out) {
        job->ptype = PT_HANG;
        return;
    }

    char *text = job->err_path ? fs_read_file(job->err_path, NULL) : NULL;
    if (text) {
        parse_asan(job, text);
        free(text);
    }

    if (job->ptype != PT_CLEAN) return; /* ASan/LSan already decided */

    /* No sanitizer report: fall back to the raw outcome. */
    if (job->signalnum != 0) {
#if !defined(_WIN32)
        if (job->signalnum == 11 /* SIGSEGV */) {
            /* Under an injected NULL, a bare segfault is almost always a
             * dereference of the unchecked NULL. */
            job->ptype = PT_NULLDEREF;
            return;
        }
#endif
        job->ptype = PT_ABNORMAL;
    } else if (job->exit_code != 0) {
        job->ptype = PT_ABNORMAL;
    } else {
        job->ptype = PT_CLEAN;
    }
    (void)target_path;
}
