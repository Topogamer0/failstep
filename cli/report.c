/*
 * failstep CLI -- group equivalent problems and emit text / JSON / SARIF.
 *
 * Two failing runs are the same problem when they failed the same allocation
 * site and produced the same error stack. Each group reports the injected
 * failure, the error, the number of occurrences and an exact reproducer.
 *
 * SPDX-License-Identifier: MIT
 */
#include "cli.h"
#include <failstep/failstep.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- signatures & grouping --------------------------------------------- */

static void append(char **buf, size_t *len, size_t *cap, const char *s) {
    size_t n = strlen(s);
    if (*len + n + 1 > *cap) {
        while (*len + n + 1 > *cap) *cap = *cap ? *cap * 2 : 256;
        *buf = (char *)realloc(*buf, *cap);
    }
    memcpy(*buf + *len, s, n + 1);
    *len += n;
}

static char *job_signature(const fs_job *j) {
    char *buf = NULL;
    size_t len = 0, cap = 0;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s|0x%llx|", fs_ptype_name(j->ptype), j->site);
    append(&buf, &len, &cap, tmp);
    int top = j->err_n < 4 ? j->err_n : 4;
    for (int i = 0; i < top; i++) {
        const fs_frame *f = &j->err[i];
        snprintf(tmp, sizeof(tmp), "%s@%s:%d;", f->func ? f->func : "?", f->file ? f->file : "?",
                 f->line);
        append(&buf, &len, &cap, tmp);
    }
    if (j->err_n == 0) {
        snprintf(tmp, sizeof(tmp), "exit=%d;sig=%d", j->exit_code, j->signalnum);
        append(&buf, &len, &cap, tmp);
    }
    return buf ? buf : fs_xstrdup("");
}

static int severity(fs_ptype t) {
    switch (t) {
    case PT_ASAN: return 5;
    case PT_NULLDEREF: return 4;
    case PT_LEAK: return 3;
    case PT_HANG: return 2;
    case PT_ABNORMAL: return 1;
    default: return 0;
    }
}

static int group_cmp(const void *a, const void *b) {
    const fs_group *ga = (const fs_group *)a, *gb = (const fs_group *)b;
    int sa = severity(ga->ptype), sb = severity(gb->ptype);
    if (sa != sb) return sb - sa;
    return gb->count - ga->count;
}

static int build_groups(fs_job *jobs, int njobs, fs_group **out) {
    fs_group *g = (fs_group *)fs_xcalloc((size_t)njobs + 1, sizeof(fs_group));
    int ng = 0;
    for (int i = 0; i < njobs; i++) {
        if (!jobs[i].ran || !fs_ptype_is_problem(jobs[i].ptype)) continue;
        char *sig = job_signature(&jobs[i]);
        int found = -1;
        for (int k = 0; k < ng; k++)
            if (strcmp(g[k].sig, sig) == 0) {
                found = k;
                break;
            }
        if (found >= 0) {
            g[found].count++;
            free(sig);
        } else {
            g[ng].ptype = jobs[i].ptype;
            g[ng].site = jobs[i].site;
            g[ng].sig = sig;
            g[ng].rep = &jobs[i];
            g[ng].count = 1;
            ng++;
        }
    }
    qsort(g, (size_t)ng, sizeof(fs_group), group_cmp);
    *out = g;
    return ng;
}

/* ---- orderly exits (info, not problems) -------------------------------- */

/* Runs that ended in an orderly exit with an expected status, grouped by that
 * status, with the allocation numbers whose failure led to it. */
typedef struct {
    int exit_code;
    int runs;
    unsigned long long *idx; /* sorted allocation numbers */
} fs_info;

static int ull_cmp(const void *a, const void *b) {
    unsigned long long x = *(const unsigned long long *)a, y = *(const unsigned long long *)b;
    return x < y ? -1 : x > y;
}

static int info_cmp(const void *a, const void *b) {
    const fs_info *x = (const fs_info *)a, *y = (const fs_info *)b;
    return x->exit_code < y->exit_code ? -1 : x->exit_code > y->exit_code;
}

static int build_info(const fs_job *jobs, int njobs, fs_info **out) {
    fs_info *in = (fs_info *)fs_xcalloc((size_t)njobs + 1, sizeof(fs_info));
    int n = 0;
    for (int i = 0; i < njobs; i++) {
        if (!jobs[i].ran || jobs[i].ptype != PT_EXIT) continue;
        int k = 0;
        while (k < n && in[k].exit_code != jobs[i].exit_code) k++;
        if (k == n) {
            in[n].exit_code = jobs[i].exit_code;
            in[n].idx = (unsigned long long *)fs_xcalloc((size_t)njobs, sizeof(unsigned long long));
            n++;
        }
        in[k].idx[in[k].runs++] = jobs[i].index;
    }
    for (int k = 0; k < n; k++) qsort(in[k].idx, (size_t)in[k].runs, sizeof(*in[k].idx), ull_cmp);
    qsort(in, (size_t)n, sizeof(fs_info), info_cmp);
    *out = in;
    return n;
}

/* "exits cleanly with code 1 when allocation #1, #2 or #5 fails (3 runs)" */
static void info_message(const fs_info *in, char *buf, size_t n) {
    enum { SHOWN = 10 };
    size_t off = (size_t)snprintf(buf, n, "exits cleanly with code %d when allocation ", in->exit_code);
    int shown = in->runs < SHOWN ? in->runs : SHOWN;
    for (int i = 0; i < shown && off < n; i++) {
        const char *sep = i == 0 ? "" : (i == shown - 1 && in->runs <= SHOWN) ? " or " : ", ";
        off += (size_t)snprintf(buf + off, n - off, "%s#%llu", sep, in->idx[i]);
    }
    if (in->runs > SHOWN && off < n)
        off += (size_t)snprintf(buf + off, n - off, " or %d others", in->runs - SHOWN);
    if (off < n) off += (size_t)snprintf(buf + off, n - off, " fails");
    if (in->runs > 1 && off < n) off += (size_t)snprintf(buf + off, n - off, " (%d runs)", in->runs);
    /* 128+N is what a shell reports for a child killed by signal N: a wrapper
     * script around the real program can turn a crash into such a status. */
    if (in->exit_code > 128 && in->exit_code < 160 && off < n)
        snprintf(buf + off, n - off,
                 "; note: %d = 128+%d, how a shell reports a child killed by signal %d -- if the"
                 " target is a wrapper script, the real program may have crashed",
                 in->exit_code, in->exit_code - 128, in->exit_code - 128);
}

static void free_info(fs_info *in, int n) {
    for (int k = 0; k < n; k++) free(in[k].idx);
    free(in);
}

/* ---- describing an abnormal exit -------------------------------------- */

static const char *signal_name(int sig) {
    switch (sig) {
#ifdef SIGABRT
    case SIGABRT: return "SIGABRT";
#endif
#ifdef SIGSEGV
    case SIGSEGV: return "SIGSEGV";
#endif
#ifdef SIGBUS
    case SIGBUS: return "SIGBUS";
#endif
#ifdef SIGILL
    case SIGILL: return "SIGILL";
#endif
#ifdef SIGFPE
    case SIGFPE: return "SIGFPE";
#endif
#ifdef SIGKILL
    case SIGKILL: return "SIGKILL";
#endif
#ifdef SIGTRAP
    case SIGTRAP: return "SIGTRAP";
#endif
#ifdef SIGTERM
    case SIGTERM: return "SIGTERM";
#endif
    default: return NULL;
    }
}

/* One line saying how the process ended, for problems without an ASan stack. */
static void describe_exit(const fs_cfg *cfg, const fs_job *j, char *buf, size_t n) {
    if (j->signalnum != 0) {
        const char *name = signal_name(j->signalnum);
        if (name) snprintf(buf, n, "killed by signal %d (%s)", j->signalnum, name);
        else snprintf(buf, n, "killed by signal %d", j->signalnum);
        return;
    }
#if defined(_WIN32)
    if ((unsigned)j->exit_code >= 0xC0000000u) {
        snprintf(buf, n, "crashed with exception 0x%08X", (unsigned)j->exit_code);
        return;
    }
#endif
    if (j->ptype == PT_ABNORMAL) {
        /* an orderly exit reported because its status is not expected */
        size_t off = (size_t)snprintf(buf, n, "exited with status %d, unexpected under ", j->exit_code);
        if (cfg->n_ok_exit > 0 && off < n) {
            off += (size_t)snprintf(buf + off, n - off, "--ok-exit ");
            for (int i = 0; i < cfg->n_ok_exit && off < n; i++)
                off += (size_t)snprintf(buf + off, n - off, "%s%d", i ? "," : "", cfg->ok_exit[i]);
        } else if (off < n) {
            snprintf(buf + off, n - off, "--strict-exit");
        }
        return;
    }
    snprintf(buf, n, "exit=%d signal=%d", j->exit_code, j->signalnum);
}

/* ---- reproducer -------------------------------------------------------- */

static void repro_env(const fs_cfg *cfg, const fs_job *j, char *buf, size_t n) {
    if (strcmp(cfg->mode, "fuzz") == 0) {
        /* The input file on the command line reproduces it; no env needed. */
        buf[0] = '\0';
    } else if (strcmp(cfg->mode, "sites") == 0) {
        snprintf(buf, n, "FAILSTEP_MODE=site FAILSTEP_FAIL_SITE=0x%llx", j->site);
    } else if (strcmp(cfg->mode, "continue") == 0) {
        snprintf(buf, n, "FAILSTEP_MODE=index FAILSTEP_SCOPED=1 FAILSTEP_FAIL_INDEX=%llu FAILSTEP_CONTINUE_STEPS=%d",
                 j->index, j->continue_steps);
    } else {
        snprintf(buf, n, "FAILSTEP_MODE=index FAILSTEP_FAIL_INDEX=%llu", j->index);
    }
}

static void repro_cmd(const fs_cfg *cfg, const fs_job *j, char *buf, size_t n) {
    if (j->repro) {
        snprintf(buf, n, "%s", j->repro);
        return;
    }
    char env[256];
    repro_env(cfg, j, env, sizeof(env));
    size_t off = (size_t)snprintf(buf, n, "%s", env);
    for (int i = 0; i < cfg->targc && off < n; i++)
        off += (size_t)snprintf(buf + off, n - off, "%s%s", (off ? " " : ""), cfg->targv[i]);
}

/* ---- text output ------------------------------------------------------- */

static void frame_line(FILE *f, const fs_frame *fr, const char *indent) {
    if (fr->file && fr->file[0])
        fprintf(f, "%s%-24s %s:%d\n", indent, fr->func ? fr->func : "?", fr->file, fr->line);
    else if (fr->func && fr->func[0])
        fprintf(f, "%s%s\n", indent, fr->func);
    else if (fr->raw)
        fprintf(f, "%s%s\n", indent, fr->raw);
}

static void write_info_text(FILE *f, const fs_info *in, int ni) {
    if (ni == 0) return;
    fprintf(f, "\nInfo (not problems): orderly exits with an expected status\n");
    for (int k = 0; k < ni; k++) {
        char msg[1024];
        info_message(&in[k], msg, sizeof(msg));
        fprintf(f, "  - %s\n", msg);
    }
}

static void write_text(FILE *f, const fs_cfg *cfg, fs_group *g, int ng, int nran, int nfail,
                       const fs_info *in, int ni, int nexit) {
    fprintf(f, "failstep: mode=%s  runs=%d  failing=%d  problems=%d", cfg->mode, nran, nfail, ng);
    if (nexit) fprintf(f, "  clean-exits=%d", nexit);
    fputc('\n', f);
    if (ng == 0) {
        fprintf(f, "\nNo problems found: every injected allocation failure was handled cleanly.\n");
        write_info_text(f, in, ni);
        return;
    }
    for (int i = 0; i < ng; i++) {
        fs_job *j = g[i].rep;
        fprintf(f, "\n[%d] %s  (%d occurrence%s)\n", i + 1, fs_ptype_label(g[i].ptype), g[i].count,
                g[i].count == 1 ? "" : "s");
        if (j->asan_type) fprintf(f, "    error type: %s\n", j->asan_type);

        /* injected failure */
        if (j->inj_n > 0) {
            const fs_frame *a = &j->inj[0];
            if (a->file && a->file[0])
                fprintf(f, "    injected failure: allocation #%llu at %s:%d\n", j->index, a->file,
                        a->line);
            else
                fprintf(f, "    injected failure: allocation #%llu (site 0x%llx)\n", j->index,
                        j->site);
            for (int k = 0; k < j->inj_n; k++) frame_line(f, &j->inj[k], "        ");
        }

        /* error stack */
        if (j->err_n > 0) {
            fprintf(f, "    error stack:\n");
            for (int k = 0; k < j->err_n && k < 12; k++) frame_line(f, &j->err[k], "        ");
        } else if (g[i].ptype == PT_HANG) {
            fprintf(f, "    (killed after the timeout)\n");
        } else {
            char how[512];
            describe_exit(cfg, j, how, sizeof(how));
            fprintf(f, "    %s\n", how);
        }

        char cmd[2048];
        repro_cmd(cfg, j, cmd, sizeof(cmd));
        fprintf(f, "    reproduce:\n        %s\n", cmd);
    }
    write_info_text(f, in, ni);
}

/* ---- JSON output ------------------------------------------------------- */

static void json_str(FILE *f, const char *s) {
    fputc('"', f);
    for (const char *p = s ? s : ""; *p; p++) {
        unsigned char c = (unsigned char)*p;
        switch (c) {
        case '"': fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc((int)c, f);
        }
    }
    fputc('"', f);
}

static void json_frames(FILE *f, const fs_frame *fr, int n) {
    fputc('[', f);
    for (int i = 0; i < n; i++) {
        if (i) fputc(',', f);
        fputs("{\"function\":", f);
        json_str(f, fr[i].func ? fr[i].func : "");
        fputs(",\"file\":", f);
        json_str(f, fr[i].file ? fr[i].file : "");
        fprintf(f, ",\"line\":%d}", fr[i].line);
    }
    fputc(']', f);
}

static void write_json(FILE *f, const fs_cfg *cfg, fs_group *g, int ng, int nran, int nfail,
                       const fs_info *in, int ni, int nexit) {
    fputs("{\n  \"tool\": \"failstep\",\n", f);
    fputs("  \"version\": \"" FAILSTEP_VERSION_STRING "\",\n", f);
    fputs("  \"mode\": ", f);
    json_str(f, cfg->mode);
    fprintf(f, ",\n  \"runs\": %d,\n  \"failing_runs\": %d,\n  \"problems\": %d,\n", nran, nfail, ng);
    fprintf(f, "  \"clean_exits\": %d,\n", nexit);
    fputs("  \"info\": [", f);
    for (int k = 0; k < ni; k++) {
        char msg[1024];
        info_message(&in[k], msg, sizeof(msg));
        if (k) fputc(',', f);
        fprintf(f, "\n    {\"type\": \"clean-exit\", \"exit_code\": %d, \"runs\": %d, \"alloc_indices\": [",
                in[k].exit_code, in[k].runs);
        for (int i = 0; i < in[k].runs; i++) fprintf(f, "%s%llu", i ? ", " : "", in[k].idx[i]);
        fputs("], \"message\": ", f);
        json_str(f, msg);
        fputc('}', f);
    }
    fputs(ni ? "\n  ],\n" : "],\n", f);
    fputs("  \"results\": [", f);
    for (int i = 0; i < ng; i++) {
        fs_job *j = g[i].rep;
        char cmd[2048];
        repro_cmd(cfg, j, cmd, sizeof(cmd));
        if (i) fputc(',', f);
        fputs("\n    {\n      \"type\": ", f);
        json_str(f, fs_ptype_name(g[i].ptype));
        fputs(",\n      \"label\": ", f);
        json_str(f, fs_ptype_label(g[i].ptype));
        fprintf(f, ",\n      \"count\": %d,\n", g[i].count);
        fprintf(f, "      \"site\": \"0x%llx\",\n", g[i].site);
        fprintf(f, "      \"alloc_index\": %llu,\n", j->index);
        fprintf(f, "      \"exit_code\": %d,\n      \"signal\": %d,\n", j->exit_code, j->signalnum);
        fputs("      \"error_type\": ", f);
        json_str(f, j->asan_type ? j->asan_type : "");
        fputs(",\n      \"injected_stack\": ", f);
        json_frames(f, j->inj, j->inj_n);
        fputs(",\n      \"error_stack\": ", f);
        json_frames(f, j->err, j->err_n);
        fputs(",\n      \"reproduce\": ", f);
        json_str(f, cmd);
        fputs("\n    }", f);
    }
    fputs("\n  ]\n}\n", f);
}

/* ---- SARIF output ------------------------------------------------------ */

static const char *sarif_level(fs_ptype t) {
    return (t == PT_ABNORMAL || t == PT_HANG) ? "warning" : "error";
}

/* Is this frame sanitizer/libc-internal rather than the user's code? */
static int frame_is_internal_loc(const fs_frame *fr) {
    const char *fn = fr->func ? fr->func : "";
    const char *fl = fr->file ? fr->file : "";
    if (!strcmp(fn, "malloc") || !strcmp(fn, "free") || !strcmp(fn, "calloc") ||
        !strcmp(fn, "realloc") || strstr(fn, "failstep_") || strstr(fn, "__interceptor") ||
        strstr(fn, "__asan") || strstr(fn, "printf_common"))
        return 1;
    if (strstr(fl, "libsanitizer") || strstr(fl, "sanitizer_common") || strstr(fl, "asan/") ||
        strstr(fl, "compiler-rt"))
        return 1;
    return 0;
}

/* Choose a single, developer-actionable source location for SARIF: the first
 * user frame of the error stack, else the injected allocation site. */
static const fs_frame *pick_location(const fs_job *j) {
    for (int i = 0; i < j->err_n; i++)
        if (j->err[i].file && j->err[i].file[0] && !frame_is_internal_loc(&j->err[i]))
            return &j->err[i];
    if (j->inj_n > 0) return &j->inj[0];
    return j->err_n > 0 ? &j->err[0] : NULL;
}

static void write_sarif(FILE *f, const fs_cfg *cfg, fs_group *g, int ng, const fs_info *in, int ni) {
    fputs("{\n  \"version\": \"2.1.0\",\n", f);
    fputs("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n", f);
    fputs("  \"runs\": [\n    {\n      \"tool\": {\n        \"driver\": {\n", f);
    fputs("          \"name\": \"failstep\",\n", f);
    fputs("          \"version\": \"" FAILSTEP_VERSION_STRING "\",\n", f);
    fputs("          \"informationUri\": \"https://github.com/Topogamer0/failstep\",\n", f);
    fputs("          \"rules\": [\n", f);
    const fs_ptype rules[] = {PT_ASAN, PT_NULLDEREF, PT_LEAK, PT_HANG, PT_ABNORMAL};
    for (size_t r = 0; r < sizeof(rules) / sizeof(rules[0]); r++) {
        if (r) fputc(',', f);
        fputs("            {\"id\": ", f);
        json_str(f, fs_ptype_name(rules[r]));
        fputs(", \"name\": ", f);
        json_str(f, fs_ptype_label(rules[r]));
        fputs(", \"shortDescription\": {\"text\": ", f);
        json_str(f, fs_ptype_label(rules[r]));
        fputs("}}\n", f);
    }
    fputs("          ]\n        }\n      },\n", f);
    /* Expected orderly exits are not results (they would surface as alerts):
     * they travel as notes on the invocation instead. */
    fputs("      \"invocations\": [{\"executionSuccessful\": true, \"toolExecutionNotifications\": [", f);
    for (int k = 0; k < ni; k++) {
        char note[1024];
        info_message(&in[k], note, sizeof(note));
        if (k) fputc(',', f);
        fputs("\n        {\"level\": \"note\", \"descriptor\": {\"id\": \"clean-exit\"}, \"message\": {\"text\": ", f);
        json_str(f, note);
        fputs("}}", f);
    }
    fputs(ni ? "\n      ]}],\n" : "]}],\n", f);
    fputs("      \"results\": [", f);
    for (int i = 0; i < ng; i++) {
        fs_job *j = g[i].rep;
        char cmd[2048], how[512] = "", msg[3200];
        repro_cmd(cfg, j, cmd, sizeof(cmd));
        const fs_frame *loc = pick_location(j);
        if (g[i].ptype == PT_ABNORMAL) {
            char d[480];
            describe_exit(cfg, j, d, sizeof(d));
            snprintf(how, sizeof(how), ": %s,", d);
        }
        snprintf(msg, sizeof(msg), "%s%s after injected allocation failure #%llu (%d occurrence%s). Reproduce: %s",
                 fs_ptype_label(g[i].ptype), how, j->index, g[i].count, g[i].count == 1 ? "" : "s", cmd);
        if (i) fputc(',', f);
        fputs("\n        {\n          \"ruleId\": ", f);
        json_str(f, fs_ptype_name(g[i].ptype));
        fprintf(f, ",\n          \"level\": \"%s\",\n", sarif_level(g[i].ptype));
        fputs("          \"message\": {\"text\": ", f);
        json_str(f, msg);
        fputs("},\n", f);
        if (loc && loc->file && loc->file[0]) {
            fputs("          \"locations\": [{\"physicalLocation\": {\"artifactLocation\": {\"uri\": ", f);
            json_str(f, loc->file);
            fprintf(f, "}, \"region\": {\"startLine\": %d}}}]\n", loc->line > 0 ? loc->line : 1);
        } else {
            fputs("          \"locations\": []\n", f);
        }
        fputs("        }", f);
    }
    fputs("\n      ]\n    }\n  ]\n}\n", f);
}

/* ---- entry ------------------------------------------------------------- */

int fs_report(const fs_cfg *cfg, fs_job *jobs, int njobs) {
    int nran = 0, nfail = 0, nexit = 0;
    for (int i = 0; i < njobs; i++) {
        if (!jobs[i].ran) continue;
        nran++;
        if (fs_ptype_is_problem(jobs[i].ptype)) nfail++;
        else if (jobs[i].ptype == PT_EXIT) nexit++;
    }

    fs_group *g;
    int ng = build_groups(jobs, njobs, &g);
    fs_info *in;
    int ni = build_info(jobs, njobs, &in);

    FILE *f = stdout;
    if (cfg->out_file) {
        f = fopen(cfg->out_file, "w");
        if (!f) {
            fprintf(stderr, "failstep: cannot open %s\n", cfg->out_file);
            f = stdout;
        }
    }

    if (strcmp(cfg->format, "json") == 0) write_json(f, cfg, g, ng, nran, nfail, in, ni, nexit);
    else if (strcmp(cfg->format, "sarif") == 0) write_sarif(f, cfg, g, ng, in, ni);
    else write_text(f, cfg, g, ng, nran, nfail, in, ni, nexit);

    if (f != stdout) fclose(f);

    for (int i = 0; i < ng; i++) free(g[i].sig);
    free(g);
    free_info(in, ni);
    return ng;
}
