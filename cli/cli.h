/*
 * failstep CLI -- shared declarations.
 * SPDX-License-Identifier: MIT
 */
#ifndef FAILSTEP_CLI_H
#define FAILSTEP_CLI_H

#include <stddef.h>

/* ---- problem classification -------------------------------------------- */

typedef enum {
    PT_CLEAN = 0,   /* no problem: the program handled the failure */
    PT_ASAN,        /* AddressSanitizer reported memory corruption */
    PT_LEAK,        /* LeakSanitizer reported a leak */
    PT_NULLDEREF,   /* dereferenced the NULL the failed allocation returned */
    PT_HANG,        /* exceeded the timeout */
    PT_ABNORMAL     /* crashed or exited non-zero without an ASan report */
} fs_ptype;

const char *fs_ptype_name(fs_ptype t);   /* stable machine id, e.g. "asan-error" */
const char *fs_ptype_label(fs_ptype t);  /* human label */

/* ---- a resolved stack frame -------------------------------------------- */

typedef struct {
    char *func;               /* symbol, may be NULL */
    char *file;               /* source file, may be NULL */
    int line;                 /* source line, 0 if unknown */
    unsigned long long off;   /* module offset (injected frames only) */
    char *module;             /* module path (injected frames only) */
    char *raw;                /* original address text / unparsed line */
} fs_frame;

/* ---- one run of the target (one injected failure) ---------------------- */

typedef struct {
    char *key;                /* resume/repro key, e.g. "index-5" */

    /* what was injected */
    unsigned long long index;
    unsigned long long site;
    int scoped;               /* continue mode */
    int continue_steps;
    fs_frame *inj;            /* stack of the failed allocation */
    int inj_n;

    /* raw outcome */
    int ran;                  /* 0 if skipped/not run */
    int exit_code;
    int signalnum;            /* 0 if none */
    int timed_out;

    /* analysis */
    fs_ptype ptype;
    char *asan_type;          /* e.g. "heap-use-after-free" */
    fs_frame *err;            /* stack of the ASan error */
    int err_n;
    char *err_path;           /* captured stderr file */
    char *repro;              /* explicit reproducer command (fuzz mode) */
} fs_job;

/* ---- a group of equivalent problems ------------------------------------ */

typedef struct {
    fs_ptype ptype;
    unsigned long long site;
    char *sig;                /* grouping signature */
    fs_job *rep;              /* representative job (first seen) */
    int count;
} fs_group;

/* ---- configuration ----------------------------------------------------- */

typedef struct {
    const char *mode;         /* enumerate | sites | continue | fuzz */
    char **targv;             /* target argv (NULL-terminated) */
    int targc;
    int jobs;                 /* parallel workers */
    int timeout_ms;
    const char *outdir;       /* work/state directory */
    int resume;
    const char *format;       /* text | json | sarif */
    const char *out_file;     /* NULL = stdout */
    int continue_steps;
    int max_runs;             /* 0 = unlimited; safety cap */
    int quiet;
    int verbose;
} fs_cfg;

/* ---- process control (proc.c) ------------------------------------------ */

typedef struct fs_proc fs_proc;

typedef struct {
    int exit_code;
    int signalnum;
    int timed_out;
} fs_proc_result;

/* Current monotonic time in milliseconds. */
long long fs_now_ms(void);

/* Start `argv` with the given extra "KEY=VALUE" environment entries, redirecting
 * stdout to out_path and stderr to err_path (either may be NULL -> /dev/null).
 * Returns a handle or NULL on failure. */
fs_proc *fs_proc_start(char *const argv[], char *const env_add[], const char *out_path,
                       const char *err_path);

/* Non-blocking reap. Returns 1 and fills `r` if the process has finished,
 * 0 if it is still running. Enforces `deadline_ms` (absolute, from fs_now_ms):
 * if exceeded, the process group is killed and reported as timed_out. */
int fs_proc_poll(fs_proc *p, long long deadline_ms, fs_proc_result *r);

/* Frees the handle (process must have been reaped). */
void fs_proc_free(fs_proc *p);

/* ---- analysis (analyze.c) ---------------------------------------------- */

/* Parses the failstep report file (the injected failure) into the job. */
int fs_read_report(const char *path, fs_job *job);

/* Parses the failstep stats file: returns total alloc count; fills *sites with
 * a malloc'd array of site hashes (count in *nsites), caller frees. */
int fs_read_stats(const char *path, unsigned long long *total, unsigned long long **sites,
                  size_t *nsites);

/* Reads a captured stderr file, detects ASan/LSan output, classifies the job,
 * and fills job->ptype/asan_type/err. The target binary path is used to
 * symbolize injected-frame offsets with addr2line/atos. */
void fs_analyze(fs_job *job, const char *target_path);

/* ---- reporting (report.c) ---------------------------------------------- */

/* Groups jobs that share the same cause and writes the chosen format.
 * Returns the number of distinct problems. */
int fs_report(const fs_cfg *cfg, fs_job *jobs, int njobs);

/* ---- small helpers ----------------------------------------------------- */

char *fs_xstrdup(const char *s);
void *fs_xmalloc(size_t n);
void *fs_xcalloc(size_t n, size_t sz);
char *fs_read_file(const char *path, size_t *len_out); /* NUL-terminated, caller frees */
void fs_frames_free(fs_frame *f, int n);
void fs_job_free(fs_job *j);

#endif /* FAILSTEP_CLI_H */
