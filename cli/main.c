#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
/*
 * failstep CLI -- entry point and orchestration.
 *
 * Runs a target repeatedly, each time failing one allocation, in parallel
 * worker processes with a per-run timeout, and is resumable if interrupted.
 *
 * SPDX-License-Identifier: MIT
 */
#include "cli.h"
#include <failstep/failstep.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <time.h>
#  include <unistd.h>
#else
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <direct.h>
#  include <windows.h>
#endif

/* ---- platform helpers -------------------------------------------------- */

static int cpu_count(void) {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return (int)si.dwNumberOfProcessors;
#else
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    return n > 0 ? (int)n : 1;
#endif
}

static void make_one_dir(const char *path) {
#if defined(_WIN32)
    _mkdir(path);
#else
    mkdir(path, 0755);
#endif
}

/* Create `path` and any missing parent directories (like mkdir -p). */
static void make_dir(const char *path) {
    char buf[1024];
    size_t n = strlen(path);
    if (n >= sizeof(buf)) {
        make_one_dir(path);
        return;
    }
    memcpy(buf, path, n + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char sep = *p;
            *p = '\0';
            if (buf[0]) make_one_dir(buf);
            *p = sep;
        }
    }
    make_one_dir(buf);
}

static void sleep_ms(int ms) {
#if defined(_WIN32)
    Sleep((DWORD)ms);
#else
    struct timespec ts = {ms / 1000, (long)(ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
#endif
}

static int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (f) {
        fclose(f);
        return 1;
    }
    return 0;
}

/* ---- usage ------------------------------------------------------------- */

static void usage(FILE *f) {
    fputs(
        "failstep -- systematic allocation-failure testing, ASan-compatible\n"
        "\n"
        "usage: failstep <mode> [options] -- <target> [args...]\n"
        "\n"
        "modes:\n"
        "  enumerate   fail the 1st allocation, then the 2nd, ... one per run\n"
        "  sites       fail each distinct allocation site once (fast)\n"
        "  continue    fail allocation N, then run K more steps in-process\n"
        "              (needs a target built with failstep_run_harness)\n"
        "  fuzz        run a libFuzzer target and report the crash it finds\n"
        "\n"
        "options:\n"
        "  -j, --jobs N       parallel workers (default: CPUs)\n"
        "  -t, --timeout SEC  per-run timeout in seconds (default 30)\n"
        "  -o, --output DIR   work/state directory (default failstep-out)\n"
        "  -f, --format FMT   text | json | sarif (default text)\n"
        "      --out FILE     write the report to FILE instead of stdout\n"
        "  -k, --steps N      continue mode: follow-up steps (default 2)\n"
        "  -r, --resume       reuse completed runs from a previous invocation\n"
        "      --max N        cap the number of runs (safety)\n"
        "  -q, --quiet        no progress output\n"
        "  -v, --verbose      one line per run\n"
        "  -h, --help         this help\n"
        "      --version      print version\n"
        "\n"
        "exit codes: 0 no problems, 1 problems found, 2 usage/internal error\n",
        f);
}

/* ---- env construction -------------------------------------------------- */

/* Build a NULL-terminated array of "KEY=VALUE" strings for the child. */
typedef struct {
    char *v[16];
    int n;
} envset;

static void env_add(envset *e, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (e->n < (int)(sizeof(e->v) / sizeof(e->v[0]) - 1)) e->v[e->n++] = fs_xstrdup(buf);
}

static void env_free(envset *e) {
    for (int i = 0; i < e->n; i++) free(e->v[i]);
}

static const char *ASAN_DEFAULTS =
    "ASAN_OPTIONS=detect_leaks=1:abort_on_error=0:exitcode=1:handle_segv=1";

/* ---- run one target process to completion ------------------------------ */

static void run_once(char *const argv[], envset *env, const char *out, const char *err,
                     int timeout_ms, fs_proc_result *res) {
    char *envv[18];
    int n = 0;
    for (int i = 0; i < env->n; i++) envv[n++] = env->v[i];
    envv[n] = NULL;

    memset(res, 0, sizeof(*res));
    fs_proc *p = fs_proc_start(argv, envv, out, err);
    if (!p) {
        res->exit_code = 127;
        return;
    }
    long long deadline = fs_now_ms() + timeout_ms;
    while (!fs_proc_poll(p, deadline, res)) sleep_ms(10);
    fs_proc_free(p);
}

/* ---- the count pass ---------------------------------------------------- */

static int count_pass(const fs_cfg *cfg, const char *statp, unsigned long long *total,
                      unsigned long long **sites, size_t *nsites) {
    char outp[1024], errp[1024];
    snprintf(outp, sizeof(outp), "%s/count.out", cfg->outdir);
    snprintf(errp, sizeof(errp), "%s/count.err", cfg->outdir);

    envset e = {{0}, 0};
    env_add(&e, "FAILSTEP_MODE=count");
    env_add(&e, "FAILSTEP_STATS=%s", statp);
    if (strcmp(cfg->mode, "continue") == 0) {
        env_add(&e, "FAILSTEP_SCOPED=1");
        env_add(&e, "FAILSTEP_CONTINUE_STEPS=%d", cfg->continue_steps);
    }
    env_add(&e, "%s", ASAN_DEFAULTS);

    fs_proc_result r;
    run_once(cfg->targv, &e, outp, errp, cfg->timeout_ms * 4, &r);
    env_free(&e);

    if (!fs_read_stats(statp, total, sites, nsites)) {
        fprintf(stderr, "failstep: the count pass produced no stats (did the target link "
                        "libfailstep and use the override header / --wrap, and did it exit?)\n");
        fprintf(stderr, "failstep: see %s and %s\n", outp, errp);
        return 0;
    }
    return 1;
}

/* ---- job key / paths --------------------------------------------------- */

static void job_key(const fs_cfg *cfg, fs_job *j, char *buf, size_t n) {
    if (strcmp(cfg->mode, "sites") == 0) snprintf(buf, n, "site-0x%llx", j->site);
    else snprintf(buf, n, "index-%llu", j->index);
}

/* ---- persist / load a completed run ------------------------------------ */

static void rec_write(const char *path, const fs_job *j) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "outcome %d %d %d\n", j->exit_code, j->signalnum, j->timed_out);
    fclose(f);
}

static int rec_read(const char *path, fs_job *j) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    int ec = 0, sg = 0, to = 0;
    if (fscanf(f, "outcome %d %d %d", &ec, &sg, &to) == 3) {
        j->exit_code = ec;
        j->signalnum = sg;
        j->timed_out = to;
        fclose(f);
        return 1;
    }
    fclose(f);
    return 0;
}

/* ---- scheduling one worker --------------------------------------------- */

typedef struct {
    fs_job *job;
    fs_proc *proc;
    fs_proc_result res;
    long long deadline;
    char reportp[1024];
    char errp[1024];
    char recp[1024];
    int active;
} slot;

static void start_job(const fs_cfg *cfg, slot *s, fs_job *j) {
    char key[256];
    job_key(cfg, j, key, sizeof(key));
    char outp[1024];
    snprintf(s->reportp, sizeof(s->reportp), "%s/%s.report", cfg->outdir, key);
    snprintf(s->errp, sizeof(s->errp), "%s/%s.err", cfg->outdir, key);
    snprintf(s->recp, sizeof(s->recp), "%s/%s.rec", cfg->outdir, key);
    snprintf(outp, sizeof(outp), "%s/%s.out", cfg->outdir, key);
    remove(s->reportp);

    envset e = {{0}, 0};
    if (strcmp(cfg->mode, "sites") == 0) {
        env_add(&e, "FAILSTEP_MODE=site");
        env_add(&e, "FAILSTEP_FAIL_SITE=0x%llx", j->site);
    } else {
        env_add(&e, "FAILSTEP_MODE=index");
        env_add(&e, "FAILSTEP_FAIL_INDEX=%llu", j->index);
    }
    if (strcmp(cfg->mode, "continue") == 0) {
        env_add(&e, "FAILSTEP_SCOPED=1");
        env_add(&e, "FAILSTEP_CONTINUE_STEPS=%d", cfg->continue_steps);
        j->scoped = 1;
        j->continue_steps = cfg->continue_steps;
    }
    env_add(&e, "FAILSTEP_REPORT=%s", s->reportp);
    env_add(&e, "%s", ASAN_DEFAULTS);

    char *envv[18];
    int n = 0;
    for (int i = 0; i < e.n; i++) envv[n++] = e.v[i];
    envv[n] = NULL;

    memset(&s->res, 0, sizeof(s->res));
    s->job = j;
    s->proc = fs_proc_start(cfg->targv, envv, outp, s->errp);
    s->deadline = fs_now_ms() + cfg->timeout_ms;
    s->active = 1;
    if (!s->proc) {
        j->ran = 1;
        j->exit_code = 127;
        j->ptype = PT_ABNORMAL;
        s->active = 0;
    }
    env_free(&e);
}

static void finish_job(const fs_cfg *cfg, slot *s) {
    fs_job *j = s->job;
    j->ran = 1;
    j->exit_code = s->res.exit_code;
    j->signalnum = s->res.signalnum;
    j->timed_out = s->res.timed_out;
    if (file_exists(s->reportp)) fs_read_report(s->reportp, j);
    j->err_path = fs_xstrdup(s->errp);
    fs_analyze(j, cfg->targv[0]);
    rec_write(s->recp, j);
    s->active = 0;
    fs_proc_free(s->proc);
    s->proc = NULL;
}

/* ---- the parallel driver ----------------------------------------------- */

static void drive(const fs_cfg *cfg, fs_job *jobs, int njobs) {
    slot *slots = (slot *)fs_xcalloc((size_t)cfg->jobs, sizeof(slot));
    int next = 0, done = 0;

    while (done < njobs) {
        /* fill free slots */
        for (int i = 0; i < cfg->jobs && next < njobs; i++) {
            if (slots[i].active) continue;
            /* skip already-completed (resume) jobs */
            while (next < njobs && jobs[next].ran) {
                done++;
                next++;
            }
            if (next >= njobs) break;
            start_job(cfg, &slots[i], &jobs[next]);
            next++;
            if (!slots[i].active) { /* failed to spawn: counted as done */
                done++;
            }
        }
        /* poll active slots */
        int any_active = 0;
        for (int i = 0; i < cfg->jobs; i++) {
            if (!slots[i].active) continue;
            any_active = 1;
            if (fs_proc_poll(slots[i].proc, slots[i].deadline, &slots[i].res)) {
                finish_job(cfg, &slots[i]);
                done++;
                if (!cfg->quiet) {
                    fs_job *j = slots[i].job;
                    if (cfg->verbose || j->ptype != PT_CLEAN)
                        fprintf(stderr, "  [%d/%d] %-18s %s\n", done, njobs,
                                (strcmp(cfg->mode, "sites") == 0) ? "site" : "run",
                                j->ptype == PT_CLEAN ? "clean" : fs_ptype_label(j->ptype));
                    else if ((done % 50) == 0)
                        fprintf(stderr, "  [%d/%d] ...\n", done, njobs);
                }
            }
        }
        if (next >= njobs && !any_active) break;
        sleep_ms(5);
    }
    free(slots);
}

/* ---- fuzz mode --------------------------------------------------------- */

static int run_fuzz(fs_cfg *cfg) {
    char outp[1024], errp[1024];
    snprintf(outp, sizeof(outp), "%s/fuzz.out", cfg->outdir);
    snprintf(errp, sizeof(errp), "%s/fuzz.err", cfg->outdir);

    envset e = {{0}, 0};
    env_add(&e, "%s", ASAN_DEFAULTS);
    /* libFuzzer manages its own time; give the whole run a generous ceiling. */
    int tmo = cfg->timeout_ms > 0 ? cfg->timeout_ms : 60000;
    fs_proc_result r;
    run_once(cfg->targv, &e, outp, errp, tmo, &r);
    env_free(&e);

    fs_job *j = fs_xcalloc(1, sizeof(fs_job));
    j->ran = 1;
    j->exit_code = r.exit_code;
    j->signalnum = r.signalnum;
    j->timed_out = r.timed_out;
    j->err_path = fs_xstrdup(errp);
    fs_analyze(j, cfg->targv[0]);

    /* locate the crash input libFuzzer wrote, for the reproducer */
    size_t len;
    char *text = fs_read_file(errp, &len);
    char crash[1024] = {0};
    if (text) {
        char *w = strstr(text, "Test unit written to ");
        if (w) {
            w += strlen("Test unit written to ");
            char *nl = strchr(w, '\n');
            if (nl) *nl = '\0';
            snprintf(crash, sizeof(crash), "%s", w);
        }
        free(text);
    }
    if (crash[0]) {
        char cmd[1200];
        snprintf(cmd, sizeof(cmd), "%s %s", cfg->targv[0], crash);
        j->repro = fs_xstrdup(cmd);
    }

    int ng = fs_report(cfg, j, 1);
    fs_job_free(j);
    free(j);
    return ng;
}

/* ---- argument parsing -------------------------------------------------- */

int main(int argc, char **argv) {
    fs_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.jobs = cpu_count();
    cfg.timeout_ms = 30000;
    cfg.outdir = "failstep-out";
    cfg.format = "text";
    cfg.continue_steps = 2;

    if (argc < 2) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "--version") == 0) {
        printf("failstep %d.%d.%d\n", FAILSTEP_VERSION_MAJOR, FAILSTEP_VERSION_MINOR,
               FAILSTEP_VERSION_PATCH);
        return 0;
    }

    cfg.mode = argv[1];
    if (strcmp(cfg.mode, "enumerate") && strcmp(cfg.mode, "sites") &&
        strcmp(cfg.mode, "continue") && strcmp(cfg.mode, "fuzz")) {
        fprintf(stderr, "failstep: unknown mode '%s'\n\n", cfg.mode);
        usage(stderr);
        return 2;
    }

    int i = 2;
    for (; i < argc; i++) {
        char *a = argv[i];
        if (strcmp(a, "--") == 0) {
            i++;
            break;
        } else if ((!strcmp(a, "-j") || !strcmp(a, "--jobs")) && i + 1 < argc) {
            cfg.jobs = atoi(argv[++i]);
            if (cfg.jobs < 1) cfg.jobs = 1;
        } else if ((!strcmp(a, "-t") || !strcmp(a, "--timeout")) && i + 1 < argc) {
            cfg.timeout_ms = (int)(atof(argv[++i]) * 1000);
            if (cfg.timeout_ms < 100) cfg.timeout_ms = 100;
        } else if ((!strcmp(a, "-o") || !strcmp(a, "--output")) && i + 1 < argc) {
            cfg.outdir = argv[++i];
        } else if ((!strcmp(a, "-f") || !strcmp(a, "--format")) && i + 1 < argc) {
            cfg.format = argv[++i];
        } else if (!strcmp(a, "--out") && i + 1 < argc) {
            cfg.out_file = argv[++i];
        } else if ((!strcmp(a, "-k") || !strcmp(a, "--steps")) && i + 1 < argc) {
            cfg.continue_steps = atoi(argv[++i]);
        } else if (!strcmp(a, "--max") && i + 1 < argc) {
            cfg.max_runs = atoi(argv[++i]);
        } else if (!strcmp(a, "-r") || !strcmp(a, "--resume")) {
            cfg.resume = 1;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            cfg.quiet = 1;
        } else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
            cfg.verbose = 1;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 0;
        } else {
            fprintf(stderr, "failstep: unknown option '%s'\n", a);
            return 2;
        }
    }
    if (i >= argc) {
        fprintf(stderr, "failstep: no target given (use -- <target> [args])\n");
        return 2;
    }
    cfg.targv = &argv[i];
    cfg.targc = argc - i;

    if (strcmp(cfg.format, "text") && strcmp(cfg.format, "json") && strcmp(cfg.format, "sarif")) {
        fprintf(stderr, "failstep: unknown format '%s'\n", cfg.format);
        return 2;
    }

    make_dir(cfg.outdir);

    if (strcmp(cfg.mode, "fuzz") == 0) {
        int ng = run_fuzz(&cfg);
        return ng > 0 ? 1 : 0;
    }

    /* count pass */
    char statp[1024];
    snprintf(statp, sizeof(statp), "%s/stats.txt", cfg.outdir);
    unsigned long long total = 0, *sites = NULL;
    size_t nsites = 0;
    if (!count_pass(&cfg, statp, &total, &sites, &nsites)) return 2;

    if (!cfg.quiet)
        fprintf(stderr, "failstep: %llu allocations, %zu distinct sites\n", total, nsites);

    /* build jobs */
    int njobs;
    fs_job *jobs;
    if (strcmp(cfg.mode, "sites") == 0) {
        njobs = (int)nsites;
        if (cfg.max_runs > 0 && njobs > cfg.max_runs) njobs = cfg.max_runs;
        jobs = (fs_job *)fs_xcalloc((size_t)njobs, sizeof(fs_job));
        for (int k = 0; k < njobs; k++) jobs[k].site = sites[k];
    } else {
        njobs = (int)total;
        if (cfg.max_runs > 0 && njobs > cfg.max_runs) njobs = cfg.max_runs;
        jobs = (fs_job *)fs_xcalloc((size_t)(njobs > 0 ? njobs : 1), sizeof(fs_job));
        for (int k = 0; k < njobs; k++) jobs[k].index = (unsigned long long)(k + 1);
    }
    free(sites);

    if (njobs == 0) {
        fprintf(stderr, "failstep: the target made no allocations through failstep.\n");
        fs_report(&cfg, jobs, 0);
        free(jobs);
        return 0;
    }

    /* resume: mark completed runs */
    if (cfg.resume) {
        int resumed = 0;
        for (int k = 0; k < njobs; k++) {
            char key[256], recp[1024];
            job_key(&cfg, &jobs[k], key, sizeof(key));
            snprintf(recp, sizeof(recp), "%s/%s.rec", cfg.outdir, key);
            if (rec_read(recp, &jobs[k])) {
                char reportp[1024], errp[1024];
                snprintf(reportp, sizeof(reportp), "%s/%s.report", cfg.outdir, key);
                snprintf(errp, sizeof(errp), "%s/%s.err", cfg.outdir, key);
                if (file_exists(reportp)) fs_read_report(reportp, &jobs[k]);
                jobs[k].err_path = fs_xstrdup(errp);
                if (strcmp(cfg.mode, "continue") == 0) {
                    jobs[k].scoped = 1;
                    jobs[k].continue_steps = cfg.continue_steps;
                }
                fs_analyze(&jobs[k], cfg.targv[0]);
                jobs[k].ran = 1;
                resumed++;
            }
        }
        if (!cfg.quiet && resumed) fprintf(stderr, "failstep: resumed %d completed runs\n", resumed);
    }

    drive(&cfg, jobs, njobs);

    int ng = fs_report(&cfg, jobs, njobs);

    for (int k = 0; k < njobs; k++) fs_job_free(&jobs[k]);
    free(jobs);
    return ng > 0 ? 1 : 0;
}
