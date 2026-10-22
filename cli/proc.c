#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#  define _POSIX_C_SOURCE 200809L
#endif
/*
 * failstep CLI -- process control: start a target with extra environment,
 * redirect its output, poll for completion and enforce a timeout.
 *
 * SPDX-License-Identifier: MIT
 */
#include "cli.h"

#include <stdlib.h>
#include <string.h>

long long fs_now_ms(void);

#if !defined(_WIN32)

/* ======================================================================= */
/* POSIX                                                                   */
/* ======================================================================= */
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

struct fs_proc {
    pid_t pid;
    int killed;
    int reaped;
    fs_proc_result result;
};

long long fs_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int open_out(const char *path) {
    if (!path) return open("/dev/null", O_WRONLY);
    return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
}

fs_proc *fs_proc_start(char *const argv[], char *const env_add[], const char *out_path,
                       const char *err_path) {
    int ofd = open_out(out_path);
    int efd = open_out(err_path);
    if (ofd < 0 || efd < 0) {
        if (ofd >= 0) close(ofd);
        if (efd >= 0) close(efd);
        return NULL;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(ofd);
        close(efd);
        return NULL;
    }
    if (pid == 0) {
        /* child: own process group so the whole subtree can be killed */
        setpgid(0, 0);
        dup2(ofd, 1);
        dup2(efd, 2);
        close(ofd);
        close(efd);
        for (int i = 0; env_add && env_add[i]; i++) {
            char *eq = strchr(env_add[i], '=');
            if (!eq) continue;
            size_t klen = (size_t)(eq - env_add[i]);
            char key[256];
            if (klen >= sizeof(key)) continue;
            memcpy(key, env_add[i], klen);
            key[klen] = '\0';
            setenv(key, eq + 1, 1);
        }
        execvp(argv[0], argv);
        _exit(127);
    }

    /* parent */
    setpgid(pid, pid); /* race-safe: set in both parent and child */
    close(ofd);
    close(efd);

    fs_proc *p = (fs_proc *)fs_xcalloc(1, sizeof(*p));
    p->pid = pid;
    return p;
}

int fs_proc_poll(fs_proc *p, long long deadline_ms, fs_proc_result *r) {
    if (p->reaped) {
        *r = p->result;
        return 1;
    }
    if (!p->killed && fs_now_ms() >= deadline_ms) {
        kill(-p->pid, SIGKILL);
        p->killed = 1;
        p->result.timed_out = 1;
    }

    int status = 0;
    pid_t w = waitpid(p->pid, &status, WNOHANG);
    if (w == 0) return 0; /* still running */

    if (w == p->pid) {
        if (WIFEXITED(status)) p->result.exit_code = WEXITSTATUS(status);
        else if (WIFSIGNALED(status)) p->result.signalnum = WTERMSIG(status);
    }
    /* w < 0 (ECHILD): treat as finished with whatever we recorded */
    p->reaped = 1;
    *r = p->result;
    return 1;
}

void fs_proc_free(fs_proc *p) {
    free(p);
}

#else

/* ======================================================================= */
/* Windows                                                                 */
/* ======================================================================= */
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

struct fs_proc {
    PROCESS_INFORMATION pi;
    int killed;
    int reaped;
    fs_proc_result result;
};

long long fs_now_ms(void) {
    return (long long)GetTickCount64();
}

static HANDLE open_out(const char *path) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    const char *p = path ? path : "NUL";
    return CreateFileA(p, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
}

/* Build a command line by quoting each argv element (sufficient for our use). */
static char *build_cmdline(char *const argv[]) {
    size_t cap = 1;
    for (int i = 0; argv[i]; i++) cap += strlen(argv[i]) * 2 + 4;
    char *s = (char *)fs_xmalloc(cap);
    s[0] = '\0';
    for (int i = 0; argv[i]; i++) {
        if (i) strcat(s, " ");
        strcat(s, "\"");
        for (const char *c = argv[i]; *c; c++) {
            if (*c == '"' || *c == '\\') strncat(s, "\\", 1);
            strncat(s, c, 1);
        }
        strcat(s, "\"");
    }
    return s;
}

static char *build_env(char *const env_add[]) {
    char *base = GetEnvironmentStringsA();
    size_t blen = 0;
    while (base[blen] != '\0' || base[blen + 1] != '\0') blen++;
    blen++; /* final NUL of last entry */
    size_t extra = 0;
    for (int i = 0; env_add && env_add[i]; i++) extra += strlen(env_add[i]) + 1;
    char *out = (char *)fs_xmalloc(blen + extra + 1);
    memcpy(out, base, blen);
    size_t pos = blen;
    for (int i = 0; env_add && env_add[i]; i++) {
        size_t n = strlen(env_add[i]) + 1;
        memcpy(out + pos, env_add[i], n);
        pos += n;
    }
    out[pos] = '\0';
    FreeEnvironmentStringsA(base);
    return out;
}

fs_proc *fs_proc_start(char *const argv[], char *const env_add[], const char *out_path,
                       const char *err_path) {
    HANDLE ho = open_out(out_path);
    HANDLE he = open_out(err_path);
    if (ho == INVALID_HANDLE_VALUE || he == INVALID_HANDLE_VALUE) {
        if (ho != INVALID_HANDLE_VALUE) CloseHandle(ho);
        if (he != INVALID_HANDLE_VALUE) CloseHandle(he);
        return NULL;
    }

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = ho;
    si.hStdError = he;

    char *cmd = build_cmdline(argv);
    char *env = build_env(env_add);

    fs_proc *p = (fs_proc *)fs_xcalloc(1, sizeof(*p));
    BOOL ok = CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW, env, NULL, &si, &p->pi);
    free(cmd);
    free(env);
    CloseHandle(ho);
    CloseHandle(he);
    if (!ok) {
        free(p);
        return NULL;
    }
    return p;
}

int fs_proc_poll(fs_proc *p, long long deadline_ms, fs_proc_result *r) {
    if (p->reaped) {
        *r = p->result;
        return 1;
    }
    if (!p->killed && fs_now_ms() >= deadline_ms) {
        TerminateProcess(p->pi.hProcess, 1);
        p->killed = 1;
        p->result.timed_out = 1;
    }
    DWORD w = WaitForSingleObject(p->pi.hProcess, 0);
    if (w == WAIT_TIMEOUT) return 0;
    DWORD code = 0;
    GetExitCodeProcess(p->pi.hProcess, &code);
    p->result.exit_code = (int)code;
    CloseHandle(p->pi.hProcess);
    CloseHandle(p->pi.hThread);
    p->reaped = 1;
    *r = p->result;
    return 1;
}

void fs_proc_free(fs_proc *p) {
    free(p);
}

#endif
