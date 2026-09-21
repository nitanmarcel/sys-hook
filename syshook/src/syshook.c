#include "syshook_internal.h"

#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

syshook_entry g_syshook_hooks[SYSHOOK_MAX_HOOKS];
int           g_syshook_count = 0;

static int g_initialized = 0;
static int g_installed    = 0;

const syshook_entry *syshook_find(long nr) {
    for (int i = 0; i < g_syshook_count; i++) {
        if (g_syshook_hooks[i].nr == nr)
            return &g_syshook_hooks[i];
    }
    return NULL;
}

syshook_status syshook_init(void) {
#if !defined(__aarch64__)
    return SYSHOOK_ERR_UNSUPPORTED;
#else
    if (g_initialized)
        return SYSHOOK_OK;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = syshook_sigsys_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGSYS, &sa, NULL) != 0)
        return SYSHOOK_ERR_SIGNAL;

    g_initialized = 1;
    return SYSHOOK_OK;
#endif
}

syshook_status syshook_add(long nr, syshook_fn cb, void *user) {
    if (!g_initialized || g_installed)
        return SYSHOOK_ERR_STATE;
    if (!cb || nr < 0)
        return SYSHOOK_ERR_INVALID;

    for (int i = 0; i < g_syshook_count; i++) {
        if (g_syshook_hooks[i].nr == nr) {
            g_syshook_hooks[i].cb   = cb;
            g_syshook_hooks[i].user = user;
            return SYSHOOK_OK;
        }
    }
    if (g_syshook_count >= SYSHOOK_MAX_HOOKS)
        return SYSHOOK_ERR_LIMIT;

    g_syshook_hooks[g_syshook_count].nr   = nr;
    g_syshook_hooks[g_syshook_count].cb   = cb;
    g_syshook_hooks[g_syshook_count].user = user;
    g_syshook_count++;
    return SYSHOOK_OK;
}

syshook_status syshook_install_scoped(syshook_scope scope) {
#if !defined(__aarch64__)
    (void)scope;
    return SYSHOOK_ERR_UNSUPPORTED;
#else
    if (!g_initialized || g_installed)
        return SYSHOOK_ERR_STATE;
    if (g_syshook_count == 0)
        return SYSHOOK_ERR_INVALID;

    struct sock_filter filter[3 + 5 + 1 + 2 * SYSHOOK_MAX_HOOKS + 1];
    const uintptr_t ip = (uintptr_t)&syshook_trampoline_ret;
    const int len = syshook_build_filter(filter,
                                         (int)(sizeof(filter) / sizeof(filter[0])),
                                         g_syshook_hooks, g_syshook_count,
                                         ip, (uint16_t)SYSHOOK_TRAP_MARKER);
    if (len < 0)
        return SYSHOOK_ERR_LIMIT;

    struct sock_fprog prog = { .len = (unsigned short)len, .filter = filter };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return SYSHOOK_ERR_NO_NEW_PRIVS;

    if (scope == SYSHOOK_ALL_THREADS) {
        long rc = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                          SECCOMP_FILTER_FLAG_TSYNC, &prog);
        if (rc == 0) {
            g_installed = 1;
            return SYSHOOK_OK;
        }
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        return SYSHOOK_ERR_SECCOMP;

    g_installed = 1;
    return SYSHOOK_OK;
#endif
}

syshook_status syshook_install(void) {
    return syshook_install_scoped(SYSHOOK_ALL_THREADS);
}

syshook_status syshook_hook(long nr, syshook_fn cb, void *user) {
    syshook_status s = syshook_init();
    if (s != SYSHOOK_OK)
        return s;
    s = syshook_add(nr, cb, user);
    if (s != SYSHOOK_OK)
        return s;
    return syshook_install();
}

const char *syshook_strstatus(syshook_status s) {
    switch (s) {
        case SYSHOOK_OK:               return "ok";
        case SYSHOOK_ERR_UNSUPPORTED:  return "unsupported (aarch64 only)";
        case SYSHOOK_ERR_STATE:        return "invalid state / call order";
        case SYSHOOK_ERR_LIMIT:        return "too many hooks";
        case SYSHOOK_ERR_INVALID:      return "invalid argument";
        case SYSHOOK_ERR_NO_NEW_PRIVS: return "prctl(PR_SET_NO_NEW_PRIVS) failed";
        case SYSHOOK_ERR_SIGNAL:       return "sigaction(SIGSYS) failed";
        case SYSHOOK_ERR_SECCOMP:      return "seccomp filter install failed";
    }
    return "unknown";
}
