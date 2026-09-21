#include <jni.h>
#include <android/log.h>

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "syshook/syshook.h"

#define TAG "SysHookTest"

#define PATH_PASSTHROUGH "/proc/self/cmdline"
#define PATH_RAW_PROBE   "/proc/self/syshook_probe_raw"
#define PATH_FORBIDDEN   "/proc/self/syshook_forbidden"
#define PATH_REDIR_SRC   "/proc/self/syshook_redirect_src"

static const char kRedirectDst[] = PATH_PASSTHROUGH;

static _Atomic int g_openat_calls = 0;
static _Atomic int g_raw_probe_seen = 0;

static int ss_contains(const char *hay, const char *needle) {
    if (!hay || !needle) return 0;
    for (size_t i = 0; hay[i] && i < 4096; i++) {
        size_t j = 0;
        while (needle[j] && hay[i + j] == needle[j]) j++;
        if (!needle[j]) return 1;
    }
    return 0;
}

static syshook_action on_openat(syshook_ctx *ctx, long *result, void *user) {
    (void)user;
    atomic_fetch_add_explicit(&g_openat_calls, 1, memory_order_relaxed);

    const char *path = (const char *)ctx->args[1];
    if (!path)
        return SYSHOOK_CONTINUE;

    if (ss_contains(path, "syshook_probe_raw"))
        atomic_store_explicit(&g_raw_probe_seen, 1, memory_order_relaxed);

    if (ss_contains(path, "syshook_forbidden")) {
        *result = -EACCES;
        return SYSHOOK_BYPASS;
    }

    if (ss_contains(path, "syshook_redirect_src"))
        ctx->args[1] = (long)kRedirectDst;

    return SYSHOOK_CONTINUE;
}

static long raw_openat(int dirfd, const char *path, int flags, int mode) {
    register long x8 __asm__("x8") = __NR_openat;
    register long x0 __asm__("x0") = dirfd;
    register long x1 __asm__("x1") = (long)path;
    register long x2 __asm__("x2") = flags;
    register long x3 __asm__("x3") = mode;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3)
                     : "memory");
    return x0;
}

typedef struct {
    syshook_status init_st, add_st, install_st;
    int count_before, count_after;
    int passthrough_fd, passthrough_errno;
    int raw_seen;
    int deny_ret, deny_errno;
    int redirect_fd, redirect_errno;
} selftest_result;

static void *selftest_thread(void *arg) {
    selftest_result *r = (selftest_result *)arg;

    r->init_st = syshook_init();
    r->add_st = syshook_add(__NR_openat, on_openat, NULL);
    r->install_st = syshook_install_scoped(SYSHOOK_THIS_THREAD);
    if (r->install_st != SYSHOOK_OK)
        return NULL;

    r->count_before = atomic_load(&g_openat_calls);

    r->passthrough_fd = open(PATH_PASSTHROUGH, O_RDONLY);
    r->passthrough_errno = errno;
    if (r->passthrough_fd >= 0) close(r->passthrough_fd);

    errno = 0;
    raw_openat(AT_FDCWD, PATH_RAW_PROBE, O_RDONLY, 0);
    r->raw_seen = atomic_load(&g_raw_probe_seen);

    errno = 0;
    r->deny_ret = open(PATH_FORBIDDEN, O_RDONLY);
    r->deny_errno = errno;

    errno = 0;
    r->redirect_fd = open(PATH_REDIR_SRC, O_RDONLY);
    r->redirect_errno = errno;
    if (r->redirect_fd >= 0) close(r->redirect_fd);

    r->count_after = atomic_load(&g_openat_calls);
    return NULL;
}

static int append(char *buf, size_t cap, size_t *off, const char *fmt, ...) {
    if (*off >= cap) return 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n > 0) *off += (size_t)n;
    return n;
}

#define PASS(c) ((c) ? "PASS" : "FAIL")

JNIEXPORT jstring JNICALL
Java_com_example_syshook_MainActivity_nativeRunSelfTest(JNIEnv *env, jclass clazz) {
    (void)clazz;

    selftest_result r;
    memset(&r, 0, sizeof(r));

    pthread_t th;
    if (pthread_create(&th, NULL, selftest_thread, &r) != 0) {
        return (*env)->NewStringUTF(env, "pthread_create failed");
    }
    pthread_join(th, NULL);

    int ok_install   = (r.init_st == SYSHOOK_OK &&
                        r.add_st == SYSHOOK_OK &&
                        r.install_st == SYSHOOK_OK);
    int ok_fired     = (r.count_after > r.count_before);
    int ok_pass      = (r.passthrough_fd >= 0);
    int ok_raw       = (r.raw_seen == 1);
    int ok_deny      = (r.deny_ret == -1 && r.deny_errno == EACCES);
    int ok_redirect  = (r.redirect_fd >= 0);
    int all = ok_install && ok_fired && ok_pass && ok_raw && ok_deny && ok_redirect;

    char buf[2048];
    size_t off = 0;
    append(buf, sizeof(buf), &off, "syshook self-test: %s\n\n", all ? "ALL PASS" : "FAILURES");
    append(buf, sizeof(buf), &off, "[%s] install       init=%s add=%s install=%s\n",
           PASS(ok_install), syshook_strstatus(r.init_st),
           syshook_strstatus(r.add_st), syshook_strstatus(r.install_st));
    append(buf, sizeof(buf), &off, "[%s] callback fired  openat traps: %d\n",
           PASS(ok_fired), r.count_after - r.count_before);
    append(buf, sizeof(buf), &off, "[%s] passthrough     open(cmdline) fd=%d\n",
           PASS(ok_pass), r.passthrough_fd);
    append(buf, sizeof(buf), &off, "[%s] raw svc caught  direct svc openat intercepted=%d\n",
           PASS(ok_raw), r.raw_seen);
    append(buf, sizeof(buf), &off, "[%s] redirect arg    open(missing)->cmdline fd=%d\n",
           PASS(ok_redirect), r.redirect_fd);
    append(buf, sizeof(buf), &off, "[%s] deny (fake ret) open(forbidden) ret=%d errno=%d(%s)\n",
           PASS(ok_deny), r.deny_ret, r.deny_errno,
           r.deny_errno == EACCES ? "EACCES" : "?");

    __android_log_print(ANDROID_LOG_INFO, TAG, "%s", buf);
    return (*env)->NewStringUTF(env, buf);
}
