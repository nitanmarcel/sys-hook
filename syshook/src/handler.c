#include "syshook_internal.h"

#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>

void syshook_sigsys_handler(int sig, siginfo_t *si, void *uctx) {
    (void)sig;

    if (si->si_code != SYS_SECCOMP)
        return;

    if ((unsigned)(si->si_errno & 0xffff) != SYSHOOK_TRAP_MARKER) {
        signal(SIGSYS, SIG_DFL);
        syscall(__NR_tgkill, syscall(__NR_getpid), syscall(__NR_gettid), SIGSYS);
        return;
    }

    const int saved_errno = errno;

    ucontext_t *uc = (ucontext_t *)uctx;
    uint64_t *regs = (uint64_t *)uc->uc_mcontext.regs;

    syshook_ctx ctx;
    ctx.nr      = (long)regs[8];
    ctx.args[0] = (long)regs[0];
    ctx.args[1] = (long)regs[1];
    ctx.args[2] = (long)regs[2];
    ctx.args[3] = (long)regs[3];
    ctx.args[4] = (long)regs[4];
    ctx.args[5] = (long)regs[5];
    ctx.pc      = si->si_call_addr;

    const syshook_entry *e = syshook_find(ctx.nr);

    long result = 0;
    syshook_action action = SYSHOOK_CONTINUE;
    if (e && e->cb)
        action = e->cb(&ctx, &result, e->user);

    if (action == SYSHOOK_CONTINUE) {
        result = syshook_trampoline(ctx.nr, ctx.args[0], ctx.args[1], ctx.args[2],
                                    ctx.args[3], ctx.args[4], ctx.args[5]);
    }

    regs[0] = (uint64_t)result;
    errno = saved_errno;
}
