#ifndef SYSHOOK_INTERNAL_H
#define SYSHOOK_INTERNAL_H

#include "syshook/syshook.h"

#include <stdint.h>
#include <signal.h>
#include <linux/filter.h>

#define SYSHOOK_MAX_HOOKS 64

#define SYSHOOK_TRAP_MARKER 0x5AA5u

typedef struct {
    long        nr;
    syshook_fn  cb;
    void       *user;
} syshook_entry;

extern syshook_entry g_syshook_hooks[SYSHOOK_MAX_HOOKS];
extern int           g_syshook_count;

const syshook_entry *syshook_find(long nr);

extern long syshook_trampoline(long nr, long a0, long a1, long a2,
                               long a3, long a4, long a5);

extern void syshook_trampoline_ret(void);

int syshook_build_filter(struct sock_filter *out, int cap,
                         const syshook_entry *hooks, int count,
                         uintptr_t trampoline_ip, uint16_t marker);

void syshook_sigsys_handler(int sig, siginfo_t *si, void *uctx);

#endif
