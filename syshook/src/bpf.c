#include "syshook_internal.h"

#include <stddef.h>
#include <linux/audit.h>
#include <linux/seccomp.h>
#include <linux/filter.h>

static struct sock_filter stmt(uint16_t code, uint32_t k) {
    struct sock_filter f = { code, 0, 0, k };
    return f;
}
static struct sock_filter jump(uint16_t code, uint32_t k, uint8_t jt, uint8_t jf) {
    struct sock_filter f = { code, jt, jf, k };
    return f;
}

int syshook_build_filter(struct sock_filter *out, int cap,
                         const syshook_entry *hooks, int count,
                         uintptr_t trampoline_ip, uint16_t marker) {
    const int need = 3 + 5 + 1 + 2 * count + 1;
    if (count < 0 || need > cap)
        return -1;

    const uint32_t ip_lo = (uint32_t)(trampoline_ip & 0xffffffffu);
    const uint32_t ip_hi = (uint32_t)(trampoline_ip >> 32);
    const uint32_t trap  = SECCOMP_RET_TRAP | ((uint32_t)marker & SECCOMP_RET_DATA);

    int k = 0;

    out[k++] = stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    out[k++] = jump(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64, 1, 0);
    out[k++] = stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    out[k++] = stmt(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, instruction_pointer));
    out[k++] = jump(BPF_JMP | BPF_JEQ | BPF_K, ip_lo, 0, 3);
    out[k++] = stmt(BPF_LD | BPF_W | BPF_ABS,
                    offsetof(struct seccomp_data, instruction_pointer) + 4);
    out[k++] = jump(BPF_JMP | BPF_JEQ | BPF_K, ip_hi, 0, 1);
    out[k++] = stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    out[k++] = stmt(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    for (int i = 0; i < count; i++) {
        out[k++] = jump(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)hooks[i].nr, 0, 1);
        out[k++] = stmt(BPF_RET | BPF_K, trap);
    }

    out[k++] = stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    return k;
}
