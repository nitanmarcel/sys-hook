    .text
    .align  2
    .global syshook_trampoline
    .hidden syshook_trampoline
    .type   syshook_trampoline, %function
syshook_trampoline:
    bti     c
    mov     x8, x0
    mov     x0, x1
    mov     x1, x2
    mov     x2, x3
    mov     x3, x4
    mov     x4, x5
    mov     x5, x6
    svc     #0

    .global syshook_trampoline_ret
    .hidden syshook_trampoline_ret
    .type   syshook_trampoline_ret, %function
syshook_trampoline_ret:
    ret
    .size   syshook_trampoline, . - syshook_trampoline

    .section .note.GNU-stack, "", %progbits
