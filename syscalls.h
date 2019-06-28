#pragma once

static inline int64_t syscall6(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6) {
    int64_t res;
    register int64_t r8 __asm__("r8") = arg5;
    register int64_t r9 __asm__("r9") = arg6;
    // r10 takes the place of rcx in the usual convention since rcx is taken by syscall
    register int64_t r10 __asm__("r10") = arg4;
    __asm__ __volatile__ ("syscall"
            : /* return value(s) */
            "=a" (res),
            /* clobbered inputs */
            "=D" (arg1), "=S" (arg2), "=d" (arg3), "=r" (r8), "=r" (r9), "=r"(r10)
            : "a" (nr), "D" (arg1), "S" (arg2), "d" (arg3), "r" (r8), "r" (r9), "r"(r10)
            : "r11", "%rcx", "memory");
    return res;
}
static inline int64_t syscall5(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
    return syscall6(nr, arg1, arg2, arg3, arg4, arg5, 0);
}
static inline int64_t syscall4(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4) {
    return syscall6(nr, arg1, arg2, arg3, arg4, 0, 0);
}
static inline int64_t syscall3(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    return syscall6(nr, arg1, arg2, arg3, 0, 0, 0);
}
static inline int64_t syscall2(uint64_t nr, uint64_t arg1, uint64_t arg2) {
    return syscall6(nr, arg1, arg2, 0, 0, 0, 0);
}
static inline int64_t syscall1(uint64_t nr, uint64_t arg1) {
    return syscall6(nr, arg1, 0, 0, 0, 0, 0);
}
