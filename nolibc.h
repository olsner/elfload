#pragma once

#include <stddef.h>
#include <stdint.h>
#include <syscall.h>

// TODO Extract a utility header with the syscall wrappers and constants for doing Unix stuff without libc.

#include <linux/fcntl.h>

typedef intptr_t ssize_t;
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

static inline int64_t syscall3(uint64_t nr, uint64_t arg1, uint64_t arg2, uint64_t arg3) {
    int64_t res;
    __asm__ __volatile__ ("syscall"
            : /* return value */
            "=a" (res),
            /* clobbered inputs */
            "=D" (arg1), "=S" (arg2), "=d" (arg3)
            /* inputs */
            : "a" (nr), "D" (arg1), "S" (arg2), "d"(arg3)
            /* clobbers all caller-save registers */
            : "r8", "r9", "r10", "r11", "%rcx", "memory");
    return res;
}
static ssize_t read(int fd, void* buf, size_t n) {
    return syscall3(__NR_read, fd, (uintptr_t)buf, n);
}
static ssize_t write(int fd, const void* buf, size_t n) {
    return syscall3(__NR_write, fd, (uintptr_t)buf, n);
}
__attribute__((noreturn)) static void exit(int res) {
    syscall3(__NR_exit, res, 0, 0);
    __builtin_unreachable();
}
static int open(const char* path, int flags) {
    return syscall3(__NR_open, (uintptr_t)path, flags, 0);
}
static int close(int fd) {
    return syscall3(__NR_close, fd, 0, 0);
}
