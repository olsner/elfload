#pragma once

#include <stddef.h>
#include <stdint.h>
#include <syscall.h>

#include <linux/fcntl.h>

#include "syscalls.h"

typedef intptr_t ssize_t;
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

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
