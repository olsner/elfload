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
static void exit(int res) {
    syscall3(__NR_exit, res, 0, 0);
}
static int open(const char* path, int flags) {
    return syscall3(__NR_open, (uintptr_t)path, flags, 0);
}
static int close(int fd) {
    syscall3(__NR_close, fd, 0, 0);
}
__asm__("\
.global _start\n\
_start:\n\
    movq %rsp, %rsi\n\
    jmp start\n\
        ");

void do_cat(int fd) {
    static char buf[4096];
    for (;;) {
        ssize_t res = read(fd, buf, sizeof(buf));
        if (res < 0) {
            exit(1);
        }
        else if (res == 0) {
            return;
        }
        res = write(STDOUT_FILENO, buf, res);
        if (res <= 0) {
            exit(res < 0);
        }
    }
}
void start(void (*fini)(), uintptr_t* stack) {
    int argc = *stack++;
    const char* argv0 = (const char *)*stack++;
    if (argc == 1)
        do_cat(STDIN_FILENO);
    else while (--argc) {
        int fd = open((const char *)*stack++, O_RDONLY);
        if (fd < 0) exit(1);
        do_cat(fd);
        close(fd);
    }
    exit(0);
}
