#include <limits.h>
#include <stdio.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/time.h>
#include "nolibc.h"

#define PAGE_SIZE 4096

typedef uint64_t u64;

static void get_vdso_range(uintptr_t *start, uintptr_t *end) {
    uintptr_t vdso_start = getauxval(AT_SYSINFO_EHDR);
    size_t vdso_size = 2 * PAGE_SIZE;
    const size_t vvar_size = 3 * PAGE_SIZE;
    *start = vdso_start - vvar_size;
    *end = vdso_start + vdso_size;
}

static void do_cat(int fd) {
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

// Test program to see what happens if you unmap the vdso
int main(int argc, char* argv[]) {
    uintptr_t start, end;
    get_vdso_range(&start, &end);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    munmap((void*)start, end - start);
    // List mappings for debugging, to show that vdso is indeed unmapped.
    {
        int fd = open("/proc/self/maps", O_RDONLY);
        if (fd < 0) exit(1);
        do_cat(fd);
        close(fd);
    }
    // After vDSO is unmapped, this crashes. But only when dynamically linked!
    gettimeofday(&tv, NULL);
    exit(0);
}
