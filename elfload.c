#include "elfload.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

int el_memexecve(const void *elf, size_t size, char *const argv[], char *const envp[]) {
    return ENOSYS;
}

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(int fd, char *const argv[], char *const envp[]) {
    struct stat st;
    if (fstat(fd, &st)) {
        return -1;
    }

    // Mapped PROT_READ initially. memexecve will remap the pages with appropriate protections.
    void* mem = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mem == MAP_FAILED) {
        return -1;
    }

    if (el_memexecve(mem, st.st_size, argv, envp)) {
        munmap(mem, st.st_size);
        return -1;
    }

    // memexecve may never return successfully
    abort();
}
int el_execatve(int cwd, const char *path, char *const argv[], char *const envp[]) {
    int fd = openat(cwd, path, O_CLOEXEC | O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    if (el_fexecve(fd, argv, envp)) {
        close(fd);
        return -1;
    }

    // el_fexecve may never return successfully
    abort();
}
int el_execve(const char *path, char *const argv[], char *const envp[]) {
    return el_execatve(AT_FDCWD, path, argv, envp);
}
