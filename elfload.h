#pragma once

#include <stddef.h>

#ifdef __cplusplus
#define BEGIN_DECLS extern "C" {
#define END_DECLS }
#else
#define BEGIN_DECLS
#define END_DECLS
#endif

BEGIN_DECLS

// TODO Add support for environment and command-line arguments

/**
 * Load then pass control to an elf stored/mapped at the given location in
 * memory. No assumptions made on the load address of the ELF and potential
 * overlap with the current program.
 *
 * (That last part might be tricky...)
 *
 * Size may be 0 to automatically detect the size based on headers. This can't
 * be used with untrusted input (otoh you're about to execute the code, so it
 * better be trusted!).
 *
 * Returns -1 on error after setting errno.
 * Does not return on success.
 */
int el_memexecve(const void *elf, size_t size, char *const argv[], char *const envp[]);

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(int fd, char *const argv[], char *const envp[]);
int el_execatve(int cwd, const char *path, char *const argv[], char *const envp[]);
int el_execve(const char *path, char *const argv[], char *const envp[]);

END_DECLS
