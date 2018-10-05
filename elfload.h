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

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(int fd, char *const argv[], char *const envp[]);
int el_execatve(int cwd, const char *path, char *const argv[], char *const envp[]);
int el_execve(const char *path, char *const argv[], char *const envp[]);

END_DECLS
