#pragma once

#include <stddef.h>
#include <unistd.h>

#ifdef __cplusplus
#define BEGIN_DECLS extern "C" {
#define END_DECLS }
#else
#define BEGIN_DECLS
#define END_DECLS
#endif

/* Flags for el_execveat. May be redundant or defined by glibc later. */
/* Also provided by linux/fcntl.h, but that conflicts with glibc fcntl.h. */
#ifndef AT_EMPTY_PATH
#define AT_SYMLINK_NOFOLLOW	0x100   /* Do not follow symbolic links.  */
#define AT_EMPTY_PATH		0x1000	/* Allow empty relative pathname */
#endif

BEGIN_DECLS

/**
 * Like with fexecve, the FD_CLOEXEC flag should usually be set on the executable.
 */
int el_fexecve(int fd, char *const argv[], char *const envp[]);
int el_execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
int el_execve(const char *path, char *const argv[], char *const envp[]);

END_DECLS
