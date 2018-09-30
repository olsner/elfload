#include <stdio.h>
#include <stdlib.h>

#include "elfload.h"

extern char** environ;

static int usage(const char *me) {
    printf("Usage: %s ELFFILE [ARGS...]\n", me);
    return EXIT_FAILURE;
}

int main(int argc, char *const argv[]) {
    if (argc > 2) {
        if (el_execve(argv[1], argv + 1, environ)) {
            perror("el_execve");
            return EXIT_FAILURE;
        }
        fprintf(stderr, "%s: el_execve unexpectedly returned succesfully\n", argv[0]);
        return EXIT_FAILURE;
    } else {
        return usage(argv[0]);
    }
}
