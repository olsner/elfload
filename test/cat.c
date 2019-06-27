#include "../nolibc.h"
#include "../nolibc_entrypoint.h"

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
