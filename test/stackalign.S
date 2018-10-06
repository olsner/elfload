#include <asm/unistd.h>

.section .text
.global _start
_start:
    /* At entry, the stack should be 16-byte aligned. */
    /* Returns 0 on success, 1 on failure. */
    movq %rsp, %rdi
    andl $15, %edi
    movl $__NR_exit, %eax
    syscall
