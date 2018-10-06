#include <asm/unistd.h>

.section .text
.global _start
_start:
    xorl %edi,%edi
    movl $__NR_exit, %eax
    syscall
