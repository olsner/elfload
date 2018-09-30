#include <asm/unistd.h>

.section .rodata
msg:
    .string "Hello from asm!\n"
.equ msg_size, . - msg

.section .text
.global _start
_start:
    /* write(1, msg, sizeof(msg));
     */
    movl $1, %edi
    leaq (msg), %rsi
    movl $msg_size, %edx
    movl $__NR_write, %eax
    syscall

    xorl %edi,%edi
    movl $__NR_exit, %eax
    syscall
