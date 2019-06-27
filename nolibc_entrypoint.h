#pragma once

__attribute__((noreturn)) void start(void (*fini)(), uintptr_t* stack);

__asm__("\
.global _start\n\
_start:\n\
    movq %rsp, %rsi\n\
    jmp start\n\
        ");
