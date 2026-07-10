/*
 * Application entry stub — placed first in the image so the PE entry
 * point (RVA 0x1000) lands here. The kernel calls us cdecl with the
 * API table pointer on the stack; app_main has the same signature, so
 * a tail jump forwards everything, and app_main's return value becomes
 * the process exit code.
 */
.section .entry
.global _start
_start:
    jmp app_main

.section .note.GNU-stack, "", @progbits
