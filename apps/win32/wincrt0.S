/*
 * Entry stub for Windows-style apps. Like a real PE, the entry point
 * takes no arguments — the program reaches the OS purely through its
 * DLL imports. Mirrors a minimal mainCRTStartup: call the program,
 * then ExitProcess with its return value.
 */
.section .entry
.global _start
_start:
    call wmain
    push %eax
    call ExitProcess
1:  jmp 1b

.section .note.GNU-stack, "", @progbits
