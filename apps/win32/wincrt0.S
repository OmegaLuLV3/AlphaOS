/*
 * Entry stub for Windows-style apps, x86-64. Like a real PE, the entry
 * point takes no arguments — the program reaches the OS purely through
 * its DLL imports. Mirrors a minimal mainCRTStartup: call the program
 * (plain System V call — wmain is ours, not an import), then
 * ExitProcess(eax) using the real Microsoft x64 convention: first
 * integer argument in ECX, 32 bytes of caller-allocated shadow space,
 * 16-byte stack alignment at the call.
 */
.section .entry
.global _start
_start:
    and $-16, %rsp        /* force 16-byte alignment before any call  */

    call wmain             /* System V call: our own function, eax = ret */

    mov %eax, %ecx          /* ms_abi: first arg in ECX                 */
    sub $32, %rsp            /* ms_abi shadow space (stays 16-aligned)   */
    call ExitProcess          /* does not return                        */
1:  jmp 1b

.section .note.GNU-stack, "", @progbits
