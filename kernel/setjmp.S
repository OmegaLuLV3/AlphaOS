/*
 * Minimal x86-64 setjmp/longjmp (System V ABI), used for two things:
 *  - process exit(): jump from inside an app back into the kernel loader
 *  - fault isolation: an exception in an app longjmps back to the shell
 *
 * Buffer layout: rbx, rbp, r12, r13, r14, r15, rsp, rip (8 x u64) —
 * exactly the System V callee-saved registers plus the resume point.
 */

.section .text

.global k_setjmp
k_setjmp:
    mov %rbx,   (%rdi)
    mov %rbp,  8(%rdi)
    mov %r12, 16(%rdi)
    mov %r13, 24(%rdi)
    mov %r14, 32(%rdi)
    mov %r15, 40(%rdi)
    lea 8(%rsp), %rax        /* rsp as it will be after our caller's ret */
    mov %rax, 48(%rdi)
    mov (%rsp), %rax         /* return address = resume rip */
    mov %rax, 56(%rdi)
    xor %eax, %eax
    ret

.global k_longjmp
k_longjmp:
    mov %esi, %eax            /* ret value (arg1) */
    test %eax, %eax
    jnz 1f
    inc %eax
1:
    mov   (%rdi), %rbx
    mov  8(%rdi), %rbp
    mov 16(%rdi), %r12
    mov 24(%rdi), %r13
    mov 32(%rdi), %r14
    mov 40(%rdi), %r15
    mov 48(%rdi), %rsp
    jmp *56(%rdi)

.section .note.GNU-stack, "", @progbits
