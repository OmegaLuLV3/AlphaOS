/*
 * Minimal i386 setjmp/longjmp used for two things:
 *  - process exit(): jump from inside an app back into the kernel loader
 *  - fault isolation: an exception in an app longjmps back to the shell
 *
 * Buffer layout: ebx, esi, edi, ebp, esp, eip  (6 x u32)
 */

.section .text

.global k_setjmp
k_setjmp:
    mov 4(%esp), %eax
    mov %ebx,   (%eax)
    mov %esi,  4(%eax)
    mov %edi,  8(%eax)
    mov %ebp, 12(%eax)
    lea 4(%esp), %ecx        /* esp as it will be after our caller's ret */
    mov %ecx, 16(%eax)
    mov (%esp), %ecx         /* return address = resume eip */
    mov %ecx, 20(%eax)
    xor %eax, %eax
    ret

.global k_longjmp
k_longjmp:
    mov 4(%esp), %edx        /* jmp_buf   */
    mov 8(%esp), %eax        /* ret value */
    test %eax, %eax
    jnz 1f
    inc %eax
1:
    mov   (%edx), %ebx
    mov  4(%edx), %esi
    mov  8(%edx), %edi
    mov 12(%edx), %ebp
    mov 16(%edx), %esp
    jmp *20(%edx)

.section .note.GNU-stack, "", @progbits
