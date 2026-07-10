/*
 * Interrupt and exception stubs, 64-bit. x86-64 has no pusha/popa, so
 * the register save is done by hand; the layout here must match
 * regs_t in kernel.h exactly. In long mode the CPU always pushes
 * SS:RSP as part of the interrupt frame (unlike 32-bit protected mode,
 * where that only happens on a privilege change), so the frame is a
 * fixed 5 qwords: RIP, CS, RFLAGS, RSP, SS.
 */

.section .text

.macro ISR_NOERR n
.global isr\n
isr\n:
    push $0                  /* fake error code */
    push $\n
    jmp isr_common
.endm

.macro ISR_ERR n
.global isr\n
isr\n:
    push $\n                 /* CPU already pushed an error code */
    jmp isr_common
.endm

.macro IRQ n, vec
.global irq\n
irq\n:
    push $0
    push $\vec
    jmp isr_common
.endm

ISR_NOERR 0
ISR_NOERR 1
ISR_NOERR 2
ISR_NOERR 3
ISR_NOERR 4
ISR_NOERR 5
ISR_NOERR 6
ISR_NOERR 7
ISR_ERR   8
ISR_NOERR 9
ISR_ERR   10
ISR_ERR   11
ISR_ERR   12
ISR_ERR   13
ISR_ERR   14
ISR_NOERR 15
ISR_NOERR 16
ISR_ERR   17
ISR_NOERR 18
ISR_NOERR 19
ISR_NOERR 20
ISR_NOERR 21
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_NOERR 29
ISR_ERR   30
ISR_NOERR 31

IRQ 0,  32
IRQ 1,  33
IRQ 2,  34
IRQ 3,  35
IRQ 4,  36
IRQ 5,  37
IRQ 6,  38
IRQ 7,  39
IRQ 8,  40
IRQ 9,  41
IRQ 10, 42
IRQ 11, 43
IRQ 12, 44
IRQ 13, 45
IRQ 14, 46
IRQ 15, 47

isr_common:
    push %rax
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    push %rbp
    push %r8
    push %r9
    push %r10
    push %r11
    push %r12
    push %r13
    push %r14
    push %r15

    mov %rsp, %rdi            /* arg0: regs_t * (System V: rdi) */
    call interrupt_dispatch

    pop %r15
    pop %r14
    pop %r13
    pop %r12
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rbp
    pop %rdi
    pop %rsi
    pop %rdx
    pop %rcx
    pop %rbx
    pop %rax
    add $16, %rsp              /* discard int_no + err_code */
    iretq

.section .note.GNU-stack, "", @progbits
