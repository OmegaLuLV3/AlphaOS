/* Multiboot entry point: the first code that runs after the bootloader. */

#define MB_MAGIC    0x1BADB002
#define MB_FLAGS    0x00000003          /* page-align modules + memory info */
#define MB_CHECKSUM -(MB_MAGIC + MB_FLAGS)

.section .multiboot, "a"
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM

.section .bss
.align 16
stack_bottom:
.skip 32768
stack_top:

.section .text
.global _start
.type _start, @function
_start:
    cli
    mov $stack_top, %esp
    push %ebx                 /* multiboot info pointer */
    push %eax                 /* multiboot magic        */
    call kmain
1:  cli
    hlt
    jmp 1b

/* gdt_flush(u32 gdtr_ptr) — load GDT and reload segment registers */
.global gdt_flush
gdt_flush:
    mov 4(%esp), %eax
    lgdt (%eax)
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    ljmp $0x08, $.flush
.flush:
    ret

/* idt_flush(u32 idtr_ptr) */
.global idt_flush
idt_flush:
    mov 4(%esp), %eax
    lidt (%eax)
    ret

/* paging_enable(u32 page_dir_phys) */
.global paging_enable
paging_enable:
    mov 4(%esp), %eax
    mov %eax, %cr3
    mov %cr0, %eax
    or  $0x80000000, %eax
    mov %eax, %cr0
    ret

/* tlb_flush(void) — reload CR3 to invalidate the whole TLB */
.global tlb_flush
tlb_flush:
    mov %cr3, %eax
    mov %eax, %cr3
    ret

.section .note.GNU-stack, "", @progbits
