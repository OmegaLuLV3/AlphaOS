/*
 * Multiboot entry point and the 32-bit -> long-mode transition.
 *
 * GRUB/QEMU hand off control in 32-bit protected mode, paging disabled
 * (that's what the Multiboot spec guarantees, regardless of whether the
 * kernel ELF itself is 32- or 64-bit). Long mode *requires* paging to
 * be active before any 64-bit code can run, so this file:
 *
 *   1. runs a small .code32 trampoline that builds a temporary
 *      identity map for the first 1 GiB using 2 MiB pages (just enough
 *      to cover the kernel image, its stack, and the multiboot info
 *      it needs to read before kernel/paging.c takes over),
 *   2. enables PAE, long mode (EFER.LME), then paging,
 *   3. far-jumps into a .code64 section that sets up segment
 *      registers, a real 64-bit stack, and calls kmain(magic, mbi).
 *
 * This whole file is assembled as part of a 64-bit (ELF64) object —
 * .code32/.code64 are assembler directives that select instruction
 * encoding, independent of the object's ELF class. Linux's own
 * arch/x86/boot/compressed/head_64.S uses the identical technique.
 *
 * kernel/paging.c later replaces this temporary 1 GiB/2 MiB-page map
 * with a real 4 KiB-granular one built from PMM-allocated frames, so
 * paging_map()/paging_unmap() can remap individual pages (needed for
 * loading app images and the framebuffer).
 */

#define MB_MAGIC    0x1BADB002
#define MB_FLAGS    0x00000003          /* page-align modules + memory info */
#define MB_CHECKSUM -(MB_MAGIC + MB_FLAGS)

.section .multiboot, "a"
.align 4
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM

.section .bss
.align 4096
boot_pml4:
.skip 4096
boot_pdpt:
.skip 4096
boot_pd:
.skip 4096
.align 16
stack_bottom:
.skip 65536
stack_top:

.section .data
.align 4
saved_magic: .long 0
saved_mbi:   .long 0

.align 8
boot_gdt:
    .quad 0                             /* null                        */
    .quad 0x00AF9A000000FFFF            /* 64-bit code: L=1, present   */
    .quad 0x00CF92000000FFFF            /* 32-bit data (used pre-jump) */
    .quad 0x00AF92000000FFFF            /* 64-bit data                */
boot_gdt_ptr:
    .word boot_gdt_ptr - boot_gdt - 1
    .quad boot_gdt

.section .text
.code32
.global _start
.type _start, @function
_start:
    cli
    mov %eax, saved_magic
    mov %ebx, saved_mbi
    mov $stack_top, %esp

    /* zero the three page-table pages (3 * 4096 / 4 dwords) */
    mov $boot_pml4, %edi
    xor %eax, %eax
    mov $3072, %ecx
    rep stosl

    /* PML4[0] -> PDPT */
    mov $boot_pdpt, %eax
    or  $0x3, %eax                      /* present | writable */
    mov $boot_pml4, %edi
    mov %eax, (%edi)

    /* PDPT[0] -> PD */
    mov $boot_pd, %eax
    or  $0x3, %eax
    mov $boot_pdpt, %edi
    mov %eax, (%edi)

    /* PD[0..511]: 512 * 2 MiB = 1 GiB identity-mapped, present|writable|PS */
    mov $boot_pd, %edi
    xor %eax, %eax
    or  $0x83, %eax
    mov $512, %ecx
1:
    mov %eax, (%edi)
    add $8, %edi
    add $0x200000, %eax
    loop 1b

    /* PAE */
    mov %cr4, %eax
    or  $0x20, %eax
    mov %eax, %cr4

    /* CR3 = PML4 */
    mov $boot_pml4, %eax
    mov %eax, %cr3

    /* long mode enable (EFER.LME, MSR 0xC0000080 bit 8) */
    mov $0xC0000080, %ecx
    rdmsr
    or  $0x100, %eax
    wrmsr

    /* enable paging -> CPU is now in IA-32e compatibility submode */
    mov %cr0, %eax
    or  $0x80000000, %eax
    mov %eax, %cr0

    lgdt boot_gdt_ptr

    /* reload every segment register from the new GDT before the jump */
    mov $0x18, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    /* far jump loads CS with the 64-bit code selector -> full long mode */
    ljmp $0x08, $long_mode_entry

.code64
long_mode_entry:
    mov $0x18, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss

    mov $stack_top, %rsp
    xor %rbp, %rbp

    mov saved_magic(%rip), %edi         /* arg0: magic (System V: rdi) */
    mov saved_mbi(%rip), %esi           /* arg1: mbi ptr (rsi)         */
    call kmain
1:  cli
    hlt
    jmp 1b

/*
 * gdt_flush(u64 gdtr_ptr) — load a new GDT and reload every segment
 * register. Reloading CS in long mode has no direct far-jump-with-
 * immediate form, so we use the classic push-selector/push-target/
 * lretq trick.
 */
.global gdt_flush
gdt_flush:
    lgdt (%rdi)
    mov $0x10, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    pushq $0x08
    leaq .Lflush(%rip), %rax
    pushq %rax
    lretq
.Lflush:
    ret

/* idt_flush(u64 idtr_ptr) */
.global idt_flush
idt_flush:
    lidt (%rdi)
    ret

/* paging_enable(u64 pml4_phys) — install a new top-level page table */
.global paging_enable
paging_enable:
    mov %rdi, %cr3
    ret

/* tlb_flush(void) — reload CR3 to invalidate the whole TLB */
.global tlb_flush
tlb_flush:
    mov %cr3, %rax
    mov %rax, %cr3
    ret

.section .note.GNU-stack, "", @progbits
