/* AlphaOS kernel entry point. */
#include "kernel.h"

extern u8 kernel_end; /* provided by the linker script */

bool crypto_ok; /* set by crypto_selftest() in kmain(); see kernel.h */

/*
 * SSE2 is mandatory baseline on real x86-64 (part of the ABI, not an
 * optional extension), so any externally-compiled binary — not just
 * ones built with our own -mgeneral-regs-only kernel toolchain — is
 * free to use it, and normal compiler codegen frequently does (e.g. a
 * struct zero-init often becomes `pxor %xmm0,%xmm0`). Without this,
 * CR4.OSFXSR defaults to 0 and every such instruction is simply
 * unrecognized by the CPU: #UD (invalid opcode), immediately.
 *
 * No FPU/SSE context save-restore is needed beyond this one-time
 * enable: the kernel's own code never touches XMM/x87 state (that's
 * exactly what -mgeneral-regs-only guarantees for every C file in
 * this kernel), and AlphaOS never runs two processes concurrently, so
 * there's no second execution context whose SSE state could ever
 * collide with an app's.
 */
static void fpu_enable(void)
{
    u64 cr0, cr4;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 &= ~0x4ull; /* clear EM: we have real SSE hardware, don't trap */
    cr0 |= 0x2ull;  /* set MP: coprocessor present */
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));

    __asm__ volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x600ull; /* OSFXSR | OSXMMEXCPT */
    __asm__ volatile("mov %0, %%cr4" : : "r"(cr4));
}

void kmain(u32 magic, multiboot_info_t *mbi)
{
    console_init();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        panic("not booted by a multiboot loader");

    fpu_enable();
    gdt_init();
    idt_init();
    pic_init();
    pit_init(100);
    keyboard_init();

    pmm_init(mbi, (uptr)&kernel_end);
    paging_init();
    kheap_init();
    ramdisk_init(mbi);

    /* Crypto self-test before anything is ever allowed to trust these
       primitives for a real TLS connection: known-answer vectors,
       checked on the actual compiled kernel code at boot, not just
       once on a host prototype. A silently-wrong hash or PRF is a
       fundamentally different (much worse) failure mode than a crash
       -- see kernel/crypto.c's header comment. Fails closed: TLS code
       checks crypto_ok() and refuses to run rather than trusting
       primitives that didn't pass. */
    crypto_ok = crypto_selftest();
    kprintf("crypto: self-test %s\n", crypto_ok ? "passed" : "FAILED");

    /* Same fail-closed discipline as the crypto self-test above, for
       the ASN.1/X.509 layer TLS certificate validation depends on. */
    bool x509_ok = x509_selftest();
    kprintf("x509: self-test %s\n", x509_ok ? "passed" : "FAILED");

    bool roots_ok = x509_roots_selftest();
    kprintf("x509: trusted-root self-test %s\n", roots_ok ? "passed" : "FAILED");

    /* driver bring-up */
    font_init();  /* capture the VGA font while still in text mode */
    pci_scan();
    mouse_init();
    net_init();   /* RTL8139 NIC, if present -- degrades gracefully if not */
    win32_init(); /* export tables for Windows-style .exe imports */
    ai_init();    /* host-bridged AI assistant channel (COM2) */
    bool gui = bga_init(1024, 768) == 0;
    if (gui) {
        gui_init();
        console_use_gui(); /* console output now goes to the terminal */
    }

    sti();

    console_set_color(ALPHA_LCYAN, ALPHA_BLACK);
    kprint("\n  AlphaOS 0.11 -- a lightweight OS that runs .exe files\n");
    console_set_color(ALPHA_DGREY, ALPHA_BLACK);
    kprintf("  %u KiB RAM managed | %u KiB in use | %u file(s) on ramdisk\n",
            pmm_total_kib(), pmm_total_kib() - pmm_free_kib(),
            ramdisk_count());
    kprintf("  display: %s | %u PCI device(s)\n",
            gui ? "1024x768x32 desktop" : "VGA text mode", pci_count());
    console_set_color(ALPHA_LGREY, ALPHA_BLACK);
    kprint("  type 'help' for commands\n\n");

    shell_run();
}
