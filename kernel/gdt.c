/*
 * 64-bit GDT: null, kernel code (L=1, long mode), kernel data. Boot.S
 * already installed a working equivalent to reach kmain; this rebuilds
 * the "official" kernel GDT the same way the rest of the kernel expects
 * to control it (gdt_init() called from kmain, mirroring the 32-bit
 * design). Segmentation is largely vestigial in long mode — there's no
 * ring transitions here, so no TSS is required.
 */
#include "kernel.h"

struct gdt_entry {
    u16 limit_low;
    u16 base_low;
    u8  base_mid;
    u8  access;
    u8  gran;
    u8  base_high;
} __attribute__((packed));

struct gdt_ptr {
    u16 limit;
    u64 base;
} __attribute__((packed));

static struct gdt_entry gdt[3];
static struct gdt_ptr gp;

extern void gdt_flush(u64 gdtr);

static void gdt_set(int i, u8 access, u8 gran)
{
    gdt[i].base_low  = 0;
    gdt[i].base_mid  = 0;
    gdt[i].base_high = 0;
    gdt[i].limit_low = 0;
    gdt[i].gran      = gran;
    gdt[i].access    = access;
}

void gdt_init(void)
{
    gp.limit = sizeof(gdt) - 1;
    gp.base  = (uptr)&gdt;

    gdt_set(0, 0, 0);
    gdt_set(1, 0x9A, 0xA0); /* ring0 code: present, execute/read, L=1 */
    gdt_set(2, 0x92, 0x00); /* ring0 data: present, read/write        */

    gdt_flush((uptr)&gp);
}
