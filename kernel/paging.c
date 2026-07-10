/*
 * Paging. The kernel identity-maps all managed physical RAM, so kernel
 * virtual == physical. Applications are mapped high (default image base
 * 0x40000000) into pages allocated from the PMM, which keeps every app
 * image out of the kernel's address range and lets the loader always
 * honor the PE ImageBase.
 */
#include "kernel.h"

#define PDE_PRESENT 0x1
#define PDE_RW      0x2

static u32 page_dir[1024] __attribute__((aligned(PAGE_SIZE)));

extern void paging_enable(u32 dir_phys);

static u32 *get_table(u32 virt, int create)
{
    u32 pde = virt >> 22;
    if (!(page_dir[pde] & PDE_PRESENT)) {
        if (!create)
            return NULL;
        u32 phys = pmm_alloc_frame();
        if (!phys)
            return NULL;
        memset((void *)phys, 0, PAGE_SIZE); /* identity-mapped kernel RAM */
        page_dir[pde] = phys | PDE_PRESENT | PDE_RW;
    }
    return (u32 *)(page_dir[pde] & ~0xFFF);
}

int paging_map(u32 virt, u32 phys, int writable)
{
    u32 *table = get_table(virt, 1);
    if (!table)
        return -1;
    table[(virt >> 12) & 0x3FF] =
        (phys & ~0xFFF) | PDE_PRESENT | (writable ? PDE_RW : 0);
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
    return 0;
}

void paging_unmap(u32 virt)
{
    u32 *table = get_table(virt, 0);
    if (!table)
        return;
    table[(virt >> 12) & 0x3FF] = 0;
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
}

void paging_init(void)
{
    u32 end = pmm_managed_end();

    /* identity map all managed RAM with 4 KiB pages, except page 0:
       leaving it unmapped turns null-pointer dereferences into page
       faults instead of silent reads of the real-mode IVT */
    for (u32 addr = PAGE_SIZE; addr < end; addr += PAGE_SIZE) {
        u32 *table = get_table(addr, 1);
        if (!table)
            panic("paging: out of frames for page tables");
        table[(addr >> 12) & 0x3FF] = addr | PDE_PRESENT | PDE_RW;
    }

    paging_enable((u32)page_dir);
}
