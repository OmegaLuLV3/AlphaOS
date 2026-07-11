/*
 * 4-level paging (PML4 -> PDPT -> PD -> PT, 4 KiB pages). boot.S
 * already put the CPU in long mode using a temporary 1 GiB/2 MiB-page
 * identity map; paging_init() replaces it with a real 4 KiB-granular
 * map built from PMM-allocated frames, covering every managed physical
 * page. That granularity is what lets paging_map()/paging_unmap() punch
 * individual holes later — for app images and the framebuffer — without
 * touching neighboring pages.
 *
 * The kernel identity-maps all managed physical RAM (kernel virtual ==
 * physical), same as the 32-bit design. Everything we care about —
 * kernel, apps, framebuffer — stays below 4 GiB by construction, so a
 * single PML4 entry (covering 512 GiB) is all that's ever used.
 *
 * paging_map() takes independent writable/executable flags (backed by
 * the PTE's NX bit, gated on EFER.NXE which boot.S sets) so callers can
 * build W^X mappings instead of the old implicit "always executable"
 * default: kheap_init() marks the whole kernel heap non-executable
 * (nothing legitimate is ever *code* in there), bga.c marks the
 * framebuffer non-executable, and pe.c marks a loaded image's real
 * code sections read-only+executable once relocations/imports are done
 * writing to them. See SECURITY.md for what this does and doesn't cover.
 */
#include "kernel.h"

#define PTE_PRESENT 0x1ull
#define PTE_RW      0x2ull
#define PTE_NX      (1ull << 63)
#define ENTRIES     512

static u64 pml4[ENTRIES] __attribute__((aligned(PAGE_SIZE)));

extern void paging_enable(uptr pml4_phys);

/* walk one level: table[index] must point at (or be freshly allocated
   to point at) the next-level table; returns its virtual address,
   which equals its physical address under our identity mapping */
static u64 *walk(u64 *table, u32 index, int create)
{
    if (!(table[index] & PTE_PRESENT)) {
        if (!create)
            return NULL;
        uptr phys = pmm_alloc_frame();
        if (!phys)
            return NULL;
        memset((void *)phys, 0, PAGE_SIZE);
        table[index] = phys | PTE_PRESENT | PTE_RW;
    }
    return (u64 *)(uptr)(table[index] & ~0xFFFull);
}

static u64 *get_pt(uptr virt, int create)
{
    u32 pml4_i = (virt >> 39) & 0x1FF;
    u32 pdpt_i = (virt >> 30) & 0x1FF;
    u32 pd_i   = (virt >> 21) & 0x1FF;

    u64 *pdpt = walk(pml4, pml4_i, create);
    if (!pdpt)
        return NULL;
    u64 *pd = walk(pdpt, pdpt_i, create);
    if (!pd)
        return NULL;
    return walk(pd, pd_i, create);
}

int paging_map(uptr virt, uptr phys, int writable, int executable)
{
    u64 *pt = get_pt(virt, 1);
    if (!pt)
        return -1;
    u32 pt_i = (virt >> 12) & 0x1FF;
    u64 flags = PTE_PRESENT | (writable ? PTE_RW : 0) |
                (executable ? 0 : PTE_NX);
    pt[pt_i] = (phys & ~0xFFFull) | flags;
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
    return 0;
}

void paging_unmap(uptr virt)
{
    u64 *pt = get_pt(virt, 0);
    if (!pt)
        return;
    pt[(virt >> 12) & 0x1FF] = 0;
    __asm__ volatile("invlpg (%0)" : : "r"(virt) : "memory");
}

void paging_init(void)
{
    uptr end = pmm_managed_end();

    /* identity map all managed RAM with 4 KiB pages, except page 0:
       leaving it unmapped turns null-pointer dereferences into page
       faults instead of silent reads of the real-mode IVT */
    for (uptr addr = PAGE_SIZE; addr < end; addr += PAGE_SIZE) {
        u64 *pt = get_pt(addr, 1);
        if (!pt)
            panic("paging: out of frames for page tables");
        pt[(addr >> 12) & 0x1FF] = addr | PTE_PRESENT | PTE_RW;
    }

    paging_enable((uptr)pml4);

    /* CR0.WP: without this, supervisor-mode (ring 0) writes ignore the
       R/W bit in a PTE entirely -- and every app here runs in ring 0
       (see kernel.h/pe.c). So a page marked read-only means nothing
       for W^X purposes until this is set; with it, pe.c's per-section
       remap of real executable sections to read-only+exec actually
       denies writes, not just NX-based instruction fetches. */
    u64 cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x10000ull;
    __asm__ volatile("mov %0, %%cr0" : : "r"(cr0));
}
