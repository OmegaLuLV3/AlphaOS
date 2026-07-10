/*
 * Physical memory manager: bitmap allocator over 4 KiB frames.
 * One bit per frame, so managing 512 MiB costs just 16 KiB of bitmap.
 */
#include "kernel.h"

#define MAX_MANAGED (512u * 1024 * 1024)
#define MAX_FRAMES  (MAX_MANAGED / PAGE_SIZE)

static u32 bitmap[MAX_FRAMES / 32];
static u32 total_frames;   /* frames of RAM we manage       */
static u32 used_frames;
static u32 search_hint;    /* first index that may be free  */

static inline void bm_set(u32 f)   { bitmap[f / 32] |=  (1u << (f % 32)); }
static inline void bm_clear(u32 f) { bitmap[f / 32] &= ~(1u << (f % 32)); }
static inline int  bm_test(u32 f)  { return bitmap[f / 32] & (1u << (f % 32)); }

void pmm_reserve(uptr start, uptr end)
{
    u32 f = PAGE_ALIGN_DOWN(start) / PAGE_SIZE;
    u32 fe = PAGE_ALIGN_UP(end) / PAGE_SIZE;
    for (; f < fe && f < total_frames; f++) {
        if (!bm_test(f)) {
            bm_set(f);
            used_frames++;
        }
    }
}

void pmm_init(multiboot_info_t *mbi, uptr kernel_end)
{
    if (!(mbi->flags & MB_FLAG_MEM))
        panic("bootloader did not provide memory info");

    u32 total_bytes = (1024 + mbi->mem_upper) * 1024;
    if (total_bytes > MAX_MANAGED)
        total_bytes = MAX_MANAGED;
    total_frames = total_bytes / PAGE_SIZE;

    /* everything below the kernel's end is off-limits:
       real-mode IVT, BIOS data, VGA memory, the kernel image, and the
       temporary boot-time page tables/stack (also part of .bss) */
    pmm_reserve(0, kernel_end);

    /* reserve the multiboot info block and any modules (initrd) */
    pmm_reserve((uptr)mbi, (uptr)mbi + sizeof(*mbi));
    if (mbi->flags & MB_FLAG_MODS) {
        multiboot_module_t *mods = (multiboot_module_t *)(uptr)mbi->mods_addr;
        pmm_reserve(mbi->mods_addr,
                    (uptr)mbi->mods_addr + mbi->mods_count * sizeof(*mods));
        for (u32 i = 0; i < mbi->mods_count; i++)
            pmm_reserve(mods[i].mod_start, mods[i].mod_end);
    }
}

uptr pmm_alloc_frame(void)
{
    for (u32 f = search_hint; f < total_frames; f++) {
        if (!bm_test(f)) {
            bm_set(f);
            used_frames++;
            search_hint = f + 1;
            return (uptr)f * PAGE_SIZE;
        }
    }
    return 0;
}

uptr pmm_alloc_contig(u32 n)
{
    u32 run = 0;
    for (u32 f = 0; f < total_frames; f++) {
        run = bm_test(f) ? 0 : run + 1;
        if (run == n) {
            u32 start = f - n + 1;
            for (u32 i = start; i <= f; i++)
                bm_set(i);
            used_frames += n;
            return (uptr)start * PAGE_SIZE;
        }
    }
    return 0;
}

void pmm_free_frame(uptr addr)
{
    u32 f = addr / PAGE_SIZE;
    if (f >= total_frames || !bm_test(f))
        return;
    bm_clear(f);
    used_frames--;
    if (f < search_hint)
        search_hint = f;
}

u32  pmm_total_kib(void)   { return total_frames * (PAGE_SIZE / 1024); }
u32  pmm_free_kib(void)    { return (total_frames - used_frames) * (PAGE_SIZE / 1024); }
uptr pmm_managed_end(void) { return (uptr)total_frames * PAGE_SIZE; }
