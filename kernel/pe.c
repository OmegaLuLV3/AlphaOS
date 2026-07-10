/*
 * PE32 (.exe) loader.
 *
 * Validates the full header chain (DOS MZ -> PE signature -> COFF ->
 * optional header -> sections), maps the image at its preferred
 * ImageBase via paging, copies section raw data, zero-fills the
 * VirtualSize tail (.bss), applies base relocations if present, then
 * calls the entry point with the AlphaOS API table.
 *
 * Resource management: image pages, page tables, and every tracked heap
 * allocation the app made are reclaimed when it exits — including when
 * it crashes and is killed by the fault handler.
 */
#include "kernel.h"

/* ---- PE structures (subset) ---------------------------------------- */

typedef struct {
    u16 e_magic;      /* 'MZ' */
    u16 skip[29];
    u32 e_lfanew;     /* offset of PE header */
} __attribute__((packed)) dos_header_t;

typedef struct {
    u16 machine;
    u16 num_sections;
    u32 timestamp;
    u32 symtab_ptr;
    u32 num_symbols;
    u16 opt_hdr_size;
    u16 characteristics;
} __attribute__((packed)) coff_header_t;

typedef struct {
    u16 magic;        /* 0x10B = PE32 */
    u8  linker_major, linker_minor;
    u32 size_of_code;
    u32 size_of_init_data;
    u32 size_of_uninit_data;
    u32 entry_point;  /* RVA */
    u32 base_of_code;
    u32 base_of_data;
    u32 image_base;
    u32 section_align;
    u32 file_align;
    u16 os_major, os_minor;
    u16 img_major, img_minor;
    u16 subsys_major, subsys_minor;
    u32 win32_version;
    u32 size_of_image;
    u32 size_of_headers;
    u32 checksum;
    u16 subsystem;
    u16 dll_characteristics;
    u32 stack_reserve, stack_commit;
    u32 heap_reserve, heap_commit;
    u32 loader_flags;
    u32 num_data_dirs;
    struct { u32 rva; u32 size; } data_dir[16];
} __attribute__((packed)) opt_header_t;

typedef struct {
    char name[8];
    u32 virtual_size;
    u32 virtual_addr;   /* RVA */
    u32 raw_size;
    u32 raw_ptr;
    u32 reloc_ptr, line_ptr;
    u16 num_relocs, num_lines;
    u32 characteristics;
} __attribute__((packed)) section_header_t;

#define PE_MACHINE_I386   0x014C
#define PE_MAGIC_PE32     0x010B
#define DIR_BASERELOC     5
#define MAX_IMAGE_SIZE    (16u * 1024 * 1024)

process_t *current_process;

/* ---- validation ----------------------------------------------------- */

typedef struct {
    const coff_header_t *coff;
    const opt_header_t *opt;
    const section_header_t *sections;
} pe_view_t;

static const char *pe_parse(const rd_file_t *f, pe_view_t *out)
{
    if (f->size < sizeof(dos_header_t))
        return "file too small";
    const dos_header_t *dos = (const dos_header_t *)f->data;
    if (dos->e_magic != 0x5A4D)
        return "missing MZ signature (not a .exe)";
    if (dos->e_lfanew + 4 + sizeof(coff_header_t) > f->size)
        return "PE header out of bounds";
    if (memcmp(f->data + dos->e_lfanew, "PE\0\0", 4) != 0)
        return "missing PE signature";

    const coff_header_t *coff =
        (const coff_header_t *)(f->data + dos->e_lfanew + 4);
    if (coff->machine != PE_MACHINE_I386)
        return "not an i386 image";
    if (coff->opt_hdr_size < 0x60)
        return "optional header too small";

    const opt_header_t *opt = (const opt_header_t *)(coff + 1);
    if ((const u8 *)opt + coff->opt_hdr_size > f->data + f->size)
        return "optional header out of bounds";
    if (opt->magic != PE_MAGIC_PE32)
        return "not a PE32 image (PE32+ unsupported)";
    if (opt->section_align != PAGE_SIZE)
        return "section alignment must be 4096";
    if (opt->size_of_image == 0 || opt->size_of_image > MAX_IMAGE_SIZE)
        return "bad image size";
    if (opt->image_base < pmm_managed_end() ||
        opt->image_base + opt->size_of_image < opt->image_base)
        return "image base collides with kernel address space";
    if (opt->image_base & 0xFFF)
        return "image base not page aligned";

    const section_header_t *sec =
        (const section_header_t *)((const u8 *)opt + coff->opt_hdr_size);
    if ((const u8 *)(sec + coff->num_sections) > f->data + f->size)
        return "section table out of bounds";
    for (u32 i = 0; i < coff->num_sections; i++) {
        if (sec[i].raw_ptr + sec[i].raw_size > f->size)
            return "section raw data out of bounds";
        if (sec[i].virtual_addr + sec[i].virtual_size > opt->size_of_image)
            return "section exceeds image size";
    }
    if (opt->entry_point >= opt->size_of_image)
        return "entry point outside image";

    out->coff = coff;
    out->opt = opt;
    out->sections = sec;
    return NULL;
}

/* ---- info dump (shell `peinfo` command) ----------------------------- */

void pe_info(const rd_file_t *f)
{
    pe_view_t pe;
    const char *err = pe_parse(f, &pe);
    if (err) {
        kprintf("peinfo: %s: %s\n", f->name, err);
        return;
    }
    kprintf("%s: PE32 executable, %u bytes\n", f->name, f->size);
    kprintf("  machine        i386 (0x%x)\n", pe.coff->machine);
    kprintf("  sections       %d\n", pe.coff->num_sections);
    kprintf("  image base     %p\n", pe.opt->image_base);
    kprintf("  entry point    %p (RVA 0x%x)\n",
            pe.opt->image_base + pe.opt->entry_point, pe.opt->entry_point);
    kprintf("  image size     %u KiB\n", pe.opt->size_of_image / 1024);
    kprintf("  subsystem      %d\n", pe.opt->subsystem);
    for (u32 i = 0; i < pe.coff->num_sections; i++) {
        const section_header_t *s = &pe.sections[i];
        char name[9];
        memcpy(name, s->name, 8);
        name[8] = 0;
        kprintf("  section %s  rva=0x%05x vsize=%u raw=%u\n",
                name, s->virtual_addr, s->virtual_size, s->raw_size);
    }
}

/* ---- loading & execution -------------------------------------------- */

static void apply_relocs(const rd_file_t *f, const pe_view_t *pe,
                         u32 loaded_base)
{
    s32 delta = (s32)(loaded_base - pe->opt->image_base);
    if (delta == 0 || pe->opt->num_data_dirs <= DIR_BASERELOC)
        return;
    u32 rva = pe->opt->data_dir[DIR_BASERELOC].rva;
    u32 size = pe->opt->data_dir[DIR_BASERELOC].size;
    if (!rva || !size)
        return;

    u8 *block = (u8 *)(loaded_base + rva);
    u8 *end = block + size;
    while (block + 8 <= end) {
        u32 page_rva = *(u32 *)block;
        u32 block_size = *(u32 *)(block + 4);
        if (block_size < 8)
            break;
        u16 *entries = (u16 *)(block + 8);
        u32 n = (block_size - 8) / 2;
        for (u32 i = 0; i < n; i++) {
            u16 e = entries[i];
            if ((e >> 12) == 3) /* IMAGE_REL_BASED_HIGHLOW */
                *(u32 *)(loaded_base + page_rva + (e & 0xFFF)) += delta;
        }
        block += block_size;
    }
    (void)f;
}

int pe_run(const rd_file_t *f)
{
    pe_view_t pe;
    const char *err = pe_parse(f, &pe);
    if (err) {
        kprintf("exec: %s: %s\n", f->name, err);
        return -1;
    }

    u32 base = pe.opt->image_base;
    u32 pages = PAGE_ALIGN_UP(pe.opt->size_of_image) / PAGE_SIZE;

    /* keep the frame list so we can return them to the PMM on exit */
    u32 *frames = kmalloc(pages * sizeof(u32));
    if (!frames) {
        kprint("exec: out of memory\n");
        return -1;
    }

    u32 mapped = 0;
    for (; mapped < pages; mapped++) {
        u32 phys = pmm_alloc_frame();
        if (!phys || paging_map(base + mapped * PAGE_SIZE, phys, 1) < 0) {
            if (phys)
                pmm_free_frame(phys);
            break;
        }
        frames[mapped] = phys;
    }
    if (mapped < pages) {
        kprint("exec: out of physical memory\n");
        goto fail_unmap;
    }

    /* image is now addressable at its ImageBase: build it */
    memset((void *)base, 0, pages * PAGE_SIZE);
    memcpy((void *)base, f->data,
           pe.opt->size_of_headers < f->size ? pe.opt->size_of_headers
                                             : f->size);
    for (u32 i = 0; i < pe.coff->num_sections; i++) {
        const section_header_t *s = &pe.sections[i];
        u32 copy = s->raw_size < s->virtual_size ? s->raw_size
                                                 : s->virtual_size;
        memcpy((void *)(base + s->virtual_addr), f->data + s->raw_ptr, copy);
    }
    apply_relocs(f, &pe, base);

    /* run it */
    process_t proc;
    memset(&proc, 0, sizeof(proc));
    proc.name = f->name;
    proc.image_base = base;
    proc.image_pages = pages;
    current_process = &proc;

    int jmp = k_setjmp(proc.exit_jmp);
    if (jmp == 0) {
        typedef int (*entry_fn)(const alpha_api_t *);
        entry_fn entry = (entry_fn)(base + pe.opt->entry_point);
        proc.running = true;
        proc.exit_code = entry(api_table());
    }
    /* jmp==1: app called exit(); jmp==2: app crashed and was killed */
    proc.running = false;
    sti(); /* a fault longjmp arrives here with interrupts off */

    u32 leaked = proc.heap_bytes;
    proc_release_all(&proc);
    current_process = NULL;

    if (leaked)
        kprintf("[os] reclaimed %u bytes the process left allocated\n",
                leaked);

    for (u32 i = 0; i < pages; i++) {
        paging_unmap(base + i * PAGE_SIZE);
        pmm_free_frame(frames[i]);
    }
    kfree(frames);
    return proc.exit_code;

fail_unmap:
    for (u32 i = 0; i < mapped; i++) {
        paging_unmap(base + i * PAGE_SIZE);
        pmm_free_frame(frames[i]);
    }
    kfree(frames);
    return -1;
}
