/*
 * Initrd: a flat read-only archive ("ARFS") built by tools/mkinitrd.py
 * and passed in by the bootloader as a multiboot module.
 *
 *   header:  "ARFS" | u32 count
 *   entry:   char name[32] | u32 offset | u32 size     (x count)
 *   data:    file blobs (offsets relative to archive start)
 */
#include "kernel.h"

#define MAX_FILES 64

typedef struct {
    char name[32];
    u32 offset;
    u32 size;
} __attribute__((packed)) arfs_entry_t;

static rd_file_t files[MAX_FILES];
static char names[MAX_FILES][32];
static u32 nfiles;

void ramdisk_init(multiboot_info_t *mbi)
{
    if (!(mbi->flags & MB_FLAG_MODS) || mbi->mods_count == 0) {
        kprint("ramdisk: no initrd module supplied\n");
        return;
    }

    multiboot_module_t *mod = (multiboot_module_t *)mbi->mods_addr;
    const u8 *base = (const u8 *)mod->mod_start;
    u32 mod_size = mod->mod_end - mod->mod_start;

    if (mod_size < 8 || memcmp(base, "ARFS", 4) != 0) {
        kprint("ramdisk: bad archive magic\n");
        return;
    }

    u32 count = *(const u32 *)(base + 4);
    if (count > MAX_FILES)
        count = MAX_FILES;

    const arfs_entry_t *ents = (const arfs_entry_t *)(base + 8);
    for (u32 i = 0; i < count; i++) {
        if (ents[i].offset + ents[i].size > mod_size)
            continue;
        strncpy(names[nfiles], ents[i].name, 31);
        files[nfiles].name = names[nfiles];
        files[nfiles].data = base + ents[i].offset;
        files[nfiles].size = ents[i].size;
        nfiles++;
    }
}

u32 ramdisk_count(void)
{
    return nfiles;
}

rd_file_t *ramdisk_get(u32 index)
{
    return index < nfiles ? &files[index] : NULL;
}

rd_file_t *ramdisk_find(const char *name)
{
    for (u32 i = 0; i < nfiles; i++)
        if (strcmp(files[i].name, name) == 0)
            return &files[i];
    return NULL;
}
