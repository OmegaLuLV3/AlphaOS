#ifndef MULTIBOOT_H
#define MULTIBOOT_H

#include "../include/types.h"

#define MULTIBOOT_BOOTLOADER_MAGIC 0x2BADB002

#define MB_FLAG_MEM   (1 << 0)
#define MB_FLAG_MODS  (1 << 3)
#define MB_FLAG_MMAP  (1 << 6)

typedef struct multiboot_module {
    u32 mod_start;
    u32 mod_end;
    u32 string;
    u32 reserved;
} multiboot_module_t;

typedef struct multiboot_info {
    u32 flags;
    u32 mem_lower;   /* KiB below 1 MiB   */
    u32 mem_upper;   /* KiB above 1 MiB   */
    u32 boot_device;
    u32 cmdline;
    u32 mods_count;
    u32 mods_addr;
    u32 syms[4];
    u32 mmap_length;
    u32 mmap_addr;
} multiboot_info_t;

#endif
