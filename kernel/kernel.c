/* AlphaOS kernel entry point. */
#include "kernel.h"

extern u8 kernel_end; /* provided by the linker script */

void kmain(u32 magic, multiboot_info_t *mbi)
{
    console_init();

    if (magic != MULTIBOOT_BOOTLOADER_MAGIC)
        panic("not booted by a multiboot loader");

    gdt_init();
    idt_init();
    pic_init();
    pit_init(100);
    keyboard_init();

    pmm_init(mbi, (u32)&kernel_end);
    paging_init();
    kheap_init();
    ramdisk_init(mbi);

    sti();

    console_set_color(ALPHA_LCYAN, ALPHA_BLACK);
    kprint("\n  AlphaOS 0.1 -- a lightweight OS that runs .exe files\n");
    console_set_color(ALPHA_DGREY, ALPHA_BLACK);
    kprintf("  %u KiB RAM managed | %u KiB in use | %u file(s) on ramdisk\n",
            pmm_total_kib(), pmm_total_kib() - pmm_free_kib(),
            ramdisk_count());
    console_set_color(ALPHA_LGREY, ALPHA_BLACK);
    kprint("  type 'help' for commands\n\n");

    shell_run();
}
