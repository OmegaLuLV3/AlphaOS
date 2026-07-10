/*
 * Applications link at ImageBase (0x40000000) + one page of PE headers.
 * The ELF output is flattened with objcopy and wrapped into a PE32 by
 * tools/mkpe.py; __bss_size is exported so mkpe.py can set VirtualSize.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x40001000;

    .text : {
        KEEP(*(.entry))
        *(.text*)
    }
    .rodata : { *(.rodata*) }
    .data : { *(.data*) }

    __bss_start = .;
    .bss (NOLOAD) : { *(.bss*) *(COMMON) }
    __bss_end = .;
    __bss_size = __bss_end - __bss_start;
}
