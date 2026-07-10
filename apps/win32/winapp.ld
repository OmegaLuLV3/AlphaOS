/*
 * Windows-style AlphaOS apps: the IAT sits at the top of the image
 * (RVA 0x1000, matching what mkpe.py records in the PE data
 * directories), code starts at the fixed entry RVA 0x1100.
 */
ENTRY(_start)

SECTIONS
{
    . = 0x40001000;
    .iat : { *(.iat) }
    ASSERT(SIZEOF(.iat) <= 0x100, ".iat grew past 256 bytes: bump entry RVA")

    . = 0x40001100;
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
