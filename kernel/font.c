/*
 * Bitmap font for the GUI: the 8x16 glyphs are captured from VGA plane 2
 * at boot, while the card is still in text mode (the BIOS loads its ROM
 * font there). Saves us from embedding a font and matches the classic
 * console look.
 */
#include "kernel.h"

u8 vga_font[256 * 16];

void font_init(void)
{
    volatile u8 *vram = (volatile u8 *)0xA0000;

    /* switch VGA sequencer/graphics regs to expose plane 2 linearly */
    outb(0x3C4, 0x02); outb(0x3C5, 0x04); /* write plane 2 */
    outb(0x3C4, 0x04); outb(0x3C5, 0x06); /* seq: flat, no odd/even */
    outb(0x3CE, 0x04); outb(0x3CF, 0x02); /* read plane 2 */
    outb(0x3CE, 0x05); outb(0x3CF, 0x00); /* graphics: read mode 0 */
    outb(0x3CE, 0x06); outb(0x3CF, 0x04); /* map A0000, 64K */

    /* glyphs are stored 32 bytes apart; 8x16 uses the first 16 */
    for (int ch = 0; ch < 256; ch++)
        for (int row = 0; row < 16; row++)
            vga_font[ch * 16 + row] = vram[ch * 32 + row];

    /* restore text-mode register state */
    outb(0x3C4, 0x02); outb(0x3C5, 0x03);
    outb(0x3C4, 0x04); outb(0x3C5, 0x02);
    outb(0x3CE, 0x04); outb(0x3CF, 0x00);
    outb(0x3CE, 0x05); outb(0x3CF, 0x10);
    outb(0x3CE, 0x06); outb(0x3CF, 0x0E);

    u32 nonzero = 0;
    for (u32 i = 0; i < sizeof(vga_font); i++)
        if (vga_font[i])
            nonzero++;
    kprintf("font: captured 8x16 VGA font (%u glyph bytes)\n", nonzero);
}
