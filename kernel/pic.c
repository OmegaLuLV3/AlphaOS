/* 8259A PIC: remap IRQs 0-15 to vectors 32-47. */
#include "kernel.h"

#define PIC1_CMD  0x20
#define PIC1_DATA 0x21
#define PIC2_CMD  0xA0
#define PIC2_DATA 0xA1

void pic_init(void)
{
    outb(PIC1_CMD, 0x11); io_wait();   /* ICW1: init + ICW4 */
    outb(PIC2_CMD, 0x11); io_wait();
    outb(PIC1_DATA, 32);  io_wait();   /* ICW2: vector offsets */
    outb(PIC2_DATA, 40);  io_wait();
    outb(PIC1_DATA, 4);   io_wait();   /* ICW3: cascade on IRQ2 */
    outb(PIC2_DATA, 2);   io_wait();
    outb(PIC1_DATA, 0x01); io_wait();  /* ICW4: 8086 mode */
    outb(PIC2_DATA, 0x01); io_wait();

    outb(PIC1_DATA, 0xF8); /* unmask IRQ 0 (timer), 1 (kbd), 2 (cascade) */
    outb(PIC2_DATA, 0xEF); /* unmask IRQ 12 (PS/2 mouse) */
}

void pic_eoi(u8 irq)
{
    if (irq >= 8)
        outb(PIC2_CMD, 0x20);
    outb(PIC1_CMD, 0x20);
}
