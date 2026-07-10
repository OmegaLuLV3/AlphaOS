/* 16550 UART driver for COM1 — kernel log and headless console. */
#include "kernel.h"

#define COM1 0x3F8

void serial_init(void)
{
    outb(COM1 + 1, 0x00); /* disable interrupts (we poll)          */
    outb(COM1 + 3, 0x80); /* DLAB on                               */
    outb(COM1 + 0, 0x01); /* divisor 1 -> 115200 baud              */
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03); /* 8N1                                   */
    outb(COM1 + 2, 0xC7); /* FIFO on, cleared, 14-byte threshold   */
    outb(COM1 + 4, 0x0B); /* DTR + RTS + OUT2                      */
}

void serial_putc(char c)
{
    while (!(inb(COM1 + 5) & 0x20))
        ;
    outb(COM1, c);
}

int serial_getc(void)
{
    if (!(inb(COM1 + 5) & 0x01))
        return -1;
    return inb(COM1);
}
