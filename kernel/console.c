/*
 * VGA text-mode console, mirrored to COM1 so the OS is fully usable
 * over a serial line (qemu -nographic).
 */
#include "kernel.h"

#define VGA_MEM  ((volatile u16 *)0xB8000)
#define COLS 80
#define ROWS 25

static u8 cur_x, cur_y;
static u8 color = 0x07; /* light grey on black */

static void move_cursor(void)
{
    u16 pos = cur_y * COLS + cur_x;
    outb(0x3D4, 14);
    outb(0x3D5, pos >> 8);
    outb(0x3D4, 15);
    outb(0x3D5, pos & 0xFF);
}

static void scroll(void)
{
    if (cur_y < ROWS)
        return;
    memmove((void *)VGA_MEM, (const void *)(VGA_MEM + COLS),
            (ROWS - 1) * COLS * 2);
    for (int x = 0; x < COLS; x++)
        VGA_MEM[(ROWS - 1) * COLS + x] = (color << 8) | ' ';
    cur_y = ROWS - 1;
}

void console_init(void)
{
    serial_init();
    console_clear();
}

void console_clear(void)
{
    for (int i = 0; i < COLS * ROWS; i++)
        VGA_MEM[i] = (color << 8) | ' ';
    cur_x = cur_y = 0;
    move_cursor();
    serial_putc('\033');
    serial_putc('c'); /* ANSI full reset for serial terminals */
}

void console_set_color(u8 fg, u8 bg)
{
    color = (bg << 4) | (fg & 0x0F);
}

void kputc(char c)
{
    if (c == '\n')
        serial_putc('\r');
    serial_putc(c);

    switch (c) {
    case '\n':
        cur_x = 0;
        cur_y++;
        break;
    case '\r':
        cur_x = 0;
        break;
    case '\b':
        if (cur_x) {
            cur_x--;
            VGA_MEM[cur_y * COLS + cur_x] = (color << 8) | ' ';
        }
        break;
    case '\t':
        cur_x = (cur_x + 8) & ~7;
        if (cur_x >= COLS) {
            cur_x = 0;
            cur_y++;
        }
        break;
    default:
        VGA_MEM[cur_y * COLS + cur_x] = (color << 8) | (u8)c;
        cur_x++;
        if (cur_x >= COLS) {
            cur_x = 0;
            cur_y++;
        }
    }
    scroll();
    move_cursor();
}

void kprint(const char *s)
{
    while (*s)
        kputc(*s++);
}

static void print_uint(u32 v, u32 base, int width, char pad)
{
    static const char digits[] = "0123456789abcdef";
    char buf[12];
    int i = 0;
    if (v == 0)
        buf[i++] = '0';
    while (v) {
        buf[i++] = digits[v % base];
        v /= base;
    }
    while (i < width && i < (int)sizeof(buf))
        buf[i++] = pad;
    while (i--)
        kputc(buf[i]);
}

void kprintf(const char *fmt, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);

    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            kputc(*fmt);
            continue;
        }
        fmt++;
        char pad = ' ';
        int width = 0;
        if (*fmt == '0') {
            pad = '0';
            fmt++;
        }
        while (*fmt >= '0' && *fmt <= '9') {
            width = width * 10 + (*fmt - '0');
            fmt++;
        }
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            kprint(s ? s : "(null)");
            break;
        }
        case 'c':
            kputc((char)__builtin_va_arg(ap, int));
            break;
        case 'd': {
            int v = __builtin_va_arg(ap, int);
            if (v < 0) {
                kputc('-');
                v = -v;
            }
            print_uint((u32)v, 10, width, pad);
            break;
        }
        case 'u':
            print_uint(__builtin_va_arg(ap, u32), 10, width, pad);
            break;
        case 'x':
            print_uint(__builtin_va_arg(ap, u32), 16, width, pad);
            break;
        case 'p':
            kprint("0x");
            print_uint(__builtin_va_arg(ap, u32), 16, 8, '0');
            break;
        case '%':
            kputc('%');
            break;
        default:
            kputc('%');
            kputc(*fmt);
        }
    }
    __builtin_va_end(ap);
}

void panic(const char *msg)
{
    cli();
    console_set_color(ALPHA_WHITE, ALPHA_RED);
    kprintf("\n*** KERNEL PANIC: %s ***\n", msg);
    for (;;)
        hlt();
}
