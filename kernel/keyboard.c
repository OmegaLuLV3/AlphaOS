/*
 * PS/2 keyboard (scan code set 1) with an interrupt-driven ring buffer.
 * input_getch() also polls COM1 so the shell works over serial too.
 */
#include "kernel.h"

#define BUF_SIZE 64

static volatile u8 buf[BUF_SIZE];
static volatile u32 head, tail;
static bool shift, caps;

static const char map_lower[128] = {
    0, 27, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '-', '=', '\b',
    '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '[', ']', '\n',
    0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`',
    0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0,
    '*', 0, ' ',
};
static const char map_upper[128] = {
    0, 27, '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '\b',
    '\t', 'Q', 'W', 'E', 'R', 'T', 'Y', 'U', 'I', 'O', 'P', '{', '}', '\n',
    0, 'A', 'S', 'D', 'F', 'G', 'H', 'J', 'K', 'L', ':', '"', '~',
    0, '|', 'Z', 'X', 'C', 'V', 'B', 'N', 'M', '<', '>', '?', 0,
    '*', 0, ' ',
};

static void kbd_irq(regs_t *r)
{
    (void)r;
    u8 sc = inb(0x60);

    if (sc == 0x2A || sc == 0x36) { shift = true;  return; }
    if (sc == 0xAA || sc == 0xB6) { shift = false; return; }
    if (sc == 0x3A)               { caps = !caps;  return; }
    if (sc & 0x80)
        return; /* other key releases */

    char c = shift ? map_upper[sc] : map_lower[sc];
    if (c >= 'a' && c <= 'z' && caps)
        c -= 32;
    else if (c >= 'A' && c <= 'Z' && caps && !shift)
        c += 32;
    if (!c)
        return;

    u32 next = (head + 1) % BUF_SIZE;
    if (next != tail) {
        buf[head] = (u8)c;
        head = next;
    }
}

void keyboard_init(void)
{
    irq_register(1, kbd_irq);
}

int input_getch(void)
{
    for (;;) {
        if (tail != head) {
            cli();
            u8 c = buf[tail];
            tail = (tail + 1) % BUF_SIZE;
            sti();
            return c;
        }
        int s = serial_getc();
        if (s >= 0) {
            if (s == '\r')
                s = '\n';
            if (s == 0x7F)
                s = '\b';
            return s;
        }
        sti();
        hlt(); /* wake on next timer/keyboard interrupt */
    }
}

int input_readline(char *out, u32 max)
{
    u32 n = 0;
    for (;;) {
        int c = input_getch();
        if (c == '\n') {
            kputc('\n');
            out[n] = 0;
            return (int)n;
        }
        if (c == '\b') {
            if (n) {
                n--;
                kputc('\b');
            }
            continue;
        }
        if (c >= 32 && c < 127 && n + 1 < max) {
            out[n++] = (char)c;
            kputc((char)c);
        }
    }
}
