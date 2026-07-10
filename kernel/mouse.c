/* PS/2 mouse driver (IRQ 12): 3-byte packets into a ring buffer. */
#include "kernel.h"

#define RING 64

typedef struct {
    s8 dx, dy;
    u8 buttons;
} packet_t;

static volatile packet_t ring[RING];
static volatile u32 head, tail;
static u8 pkt[3];
static u32 cycle;

static void wait_write(void)
{
    for (u32 i = 0; i < 100000; i++)
        if (!(inb(0x64) & 0x02))
            return;
}

static void wait_read(void)
{
    for (u32 i = 0; i < 100000; i++)
        if (inb(0x64) & 0x01)
            return;
}

static void mouse_send(u8 b)
{
    wait_write();
    outb(0x64, 0xD4);
    wait_write();
    outb(0x60, b);
    wait_read();
    inb(0x60); /* consume ACK */
}

static void mouse_irq(regs_t *r)
{
    (void)r;
    u8 data = inb(0x60);

    /* a valid header byte has bit 3 set and no overflow bits; this also
       rejects stray 0xFA ACKs so one bad byte can't shift the stream */
    if (cycle == 0 && (data & 0xC8) != 0x08)
        return;
    pkt[cycle++] = data;
    if (cycle < 3)
        return;
    cycle = 0;

    if (pkt[0] & 0xC0)
        return; /* overflow packet: discard */

    u32 next = (head + 1) % RING;
    if (next == tail)
        return; /* ring full: drop */
    ring[head].dx = (s8)pkt[1];
    ring[head].dy = (s8)pkt[2];
    ring[head].buttons = pkt[0] & 0x07;
    head = next;
}

void mouse_init(void)
{
    wait_write();
    outb(0x64, 0xA8); /* enable aux device */

    wait_write();
    outb(0x64, 0x20); /* read controller command byte */
    wait_read();
    u8 status = inb(0x60);
    status |= 0x02;   /* enable IRQ12 */
    status &= ~0x20;  /* enable mouse clock */
    wait_write();
    outb(0x64, 0x60);
    wait_write();
    outb(0x60, status);

    mouse_send(0xF6); /* set defaults */
    mouse_send(0xF4); /* enable data reporting */

    /* drain any late ACKs so the packet stream starts aligned */
    for (u32 i = 0; i < 16 && (inb(0x64) & 0x01); i++)
        inb(0x60);

    irq_register(12, mouse_irq);
    kprint("mouse: PS/2 mouse on IRQ 12\n");
}

int mouse_pop(int *dx, int *dy, u8 *buttons)
{
    if (tail == head)
        return 0;
    cli();
    packet_t p = ring[tail];
    tail = (tail + 1) % RING;
    sti();
    *dx = p.dx;
    *dy = -p.dy; /* PS/2 y is positive-up; screen y grows down */
    *buttons = p.buttons;
    return 1;
}
