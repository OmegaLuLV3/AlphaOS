/* 8253/8254 programmable interval timer: system tick source. */
#include "kernel.h"

static volatile u32 ticks;
static u32 tick_hz = 100;

static void pit_irq(regs_t *r)
{
    (void)r;
    ticks++;
}

void pit_init(u32 hz)
{
    tick_hz = hz;
    u32 divisor = 1193182 / hz;
    outb(0x43, 0x36); /* channel 0, lo/hi, mode 3 (square wave) */
    outb(0x40, divisor & 0xFF);
    outb(0x40, (divisor >> 8) & 0xFF);
    irq_register(0, pit_irq);
}

u32 pit_ticks(void)
{
    return ticks;
}

u32 uptime_ms(void)
{
    return ticks * (1000 / tick_hz);
}

void sleep_ms(u32 ms)
{
    u32 target = ticks + (ms * tick_hz + 999) / 1000;
    while ((s32)(ticks - target) < 0) {
        sti();
        hlt();
    }
}
