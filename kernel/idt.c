/*
 * 64-bit IDT and the central interrupt dispatcher. Gate descriptors are
 * 16 bytes in long mode (a 64-bit handler offset split across three
 * fields, plus a reserved dword). Fault isolation semantics are
 * unchanged from the 32-bit design: an exception while an app is
 * running kills just that app via longjmp; with no app running it's a
 * kernel bug and we panic.
 */
#include "kernel.h"

struct idt_entry {
    u16 base_low;
    u16 sel;
    u8  ist;
    u8  flags;
    u16 base_mid;
    u32 base_high;
    u32 reserved;
} __attribute__((packed));

struct idt_ptr {
    u16 limit;
    u64 base;
} __attribute__((packed));

static struct idt_entry idt[256];
static struct idt_ptr ip;
static irq_handler_t irq_handlers[16];

extern void idt_flush(u64 idtr);

#define ISR(n) extern void isr##n(void);
ISR(0) ISR(1) ISR(2) ISR(3) ISR(4) ISR(5) ISR(6) ISR(7)
ISR(8) ISR(9) ISR(10) ISR(11) ISR(12) ISR(13) ISR(14) ISR(15)
ISR(16) ISR(17) ISR(18) ISR(19) ISR(20) ISR(21) ISR(22) ISR(23)
ISR(24) ISR(25) ISR(26) ISR(27) ISR(28) ISR(29) ISR(30) ISR(31)
#define IRQS(n) extern void irq##n(void);
IRQS(0) IRQS(1) IRQS(2) IRQS(3) IRQS(4) IRQS(5) IRQS(6) IRQS(7)
IRQS(8) IRQS(9) IRQS(10) IRQS(11) IRQS(12) IRQS(13) IRQS(14) IRQS(15)

static const char *exception_names[32] = {
    "divide error", "debug", "NMI", "breakpoint", "overflow",
    "bound range", "invalid opcode", "device not available",
    "double fault", "coprocessor overrun", "invalid TSS",
    "segment not present", "stack fault", "general protection fault",
    "page fault", "reserved", "x87 FPU error", "alignment check",
    "machine check", "SIMD exception", "virtualization", "control",
    "reserved", "reserved", "reserved", "reserved", "reserved",
    "reserved", "reserved", "reserved", "security", "reserved",
};

static void idt_set(int n, uptr base)
{
    idt[n].base_low  = base & 0xFFFF;
    idt[n].base_mid  = (base >> 16) & 0xFFFF;
    idt[n].base_high = (base >> 32) & 0xFFFFFFFF;
    idt[n].sel   = 0x08;
    idt[n].ist   = 0;
    idt[n].flags = 0x8E; /* present, ring0, 64-bit interrupt gate */
    idt[n].reserved = 0;
}

void idt_init(void)
{
    memset(idt, 0, sizeof(idt));

#define SET(n) idt_set(n, (uptr)isr##n);
    SET(0) SET(1) SET(2) SET(3) SET(4) SET(5) SET(6) SET(7)
    SET(8) SET(9) SET(10) SET(11) SET(12) SET(13) SET(14) SET(15)
    SET(16) SET(17) SET(18) SET(19) SET(20) SET(21) SET(22) SET(23)
    SET(24) SET(25) SET(26) SET(27) SET(28) SET(29) SET(30) SET(31)
#undef SET
#define SET(n, v) idt_set(v, (uptr)irq##n);
    SET(0, 32) SET(1, 33) SET(2, 34) SET(3, 35) SET(4, 36) SET(5, 37)
    SET(6, 38) SET(7, 39) SET(8, 40) SET(9, 41) SET(10, 42) SET(11, 43)
    SET(12, 44) SET(13, 45) SET(14, 46) SET(15, 47)
#undef SET

    ip.limit = sizeof(idt) - 1;
    ip.base  = (uptr)&idt;
    idt_flush((uptr)&ip);
}

void irq_register(u8 irq, irq_handler_t handler)
{
    if (irq < 16)
        irq_handlers[irq] = handler;
}

static uptr read_cr2(void)
{
    uptr v;
    __asm__ volatile("mov %%cr2, %0" : "=r"(v));
    return v;
}

void interrupt_dispatch(regs_t *r)
{
    if (r->int_no >= 32 && r->int_no < 48) {
        u8 irq = r->int_no - 32;
        if (irq_handlers[irq])
            irq_handlers[irq](r);
        pic_eoi(irq);
        return;
    }

    /* CPU exception */
    const char *name =
        r->int_no < 32 ? exception_names[r->int_no] : "unknown";

    if (current_process && current_process->running) {
        console_set_color(ALPHA_LRED, ALPHA_BLACK);
        kprintf("\n[fault] %s (int %d, err %x) at rip=%p",
                name, (int)r->int_no, (u32)r->err_code, (void *)r->rip);
        if (r->int_no == 14)
            kprintf(" addr=%p", (void *)read_cr2());
        kprintf("\n[fault] killing process '%s'\n", current_process->name);
        console_set_color(ALPHA_LGREY, ALPHA_BLACK);
        current_process->exit_code = -1;
        k_longjmp(current_process->exit_jmp, 2);
    }

    kprintf("\nexception %d (%s) err=%x rip=%p\n",
            (int)r->int_no, name, (u32)r->err_code, (void *)r->rip);
    if (r->int_no == 14)
        kprintf("cr2=%p\n", (void *)read_cr2());
    panic("unhandled exception in kernel");
}
