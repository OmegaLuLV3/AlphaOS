/*
 * PCI bus driver: enumerates configuration space via ports 0xCF8/0xCFC.
 * Other drivers (e.g. the BGA display driver) bind to devices found here,
 * and the shell exposes the list as `lspci`.
 */
#include "kernel.h"

#define PCI_MAX 32

static pci_dev_t devices[PCI_MAX];
static u32 ndevices;

static u32 cfg_read(u8 bus, u8 slot, u8 func, u8 off)
{
    u32 addr = 0x80000000u | ((u32)bus << 16) | ((u32)slot << 11) |
               ((u32)func << 8) | (off & 0xFC);
    outl(0xCF8, addr);
    return inl(0xCFC);
}

static void cfg_write(u8 bus, u8 slot, u8 func, u8 off, u32 val)
{
    u32 addr = 0x80000000u | ((u32)bus << 16) | ((u32)slot << 11) |
               ((u32)func << 8) | (off & 0xFC);
    outl(0xCF8, addr);
    outl(0xCFC, val);
}

static const struct {
    u16 vendor, device;
    const char *name;
} known[] = {
    { 0x8086, 0x1237, "Intel 440FX host bridge" },
    { 0x8086, 0x7000, "Intel PIIX3 ISA bridge" },
    { 0x8086, 0x7010, "Intel PIIX3 IDE controller" },
    { 0x8086, 0x7110, "Intel PIIX4 ISA bridge" },
    { 0x8086, 0x7113, "Intel PIIX4 ACPI controller" },
    { 0x8086, 0x100E, "Intel 82540EM ethernet (e1000)" },
    { 0x1234, 0x1111, "QEMU/Bochs VGA display adapter" },
    { 0x1AF4, 0x1000, "virtio network device" },
    { 0x1AF4, 0x1001, "virtio block device" },
    { 0x10EC, 0x8139, "Realtek RTL8139 ethernet" },
};

static const char *class_name(u8 class_code)
{
    switch (class_code) {
    case 0x01: return "storage controller";
    case 0x02: return "network controller";
    case 0x03: return "display controller";
    case 0x04: return "multimedia device";
    case 0x06: return "bridge";
    case 0x0C: return "serial bus controller";
    default:   return "device";
    }
}

static void probe(u8 bus, u8 slot, u8 func)
{
    u32 id = cfg_read(bus, slot, func, 0x00);
    u16 vendor = id & 0xFFFF;
    if (vendor == 0xFFFF || ndevices >= PCI_MAX)
        return;

    pci_dev_t *d = &devices[ndevices++];
    d->bus = bus;
    d->slot = slot;
    d->func = func;
    d->vendor = vendor;
    d->device = id >> 16;
    u32 cls = cfg_read(bus, slot, func, 0x08);
    d->class_code = cls >> 24;
    d->subclass = (cls >> 16) & 0xFF;
    d->bar0 = cfg_read(bus, slot, func, 0x10);
    d->irq_line = cfg_read(bus, slot, func, 0x3C) & 0xFF;

    d->name = class_name(d->class_code);
    for (u32 i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if (known[i].vendor == d->vendor && known[i].device == d->device) {
            d->name = known[i].name;
            break;
        }
    }
}

void pci_scan(void)
{
    for (u8 bus = 0; bus < 8; bus++) {
        for (u8 slot = 0; slot < 32; slot++) {
            if ((cfg_read(bus, slot, 0, 0) & 0xFFFF) == 0xFFFF)
                continue;
            u8 header = (cfg_read(bus, slot, 0, 0x0C) >> 16) & 0xFF;
            u8 nfunc = (header & 0x80) ? 8 : 1;
            for (u8 f = 0; f < nfunc; f++)
                probe(bus, slot, f);
        }
    }
    kprintf("pci: %u device(s) on the bus\n", ndevices);
}

/* command register bit0 = I/O space enable, bit2 = bus master enable
   (needed for a device like the RTL8139 NIC to DMA into RAM at all) */
void pci_enable_device(pci_dev_t *d)
{
    u32 cmd = cfg_read(d->bus, d->slot, d->func, 0x04);
    cmd |= 0x1 | 0x4;
    cfg_write(d->bus, d->slot, d->func, 0x04, cmd);
}

u32 pci_count(void)
{
    return ndevices;
}

pci_dev_t *pci_get(u32 i)
{
    return i < ndevices ? &devices[i] : NULL;
}

pci_dev_t *pci_find(u16 vendor, u16 device)
{
    for (u32 i = 0; i < ndevices; i++)
        if (devices[i].vendor == vendor && devices[i].device == device)
            return &devices[i];
    return NULL;
}
