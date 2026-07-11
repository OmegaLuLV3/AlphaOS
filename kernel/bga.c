/*
 * Display driver for the Bochs/QEMU VBE graphics adapter ("BGA").
 * Binds to PCI device 1234:1111, programs the mode via the dispi
 * index/data ports, and maps the linear framebuffer. If the adapter is
 * absent (real hardware without it), the kernel stays in VGA text mode.
 */
#include "kernel.h"

#define VBE_INDEX 0x01CE
#define VBE_DATA  0x01CF

#define VBE_ID      0
#define VBE_XRES    1
#define VBE_YRES    2
#define VBE_BPP     3
#define VBE_ENABLE  4

#define VBE_ENABLED     0x01
#define VBE_LFB_ENABLED 0x40

static u32 *fb;
static int scr_w, scr_h;

static void vbe_write(u16 index, u16 value)
{
    outw(VBE_INDEX, index);
    outw(VBE_DATA, value);
}

static u16 vbe_read(u16 index)
{
    outw(VBE_INDEX, index);
    return inw(VBE_DATA);
}

int bga_init(int w, int h)
{
    u16 id = vbe_read(VBE_ID);
    if ((id & 0xFFF0) != 0xB0C0) {
        kprint("bga: no Bochs/QEMU display adapter, staying in text mode\n");
        return -1;
    }

    pci_dev_t *dev = pci_find(0x1234, 0x1111);
    if (!dev || !(dev->bar0 & ~0xFu)) {
        kprint("bga: adapter found but no framebuffer BAR\n");
        return -1;
    }
    uptr fb_phys = dev->bar0 & 0xFFFFFFF0u;

    vbe_write(VBE_ENABLE, 0);
    vbe_write(VBE_XRES, w);
    vbe_write(VBE_YRES, h);
    vbe_write(VBE_BPP, 32);
    vbe_write(VBE_ENABLE, VBE_ENABLED | VBE_LFB_ENABLED);

    /* the LFB lives far above RAM: map it identity into kernel space.
       It's pixel data, never code -- non-executable. */
    u32 size = PAGE_ALIGN_UP((u32)w * h * 4);
    for (u32 off = 0; off < size; off += PAGE_SIZE) {
        if (paging_map(fb_phys + off, fb_phys + off, 1, 0) < 0) {
            kprint("bga: failed to map framebuffer\n");
            return -1;
        }
    }

    fb = (u32 *)fb_phys;
    scr_w = w;
    scr_h = h;
    kprintf("bga: %dx%dx32 framebuffer at %p (dispi id 0x%x)\n",
            w, h, (void *)fb_phys, id);
    return 0;
}

u32 *bga_framebuffer(void) { return fb; }
int  bga_width(void)       { return scr_w; }
int  bga_height(void)      { return scr_h; }
