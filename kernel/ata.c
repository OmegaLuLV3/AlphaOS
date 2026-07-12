/*
 * kernel/ata.c -- a minimal ATA/IDE PIO disk driver, targeting the
 * primary channel's master drive via the legacy, fixed I/O ports
 * every PC-compatible IDE controller exposes for backwards
 * compatibility (0x1F0-0x1F7 command block, 0x3F6 control block) --
 * no PCI BAR discovery needed, the same reasoning kernel/rtc.c
 * already relies on for its own fixed-port hardware.
 *
 * Polling PIO, not IRQ-driven: every other blocking operation in this
 * kernel (ping, DNS, TCP, TLS handshakes) already works this way, and
 * a QEMU virtual disk responds to PIO commands fast enough that there
 * is no real throughput cost to paying for it, and one less source of
 * IRQ-ordering bugs to get wrong.
 *
 * LBA28 addressing only (up to 128GiB) -- comfortably more than this
 * kernel's 32MiB build/disk.img will ever need, and simpler than also
 * supporting LBA48.
 */
#include "kernel.h"

#define ATA_IO   0x1F0

#define ATA_REG_DATA      (ATA_IO + 0)
#define ATA_REG_ERROR     (ATA_IO + 1)
#define ATA_REG_SECCOUNT  (ATA_IO + 2)
#define ATA_REG_LBA_LOW   (ATA_IO + 3)
#define ATA_REG_LBA_MID   (ATA_IO + 4)
#define ATA_REG_LBA_HIGH  (ATA_IO + 5)
#define ATA_REG_DRIVE     (ATA_IO + 6)
#define ATA_REG_STATUS    (ATA_IO + 7)
#define ATA_REG_COMMAND   (ATA_IO + 7)

#define ATA_SR_BSY  0x80
#define ATA_SR_DRQ  0x08
#define ATA_SR_ERR  0x01

#define ATA_CMD_READ_SECTORS  0x20
#define ATA_CMD_WRITE_SECTORS 0x30
#define ATA_CMD_FLUSH_CACHE   0xE7
#define ATA_CMD_IDENTIFY      0xEC

static bool disk_present;
static u32 disk_sectors;

static u8 ata_status(void) { return inb(ATA_REG_STATUS); }

/* Bounded polling -- a real (or QEMU-virtual) ATA device answers
   within microseconds to low milliseconds; bounding the poll count
   (rather than looping forever) means a missing or faulty controller
   makes ata_init()/ata_read_sector()/ata_write_sector() fail cleanly
   instead of hanging the kernel.

   In practice FLUSH CACHE (see ata_flush_cache()) can still take far
   longer than a normal read/write command -- it can drive a real
   fsync() of the backing file on the host, which under host I/O
   contention has been observed taking several *seconds*, not the
   microseconds a bare virtual-disk command needs. That's long enough
   to overrun the 16-byte hardware FIFO of the polled (non-interrupt-
   driven -- see kernel/serial.c) serial console if nothing drains it
   in the meantime, corrupting whatever's typed next. gui_pump() (same
   call kernel/pit.c's sleep_ms() already makes for the same reason)
   periodically drains serial/keyboard input into its own much larger
   256-byte software queue during a long wait, so a slow flush can't
   silently eat console input.

   Pumping is paced by pit_ticks(), not by the loop's own iteration
   count: individual iterations can vary wildly in latency under host
   I/O contention (that's the whole problem), so a fixed iteration
   modulus can't be trusted to land often enough in wall-clock time --
   a tick-based check costs nothing extra when the device answers
   quickly (ticks rarely advance within a fast poll) and still fires
   reliably once every ~10ms of *real* time during a slow one. */
static void pump_input_if_slow(u32 *last_pump_tick)
{
    if (!gui_active())
        return;
    u32 now = pit_ticks();
    if (now == *last_pump_tick)
        return;
    *last_pump_tick = now;
    gui_pump();
}

static bool wait_not_busy(void)
{
    u32 last_pump_tick = pit_ticks();
    for (u32 i = 0; i < 100000; i++) {
        if (!(ata_status() & ATA_SR_BSY))
            return true;
        pump_input_if_slow(&last_pump_tick);
    }
    return false;
}

static bool wait_drq(void)
{
    u32 last_pump_tick = pit_ticks();
    for (u32 i = 0; i < 100000; i++) {
        u8 s = ata_status();
        if (s & ATA_SR_ERR)
            return false;
        if (s & ATA_SR_DRQ)
            return true;
        pump_input_if_slow(&last_pump_tick);
    }
    return false;
}

void ata_init(void)
{
    disk_present = false;
    disk_sectors = 0;

    pci_dev_t *d = pci_find(0x8086, 0x7010); /* PIIX3 IDE controller */
    if (!d)
        return;

    outb(ATA_REG_DRIVE, 0xA0); /* select master, no LBA bits for IDENTIFY */
    io_wait();
    outb(ATA_REG_SECCOUNT, 0);
    outb(ATA_REG_LBA_LOW, 0);
    outb(ATA_REG_LBA_MID, 0);
    outb(ATA_REG_LBA_HIGH, 0);
    outb(ATA_REG_COMMAND, ATA_CMD_IDENTIFY);

    if (ata_status() == 0)
        return; /* no drive present on this channel at all */
    if (!wait_not_busy())
        return;

    /* a non-ATA device (ATAPI/etc.) reports nonzero LBA_MID/LBA_HIGH
       at this point instead of proceeding straight to DRQ; only a
       plain ATA hard disk is supported here */
    if (inb(ATA_REG_LBA_MID) != 0 || inb(ATA_REG_LBA_HIGH) != 0)
        return;
    if (!wait_drq())
        return;

    u16 ident[256];
    for (int i = 0; i < 256; i++)
        ident[i] = inw(ATA_REG_DATA);

    /* words 60-61: total addressable LBA28 sectors */
    disk_sectors = ((u32)ident[61] << 16) | ident[60];
    disk_present = (disk_sectors > 0);
}

bool ata_ready(void) { return disk_present; }
u32  ata_sector_count(void) { return disk_sectors; }

static bool ata_select(u32 lba)
{
    if (!wait_not_busy())
        return false;
    outb(ATA_REG_DRIVE, (u8)(0xE0 | ((lba >> 24) & 0x0F)));
    outb(ATA_REG_SECCOUNT, 1);
    outb(ATA_REG_LBA_LOW, (u8)lba);
    outb(ATA_REG_LBA_MID, (u8)(lba >> 8));
    outb(ATA_REG_LBA_HIGH, (u8)(lba >> 16));
    return true;
}

bool ata_read_sector(u32 lba, u8 out[512])
{
    if (!disk_present || lba >= disk_sectors)
        return false;
    if (!ata_select(lba))
        return false;
    outb(ATA_REG_COMMAND, ATA_CMD_READ_SECTORS);
    if (!wait_not_busy() || !wait_drq())
        return false;

    for (int i = 0; i < 256; i++) {
        u16 w = inw(ATA_REG_DATA);
        out[i * 2] = (u8)w;
        out[i * 2 + 1] = (u8)(w >> 8);
    }
    return true;
}

bool ata_write_sector(u32 lba, const u8 in[512])
{
    if (!disk_present || lba >= disk_sectors)
        return false;
    if (!ata_select(lba))
        return false;
    outb(ATA_REG_COMMAND, ATA_CMD_WRITE_SECTORS);
    if (!wait_not_busy() || !wait_drq())
        return false;

    for (int i = 0; i < 256; i++) {
        u16 w = (u16)in[i * 2] | ((u16)in[i * 2 + 1] << 8);
        outw(ATA_REG_DATA, w);
    }
    return wait_not_busy();
}

/* Callers that issue several ata_write_sector() calls for one logical
   filesystem operation (e.g. fat_write_file(): data clusters + both
   FAT copies + the directory entry) call this once at the end, rather
   than ata_write_sector() flushing after every single sector -- same
   durability guarantee (nothing is claimed done until this returns),
   far fewer flushes. A real (or QEMU-virtual) FLUSH CACHE can take
   long enough that flushing per-sector needlessly stalls the whole
   kernel repeatedly for one multi-sector operation. */
bool ata_flush_cache(void)
{
    if (!disk_present)
        return false;
    if (!wait_not_busy())
        return false;
    outb(ATA_REG_COMMAND, ATA_CMD_FLUSH_CACHE);
    return wait_not_busy();
}
