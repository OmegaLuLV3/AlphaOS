/*
 * kernel/fat.c -- a minimal FAT16 read+write filesystem driver on top
 * of kernel/ata.c. Short (8.3) filenames only, no subdirectories (the
 * root directory is the only directory), no long-filename entries
 * (present on disk from other tools, but skipped over, never parsed
 * as data). This is deliberately the smallest real, standards-
 * conforming subset of FAT16 that a writable disk actually needs --
 * enough to store an update download or arbitrary files, not a
 * general-purpose DOS-compatible implementation.
 *
 * The on-disk layout is exactly the FAT16 BIOS Parameter Block (BPB)
 * every reference describes: a boot sector with the BPB, two copies
 * of the File Allocation Table, a fixed-size root directory, then the
 * data area addressed by 2-based cluster numbers. build/disk.img is
 * formatted by mtools' `mformat` at build time (a real, independent
 * FAT implementation) rather than by this code, so this file only
 * ever needs to read an already-valid filesystem and write back
 * updates that keep it valid -- not implement `mkfs` correctness too.
 */
#include "kernel.h"

#define FAT_SECTOR_SIZE 512
#define FAT_ATTR_READ_ONLY 0x01
#define FAT_ATTR_HIDDEN    0x02
#define FAT_ATTR_SYSTEM    0x04
#define FAT_ATTR_VOLUME_ID 0x08
#define FAT_ATTR_DIRECTORY 0x10
#define FAT_ATTR_LFN       0x0F /* combination of the four bits above --
                                    long-filename entries are skipped,
                                    never parsed as a real 8.3 entry */

typedef struct __attribute__((packed)) {
    u8  name[11];
    u8  attr;
    u8  reserved;
    u8  create_time_tenth;
    u16 create_time;
    u16 create_date;
    u16 last_access_date;
    u16 first_cluster_high;
    u16 write_time;
    u16 write_date;
    u16 first_cluster_low;
    u32 file_size;
} fat_dirent_t;

typedef struct {
    bool mounted;
    u16 bytes_per_sector;
    u8  sectors_per_cluster;
    u16 reserved_sectors;
    u8  num_fats;
    u16 root_entry_count;
    u16 sectors_per_fat;
    u32 fat_start;       /* first sector of FAT #1 */
    u32 root_dir_start;  /* first sector of the (fixed-size) root dir */
    u32 root_dir_sectors;
    u32 data_start;      /* sector holding cluster 2 */
    u32 total_clusters;
} fat_fs_t;

static fat_fs_t fs;

/* ---- low-level sector I/O -------------------------------------------- */

static bool fat_read_sector(u32 lba, u8 out[FAT_SECTOR_SIZE])
{
    return ata_read_sector(lba, out);
}

static bool fat_write_sector(u32 lba, const u8 in[FAT_SECTOR_SIZE])
{
    return ata_write_sector(lba, in);
}

/* ---- mount ------------------------------------------------------------ */

bool fat_mount(void)
{
    fs.mounted = false;
    if (!ata_ready())
        return false;

    u8 boot[FAT_SECTOR_SIZE];
    if (!fat_read_sector(0, boot))
        return false;

    if (boot[510] != 0x55 || boot[511] != 0xAA)
        return false; /* not a valid boot sector */

    fs.bytes_per_sector = (u16)(boot[0x0B] | (boot[0x0C] << 8));
    fs.sectors_per_cluster = boot[0x0D];
    fs.reserved_sectors = (u16)(boot[0x0E] | (boot[0x0F] << 8));
    fs.num_fats = boot[0x10];
    fs.root_entry_count = (u16)(boot[0x11] | (boot[0x12] << 8));
    fs.sectors_per_fat = (u16)(boot[0x16] | (boot[0x17] << 8));

    /* only exactly what build/disk.img is formatted as is supported --
       refuse anything else rather than guess at FAT12/FAT32 layouts
       this code was never written or verified against */
    if (fs.bytes_per_sector != FAT_SECTOR_SIZE)
        return false;
    if (fs.sectors_per_cluster == 0 || fs.num_fats == 0 ||
        fs.reserved_sectors == 0 || fs.sectors_per_fat == 0 ||
        fs.root_entry_count == 0)
        return false;
    if (memcmp(boot + 0x36, "FAT16", 5) != 0)
        return false;

    fs.fat_start = fs.reserved_sectors;
    fs.root_dir_start = fs.fat_start + (u32)fs.num_fats * fs.sectors_per_fat;
    fs.root_dir_sectors = ((u32)fs.root_entry_count * 32 + FAT_SECTOR_SIZE - 1) /
                          FAT_SECTOR_SIZE;
    fs.data_start = fs.root_dir_start + fs.root_dir_sectors;
    fs.total_clusters = (ata_sector_count() - fs.data_start) / fs.sectors_per_cluster;

    fs.mounted = true;
    return true;
}

bool fat_ready(void) { return fs.mounted; }

/* ---- FAT table access --------------------------------------------------
 *
 * Both on-disk FAT copies are kept in sync on every write -- some
 * tools trust FAT #1 exclusively, but a correct implementation
 * doesn't let the second copy silently go stale. */

static u32 cluster_fat_sector(u32 cluster, u32 *byte_off)
{
    u32 fat_byte = cluster * 2;
    *byte_off = fat_byte % FAT_SECTOR_SIZE;
    return fs.fat_start + fat_byte / FAT_SECTOR_SIZE;
}

static bool fat_get_entry(u32 cluster, u16 *value_out)
{
    u32 off;
    u32 sec = cluster_fat_sector(cluster, &off);
    u8 buf[FAT_SECTOR_SIZE];
    if (!fat_read_sector(sec, buf))
        return false;
    *value_out = (u16)(buf[off] | (buf[off + 1] << 8));
    return true;
}

static bool fat_set_entry(u32 cluster, u16 value)
{
    for (u8 copy = 0; copy < fs.num_fats; copy++) {
        u32 off;
        u32 sec = fs.fat_start + (cluster * 2) / FAT_SECTOR_SIZE +
                  (u32)copy * fs.sectors_per_fat;
        off = (cluster * 2) % FAT_SECTOR_SIZE;
        u8 buf[FAT_SECTOR_SIZE];
        if (!fat_read_sector(sec, buf))
            return false;
        buf[off] = (u8)value;
        buf[off + 1] = (u8)(value >> 8);
        if (!fat_write_sector(sec, buf))
            return false;
    }
    return true;
}

static bool fat_is_eoc(u16 v) { return v >= 0xFFF8; }

static u32 cluster_to_lba(u32 cluster)
{
    return fs.data_start + (cluster - 2) * fs.sectors_per_cluster;
}

/* Finds and allocates one free cluster (marking it EOC), or returns 0
   on failure (disk full). Cluster numbers start at 2; 0 and 1 are
   reserved and never allocated. */
static u32 fat_alloc_cluster(void)
{
    for (u32 c = 2; c < fs.total_clusters + 2; c++) {
        u16 v;
        if (!fat_get_entry(c, &v))
            return 0;
        if (v == 0x0000) {
            if (!fat_set_entry(c, 0xFFFF))
                return 0;
            return c;
        }
    }
    return 0;
}

static bool fat_free_chain(u32 start_cluster)
{
    u32 c = start_cluster;
    while (c >= 2 && !fat_is_eoc((u16)c)) {
        u16 next;
        if (!fat_get_entry(c, &next))
            return false;
        if (!fat_set_entry(c, 0x0000))
            return false;
        c = next;
    }
    return true;
}

/* ---- 8.3 name handling -------------------------------------------------
 *
 * "HELLO.TXT" -> "HELLO      TXT" (11 bytes, space-padded, no dot),
 * uppercased. No support for names longer than 8+3 characters -- they
 * are rejected outright rather than silently truncated. */
static bool fat_format_name(const char *in, u8 out[11])
{
    memset(out, ' ', 11);
    u32 i = 0, out_i = 0;
    while (in[i] && in[i] != '.') {
        if (out_i >= 8)
            return false;
        u8 c = (u8)in[i];
        if (c >= 'a' && c <= 'z')
            c = (u8)(c - 'a' + 'A');
        out[out_i++] = c;
        i++;
    }
    if (out_i == 0)
        return false;
    if (in[i] == '.') {
        i++;
        u32 ext_i = 0;
        while (in[i]) {
            if (ext_i >= 3)
                return false;
            u8 c = (u8)in[i];
            if (c >= 'a' && c <= 'z')
                c = (u8)(c - 'a' + 'A');
            out[8 + ext_i++] = c;
            i++;
        }
    }
    return true;
}

/* ---- directory entry access -------------------------------------------- */

typedef struct {
    u32 dirent_lba;
    u32 dirent_offset; /* byte offset within that sector */
    fat_dirent_t entry;
} fat_lookup_t;

static bool fat_find(const char *name, fat_lookup_t *out)
{
    u8 want[11];
    if (!fat_format_name(name, want))
        return false;

    for (u32 s = 0; s < fs.root_dir_sectors; s++) {
        u8 buf[FAT_SECTOR_SIZE];
        if (!fat_read_sector(fs.root_dir_start + s, buf))
            return false;
        for (u32 off = 0; off < FAT_SECTOR_SIZE; off += 32) {
            fat_dirent_t *d = (fat_dirent_t *)(buf + off);
            if (d->name[0] == 0x00)
                return false; /* end of directory */
            if (d->name[0] == 0xE5)
                continue; /* deleted */
            if (d->attr == FAT_ATTR_LFN || (d->attr & FAT_ATTR_VOLUME_ID))
                continue;
            if (memcmp(d->name, want, 11) == 0) {
                out->dirent_lba = fs.root_dir_start + s;
                out->dirent_offset = off;
                out->entry = *d;
                return true;
            }
        }
    }
    return false;
}

/* ---- public read/write/delete/list API --------------------------------- */

bool fat_stat(const char *name, u32 *size_out, bool *is_dir_out)
{
    fat_lookup_t look;
    if (!fat_find(name, &look))
        return false;
    if (size_out)
        *size_out = look.entry.file_size;
    if (is_dir_out)
        *is_dir_out = (look.entry.attr & FAT_ATTR_DIRECTORY) != 0;
    return true;
}

u32 fat_read_file(const char *name, u8 *buf, u32 max_len)
{
    fat_lookup_t look;
    if (!fat_find(name, &look))
        return 0;
    if (look.entry.attr & FAT_ATTR_DIRECTORY)
        return 0;

    u32 remaining = look.entry.file_size < max_len ? look.entry.file_size : max_len;
    u32 total = 0;
    u32 cluster = look.entry.first_cluster_low;
    u8 sector_buf[FAT_SECTOR_SIZE];

    while (remaining > 0 && cluster >= 2 && !fat_is_eoc((u16)cluster)) {
        for (u8 s = 0; s < fs.sectors_per_cluster && remaining > 0; s++) {
            if (!fat_read_sector(cluster_to_lba(cluster) + s, sector_buf))
                return total;
            u32 n = remaining < FAT_SECTOR_SIZE ? remaining : FAT_SECTOR_SIZE;
            memcpy(buf + total, sector_buf, n);
            total += n;
            remaining -= n;
        }
        u16 next;
        if (!fat_get_entry(cluster, &next))
            return total;
        cluster = next;
    }
    return total;
}

static bool fat_write_dirent(u32 lba, u32 off, const fat_dirent_t *d)
{
    u8 buf[FAT_SECTOR_SIZE];
    if (!fat_read_sector(lba, buf))
        return false;
    memcpy(buf + off, d, sizeof(*d));
    return fat_write_sector(lba, buf);
}

static bool fat_find_free_dirent(u32 *lba_out, u32 *off_out)
{
    for (u32 s = 0; s < fs.root_dir_sectors; s++) {
        u8 buf[FAT_SECTOR_SIZE];
        if (!fat_read_sector(fs.root_dir_start + s, buf))
            return false;
        for (u32 off = 0; off < FAT_SECTOR_SIZE; off += 32) {
            u8 first = buf[off];
            if (first == 0x00 || first == 0xE5) {
                *lba_out = fs.root_dir_start + s;
                *off_out = off;
                return true;
            }
        }
    }
    return false;
}

bool fat_write_file(const char *name, const u8 *data, u32 len)
{
    u8 name_check[11];
    if (!fat_format_name(name, name_check))
        return false; /* validate the name up front, before touching
                          any cluster allocation */

    fat_lookup_t look;
    u32 dirent_lba, dirent_off;
    if (fat_find(name, &look)) {
        if (look.entry.attr & FAT_ATTR_DIRECTORY)
            return false;
        if (look.entry.first_cluster_low >= 2)
            if (!fat_free_chain(look.entry.first_cluster_low))
                return false;
        dirent_lba = look.dirent_lba;
        dirent_off = look.dirent_offset;
    } else {
        if (!fat_find_free_dirent(&dirent_lba, &dirent_off))
            return false;
    }

    u32 first_cluster = 0;
    u32 prev_cluster = 0;
    u32 written = 0;
    u8 sector_buf[FAT_SECTOR_SIZE];

    while (written < len) {
        u32 c = fat_alloc_cluster();
        if (c == 0) {
            if (first_cluster)
                fat_free_chain(first_cluster);
            return false; /* disk full */
        }
        if (first_cluster == 0)
            first_cluster = c;
        if (prev_cluster != 0)
            if (!fat_set_entry(prev_cluster, (u16)c))
                return false;
        prev_cluster = c;

        for (u8 s = 0; s < fs.sectors_per_cluster && written < len; s++) {
            u32 n = len - written < FAT_SECTOR_SIZE ? len - written : FAT_SECTOR_SIZE;
            memset(sector_buf, 0, FAT_SECTOR_SIZE);
            memcpy(sector_buf, data + written, n);
            if (!fat_write_sector(cluster_to_lba(c) + s, sector_buf))
                return false;
            written += n;
        }
    }
    if (prev_cluster != 0)
        fat_set_entry(prev_cluster, 0xFFFF); /* redundant (alloc already
            marks it EOC) but explicit at the chain's true final link */

    fat_dirent_t d;
    memset(&d, 0, sizeof(d));
    fat_format_name(name, d.name);
    d.attr = 0x20; /* ARCHIVE bit -- conventional for a freshly-written
                       file, not actually read-only */
    d.first_cluster_low = (u16)first_cluster;
    d.file_size = len;
    if (!fat_write_dirent(dirent_lba, dirent_off, &d))
        return false;

    /* one flush for the whole operation (data clusters + both FAT
       copies + the directory entry), not one per sector -- see
       ata_flush_cache()'s comment in kernel/ata.c */
    return ata_flush_cache();
}

bool fat_delete_file(const char *name)
{
    fat_lookup_t look;
    if (!fat_find(name, &look))
        return false;
    if (look.entry.attr & FAT_ATTR_DIRECTORY)
        return false;
    if (look.entry.first_cluster_low >= 2)
        if (!fat_free_chain(look.entry.first_cluster_low))
            return false;

    u8 buf[FAT_SECTOR_SIZE];
    if (!fat_read_sector(look.dirent_lba, buf))
        return false;
    buf[look.dirent_offset] = 0xE5;
    if (!fat_write_sector(look.dirent_lba, buf))
        return false;

    /* one flush for the whole operation (freed FAT chain entries +
       the directory entry), not one per sector */
    return ata_flush_cache();
}

u32 fat_list(fat_list_entry_t *out, u32 max_entries)
{
    u32 n = 0;
    for (u32 s = 0; s < fs.root_dir_sectors && n < max_entries; s++) {
        u8 buf[FAT_SECTOR_SIZE];
        if (!fat_read_sector(fs.root_dir_start + s, buf))
            return n;
        for (u32 off = 0; off < FAT_SECTOR_SIZE && n < max_entries; off += 32) {
            fat_dirent_t *d = (fat_dirent_t *)(buf + off);
            if (d->name[0] == 0x00)
                return n;
            if (d->name[0] == 0xE5)
                continue;
            if (d->attr == FAT_ATTR_LFN || (d->attr & FAT_ATTR_VOLUME_ID))
                continue;
            memcpy(out[n].name, d->name, 11);
            out[n].size = d->file_size;
            out[n].is_dir = (d->attr & FAT_ATTR_DIRECTORY) != 0;
            n++;
        }
    }
    return n;
}
