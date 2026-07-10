#ifndef KERNEL_H
#define KERNEL_H

#include "../include/types.h"
#include "../include/alpha_api.h"
#include "multiboot.h"

#define PAGE_SIZE 4096
#define PAGE_ALIGN_UP(x)   (((x) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_DOWN(x) ((x) & ~(PAGE_SIZE - 1))

/* ---- port I/O ------------------------------------------------------ */
static inline void outb(u16 port, u8 val)
{
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline u8 inb(u16 port)
{
    u8 v;
    __asm__ volatile("inb %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void io_wait(void) { outb(0x80, 0); }
static inline void sti(void) { __asm__ volatile("sti"); }
static inline void cli(void) { __asm__ volatile("cli"); }
static inline void hlt(void) { __asm__ volatile("hlt"); }

/* ---- string.c ------------------------------------------------------ */
void *memset(void *dst, int c, usize n);
void *memcpy(void *dst, const void *src, usize n);
void *memmove(void *dst, const void *src, usize n);
int   memcmp(const void *a, const void *b, usize n);
usize strlen(const char *s);
int   strcmp(const char *a, const char *b);
int   strncmp(const char *a, const char *b, usize n);
char *strncpy(char *dst, const char *src, usize n);

/* ---- console.c ----------------------------------------------------- */
void console_init(void);
void console_clear(void);
void console_set_color(u8 fg, u8 bg);
void kputc(char c);
void kprint(const char *s);
void kprintf(const char *fmt, ...);
void panic(const char *msg) __attribute__((noreturn));

/* ---- serial.c ------------------------------------------------------ */
void serial_init(void);
void serial_putc(char c);
int  serial_getc(void); /* -1 if no byte pending */

/* ---- gdt.c / idt.c ------------------------------------------------- */
void gdt_init(void);
void idt_init(void);

typedef struct regs {
    u32 ds;
    u32 edi, esi, ebp, esp_dummy, ebx, edx, ecx, eax;
    u32 int_no, err_code;
    u32 eip, cs, eflags;
} regs_t;

typedef void (*irq_handler_t)(regs_t *);
void irq_register(u8 irq, irq_handler_t handler);

/* ---- pic.c --------------------------------------------------------- */
void pic_init(void);
void pic_eoi(u8 irq);

/* ---- pit.c --------------------------------------------------------- */
void pit_init(u32 hz);
u32  pit_ticks(void);
u32  uptime_ms(void);
void sleep_ms(u32 ms);

/* ---- keyboard.c ---------------------------------------------------- */
void keyboard_init(void);
int  input_getch(void);                 /* blocking; merges kbd + serial */
int  input_readline(char *buf, u32 max);

/* ---- pmm.c --------------------------------------------------------- */
void pmm_init(multiboot_info_t *mbi, u32 kernel_end);
void pmm_reserve(u32 start, u32 end);
u32  pmm_alloc_frame(void);             /* returns phys addr or 0 */
u32  pmm_alloc_contig(u32 nframes);
void pmm_free_frame(u32 addr);
u32  pmm_total_kib(void);
u32  pmm_free_kib(void);
u32  pmm_managed_end(void);

/* ---- paging.c ------------------------------------------------------ */
void paging_init(void);
int  paging_map(u32 virt, u32 phys, int writable);
void paging_unmap(u32 virt);
void tlb_flush(void);

/* ---- kheap.c ------------------------------------------------------- */
void  kheap_init(void);
void *kmalloc(u32 size);
void  kfree(void *ptr);
void  kheap_stats(u32 *used, u32 *free_bytes);

/* ---- ramdisk.c ----------------------------------------------------- */
typedef struct rd_file {
    const char *name;
    const u8   *data;
    u32         size;
} rd_file_t;

void       ramdisk_init(multiboot_info_t *mbi);
u32        ramdisk_count(void);
rd_file_t *ramdisk_get(u32 index);
rd_file_t *ramdisk_find(const char *name);

/* ---- process / PE loader ------------------------------------------- */
typedef u32 jmp_buf_t[6];
int  k_setjmp(jmp_buf_t buf);
void k_longjmp(jmp_buf_t buf, int val) __attribute__((noreturn));

typedef struct process {
    const char *name;
    bool        running;
    jmp_buf_t   exit_jmp;
    int         exit_code;
    struct alloc_node *allocs;   /* tracked heap allocations */
    u32         image_base;
    u32         image_pages;
    u32         heap_bytes;      /* live tracked bytes */
} process_t;

extern process_t *current_process;

int  pe_run(const rd_file_t *file);      /* returns app exit code */
void pe_info(const rd_file_t *file);     /* print PE headers */

/* ---- api.c --------------------------------------------------------- */
const alpha_api_t *api_table(void);
void  proc_release_all(process_t *p);

/* ---- shell.c ------------------------------------------------------- */
void shell_run(void) __attribute__((noreturn));

#endif
