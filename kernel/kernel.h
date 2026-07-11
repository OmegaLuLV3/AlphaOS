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
static inline void outw(u16 port, u16 val)
{
    __asm__ volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}
static inline u16 inw(u16 port)
{
    u16 v;
    __asm__ volatile("inw %1, %0" : "=a"(v) : "Nd"(port));
    return v;
}
static inline void outl(u16 port, u32 val)
{
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}
static inline u32 inl(u16 port)
{
    u32 v;
    __asm__ volatile("inl %1, %0" : "=a"(v) : "Nd"(port));
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
char *strchr(const char *s, int c);

/* ---- console.c ----------------------------------------------------- */
void console_init(void);
void console_clear(void);
void console_set_color(u8 fg, u8 bg);
void kputc(char c);
void kprint(const char *s);
void kprintf(const char *fmt, ...);
void panic(const char *msg) __attribute__((noreturn));
void console_capture_start(char *buf, u32 max); /* mirror kputc into buf */
void console_capture_stop(void);

/* ---- serial.c ------------------------------------------------------ */
void serial_init(void);
void serial_putc(char c);
int  serial_getc(void); /* -1 if no byte pending */

/* ---- ai.c: host-bridged AI assistant channel (COM2) ------------------ */
void ai_init(void);
void ai_ask(const char *question); /* blocking; prints the reply */

/* ---- gdt.c / idt.c ------------------------------------------------- */
void gdt_init(void);
void idt_init(void);

typedef struct regs {
    u64 r15, r14, r13, r12, r11, r10, r9, r8;
    u64 rbp, rdi, rsi, rdx, rcx, rbx, rax;
    u64 int_no, err_code;
    u64 rip, cs, rflags, rsp, ss;
} regs_t;

typedef void (*irq_handler_t)(regs_t *);
void irq_register(u8 irq, irq_handler_t handler);

/* ---- pic.c --------------------------------------------------------- */
void pic_init(void);
void pic_eoi(u8 irq);
void pic_unmask(u8 irq);

/* ---- pit.c --------------------------------------------------------- */
void pit_init(u32 hz);
u32  pit_ticks(void);
u32  uptime_ms(void);
void sleep_ms(u32 ms);

/* ---- keyboard.c ---------------------------------------------------- */
void keyboard_init(void);
int  kbd_pop(void);                     /* -1 if ring buffer empty */
int  input_getch(void);                 /* blocking; merges kbd + serial */
int  input_readline(char *buf, u32 max);

/* ---- mouse.c -------------------------------------------------------- */
void mouse_init(void);
int  mouse_pop(int *dx, int *dy, u8 *buttons); /* 0 = nothing pending */

/* ---- pci.c ----------------------------------------------------------*/
typedef struct pci_dev {
    u8  bus, slot, func;
    u16 vendor, device;
    u8  class_code, subclass;
    u32 bar0;
    u8  irq_line;
    const char *name;
} pci_dev_t;

void       pci_scan(void);
void       pci_enable_device(pci_dev_t *d); /* I/O space + bus mastering */
u32        pci_count(void);
pci_dev_t *pci_get(u32 i);
pci_dev_t *pci_find(u16 vendor, u16 device);

/* ---- net.c: RTL8139 driver + Ethernet/ARP/IPv4/ICMP ------------------ */
void       net_init(void);
bool       net_ready(void);
bool       net_arp_resolve(const u8 ip[4], u8 mac_out[6]);
bool       net_ping(const u8 ip[4], u32 *rtt_ms_out);
bool       net_dns_resolve(const char *hostname, u8 ip_out[4]);
const u8  *net_gateway_ip(void);
const u8  *net_our_ip(void);

/* ---- rtc.c ----------------------------------------------------------*/
typedef struct rtc_time {
    u16 year;
    u8 month, day, hour, min, sec;
} rtc_time_t;

void rtc_read(rtc_time_t *t);

/* ---- font.c ---------------------------------------------------------*/
extern u8 vga_font[256 * 16];           /* 8x16 glyphs */
void font_init(void);

/* ---- bga.c (Bochs/QEMU display adapter) ------------------------------*/
int  bga_init(int w, int h);            /* 0 on success */
u32 *bga_framebuffer(void);
int  bga_width(void);
int  bga_height(void);

/* ---- gfx.c -----------------------------------------------------------*/
typedef struct surface {
    u32 *px;
    int w, h;
} surface_t;

#define RGB(r, g, b) (0xFF000000u | ((r) << 16) | ((g) << 8) | (b))

void gfx_fill(surface_t *s, int x, int y, int w, int h, u32 c);
void gfx_rect(surface_t *s, int x, int y, int w, int h, u32 c);
void gfx_gradient_v(surface_t *s, int x, int y, int w, int h, u32 top, u32 bot);
void gfx_blend(surface_t *s, int x, int y, int w, int h, u32 c, u8 alpha);
void gfx_char(surface_t *s, int x, int y, char ch, u32 fg);
void gfx_text(surface_t *s, int x, int y, const char *str, u32 fg);
void gfx_circle(surface_t *s, int cx, int cy, int r, u32 c);
void gfx_blit(surface_t *dst, int dx, int dy, const surface_t *src);

/* ---- pmm.c --------------------------------------------------------- */
void pmm_init(multiboot_info_t *mbi, uptr kernel_end);
void pmm_reserve(uptr start, uptr end);
uptr pmm_alloc_frame(void);             /* returns phys addr or 0 */
uptr pmm_alloc_contig(u32 nframes);
void pmm_free_frame(uptr addr);
u32  pmm_total_kib(void);
u32  pmm_free_kib(void);
uptr pmm_managed_end(void);

/* ---- paging.c ------------------------------------------------------ */
void paging_init(void);
int  paging_map(uptr virt, uptr phys, int writable, int executable);
void paging_unmap(uptr virt);
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
typedef u64 jmp_buf_t[8];
int  k_setjmp(jmp_buf_t buf);
void k_longjmp(jmp_buf_t buf, int val) __attribute__((noreturn));

typedef struct process {
    const char *name;
    bool        running;
    jmp_buf_t   exit_jmp;
    int         exit_code;
    struct alloc_node *allocs;   /* tracked heap allocations */
    uptr        image_base;
    u32         image_pages;
    u32         heap_bytes;      /* live tracked bytes */
    char        cmdline[128];    /* for GetCommandLineA */
    u32         last_error;      /* for Get/SetLastError */
} process_t;

extern process_t *current_process;

/* cmdline may be NULL (defaults to the file name) */
int  pe_run(const rd_file_t *file, const char *cmdline);
void pe_info(const rd_file_t *file);     /* print PE headers */

/* ---- win32.c: Win32-compatible export tables ------------------------- */
void  win32_init(void);
void *win_resolve(const char *dll, const char *func);
void  win32_reset_process_state(void); /* call before each win-style entry */

/* ---- window manager (wm.c) ------------------------------------------ */
#define WM_EVQ_SIZE 32

typedef struct window {
    int  x, y;              /* frame top-left on screen   */
    int  w, h;              /* canvas (content) size      */
    char title[40];
    u32 *canvas;            /* w*h ARGB32                 */
    bool closable;
    process_t *owner;       /* NULL = kernel (terminal)   */
    struct window *next;    /* z-order list, tail is topmost */
    alpha_event_t evq[WM_EVQ_SIZE];
    u32 ev_head, ev_tail;
} window_t;

void      gui_init(void);
bool      gui_active(void);
void      gui_pump(void);               /* mouse/kbd/clock + recomposite */
void      gui_inject_line(const char *cmd); /* type a command into the shell */
int       gui_term_getch(void);         /* -1 if terminal queue empty */
window_t *wm_create(const char *title, int w, int h,
                    process_t *owner, bool closable);
void      wm_destroy(window_t *win);
void      wm_present(window_t *win);
int       wm_poll_event(window_t *win, alpha_event_t *ev);
void      wm_destroy_owned(process_t *p);
void      wm_mark_dirty(void);          /* throttled recomposite */

/* ---- terminal.c (shell window in GUI mode) --------------------------- */
void terminal_create(void);
void terminal_putc(char c);
void terminal_clear(void);
void terminal_set_color(u8 fg, u8 bg);

/* console GUI routing */
void console_use_gui(void);

/* ---- api.c --------------------------------------------------------- */
const alpha_api_t *api_table(void);
void *proc_alloc(u32 size);             /* tracked per-process alloc */
int   proc_free(void *ptr);             /* 1 if ptr was tracked */
void  proc_release_all(process_t *p);

/* ---- shell.c ------------------------------------------------------- */
void shell_run(void) __attribute__((noreturn));

#endif
