/*
 * Win32-compatible API subset, exported to .exe files the native
 * Windows way: programs import these by name from KERNEL32.DLL /
 * USER32.DLL through their PE import table, and the loader patches
 * their IAT to point directly at these functions.
 *
 * All functions use the Microsoft x64 calling convention (ms_abi:
 * first four integer/pointer args in RCX, RDX, R8, R9; caller reserves
 * 32 bytes of shadow space; callee doesn't clean the stack) — exactly
 * what real 64-bit Windows uses, and what GCC's `ms_abi` attribute
 * generates. A PE32+ binary built by a real Windows toolchain against
 * this subset (no CRT) runs unmodified, because the IAT trampoline is
 * just a `jmp` — it doesn't touch registers, so caller and callee only
 * need to agree on the convention, which they do here.
 */
#include "kernel.h"

#define WINAPI __attribute__((ms_abi))

/* ---- KERNEL32 -------------------------------------------------------- */

#define STD_INPUT_HANDLE  ((u32)-10)
#define STD_OUTPUT_HANDLE ((u32)-11)
#define STD_ERROR_HANDLE  ((u32)-12)

static void WINAPI w_ExitProcess(u32 code)
{
    if (current_process && current_process->running) {
        current_process->exit_code = (int)code;
        k_longjmp(current_process->exit_jmp, 1);
    }
    panic("ExitProcess with no process running");
}

static void *WINAPI w_GetStdHandle(u32 which)
{
    switch (which) {
    case STD_INPUT_HANDLE:  return (void *)0x10;
    case STD_OUTPUT_HANDLE: return (void *)0x11;
    case STD_ERROR_HANDLE:  return (void *)0x12;
    }
    return (void *)(uptr)-1;
}

static int WINAPI w_WriteConsoleA(void *handle, const void *buf, u32 len,
                                  u32 *written, void *reserved)
{
    (void)handle;
    (void)reserved;
    const char *s = buf;
    for (u32 i = 0; i < len; i++)
        if (s[i] != '\r') /* console treats \n as newline already */
            kputc(s[i]);
    if (written)
        *written = len;
    return 1;
}

static int WINAPI w_WriteFile(void *handle, const void *buf, u32 len,
                              u32 *written, void *overlapped)
{
    return w_WriteConsoleA(handle, buf, len, written, overlapped);
}

static int WINAPI w_ReadConsoleA(void *handle, void *buf, u32 max,
                                 u32 *read, void *reserved)
{
    (void)handle;
    (void)reserved;
    if (max < 3)
        return 0;
    int n = input_readline(buf, max - 2);
    char *s = buf;
    s[n] = '\r';
    s[n + 1] = '\n';
    if (read)
        *read = n + 2;
    return 1;
}

static void WINAPI w_Sleep(u32 ms)
{
    sleep_ms(ms);
}

static u32 WINAPI w_GetTickCount(void)
{
    return uptime_ms();
}

/*
 * Windows SIZE_T is 64-bit; our allocator (kheap.c) takes a u32 size,
 * which is plenty — the whole kernel heap is 16 MiB — but silently
 * truncating a caller-supplied 64-bit size to u32 instead of rejecting
 * an oversized request is the classic allocation-size-truncation bug:
 * the caller believes it holds a large buffer, actually holds a tiny
 * truncated one, and the first write at the size it *asked for*
 * overflows into adjacent kernel heap memory (other processes'
 * tracked allocations, block headers, ...). Every allocator entry
 * point below routes through this instead of casting directly.
 */
static void *checked_alloc(u64 size)
{
    if (size > 0xFFFFFFFFu)
        return NULL;
    return proc_alloc((u32)size);
}

static void *WINAPI w_VirtualAlloc(void *addr, u64 size, u32 type, u32 prot)
{
    (void)addr;
    (void)type;
    (void)prot;
    void *p = checked_alloc(size);
    if (p)
        memset(p, 0, (u32)size); /* VirtualAlloc returns zeroed pages */
    return p;
}

static int WINAPI w_VirtualFree(void *addr, u64 size, u32 type)
{
    (void)size;
    (void)type;
    return proc_free(addr);
}

static void *WINAPI w_GetProcessHeap(void)
{
    return (void *)0xA1FA;
}

static void *WINAPI w_HeapAlloc(void *heap, u32 flags, u64 size)
{
    (void)heap;
    void *p = checked_alloc(size);
    if (p && (flags & 0x08)) /* HEAP_ZERO_MEMORY */
        memset(p, 0, (u32)size);
    return p;
}

static int WINAPI w_HeapFree(void *heap, u32 flags, void *ptr)
{
    (void)heap;
    (void)flags;
    return proc_free(ptr);
}

static char *WINAPI w_GetCommandLineA(void)
{
    static char empty[1];
    return current_process ? current_process->cmdline : empty;
}

static u32 WINAPI w_GetLastError(void)
{
    return current_process ? current_process->last_error : 0;
}

static void WINAPI w_SetLastError(u32 err)
{
    if (current_process)
        current_process->last_error = err;
}

static int WINAPI w_lstrlenA(const char *s)
{
    return s ? (int)strlen(s) : 0;
}

/*
 * CriticalSection / TLS / VirtualProtect / VirtualQuery / exception
 * filter — the rest of what a default-toolchain CRT startup needs.
 *
 * AlphaOS never runs more than one process at a time (pe_run() is
 * synchronous: the shell blocks until the app returns), so there is no
 * real concurrency here to protect against. CriticalSection functions
 * are therefore correct as no-ops, not just convenient stubs — there
 * is no other thread that could interleave. TLS is a small fixed
 * per-process slot table (reset for every new process by
 * win32_reset_process_state(), called from pe.c before the entry
 * point runs). VirtualProtect is a benign no-op: every app page is
 * already mapped read+write (see pe.c), so we have nothing weaker to
 * grant and nothing to enforce — this is a real gap (no W^X for app
 * code), documented in the security notes, not a hidden one.
 */
#define MAX_TLS 64
static void *tls_slots[MAX_TLS];
static bool  tls_used[MAX_TLS];

static void WINAPI w_InitializeCriticalSection(void *cs) { (void)cs; }
static void WINAPI w_EnterCriticalSection(void *cs)      { (void)cs; }
static void WINAPI w_LeaveCriticalSection(void *cs)      { (void)cs; }
static void WINAPI w_DeleteCriticalSection(void *cs)     { (void)cs; }

static u32 WINAPI w_TlsAlloc(void)
{
    for (u32 i = 0; i < MAX_TLS; i++) {
        if (!tls_used[i]) {
            tls_used[i] = true;
            tls_slots[i] = NULL;
            return i;
        }
    }
    return (u32)-1; /* TLS_OUT_OF_INDEXES */
}

static int WINAPI w_TlsFree(u32 idx)
{
    if (idx >= MAX_TLS || !tls_used[idx])
        return 0;
    tls_used[idx] = false;
    return 1;
}

static void *WINAPI w_TlsGetValue(u32 idx)
{
    return idx < MAX_TLS ? tls_slots[idx] : NULL;
}

static int WINAPI w_TlsSetValue(u32 idx, void *val)
{
    if (idx >= MAX_TLS)
        return 0;
    tls_slots[idx] = val;
    return 1;
}

static int WINAPI w_VirtualProtect(void *addr, u64 size, u32 new_prot,
                                   u32 *old_prot)
{
    (void)addr;
    (void)size;
    (void)new_prot;
    if (old_prot)
        *old_prot = 0x04; /* PAGE_READWRITE: honestly report what we grant */
    return 1;
}

/* MEMORY_BASIC_INFORMATION, matching the real Win64 layout closely
   enough for callers that just sanity-check State/Protect */
typedef struct {
    void *base_address;
    void *allocation_base;
    u32   allocation_protect;
    u32   partition_id;
    u64   region_size;
    u32   state;
    u32   protect;
    u32   type;
} mem_basic_info_t;

static u64 WINAPI w_VirtualQuery(const void *addr, mem_basic_info_t *info,
                                 u64 len)
{
    if (!info || len < sizeof(*info))
        return 0;
    info->base_address = (void *)addr;
    info->allocation_base = (void *)addr;
    info->allocation_protect = 0x04;   /* PAGE_READWRITE */
    info->partition_id = 0;
    info->region_size = PAGE_SIZE;
    info->state = 0x1000;              /* MEM_COMMIT */
    info->protect = 0x04;              /* PAGE_READWRITE */
    info->type = 0x20000;              /* MEM_PRIVATE */
    return sizeof(*info);
}

static void *WINAPI w_SetUnhandledExceptionFilter(void *filter)
{
    (void)filter; /* accepted and ignored: we have no SEH to dispatch to it */
    return NULL;  /* previous filter was "none" */
}

static void *WINAPI w_GetModuleHandleA(const char *name)
{
    (void)name; /* one "module" (the running image) — any name matches it */
    return current_process ? (void *)current_process->image_base : NULL;
}

/* ---- USER32 ---------------------------------------------------------- */

#define MB_MAX_LINES 8

static int WINAPI w_MessageBoxA(void *hwnd, const char *text,
                                const char *caption, u32 type)
{
    (void)hwnd;
    (void)type;
    if (!text)
        text = "";
    if (!caption)
        caption = "Message";

    if (!gui_active()) {
        kprintf("[%s] %s\n", caption, text);
        return 1; /* IDOK */
    }

    /* measure: split text on \n */
    const char *lines[MB_MAX_LINES];
    int lens[MB_MAX_LINES], nlines = 0, maxlen = 10;
    const char *p = text;
    while (nlines < MB_MAX_LINES) {
        lines[nlines] = p;
        int len = 0;
        while (p[len] && p[len] != '\n')
            len++;
        lens[nlines] = len;
        if (len > maxlen)
            maxlen = len;
        nlines++;
        if (!p[len])
            break;
        p += len + 1;
    }

    int w = maxlen * 8 + 48;
    if (w < 220) w = 220;
    if (w > 640) w = 640;
    int h = nlines * 18 + 74;

    window_t *win = wm_create(caption, w, h, current_process, true);
    if (!win) {
        kprintf("[%s] %s\n", caption, text);
        return 1;
    }

    surface_t s = { win->canvas, w, h };
    gfx_fill(&s, 0, 0, w, h, RGB(0xf0, 0xf0, 0xf0));
    for (int i = 0; i < nlines; i++) {
        char line[80];
        int n = lens[i] < 79 ? lens[i] : 79;
        memcpy(line, lines[i], n);
        line[n] = 0;
        gfx_text(&s, 24, 16 + i * 18, line, RGB(0x20, 0x24, 0x28));
    }

    /* OK button */
    int bw = 88, bh = 26;
    int bx = (w - bw) / 2, by = h - bh - 14;
    gfx_gradient_v(&s, bx, by, bw, bh, RGB(0xfd, 0xfd, 0xfd),
                   RGB(0xd8, 0xdc, 0xe0));
    gfx_rect(&s, bx, by, bw, bh, RGB(0x70, 0x80, 0x90));
    gfx_text(&s, bx + bw / 2 - 8, by + (bh - 16) / 2, "OK",
             RGB(0x20, 0x24, 0x28));
    wm_present(win);

    int result = 1; /* IDOK */
    alpha_event_t ev;
    for (;;) {
        while (wm_poll_event(win, &ev)) {
            if (ev.type == ALPHA_EV_CLOSE) {
                result = 2; /* IDCANCEL */
                goto done;
            }
            if (ev.type == ALPHA_EV_MOUSE_DOWN &&
                ev.x >= bx && ev.x < bx + bw &&
                ev.y >= by && ev.y < by + bh)
                goto done;
            if (ev.type == ALPHA_EV_KEY &&
                (ev.key == '\n' || ev.key == 27))
                goto done;
        }
        sleep_ms(10);
    }
done:
    wm_destroy(win);
    return result;
}

/*
 * ---- MSVCRT ------------------------------------------------------------
 *
 * The classic msvcrt.dll surface a default MinGW-w64 build imports for
 * its CRT startup (argv/envp setup, static-initializer running,
 * atexit, and the handful of libc functions that startup code itself
 * calls: malloc family, string functions, fprintf for early error
 * reporting). Implemented well enough to run real, unmodified
 * mingw-w64 output — verified against genuine `x86_64-w64-mingw32-gcc`
 * binaries, not just our own toolchain's apps.
 *
 * malloc/calloc/free route through proc_alloc()/proc_free(), the same
 * per-process tracker every other allocation API uses, so a CRT-heavy
 * program that leaks still gets fully reclaimed on exit or crash.
 */

#define MAX_ONEXIT 32
static void (*onexit_table[MAX_ONEXIT])(void);
static u32 onexit_count;

static int fmode_storage;
static int commode_storage;
static char *empty_argv[] = { (char *)"app.exe", NULL };
static char *empty_environ[] = { NULL };
static int   argc_storage = 1;
static char **argv_storage = empty_argv;
static char **envp_storage = empty_environ;

#define IOB_SIZE  32
#define IOB_COUNT 3   /* stdin, stdout, stderr — all we ever hand out */
static u8 fake_iob[IOB_SIZE * IOB_COUNT];

/*
 * Minimal TEB/PEB for the GS-relative reads a default MinGW/MSVC CRT
 * startup performs before main() even runs. Real Windows sets %gs to
 * point at a per-thread TEB; we have no thread scheduler, but the
 * defensive "am I running under a debugger / where's my TLS array"
 * checks CRT startup does unconditionally still execute, and without
 * *some* GS base they page-fault on a near-null offset (e.g. the
 * canonical `gs:0x30` == NtCurrentTeb() idiom).
 *
 * Only the three offsets with genuinely universal, decades-stable
 * meaning are populated deliberately (TEB self-pointer, TLS array
 * pointer, PEB pointer); the rest of the TEB/PEB is oversized and
 * zeroed so nearby speculative field reads return 0 instead of
 * faulting, rather than us having to enumerate every field a given
 * compiler version might touch. This is NOT a real TEB/PEB — no
 * per-thread stack limits, no real PEB fields (heap handle, command
 * line, loaded-module list, ...). Programs that actually depend on
 * those will fail past this point, visibly (another fault, caught by
 * the same fault-isolation path as any other crash), not silently.
 */
#define TEB_SIZE 0x1000
#define PEB_SIZE 0x400
#define TLS_ARRAY_SLOTS 8
#define TLS_TEMPLATE_SIZE 256

static u8 fake_teb[TEB_SIZE] __attribute__((aligned(16)));
static u8 fake_peb[PEB_SIZE] __attribute__((aligned(16)));
static void *tls_array[TLS_ARRAY_SLOTS];
static u8 tls_template[TLS_TEMPLATE_SIZE] __attribute__((aligned(16)));

#define IA32_GS_BASE 0xC0000101u

static void wrmsr64(u32 msr, u64 value)
{
    u32 lo = (u32)value, hi = (u32)(value >> 32);
    __asm__ volatile("wrmsr" : : "c"(msr), "a"(lo), "d"(hi));
}

void win32_setup_teb(void)
{
    memset(fake_teb, 0, sizeof(fake_teb));
    memset(fake_peb, 0, sizeof(fake_peb));
    memset(tls_template, 0, sizeof(tls_template));
    for (u32 i = 0; i < TLS_ARRAY_SLOTS; i++)
        tls_array[i] = tls_template;

    *(void **)(fake_teb + 0x30) = fake_teb;   /* NtCurrentTeb() self-pointer */
    *(void **)(fake_teb + 0x58) = tls_array;  /* ThreadLocalStoragePointer   */
    *(void **)(fake_teb + 0x60) = fake_peb;   /* ProcessEnvironmentBlock     */

    wrmsr64(IA32_GS_BASE, (u64)(uptr)fake_teb);
    /* the kernel itself never reads %gs, so leaving this set after the
       app returns is harmless — the next win-style app just overwrites
       it here again before it runs */
}

void win32_reset_process_state(void)
{
    onexit_count = 0;
    memset(tls_slots, 0, sizeof(tls_slots));
    memset(tls_used, 0, sizeof(tls_used));
    fmode_storage = 0;
    commode_storage = 0;
    win32_setup_teb();
}

static int WINAPI w___getmainargs(int *argc, char ***argv, char ***envp,
                                  int expand_wildcards, void *startup_info)
{
    (void)expand_wildcards;
    (void)startup_info;
    if (argc)
        *argc = argc_storage;
    if (argv)
        *argv = argv_storage;
    if (envp)
        *envp = envp_storage;
    return 0;
}

static void *WINAPI w___iob_func(void)
{
    return fake_iob;
}

/* returns 0=stdin, 1=stdout, 2=stderr, or -1 for anything else (treated
   as stdout, matching the "just get the bytes out" priority of a
   diagnostic console OS — see the security notes for the trade-off) */
static int iob_index(void *stream)
{
    uptr off = (uptr)stream - (uptr)fake_iob;
    if (stream && off < sizeof(fake_iob) && off % IOB_SIZE == 0)
        return (int)(off / IOB_SIZE);
    return -1;
}

static void winvprintf(const char *fmt, __builtin_va_list ap)
{
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            kputc(*fmt);
            continue;
        }
        fmt++;
        bool wide = false;
        while (*fmt == 'l' || *fmt == 'z' || *fmt == 'h') {
            wide = wide || *fmt == 'l';
            fmt++;
        }
        switch (*fmt) {
        case 's': {
            const char *s = __builtin_va_arg(ap, const char *);
            kprint(s ? s : "(null)");
            break;
        }
        case 'c':
            kputc((char)__builtin_va_arg(ap, int));
            break;
        case 'd':
        case 'i': {
            s64 v = wide ? __builtin_va_arg(ap, s64)
                        : __builtin_va_arg(ap, int);
            if (v < 0) {
                kputc('-');
                v = -v;
            }
            char buf[24];
            int i = 0;
            u64 u = (u64)v;
            if (!u)
                buf[i++] = '0';
            while (u) {
                buf[i++] = '0' + (u % 10);
                u /= 10;
            }
            while (i--)
                kputc(buf[i]);
            break;
        }
        case 'u':
        case 'x': {
            u64 v = wide ? __builtin_va_arg(ap, u64)
                        : __builtin_va_arg(ap, u32);
            u32 base = (*fmt == 'x') ? 16 : 10;
            char buf[24];
            int i = 0;
            if (!v)
                buf[i++] = '0';
            while (v) {
                buf[i++] = "0123456789abcdef"[v % base];
                v /= base;
            }
            while (i--)
                kputc(buf[i]);
            break;
        }
        case '%':
            kputc('%');
            break;
        default:
            kputc('%');
            if (*fmt)
                kputc(*fmt);
        }
    }
}

static int WINAPI w_vfprintf(void *stream, const char *fmt,
                             __builtin_va_list ap)
{
    if (iob_index(stream) == 0) /* can't printf to stdin */
        return 0;
    winvprintf(fmt, ap);
    return 0;
}

static int WINAPI w_fprintf(void *stream, const char *fmt, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    int r = w_vfprintf(stream, fmt, ap);
    __builtin_va_end(ap);
    return r;
}

static u64 WINAPI w_fwrite(const void *buf, u64 size, u64 count, void *stream)
{
    if (iob_index(stream) == 0)
        return 0;
    const char *p = buf;
    u64 n = size * count;
    for (u64 i = 0; i < n; i++)
        kputc(p[i]);
    return count;
}

static void *WINAPI w_malloc(u64 size)
{
    return checked_alloc(size);
}

static void *WINAPI w_calloc(u64 n, u64 size)
{
    /* n*size in u64 can itself wrap (classic calloc-overflow: caller
       asks for n huge, size huge, product wraps small, gets a tiny
       buffer it thinks is enormous) — reject rather than let it wrap,
       exactly like a correct calloc() must. */
    if (n && size > 0xFFFFFFFFFFFFFFFFull / n)
        return NULL;
    u64 total = n * size;
    void *p = checked_alloc(total);
    if (p)
        memset(p, 0, (u32)total);
    return p;
}

static void WINAPI w_free(void *ptr)
{
    proc_free(ptr);
}

static usize WINAPI w_strlen(const char *s)
{
    return strlen(s);
}

static int WINAPI w_strncmp(const char *a, const char *b, usize n)
{
    return strncmp(a, b, n);
}

static void *WINAPI w_memcpy(void *dst, const void *src, usize n)
{
    return memcpy(dst, src, n);
}

static void WINAPI w_exit(int code)
{
    for (u32 i = onexit_count; i > 0; i--)
        onexit_table[i - 1]();
    w_ExitProcess((u32)code);
}

static void WINAPI w_cexit(void)
{
    for (u32 i = onexit_count; i > 0; i--)
        onexit_table[i - 1]();
    onexit_count = 0;
}

static void WINAPI w_abort(void)
{
    kprint("[msvcrt] abort() called\n");
    w_ExitProcess(3); /* matches the conventional abort() exit status */
}

static void *WINAPI w_onexit(void (*func)(void))
{
    if (!func || onexit_count >= MAX_ONEXIT)
        return NULL;
    onexit_table[onexit_count++] = func;
    return (void *)func;
}

/* _initterm(begin, end): call every non-null function pointer in
   [begin, end) — this is how MSVC/MinGW run C++ static initializers
   and __attribute__((constructor)) functions before main(). */
static void WINAPI w_initterm(void (**begin)(void), void (**end)(void))
{
    for (; begin < end; begin++)
        if (*begin)
            (*begin)();
}

static void WINAPI w_amsg_exit(int code)
{
    kprintf("[msvcrt] runtime error, code %d\n", code);
    w_ExitProcess(255);
}

static void WINAPI w_set_app_type(int type)     { (void)type; }
static int  WINAPI w_setusermatherr(void *h)     { (void)h; return 0; }
static void *WINAPI w_signal(int sig, void *handler)
{
    (void)sig;
    (void)handler;
    return NULL; /* "previous handler was SIG_DFL"; we never deliver signals */
}

/* __C_specific_handler: the SEH dispatcher generated try/except and
   unwind-table code calls into on an actual exception. We don't
   implement stack unwinding, so — like real Windows would for a
   handler that can't cope — this is a hard stop, not silent
   corruption. It is only ever reached if a real hardware/software
   exception occurs, which trivial programs never trigger. */
static int WINAPI w___C_specific_handler(void *rec, void *frame, void *ctx,
                                         void *disp)
{
    (void)rec;
    (void)frame;
    (void)ctx;
    (void)disp;
    panic("__C_specific_handler: structured exception handling is not "
          "implemented");
}

/* ---- export tables ---------------------------------------------------- */

typedef struct win_export {
    const char *name;
    void *fn;
} win_export_t;

typedef struct win_module {
    const char *dll;
    const win_export_t *exports;
    u32 count;
} win_module_t;

static const win_export_t kernel32_exports[] = {
    { "ExitProcess",     w_ExitProcess },
    { "GetStdHandle",    w_GetStdHandle },
    { "WriteConsoleA",   w_WriteConsoleA },
    { "WriteFile",       w_WriteFile },
    { "ReadConsoleA",    w_ReadConsoleA },
    { "Sleep",           w_Sleep },
    { "GetTickCount",    w_GetTickCount },
    { "VirtualAlloc",    w_VirtualAlloc },
    { "VirtualFree",     w_VirtualFree },
    { "GetProcessHeap",  w_GetProcessHeap },
    { "HeapAlloc",       w_HeapAlloc },
    { "HeapFree",        w_HeapFree },
    { "GetCommandLineA", w_GetCommandLineA },
    { "GetLastError",    w_GetLastError },
    { "SetLastError",    w_SetLastError },
    { "lstrlenA",        w_lstrlenA },
    { "InitializeCriticalSection", w_InitializeCriticalSection },
    { "EnterCriticalSection",      w_EnterCriticalSection },
    { "LeaveCriticalSection",      w_LeaveCriticalSection },
    { "DeleteCriticalSection",     w_DeleteCriticalSection },
    { "TlsAlloc",         w_TlsAlloc },
    { "TlsFree",          w_TlsFree },
    { "TlsGetValue",      w_TlsGetValue },
    { "TlsSetValue",      w_TlsSetValue },
    { "VirtualProtect",   w_VirtualProtect },
    { "VirtualQuery",     w_VirtualQuery },
    { "SetUnhandledExceptionFilter", w_SetUnhandledExceptionFilter },
    { "GetModuleHandleA", w_GetModuleHandleA },
    /* LoadLibraryA / GetProcAddress defined below (need the tables) */
    { "LoadLibraryA",    NULL },
    { "GetProcAddress",  NULL },
};

static const win_export_t user32_exports[] = {
    { "MessageBoxA", w_MessageBoxA },
};

static const win_export_t msvcrt_exports[] = {
    { "__getmainargs",         w___getmainargs },
    { "__iob_func",            w___iob_func },
    { "__initenv",              NULL }, /* data export, patched in below */
    { "__set_app_type",        w_set_app_type },
    { "__setusermatherr",      w_setusermatherr },
    { "__C_specific_handler",  w___C_specific_handler },
    { "_amsg_exit",            w_amsg_exit },
    { "_cexit",                w_cexit },
    { "_commode",               NULL }, /* data export, patched in below */
    { "_fmode",                 NULL }, /* data export, patched in below */
    { "_initterm",             w_initterm },
    { "_onexit",               w_onexit },
    { "abort",                 w_abort },
    { "calloc",                w_calloc },
    { "exit",                  w_exit },
    { "fprintf",               w_fprintf },
    { "free",                  w_free },
    { "fwrite",                w_fwrite },
    { "malloc",                w_malloc },
    { "memcpy",                w_memcpy },
    { "signal",                w_signal },
    { "strlen",                w_strlen },
    { "strncmp",               w_strncmp },
    { "vfprintf",              w_vfprintf },
};

static win_module_t modules[] = {
    { "kernel32.dll", kernel32_exports,
      sizeof(kernel32_exports) / sizeof(win_export_t) },
    { "user32.dll", user32_exports,
      sizeof(user32_exports) / sizeof(win_export_t) },
    { "msvcrt.dll", msvcrt_exports,
      sizeof(msvcrt_exports) / sizeof(win_export_t) },
};

static int name_eq_nocase(const char *a, const char *b)
{
    while (*a && *b) {
        char ca = *a >= 'A' && *a <= 'Z' ? *a + 32 : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? *b + 32 : *b;
        if (ca != cb)
            return 0;
        a++;
        b++;
    }
    return *a == *b;
}

static win_module_t *find_module(const char *dll)
{
    for (u32 i = 0; i < sizeof(modules) / sizeof(modules[0]); i++)
        if (name_eq_nocase(modules[i].dll, dll))
            return &modules[i];
    return NULL;
}

void *win_resolve(const char *dll, const char *func)
{
    win_module_t *m = find_module(dll);
    if (!m)
        return NULL;
    for (u32 i = 0; i < m->count; i++)
        if (strcmp(m->exports[i].name, func) == 0)
            return m->exports[i].fn;
    return NULL;
}

static void *WINAPI w_LoadLibraryA(const char *name)
{
    return find_module(name ? name : "");
}

static void *WINAPI w_GetProcAddress(void *module, const char *name)
{
    win_module_t *m = (win_module_t *)module;
    if (!m || !name)
        return NULL;
    for (u32 i = 0; i < m->count; i++)
        if (strcmp(m->exports[i].name, name) == 0)
            return m->exports[i].fn;
    return NULL;
}

void win32_init(void)
{
    /* patch in the two self-referential exports */
    for (u32 i = 0; i < modules[0].count; i++) {
        win_export_t *e = (win_export_t *)&modules[0].exports[i];
        if (strcmp(e->name, "LoadLibraryA") == 0)
            e->fn = (void *)w_LoadLibraryA;
        else if (strcmp(e->name, "GetProcAddress") == 0)
            e->fn = (void *)w_GetProcAddress;
    }

    /* msvcrt's __initenv/_fmode/_commode are DATA the CRT reads
       directly (through one level of dllimport indirection), not
       functions to call — the IAT slot must hold the address of a
       real variable we own, not a trampoline. */
    for (u32 i = 0; i < modules[2].count; i++) {
        win_export_t *e = (win_export_t *)&modules[2].exports[i];
        if (strcmp(e->name, "__initenv") == 0)
            e->fn = (void *)&envp_storage;
        else if (strcmp(e->name, "_fmode") == 0)
            e->fn = (void *)&fmode_storage;
        else if (strcmp(e->name, "_commode") == 0)
            e->fn = (void *)&commode_storage;
    }

    kprintf("win32: %u exports in kernel32.dll, %u in user32.dll, "
            "%u in msvcrt.dll (x64 ABI)\n",
            modules[0].count, modules[1].count, modules[2].count);
}
