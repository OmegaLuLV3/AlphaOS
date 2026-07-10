/*
 * Win32-compatible API subset, exported to .exe files the native
 * Windows way: programs import these by name from KERNEL32.DLL /
 * USER32.DLL through their PE import table, and the loader patches
 * their IAT to point directly at these functions.
 *
 * All functions use the stdcall convention, exactly like real Win32,
 * so binaries built by a Windows toolchain against this subset (with
 * no CRT) run unmodified.
 */
#include "kernel.h"

#define WINAPI __attribute__((stdcall))

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

static u32 WINAPI w_GetStdHandle(u32 which)
{
    switch (which) {
    case STD_INPUT_HANDLE:  return 0x10;
    case STD_OUTPUT_HANDLE: return 0x11;
    case STD_ERROR_HANDLE:  return 0x12;
    }
    return (u32)-1;
}

static int WINAPI w_WriteConsoleA(u32 handle, const void *buf, u32 len,
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

static int WINAPI w_WriteFile(u32 handle, const void *buf, u32 len,
                              u32 *written, void *overlapped)
{
    return w_WriteConsoleA(handle, buf, len, written, overlapped);
}

static int WINAPI w_ReadConsoleA(u32 handle, void *buf, u32 max,
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

static void *WINAPI w_VirtualAlloc(void *addr, u32 size, u32 type, u32 prot)
{
    (void)addr;
    (void)type;
    (void)prot;
    void *p = proc_alloc(size);
    if (p)
        memset(p, 0, size); /* VirtualAlloc returns zeroed pages */
    return p;
}

static int WINAPI w_VirtualFree(void *addr, u32 size, u32 type)
{
    (void)size;
    (void)type;
    return proc_free(addr);
}

static u32 WINAPI w_GetProcessHeap(void)
{
    return 0xA1FA;
}

static void *WINAPI w_HeapAlloc(u32 heap, u32 flags, u32 size)
{
    (void)heap;
    void *p = proc_alloc(size);
    if (p && (flags & 0x08)) /* HEAP_ZERO_MEMORY */
        memset(p, 0, size);
    return p;
}

static int WINAPI w_HeapFree(u32 heap, u32 flags, void *ptr)
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

/* ---- USER32 ---------------------------------------------------------- */

#define MB_MAX_LINES 8

static int WINAPI w_MessageBoxA(u32 hwnd, const char *text,
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
    /* LoadLibraryA / GetProcAddress defined below (need the tables) */
    { "LoadLibraryA",    NULL },
    { "GetProcAddress",  NULL },
};

static const win_export_t user32_exports[] = {
    { "MessageBoxA", w_MessageBoxA },
};

static win_module_t modules[] = {
    { "kernel32.dll", kernel32_exports,
      sizeof(kernel32_exports) / sizeof(win_export_t) },
    { "user32.dll", user32_exports,
      sizeof(user32_exports) / sizeof(win_export_t) },
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

static u32 WINAPI w_LoadLibraryA(const char *name)
{
    return (u32)find_module(name ? name : "");
}

static void *WINAPI w_GetProcAddress(u32 module, const char *name)
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
    kprintf("win32: %u exports in kernel32.dll, %u in user32.dll\n",
            modules[0].count, modules[1].count);
}
