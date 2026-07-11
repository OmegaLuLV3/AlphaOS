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

/*
 * STARTUPINFOA — deliberately not __attribute__((packed)): GCC applies
 * the same x86-64 alignment rules MSVC/mingw do for the plain
 * Microsoft ABI, so a natural (unpacked) layout here matches the real
 * struct byte-for-byte, exactly like every other cross-toolchain
 * struct in this file (opt_header_t in pe.c relies on the same fact).
 */
typedef struct {
    u32 cb;
    char *reserved;
    char *desktop;
    char *title;
    u32 x, y, x_size, y_size;
    u32 x_count_chars, y_count_chars;
    u32 fill_attribute;
    u32 flags;
    u16 show_window;
    u16 reserved2;
    u8 *reserved2_ptr;
    void *std_input, *std_output, *std_error;
} startupinfo_a_t;

static void WINAPI w_GetStartupInfoA(startupinfo_a_t *si)
{
    if (!si)
        return;
    memset(si, 0, sizeof(*si));
    si->cb = sizeof(*si);
    si->show_window = 1; /* SW_SHOWNORMAL */
    si->std_input = (void *)0x10;
    si->std_output = (void *)0x11;
    si->std_error = (void *)0x12;
}

/* ---- USER32 / GDI32 ---------------------------------------------------
 *
 * A minimal but real window/message subsystem, backed directly by the
 * existing window manager (wm.c) — the same compositor, taskbar, and
 * mouse/keyboard pump that AlphaOS-native windowed apps (paint.exe) and
 * MessageBoxA already use. A genuine RegisterClassA/CreateWindowExA/
 * GetMessageA/DispatchMessageA-based Win32 GUI program calls into this
 * exactly as it would call into real user32.dll/gdi32.dll, including
 * having its WNDPROC invoked by DispatchMessageA with the real
 * Microsoft x64 calling convention.
 *
 * Deliberately simplified relative to real Windows: one "device
 * context" per window rather than a separate DC object model (HDC and
 * HWND are literally the same value here — real app code never
 * inspects an HDC's bit pattern, only passes it back opaquely, so this
 * is safe), no window styles/menus/child windows, no TranslateMessage
 * WM_CHAR synthesis. Enough to run real single-window GUI programs
 * that paint with GDI text/rect calls and react to input — not enough
 * to run anything with a nontrivial UI framework underneath it.
 */

typedef s64 (WINAPI *wndproc_t)(void *hwnd, u32 msg, u64 wparam, s64 lparam);

#define WM_DESTROY      0x0002
#define WM_CLOSE        0x0010
#define WM_PAINT        0x000F
#define WM_QUIT         0x0012
#define WM_LBUTTONDOWN  0x0201
#define WM_LBUTTONUP    0x0202
#define WM_MOUSEMOVE    0x0200
#define WM_KEYDOWN      0x0100
#define WM_CHAR         0x0102

#define MAX_WIN_CLASSES 16
#define MAX_HWNDS       16

typedef struct {
    bool used;
    char name[64];
    wndproc_t wndproc;
} win_class_t;

typedef struct {
    bool used;
    window_t *win;
    wndproc_t wndproc;
    bool needs_paint;
    u32 text_color; /* ARGB, set via SetTextColor */
} hwnd_state_t;

static win_class_t win_classes[MAX_WIN_CLASSES];
static hwnd_state_t hwnd_states[MAX_HWNDS];
static bool quit_posted;
static int  quit_code;

static void win32_reset_gui_state(void)
{
    memset(win_classes, 0, sizeof(win_classes));
    memset(hwnd_states, 0, sizeof(hwnd_states));
    quit_posted = false;
    quit_code = 0;
}

static win_class_t *find_class(const char *name)
{
    if (!name)
        return NULL;
    for (u32 i = 0; i < MAX_WIN_CLASSES; i++)
        if (win_classes[i].used && strcmp(win_classes[i].name, name) == 0)
            return &win_classes[i];
    return NULL;
}

static hwnd_state_t *find_hwnd(void *hwnd)
{
    for (u32 i = 0; i < MAX_HWNDS; i++)
        if (hwnd_states[i].used && hwnd_states[i].win == hwnd)
            return &hwnd_states[i];
    return NULL;
}

/* WNDCLASSA — see the STARTUPINFOA comment above re: natural alignment */
typedef struct {
    u32 style;
    wndproc_t wndproc;
    s32 cls_extra, wnd_extra;
    void *hinstance;
    void *hicon;
    void *hcursor;
    void *hbrbackground;
    const char *menu_name;
    const char *class_name;
} wndclass_a_t;

static u16 WINAPI w_RegisterClassA(const wndclass_a_t *wc)
{
    if (!wc || !wc->class_name || find_class(wc->class_name))
        return 0;
    for (u32 i = 0; i < MAX_WIN_CLASSES; i++) {
        if (!win_classes[i].used) {
            win_classes[i].used = true;
            strncpy(win_classes[i].name, wc->class_name,
                    sizeof(win_classes[i].name) - 1);
            win_classes[i].wndproc = wc->wndproc;
            return 1; /* real RegisterClassA returns a nonzero ATOM */
        }
    }
    return 0;
}

/* WNDCLASSEXA: WNDCLASSA's fields plus a leading cbSize and a trailing
   hIconSm — RegisterClassExA just needs the same inner fields */
typedef struct {
    u32 cb_size;
    u32 style;
    wndproc_t wndproc;
    s32 cls_extra, wnd_extra;
    void *hinstance;
    void *hicon;
    void *hcursor;
    void *hbrbackground;
    const char *menu_name;
    const char *class_name;
    void *hicon_sm;
} wndclassex_a_t;

static u16 WINAPI w_RegisterClassExA(const wndclassex_a_t *wc)
{
    if (!wc)
        return 0;
    wndclass_a_t plain = {
        .style = wc->style, .wndproc = wc->wndproc,
        .cls_extra = wc->cls_extra, .wnd_extra = wc->wnd_extra,
        .hinstance = wc->hinstance, .hicon = wc->hicon,
        .hcursor = wc->hcursor, .hbrbackground = wc->hbrbackground,
        .menu_name = wc->menu_name, .class_name = wc->class_name,
    };
    return w_RegisterClassA(&plain);
}

static hwnd_state_t *alloc_hwnd_state(void)
{
    for (u32 i = 0; i < MAX_HWNDS; i++)
        if (!hwnd_states[i].used)
            return &hwnd_states[i];
    return NULL;
}

static void *WINAPI w_CreateWindowExA(u32 ex_style, const char *class_name,
                                      const char *title, u32 style,
                                      s32 x, s32 y, s32 w, s32 h,
                                      void *parent, void *menu,
                                      void *hinstance, void *param)
{
    (void)ex_style;
    (void)style;
    (void)x;
    (void)y; /* wm_create always picks position via its own cascade */
    (void)parent;
    (void)menu;
    (void)hinstance;
    (void)param;

    win_class_t *cls = find_class(class_name);
    if (!cls)
        return NULL;
    if (w <= 0) /* catches CW_USEDEFAULT (0x80000000, negative as s32) */
        w = 400;
    if (h <= 0)
        h = 300;

    window_t *win = wm_create(title ? title : "", w, h, current_process,
                              true);
    if (!win)
        return NULL;
    hwnd_state_t *hs = alloc_hwnd_state();
    if (!hs) {
        wm_destroy(win);
        return NULL;
    }
    hs->used = true;
    hs->win = win;
    hs->wndproc = cls->wndproc;
    hs->needs_paint = true;
    hs->text_color = RGB(0, 0, 0);

    surface_t s = { win->canvas, win->w, win->h };
    gfx_fill(&s, 0, 0, win->w, win->h, RGB(0xf0, 0xf0, 0xf0));
    return win; /* HWND == the underlying window_t* */
}

static int WINAPI w_DestroyWindow(void *hwnd)
{
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (!hs)
        return 0;
    /* Real DestroyWindow sends WM_DESTROY synchronously to the window's
       own WndProc *before* actually tearing anything down — that's how
       a real app gets the chance to call PostQuitMessage(0) in response
       and end its own message loop. Skipping this (as an earlier
       version of this function did) silently destroys the underlying
       window while the app's GetMessageA loop keeps polling a
       still-"used" hwnd_state that just never produces another event
       again: not a crash, but a permanent hang. */
    if (hs->wndproc)
        hs->wndproc(hwnd, WM_DESTROY, 0, 0);
    wm_destroy(hs->win);
    hs->used = false;
    hs->win = NULL;
    return 1;
}

static int WINAPI w_ShowWindow(void *hwnd, int cmd)
{
    (void)cmd;
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (hs)
        wm_present(hs->win);
    return hs != NULL;
}

static int WINAPI w_UpdateWindow(void *hwnd)
{
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (hs)
        hs->needs_paint = true; /* delivered as WM_PAINT by GetMessageA */
    return hs != NULL;
}

static s64 WINAPI w_DefWindowProcA(void *hwnd, u32 msg, u64 wparam,
                                   s64 lparam)
{
    (void)wparam;
    (void)lparam;
    if (msg == WM_CLOSE)
        w_DestroyWindow(hwnd); /* matches real DefWindowProcA exactly */
    return 0;
}

typedef struct {
    void *hwnd;
    u32 message;
    u64 wparam;
    s64 lparam;
    u32 time;
    s32 pt_x, pt_y;
} msg_a_t;

static int WINAPI w_GetMessageA(msg_a_t *msg, void *hwnd_filter, u32 min,
                                u32 max)
{
    (void)hwnd_filter;
    (void)min;
    (void)max;
    if (!msg)
        return 0;

    for (;;) {
        if (quit_posted) {
            msg->hwnd = NULL;
            msg->message = WM_QUIT;
            msg->wparam = (u64)(s64)quit_code;
            msg->lparam = 0;
            return 0;
        }

        for (u32 i = 0; i < MAX_HWNDS; i++) {
            hwnd_state_t *hs = &hwnd_states[i];
            if (!hs->used || !hs->win)
                continue;
            alpha_event_t ev;
            if (!wm_poll_event(hs->win, &ev))
                continue;
            msg->hwnd = hs->win;
            msg->wparam = 0;
            msg->lparam = 0;
            switch (ev.type) {
            case ALPHA_EV_CLOSE:
                msg->message = WM_CLOSE;
                break;
            case ALPHA_EV_MOUSE_DOWN:
                msg->message = WM_LBUTTONDOWN;
                msg->wparam = (u64)ev.buttons;
                msg->lparam = (s64)((ev.y << 16) | (ev.x & 0xFFFF));
                break;
            case ALPHA_EV_MOUSE_UP:
                msg->message = WM_LBUTTONUP;
                msg->lparam = (s64)((ev.y << 16) | (ev.x & 0xFFFF));
                break;
            case ALPHA_EV_MOUSE_MOVE:
                msg->message = WM_MOUSEMOVE;
                msg->wparam = (u64)ev.buttons;
                msg->lparam = (s64)((ev.y << 16) | (ev.x & 0xFFFF));
                break;
            case ALPHA_EV_KEY:
                msg->message = WM_CHAR;
                msg->wparam = (u64)ev.key;
                break;
            default:
                continue; /* unrecognized: skip, keep polling */
            }
            return 1;
        }

        for (u32 i = 0; i < MAX_HWNDS; i++) {
            hwnd_state_t *hs = &hwnd_states[i];
            if (hs->used && hs->win && hs->needs_paint) {
                hs->needs_paint = false;
                msg->hwnd = hs->win;
                msg->message = WM_PAINT;
                msg->wparam = 0;
                msg->lparam = 0;
                return 1;
            }
        }

        sleep_ms(10); /* idle politely: the CPU sleeps in hlt */
    }
}

static int WINAPI w_TranslateMessage(const msg_a_t *msg)
{
    (void)msg; /* no WM_KEYDOWN -> WM_CHAR synthesis to do: we already
                  deliver WM_CHAR directly from ALPHA_EV_KEY */
    return 1;
}

static s64 WINAPI w_DispatchMessageA(const msg_a_t *msg)
{
    if (!msg || msg->message == WM_QUIT)
        return 0;
    hwnd_state_t *hs = find_hwnd(msg->hwnd);
    if (hs && hs->wndproc)
        return hs->wndproc(msg->hwnd, msg->message, msg->wparam,
                           msg->lparam);
    return w_DefWindowProcA(msg->hwnd, msg->message, msg->wparam,
                            msg->lparam);
}

static void WINAPI w_PostQuitMessage(int code)
{
    quit_posted = true;
    quit_code = code;
}

typedef struct { s32 left, top, right, bottom; } rect_t;

typedef struct {
    void *hdc;
    s32 erase;
    rect_t paint_rect;
    s32 restore;
    s32 inc_update;
    u8 reserved[32];
} paintstruct_t;

static void *WINAPI w_BeginPaint(void *hwnd, paintstruct_t *ps)
{
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (!hs || !hs->win)
        return NULL;
    if (ps) {
        memset(ps, 0, sizeof(*ps));
        ps->hdc = hwnd;
        ps->erase = 1;
        ps->paint_rect.right = hs->win->w;
        ps->paint_rect.bottom = hs->win->h;
    }
    return hwnd; /* HDC == HWND, see the section comment above */
}

static int WINAPI w_EndPaint(void *hwnd, const paintstruct_t *ps)
{
    (void)ps;
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (!hs || !hs->win)
        return 0;
    wm_present(hs->win);
    return 1;
}

static int WINAPI w_GetClientRect(void *hwnd, rect_t *rc)
{
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (!hs || !hs->win || !rc)
        return 0;
    rc->left = 0;
    rc->top = 0;
    rc->right = hs->win->w;
    rc->bottom = hs->win->h;
    return 1;
}

static int WINAPI w_InvalidateRect(void *hwnd, const rect_t *rc, int erase)
{
    (void)rc;
    (void)erase;
    hwnd_state_t *hs = find_hwnd(hwnd);
    if (!hs)
        return 0;
    hs->needs_paint = true;
    return 1;
}

static void *WINAPI w_LoadCursorA(void *hinstance, const char *name)
{
    (void)hinstance;
    (void)name;
    return (void *)0x1; /* any nonzero handle: we don't render a real cursor */
}

static void *WINAPI w_LoadIconA(void *hinstance, const char *name)
{
    (void)hinstance;
    (void)name;
    return (void *)0x1;
}

/* ---- GDI32 -------------------------------------------------------------
 * HDC == HWND in this simplified model (see the section comment above),
 * so every GDI call below resolves straight back to a hwnd_state_t. */

static int WINAPI w_TextOutA(void *hdc, s32 x, s32 y, const char *text,
                             s32 len)
{
    hwnd_state_t *hs = find_hwnd(hdc);
    if (!hs || !hs->win || !text)
        return 0;
    char buf[256];
    s32 n = len;
    if (n < 0)
        n = 0;
    if (n > (s32)sizeof(buf) - 1)
        n = sizeof(buf) - 1;
    memcpy(buf, text, n);
    buf[n] = 0;
    surface_t s = { hs->win->canvas, hs->win->w, hs->win->h };
    gfx_text(&s, x, y, buf, hs->text_color);
    return 1;
}

static u32 WINAPI w_SetTextColor(void *hdc, u32 colorref)
{
    hwnd_state_t *hs = find_hwnd(hdc);
    if (!hs)
        return 0xFFFFFFFF; /* CLR_INVALID */
    u32 old = hs->text_color;
    /* COLORREF is 0x00bbggrr, opposite byte order from our ARGB RGB() */
    hs->text_color = RGB(colorref & 0xFF, (colorref >> 8) & 0xFF,
                         (colorref >> 16) & 0xFF);
    return old;
}

static u32 WINAPI w_SetBkColor(void *hdc, u32 colorref)
{
    (void)hdc;
    (void)colorref; /* background fill mode not modeled: text draws with
                        a transparent background already (gfx_text only
                        touches glyph pixels) */
    return 0;
}

static int WINAPI w_SetBkMode(void *hdc, int mode)
{
    (void)hdc;
    (void)mode;
    return 1; /* OPAQUE, previous value: unused either way */
}

static int WINAPI w_FillRect(void *hdc, const rect_t *rc, void *brush)
{
    hwnd_state_t *hs = find_hwnd(hdc);
    if (!hs || !hs->win || !rc)
        return 0;
    /* stock brush handles are small integers from GetStockObject below;
       anything else defaults to white, a reasonable background guess */
    u32 color = ((uptr)brush == 1) ? RGB(0, 0, 0) : RGB(0xff, 0xff, 0xff);
    surface_t s = { hs->win->canvas, hs->win->w, hs->win->h };
    int w = rc->right - rc->left, h = rc->bottom - rc->top;
    if (w > 0 && h > 0)
        gfx_fill(&s, rc->left, rc->top, w, h, color);
    return 1;
}

static void *WINAPI w_GetStockObject(int obj)
{
    return (void *)(uptr)(obj + 1); /* nonzero, distinguishable handles */
}

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
/* _acmdln: msvcrt data export, pointer to the raw command-line string
   (same one-level-of-indirection pattern as __initenv/_fmode/_commode
   below) — value refreshed in win32_reset_process_state() since the
   command line changes per process. */
static char *acmdln_storage;

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
    win32_reset_gui_state(); /* stale window classes/HWNDs from a prior
                                 win-style process must not leak into
                                 this one — see the GUI section comment */
    acmdln_storage = current_process ? current_process->cmdline : NULL;
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

static int WINAPI w_ismbblead(u32 c)
{
    (void)c; /* single-byte codepage: no lead bytes, ever */
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
    { "GetStartupInfoA",  w_GetStartupInfoA },
    /* LoadLibraryA / GetProcAddress defined below (need the tables) */
    { "LoadLibraryA",    NULL },
    { "GetProcAddress",  NULL },
};

static const win_export_t user32_exports[] = {
    { "MessageBoxA",       w_MessageBoxA },
    { "RegisterClassA",    w_RegisterClassA },
    { "RegisterClassExA",  w_RegisterClassExA },
    { "CreateWindowExA",   w_CreateWindowExA },
    { "DestroyWindow",     w_DestroyWindow },
    { "ShowWindow",        w_ShowWindow },
    { "UpdateWindow",      w_UpdateWindow },
    { "DefWindowProcA",    w_DefWindowProcA },
    { "GetMessageA",       w_GetMessageA },
    { "TranslateMessage",  w_TranslateMessage },
    { "DispatchMessageA",  w_DispatchMessageA },
    { "PostQuitMessage",   w_PostQuitMessage },
    { "BeginPaint",        w_BeginPaint },
    { "EndPaint",          w_EndPaint },
    { "GetClientRect",     w_GetClientRect },
    { "InvalidateRect",    w_InvalidateRect },
    { "LoadCursorA",       w_LoadCursorA },
    { "LoadIconA",         w_LoadIconA },
};

static const win_export_t gdi32_exports[] = {
    { "TextOutA",       w_TextOutA },
    { "SetTextColor",   w_SetTextColor },
    { "SetBkColor",     w_SetBkColor },
    { "SetBkMode",      w_SetBkMode },
    { "FillRect",       w_FillRect },
    { "GetStockObject", w_GetStockObject },
};

static const win_export_t msvcrt_exports[] = {
    { "__getmainargs",         w___getmainargs },
    { "__iob_func",            w___iob_func },
    { "__initenv",              NULL }, /* data export, patched in below */
    { "__set_app_type",        w_set_app_type },
    { "__setusermatherr",      w_setusermatherr },
    { "__C_specific_handler",  w___C_specific_handler },
    { "_acmdln",                NULL }, /* data export, patched in below */
    { "_amsg_exit",            w_amsg_exit },
    { "_cexit",                w_cexit },
    { "_commode",               NULL }, /* data export, patched in below */
    { "_fmode",                 NULL }, /* data export, patched in below */
    { "_initterm",             w_initterm },
    { "_ismbblead",            w_ismbblead },
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
    { "gdi32.dll", gdi32_exports,
      sizeof(gdi32_exports) / sizeof(win_export_t) },
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

    /* msvcrt's __initenv/_acmdln/_fmode/_commode are DATA the CRT reads
       directly (through one level of dllimport indirection), not
       functions to call — the IAT slot must hold the address of a
       real variable we own, not a trampoline. */
    for (u32 i = 0; i < modules[2].count; i++) {
        win_export_t *e = (win_export_t *)&modules[2].exports[i];
        if (strcmp(e->name, "__initenv") == 0)
            e->fn = (void *)&envp_storage;
        else if (strcmp(e->name, "_acmdln") == 0)
            e->fn = (void *)&acmdln_storage;
        else if (strcmp(e->name, "_fmode") == 0)
            e->fn = (void *)&fmode_storage;
        else if (strcmp(e->name, "_commode") == 0)
            e->fn = (void *)&commode_storage;
    }

    kprintf("win32: %u kernel32, %u user32, %u msvcrt, %u gdi32 exports "
            "(x64 ABI)\n",
            modules[0].count, modules[1].count, modules[2].count,
            modules[3].count);
}
