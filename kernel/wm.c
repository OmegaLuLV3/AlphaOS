/*
 * Window manager + compositor: Windows-7-inspired desktop with a
 * gradient wallpaper, alpha-blended "glass" window title bars, a
 * taskbar (start orb, window buttons, RTC clock), and a start menu
 * listing every .exe on the ramdisk.
 *
 * Everything is composited into a backbuffer and flipped to the
 * framebuffer, only when something changed (event-driven, no idle CPU
 * burn — the machine still spends its time in hlt).
 */
#include "kernel.h"

#define TASKBAR_H 40
#define TITLE_H   24
#define BORDER    2

/* ---- theme ----------------------------------------------------------- */
#define COL_DESK_TOP    RGB(0x3f, 0x83, 0xc9)
#define COL_DESK_BOT    RGB(0x0d, 0x2a, 0x52)
#define COL_TASK_TOP    RGB(0x33, 0x47, 0x5e)
#define COL_TASK_BOT    RGB(0x10, 0x18, 0x24)
#define COL_TASK_LINE   RGB(0x6a, 0x8a, 0xaa)
#define COL_TITLE_ON    RGB(0x9c, 0xc3, 0xe8)
#define COL_TITLE_OFF   RGB(0x9a, 0xa4, 0xae)
#define COL_BORDER      RGB(0x27, 0x40, 0x5c)
#define COL_TEXT        RGB(0xff, 0xff, 0xff)
#define COL_TEXT_SHADOW RGB(0x10, 0x1c, 0x2c)
#define COL_CLOSE       RGB(0xc4, 0x3d, 0x3d)
#define COL_MENU_BG     RGB(0xf2, 0xf6, 0xfa)
#define COL_MENU_EDGE   RGB(0x2b, 0x5a, 0x8a)
#define COL_MENU_TEXT   RGB(0x1a, 0x2a, 0x3a)

static bool active;
static surface_t screen;      /* backbuffer */
static u32 *wallpaper;
static u32 *lfb;
static int W, H;

static window_t *bottom;      /* z-order: head=bottom, tail=top */
static window_t *drag_win;
static int drag_dx, drag_dy;

static int mx, my;
static u8 mbuttons;

static bool start_open;
static bool dirty;
static u32 last_flip_ticks;

static char last_clock[8];

/* terminal input queue: keys destined for the shell */
#define TQ_SIZE 256
static u8 tq[TQ_SIZE];
static u32 tq_head, tq_tail;

window_t *terminal_window(void);

/* ---- small helpers --------------------------------------------------- */

static window_t *topmost(void)
{
    window_t *w = bottom;
    while (w && w->next)
        w = w->next;
    return w;
}

static void tq_push(u8 c)
{
    u32 next = (tq_head + 1) % TQ_SIZE;
    if (next != tq_tail) {
        tq[tq_head] = c;
        tq_head = next;
    }
}

int gui_term_getch(void)
{
    if (tq_tail == tq_head)
        return -1;
    u8 c = tq[tq_tail];
    tq_tail = (tq_tail + 1) % TQ_SIZE;
    return c;
}

void gui_inject_line(const char *cmd)
{
    while (*cmd)
        tq_push((u8)*cmd++);
    tq_push('\n');
}

static void ev_push(window_t *win, u32 type, int x, int y, int buttons,
                    int key)
{
    u32 next = (win->ev_head + 1) % WM_EVQ_SIZE;
    if (next == win->ev_tail)
        return; /* queue full: drop */
    alpha_event_t *e = &win->evq[win->ev_head];
    e->type = type;
    e->x = x;
    e->y = y;
    e->buttons = buttons;
    e->key = key;
    win->ev_head = next;
}

int wm_poll_event(window_t *win, alpha_event_t *ev)
{
    gui_pump();
    if (win->ev_tail == win->ev_head)
        return 0;
    *ev = win->evq[win->ev_tail];
    win->ev_tail = (win->ev_tail + 1) % WM_EVQ_SIZE;
    return 1;
}

/* ---- window frame geometry ------------------------------------------- */

static int frame_w(window_t *w) { return w->w + 2 * BORDER; }
static int frame_h(window_t *w) { return w->h + TITLE_H + 2 * BORDER; }

static bool in_rect(int px, int py, int x, int y, int w, int h)
{
    return px >= x && px < x + w && py >= y && py < y + h;
}

/* ---- compositor ------------------------------------------------------ */

static const char *cursor_img[19] = {
    "X...........", "XX..........", "XoX.........", "XooX........",
    "XoooX.......", "XooooX......", "XoooooX.....", "XooooooX....",
    "XoooooooX...", "XooooooooX..", "XoooooXXXXX.", "XooXooX.....",
    "XoX.XooX....", "XX..XooX....", "X....XooX...", ".....XooX...",
    ".....XooX...", "......XX....", "............",
};

static void draw_cursor(void)
{
    for (int r = 0; r < 19; r++) {
        for (int c = 0; c < 12; c++) {
            char ch = cursor_img[r][c];
            if (ch == '.')
                continue;
            int px = mx + c, py = my + r;
            if (px < 0 || px >= W || py < 0 || py >= H)
                continue;
            screen.px[py * W + px] =
                ch == 'X' ? RGB(10, 10, 10) : RGB(250, 250, 250);
        }
    }
}

static void draw_window(window_t *win)
{
    int fx = win->x, fy = win->y, fw = frame_w(win), fh = frame_h(win);
    bool focused = (win == topmost());

    /* soft drop shadow */
    gfx_blend(&screen, fx + 4, fy + fh, fw, 4, RGB(0, 0, 0), 70);
    gfx_blend(&screen, fx + fw, fy + 4, 4, fh, RGB(0, 0, 0), 70);

    /* glass title bar: blended over whatever is beneath */
    gfx_blend(&screen, fx, fy, fw, TITLE_H,
              focused ? COL_TITLE_ON : COL_TITLE_OFF, focused ? 190 : 150);
    gfx_fill(&screen, fx, fy, fw, 1, RGB(0xd0, 0xe4, 0xf8));

    /* border */
    gfx_rect(&screen, fx, fy, fw, fh, COL_BORDER);

    /* title text with a subtle shadow */
    gfx_text(&screen, fx + 9, fy + 5, win->title, COL_TEXT_SHADOW);
    gfx_text(&screen, fx + 8, fy + 4, win->title, COL_TEXT);

    /* close button */
    if (win->closable) {
        int bx = fx + fw - 38, by = fy + 3;
        gfx_fill(&screen, bx, by, 34, TITLE_H - 6, COL_CLOSE);
        gfx_rect(&screen, bx, by, 34, TITLE_H - 6, RGB(0x6a, 0x18, 0x18));
        gfx_text(&screen, bx + 13, by + 1, "x", COL_TEXT);
    }

    /* content */
    surface_t canvas = { win->canvas, win->w, win->h };
    gfx_blit(&screen, fx + BORDER, fy + TITLE_H + BORDER, &canvas);
}

static void draw_orb(int cx, int cy)
{
    gfx_circle(&screen, cx, cy, 14, RGB(0x1a, 0x3a, 0x66));
    gfx_circle(&screen, cx, cy, 12, RGB(0x2d, 0x6f, 0xc4));
    gfx_circle(&screen, cx, cy - 2, 9, RGB(0x55, 0x9a, 0xe8));
    /* four-pane flag */
    gfx_fill(&screen, cx - 5, cy - 5, 4, 4, RGB(0xe8, 0x4c, 0x3c));
    gfx_fill(&screen, cx + 1, cy - 5, 4, 4, RGB(0x2d, 0xcc, 0x70));
    gfx_fill(&screen, cx - 5, cy + 1, 4, 4, RGB(0x34, 0x98, 0xdb));
    gfx_fill(&screen, cx + 1, cy + 1, 4, 4, RGB(0xf1, 0xc4, 0x0f));
}

static void draw_taskbar(void)
{
    int y0 = H - TASKBAR_H;
    gfx_gradient_v(&screen, 0, y0, W, TASKBAR_H, COL_TASK_TOP, COL_TASK_BOT);
    gfx_fill(&screen, 0, y0, W, 1, COL_TASK_LINE);

    draw_orb(24, y0 + TASKBAR_H / 2);

    /* one button per window */
    int x = 52;
    for (window_t *w = bottom; w; w = w->next) {
        bool focused = (w == topmost());
        gfx_blend(&screen, x, y0 + 5, 150, TASKBAR_H - 10,
                  focused ? RGB(0xa0, 0xc8, 0xf0) : RGB(0x60, 0x80, 0xa0),
                  focused ? 130 : 60);
        gfx_rect(&screen, x, y0 + 5, 150, TASKBAR_H - 10,
                 RGB(0x50, 0x68, 0x84));
        char label[18];
        strncpy(label, w->title, 17);
        label[17] = 0;
        gfx_text(&screen, x + 8, y0 + (TASKBAR_H - 16) / 2, label, COL_TEXT);
        x += 158;
        if (x > W - 260)
            break;
    }

    /* clock (RTC driver) */
    rtc_time_t t;
    rtc_read(&t);
    char clk[6] = { '0' + t.hour / 10, '0' + t.hour % 10, ':',
                    '0' + t.min / 10, '0' + t.min % 10, 0 };
    char date[11] = { '0' + t.day / 10, '0' + t.day % 10, '/',
                      '0' + t.month / 10, '0' + t.month % 10, '/',
                      '0' + (t.year / 1000) % 10, '0' + (t.year / 100) % 10,
                      '0' + (t.year / 10) % 10, '0' + t.year % 10, 0 };
    gfx_text(&screen, W - 60, y0 + 4, clk, COL_TEXT);
    gfx_text(&screen, W - 88, y0 + 21, date, RGB(0xb8, 0xc8, 0xd8));
    memcpy(last_clock, clk, sizeof(clk));
}

/* ---- start menu ------------------------------------------------------ */

#define MENU_W 240
#define ITEM_H 26

static u32 menu_items(char names[][32])
{
    u32 n = 0;
    for (u32 i = 0; i < ramdisk_count() && n < 12; i++) {
        rd_file_t *f = ramdisk_get(i);
        usize len = strlen(f->name);
        if (len > 4 && strcmp(f->name + len - 4, ".exe") == 0)
            strncpy(names[n++], f->name, 31);
    }
    strncpy(names[n++], "-", 31);           /* separator */
    strncpy(names[n++], "Reboot", 31);
    strncpy(names[n++], "Shut down", 31);
    return n;
}

static void draw_start_menu(void)
{
    char names[16][32];
    u32 n = menu_items(names);
    int mh = n * ITEM_H + 10;
    int x0 = 4, y0 = H - TASKBAR_H - mh - 4;

    gfx_blend(&screen, x0 + 4, y0 + 4, MENU_W, mh, RGB(0, 0, 0), 80);
    gfx_fill(&screen, x0, y0, MENU_W, mh, COL_MENU_BG);
    gfx_rect(&screen, x0, y0, MENU_W, mh, COL_MENU_EDGE);
    gfx_gradient_v(&screen, x0 + 1, y0 + 1, 6, mh - 2,
                   RGB(0x4a, 0x90, 0xd8), RGB(0x22, 0x4a, 0x7c));

    for (u32 i = 0; i < n; i++) {
        int iy = y0 + 5 + i * ITEM_H;
        if (names[i][0] == '-') {
            gfx_fill(&screen, x0 + 14, iy + ITEM_H / 2, MENU_W - 28, 1,
                     RGB(0xc0, 0xcc, 0xd8));
            continue;
        }
        gfx_text(&screen, x0 + 20, iy + (ITEM_H - 16) / 2, names[i],
                 COL_MENU_TEXT);
    }
}

static void start_menu_click(int px, int py)
{
    char names[16][32];
    u32 n = menu_items(names);
    int mh = n * ITEM_H + 10;
    int x0 = 4, y0 = H - TASKBAR_H - mh - 4;

    start_open = false;
    dirty = true;
    if (!in_rect(px, py, x0, y0, MENU_W, mh))
        return;

    u32 idx = (py - y0 - 5) / ITEM_H;
    if (idx >= n || names[idx][0] == '-')
        return;

    if (strcmp(names[idx], "Reboot") == 0) {
        outb(0x64, 0xFE); /* 8042 pulse reset line */
    } else if (strcmp(names[idx], "Shut down") == 0) {
        gui_inject_line("halt");
    } else {
        char cmd[40] = "run ";
        strncpy(cmd + 4, names[idx], 31);
        gui_inject_line(cmd);
    }
}

/* ---- compositing ----------------------------------------------------- */

static void composite(void)
{
    memcpy(screen.px, wallpaper, (u32)W * H * 4);
    for (window_t *w = bottom; w; w = w->next)
        draw_window(w);
    draw_taskbar();
    if (start_open)
        draw_start_menu();
    draw_cursor();
    memcpy(lfb, screen.px, (u32)W * H * 4);
    dirty = false;
    last_flip_ticks = pit_ticks();
}

void wm_mark_dirty(void)
{
    dirty = true;
    /* throttle output-driven repaints to ~30 fps */
    if (pit_ticks() - last_flip_ticks >= 3)
        composite();
}

/* ---- window list management ------------------------------------------ */

static void unlink_win(window_t *win)
{
    window_t **pp = &bottom;
    while (*pp && *pp != win)
        pp = &(*pp)->next;
    if (*pp)
        *pp = win->next;
    win->next = NULL;
}

static void raise_win(window_t *win)
{
    if (topmost() == win)
        return;
    unlink_win(win);
    window_t *t = topmost();
    if (t)
        t->next = win;
    else
        bottom = win;
    dirty = true;
}

window_t *wm_create(const char *title, int w, int h, process_t *owner,
                    bool closable)
{
    static int cascade;
    if (w < 40 || h < 30 || w > W - 20 || h > H - TASKBAR_H - TITLE_H - 20)
        return NULL;

    window_t *win = kmalloc(sizeof(window_t));
    if (!win)
        return NULL;
    memset(win, 0, sizeof(*win));
    win->canvas = kmalloc((u32)w * h * 4);
    if (!win->canvas) {
        kfree(win);
        return NULL;
    }
    win->w = w;
    win->h = h;
    strncpy(win->title, title ? title : "window", sizeof(win->title) - 1);
    win->closable = closable;
    win->owner = owner;
    win->x = 60 + (cascade % 8) * 28;
    win->y = 48 + (cascade % 8) * 24;
    cascade++;

    for (int i = 0; i < w * h; i++)
        win->canvas[i] = RGB(0xff, 0xff, 0xff);

    raise_win(win);
    dirty = true;
    composite();
    return win;
}

void wm_destroy(window_t *win)
{
    if (!win)
        return;
    if (drag_win == win)
        drag_win = NULL;
    unlink_win(win);
    kfree(win->canvas);
    kfree(win);
    dirty = true;
    composite();
}

void wm_destroy_owned(process_t *p)
{
    window_t *w = bottom;
    while (w) {
        window_t *next = w->next;
        if (w->owner == p)
            wm_destroy(w);
        w = next;
    }
}

void wm_present(window_t *win)
{
    (void)win;
    wm_mark_dirty();
}

/* ---- input handling --------------------------------------------------- */

static window_t *window_at(int px, int py)
{
    /* topmost first */
    window_t *hit = NULL;
    for (window_t *w = bottom; w; w = w->next)
        if (in_rect(px, py, w->x, w->y, frame_w(w), frame_h(w)))
            hit = w;
    return hit;
}

static void mouse_down(void)
{
    if (start_open) {
        start_menu_click(mx, my);
        return;
    }

    int y0 = H - TASKBAR_H;
    if (my >= y0) {
        if (mx < 48) {
            start_open = true;
            dirty = true;
            return;
        }
        int x = 52;
        for (window_t *w = bottom; w; w = w->next) {
            if (in_rect(mx, my, x, y0 + 5, 150, TASKBAR_H - 10)) {
                raise_win(w);
                return;
            }
            x += 158;
        }
        return;
    }

    window_t *win = window_at(mx, my);
    if (!win)
        return;
    raise_win(win);

    int ly = my - win->y;
    if (ly < TITLE_H) {
        int bx = win->x + frame_w(win) - 38;
        if (win->closable && in_rect(mx, my, bx, win->y + 3, 34,
                                     TITLE_H - 6)) {
            ev_push(win, ALPHA_EV_CLOSE, 0, 0, 0, 0);
            return;
        }
        drag_win = win;
        drag_dx = mx - win->x;
        drag_dy = my - win->y;
        return;
    }

    ev_push(win, ALPHA_EV_MOUSE_DOWN, mx - win->x - BORDER,
            my - win->y - TITLE_H - BORDER, mbuttons, 0);
}

static void handle_mouse(void)
{
    int dx, dy;
    u8 btn;
    bool moved = false;
    u8 prev = mbuttons;

    while (mouse_pop(&dx, &dy, &btn)) {
        mx += dx;
        my += dy;
        if (mx < 0) mx = 0;
        if (my < 0) my = 0;
        if (mx >= W) mx = W - 1;
        if (my >= H) my = H - 1;
        moved = dx || dy || moved;

        if ((btn & 1) && !(prev & 1)) {
            mbuttons = btn;
            mouse_down();
        } else if (!(btn & 1) && (prev & 1)) {
            mbuttons = btn;
            drag_win = NULL;
            window_t *t = topmost();
            if (t)
                ev_push(t, ALPHA_EV_MOUSE_UP, mx - t->x - BORDER,
                        my - t->y - TITLE_H - BORDER, btn, 0);
        }
        mbuttons = btn;
        prev = btn;
    }

    if (!moved)
        return;
    dirty = true;

    if (drag_win) {
        drag_win->x = mx - drag_dx;
        drag_win->y = my - drag_dy;
        if (drag_win->x < -frame_w(drag_win) + 60)
            drag_win->x = -frame_w(drag_win) + 60;
        if (drag_win->x > W - 60) drag_win->x = W - 60;
        if (drag_win->y < 0) drag_win->y = 0;
        if (drag_win->y > H - TASKBAR_H - TITLE_H)
            drag_win->y = H - TASKBAR_H - TITLE_H;
        return;
    }

    window_t *t = topmost();
    if (t && in_rect(mx, my, t->x + BORDER, t->y + TITLE_H + BORDER,
                     t->w, t->h))
        ev_push(t, ALPHA_EV_MOUSE_MOVE, mx - t->x - BORDER,
                my - t->y - TITLE_H - BORDER, mbuttons, 0);
}

/* ---- the pump: called from every blocking wait ------------------------ */

void gui_pump(void)
{
    if (!active)
        return;

    /* serial input always drives the shell (headless/automation) */
    int s;
    while ((s = serial_getc()) >= 0) {
        if (s == '\r')
            s = '\n';
        if (s == 0x7F)
            s = '\b';
        tq_push((u8)s);
    }

    /* keyboard goes to the focused window */
    int c;
    while ((c = kbd_pop()) >= 0) {
        window_t *t = topmost();
        if (t && t != terminal_window())
            ev_push(t, ALPHA_EV_KEY, 0, 0, 0, c);
        else
            tq_push((u8)c);
    }

    handle_mouse();

    /* redraw the clock when the minute changes (checked once a second) */
    static u32 last_clock_check;
    if (pit_ticks() - last_clock_check >= 100) {
        last_clock_check = pit_ticks();
        rtc_time_t t;
        rtc_read(&t);
        char clk0 = '0' + t.hour / 10;
        if (last_clock[0] != clk0 || last_clock[1] != '0' + t.hour % 10 ||
            last_clock[3] != '0' + t.min / 10 ||
            last_clock[4] != '0' + t.min % 10)
            dirty = true;
    }

    if (dirty)
        composite();
}

/* ---- init ------------------------------------------------------------- */

bool gui_active(void)
{
    return active;
}

void gui_init(void)
{
    W = bga_width();
    H = bga_height();
    lfb = bga_framebuffer();

    screen.px = kmalloc((u32)W * H * 4);
    wallpaper = kmalloc((u32)W * H * 4);
    if (!screen.px || !wallpaper)
        panic("gui: no memory for framebuffers");
    screen.w = W;
    screen.h = H;

    /* wallpaper: vertical gradient + a subtle horizon glow */
    surface_t wp = { wallpaper, W, H };
    gfx_gradient_v(&wp, 0, 0, W, H, COL_DESK_TOP, COL_DESK_BOT);
    for (int r = 0; r < 90; r++)
        gfx_blend(&wp, W / 2 - (300 - r * 2), H / 2 - 40 + r / 2,
                  (300 - r * 2) * 2, 1, RGB(0xcc, 0xe4, 0xff), 22);
    gfx_text(&wp, W - 148, H - TASKBAR_H - 24, "AlphaOS 0.2",
             RGB(0xd8, 0xe8, 0xf8));

    mx = W / 2;
    my = H / 2;
    active = true;

    terminal_create();
    composite();
    kprint("gui: desktop ready\n"); /* lands in the terminal window */
}
