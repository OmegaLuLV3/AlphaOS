/*
 * The Terminal: a text grid rendered into a window canvas. In GUI mode
 * all console output (kernel, shell, and console apps) lands here, so
 * the existing shell runs unchanged inside a window.
 */
#include "kernel.h"

#define CELL_W 8
#define CELL_H 16
#define TERM_COLS 80
#define TERM_ROWS 28
#define TERM_W (TERM_COLS * CELL_W)   /* 640 */
#define TERM_H (TERM_ROWS * CELL_H)   /* 448 */

static window_t *term;
static surface_t surf;
static int cx, cy;
static u8 cur_fg = ALPHA_LGREY, cur_bg = ALPHA_BLACK;

/* VGA palette -> ARGB, tuned slightly for a dark terminal background */
static const u32 palette[16] = {
    RGB(0x14, 0x18, 0x1e), RGB(0x2a, 0x4d, 0xd4), RGB(0x28, 0xb4, 0x54),
    RGB(0x28, 0xb0, 0xb0), RGB(0xd0, 0x45, 0x45), RGB(0xc0, 0x50, 0xc0),
    RGB(0xb0, 0x80, 0x30), RGB(0xc8, 0xd0, 0xd8), RGB(0x60, 0x6a, 0x74),
    RGB(0x60, 0x90, 0xff), RGB(0x60, 0xe8, 0x90), RGB(0x60, 0xe0, 0xe0),
    RGB(0xff, 0x70, 0x70), RGB(0xe8, 0x80, 0xe8), RGB(0xf8, 0xd8, 0x60),
    RGB(0xf4, 0xf8, 0xfc),
};

window_t *terminal_window(void);

static void draw_cursor(bool on)
{
    u32 c = on ? palette[cur_fg] : palette[ALPHA_BLACK];
    gfx_fill(&surf, cx * CELL_W, cy * CELL_H + CELL_H - 2, CELL_W, 2, c);
}

static void scroll(void)
{
    if (cy < TERM_ROWS)
        return;
    memmove(surf.px, surf.px + CELL_H * TERM_W,
            (TERM_H - CELL_H) * TERM_W * 4);
    gfx_fill(&surf, 0, TERM_H - CELL_H, TERM_W, CELL_H,
             palette[ALPHA_BLACK]);
    cy = TERM_ROWS - 1;
}

void terminal_create(void)
{
    term = wm_create("Terminal - AlphaOS Shell", TERM_W, TERM_H, NULL,
                     false);
    surf.px = term->canvas;
    surf.w = TERM_W;
    surf.h = TERM_H;
    gfx_fill(&surf, 0, 0, TERM_W, TERM_H, palette[ALPHA_BLACK]);
    cx = cy = 0;
    draw_cursor(true);
}

window_t *terminal_window(void)
{
    return term;
}

void terminal_putc(char c)
{
    if (!term)
        return;
    draw_cursor(false);

    switch (c) {
    case '\n':
        cx = 0;
        cy++;
        break;
    case '\r':
        cx = 0;
        break;
    case '\b':
        if (cx) {
            cx--;
            gfx_fill(&surf, cx * CELL_W, cy * CELL_H, CELL_W, CELL_H,
                     palette[ALPHA_BLACK]);
        }
        break;
    case '\t':
        cx = (cx + 8) & ~7;
        if (cx >= TERM_COLS) {
            cx = 0;
            cy++;
        }
        break;
    default:
        gfx_fill(&surf, cx * CELL_W, cy * CELL_H, CELL_W, CELL_H,
                 palette[cur_bg]);
        gfx_char(&surf, cx * CELL_W, cy * CELL_H, c, palette[cur_fg]);
        cx++;
        if (cx >= TERM_COLS) {
            cx = 0;
            cy++;
        }
    }
    scroll();
    draw_cursor(true);
    wm_mark_dirty();
}

void terminal_clear(void)
{
    if (!term)
        return;
    gfx_fill(&surf, 0, 0, TERM_W, TERM_H, palette[ALPHA_BLACK]);
    cx = cy = 0;
    draw_cursor(true);
    wm_mark_dirty();
}

void terminal_set_color(u8 fg, u8 bg)
{
    cur_fg = fg & 0x0F;
    cur_bg = bg & 0x0F;
}
