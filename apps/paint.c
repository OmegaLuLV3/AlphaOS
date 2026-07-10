/*
 * paint.exe — a windowed GUI application. Opens its own window through
 * the AlphaOS v2 API, draws with the mouse, palette bar on top.
 * Close the window (or crash it) and the OS reclaims everything.
 */
#include "alpha.h"

#define W 420
#define H 300
#define PAL_H 22
#define NCOLORS 8

static const unsigned int palette[NCOLORS] = {
    0xFF101418, 0xFFE84C3C, 0xFF2DCC70, 0xFF3498DB,
    0xFFF1C40F, 0xFF8E44AD, 0xFF7F8C8D, 0xFFFFFFFF,
};

static unsigned int *canvas;

static void dot(int x, int y, unsigned int color)
{
    for (int dy = -1; dy <= 1; dy++)
        for (int dx = -1; dx <= 1; dx++) {
            int px = x + dx, py = y + dy;
            if (px >= 0 && px < W && py >= PAL_H && py < H)
                canvas[py * W + px] = color;
        }
}

/* interpolate between events so fast mouse motion still draws a stroke */
static void stroke(int x0, int y0, int x1, int y1, unsigned int color)
{
    int dx = x1 > x0 ? x1 - x0 : x0 - x1;
    int dy = y1 > y0 ? y1 - y0 : y0 - y1;
    int steps = (dx > dy ? dx : dy) + 1;
    for (int i = 0; i <= steps; i++)
        dot(x0 + (x1 - x0) * i / steps, y0 + (y1 - y0) * i / steps, color);
}

int app_main(const alpha_api_t *os)
{
    if (os->version < 2 || !os->win_create) {
        os->print("paint: this program needs the GUI (run with a display)\n");
        return 1;
    }

    void *win = os->win_create("Paint", W, H);
    if (!win) {
        os->print("paint: could not create a window\n");
        return 1;
    }
    canvas = os->win_canvas(win);

    /* white canvas + palette bar */
    for (int i = 0; i < W * H; i++)
        canvas[i] = 0xFFFFFFFF;
    for (int p = 0; p < NCOLORS; p++)
        for (int y = 0; y < PAL_H - 2; y++)
            for (int x = 0; x < 24; x++)
                canvas[y * W + p * 26 + x + 2] = palette[p];
    os->win_present(win);

    os->print("paint: window open -- draw with the mouse, "
              "click a swatch to change color\n");

    unsigned int color = palette[0];
    int drawing = 0, running = 1;
    int lx = 0, ly = 0;
    alpha_event_t ev;

    while (running) {
        int changed = 0;
        while (os->win_poll(win, &ev)) {
            switch (ev.type) {
            case ALPHA_EV_CLOSE:
                running = 0;
                break;
            case ALPHA_EV_MOUSE_DOWN:
                if (ev.y < PAL_H) {
                    int p = (ev.x - 2) / 26;
                    if (p >= 0 && p < NCOLORS)
                        color = palette[p];
                } else {
                    drawing = 1;
                    lx = ev.x;
                    ly = ev.y;
                    dot(ev.x, ev.y, color);
                    changed = 1;
                }
                break;
            case ALPHA_EV_MOUSE_UP:
                drawing = 0;
                break;
            case ALPHA_EV_MOUSE_MOVE:
                if (drawing && (ev.buttons & 1)) {
                    stroke(lx, ly, ev.x, ev.y, color);
                    lx = ev.x;
                    ly = ev.y;
                    changed = 1;
                }
                break;
            }
        }
        if (changed)
            os->win_present(win);
        os->sleep_ms(10); /* idle politely: the CPU sleeps in hlt */
    }

    os->win_destroy(win);
    os->print("paint: window closed, bye\n");
    return 0;
}
