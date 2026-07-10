/* Software 2D drawing primitives over ARGB32 surfaces, with clipping. */
#include "kernel.h"

static int clip(surface_t *s, int *x, int *y, int *w, int *h)
{
    if (*x < 0) { *w += *x; *x = 0; }
    if (*y < 0) { *h += *y; *y = 0; }
    if (*x + *w > s->w) *w = s->w - *x;
    if (*y + *h > s->h) *h = s->h - *y;
    return *w > 0 && *h > 0;
}

void gfx_fill(surface_t *s, int x, int y, int w, int h, u32 c)
{
    if (!clip(s, &x, &y, &w, &h))
        return;
    for (int j = 0; j < h; j++) {
        u32 *row = s->px + (y + j) * s->w + x;
        for (int i = 0; i < w; i++)
            row[i] = c;
    }
}

void gfx_rect(surface_t *s, int x, int y, int w, int h, u32 c)
{
    gfx_fill(s, x, y, w, 1, c);
    gfx_fill(s, x, y + h - 1, w, 1, c);
    gfx_fill(s, x, y, 1, h, c);
    gfx_fill(s, x + w - 1, y, 1, h, c);
}

void gfx_gradient_v(surface_t *s, int x, int y, int w, int h, u32 top, u32 bot)
{
    int oy = y, oh = h;
    if (!clip(s, &x, &y, &w, &h))
        return;
    int tr = (top >> 16) & 0xFF, tg = (top >> 8) & 0xFF, tb = top & 0xFF;
    int br = (bot >> 16) & 0xFF, bg = (bot >> 8) & 0xFF, bb = bot & 0xFF;
    for (int j = 0; j < h; j++) {
        int t = oh > 1 ? ((y + j - oy) * 255) / (oh - 1) : 0;
        u32 c = RGB(tr + (br - tr) * t / 255,
                    tg + (bg - tg) * t / 255,
                    tb + (bb - tb) * t / 255);
        u32 *row = s->px + (y + j) * s->w + x;
        for (int i = 0; i < w; i++)
            row[i] = c;
    }
}

void gfx_blend(surface_t *s, int x, int y, int w, int h, u32 c, u8 alpha)
{
    if (!clip(s, &x, &y, &w, &h))
        return;
    u32 sr = (c >> 16) & 0xFF, sg = (c >> 8) & 0xFF, sb = c & 0xFF;
    u32 a = alpha, na = 255 - alpha;
    for (int j = 0; j < h; j++) {
        u32 *row = s->px + (y + j) * s->w + x;
        for (int i = 0; i < w; i++) {
            u32 d = row[i];
            u32 r = ((d >> 16 & 0xFF) * na + sr * a) >> 8;
            u32 g = ((d >> 8 & 0xFF) * na + sg * a) >> 8;
            u32 b = ((d & 0xFF) * na + sb * a) >> 8;
            row[i] = 0xFF000000 | (r << 16) | (g << 8) | b;
        }
    }
}

void gfx_char(surface_t *s, int x, int y, char ch, u32 fg)
{
    const u8 *glyph = &vga_font[(u8)ch * 16];
    for (int row = 0; row < 16; row++) {
        int py = y + row;
        if (py < 0 || py >= s->h)
            continue;
        u8 bits = glyph[row];
        for (int col = 0; col < 8; col++) {
            if (!(bits & (0x80 >> col)))
                continue;
            int px = x + col;
            if (px >= 0 && px < s->w)
                s->px[py * s->w + px] = fg;
        }
    }
}

void gfx_text(surface_t *s, int x, int y, const char *str, u32 fg)
{
    for (; *str; str++, x += 8)
        gfx_char(s, x, y, *str, fg);
}

void gfx_circle(surface_t *s, int cx, int cy, int r, u32 c)
{
    for (int dy = -r; dy <= r; dy++) {
        int dx = 0;
        while ((dx + 1) * (dx + 1) + dy * dy <= r * r)
            dx++;
        gfx_fill(s, cx - dx, cy + dy, 2 * dx + 1, 1, c);
    }
}

void gfx_blit(surface_t *dst, int dx, int dy, const surface_t *src)
{
    int x = dx, y = dy, w = src->w, h = src->h;
    int sx = 0, sy = 0;
    if (x < 0) { sx = -x; w += x; x = 0; }
    if (y < 0) { sy = -y; h += y; y = 0; }
    if (x + w > dst->w) w = dst->w - x;
    if (y + h > dst->h) h = dst->h - y;
    for (int j = 0; j < h; j++)
        memcpy(dst->px + (y + j) * dst->w + x,
               src->px + (sy + j) * src->w + sx, w * 4);
}
