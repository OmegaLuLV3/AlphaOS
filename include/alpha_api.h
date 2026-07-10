/*
 * AlphaOS application API.
 *
 * Every .exe entry point receives a pointer to this table on the stack
 * (cdecl):  int app_main(const alpha_api_t *os);
 *
 * This header is shared between the kernel (which implements the table)
 * and applications (which consume it), so it must stay ABI-stable:
 * only append fields, never reorder or remove them, and bump
 * ALPHA_API_VERSION when appending.
 */
#ifndef ALPHA_API_H
#define ALPHA_API_H

#define ALPHA_API_VERSION 2

typedef struct alpha_meminfo {
    unsigned int total_kib;   /* usable RAM managed by the kernel        */
    unsigned int free_kib;    /* currently free physical memory          */
    unsigned int heap_used;   /* bytes used in the kernel heap           */
    unsigned int heap_free;   /* bytes free in the kernel heap           */
} alpha_meminfo_t;

/* window events (API v2) */
enum {
    ALPHA_EV_NONE = 0,
    ALPHA_EV_KEY,          /* key: ASCII code                       */
    ALPHA_EV_MOUSE_DOWN,   /* x,y: canvas coords, buttons: bitmask  */
    ALPHA_EV_MOUSE_UP,
    ALPHA_EV_MOUSE_MOVE,
    ALPHA_EV_CLOSE,        /* user clicked the close button         */
};

typedef struct alpha_event {
    unsigned int type;
    int x, y;
    int buttons;           /* bit 0 = left, bit 1 = right */
    int key;
} alpha_event_t;

typedef struct alpha_api {
    unsigned int version;

    /* console */
    void (*print)(const char *s);
    void (*putchar)(char c);
    void (*clear)(void);
    void (*set_color)(unsigned char fg, unsigned char bg);

    /* input (blocking) */
    int  (*getch)(void);
    int  (*readline)(char *buf, unsigned int max);

    /* memory — allocations are tracked per process and reclaimed on exit */
    void *(*alloc)(unsigned int size);
    void  (*free)(void *ptr);
    void  (*meminfo)(alpha_meminfo_t *out);

    /* time */
    void         (*sleep_ms)(unsigned int ms);
    unsigned int (*uptime_ms)(void);

    /* process */
    void (*exit)(int code); /* does not return */

    /* ---- v2: windowing (NULL / absent when the OS runs in text mode;
       check version >= 2 AND win_create != NULL before using) ---- */
    void *(*win_create)(const char *title, int w, int h);
    void  (*win_destroy)(void *win);
    unsigned int *(*win_canvas)(void *win);  /* w*h ARGB32 pixels */
    void  (*win_present)(void *win);         /* push canvas to screen */
    int   (*win_poll)(void *win, alpha_event_t *ev); /* 1 = got event */
} alpha_api_t;

/* VGA color codes for set_color() */
enum {
    ALPHA_BLACK = 0,  ALPHA_BLUE = 1,     ALPHA_GREEN = 2,  ALPHA_CYAN = 3,
    ALPHA_RED = 4,    ALPHA_MAGENTA = 5,  ALPHA_BROWN = 6,  ALPHA_LGREY = 7,
    ALPHA_DGREY = 8,  ALPHA_LBLUE = 9,    ALPHA_LGREEN = 10, ALPHA_LCYAN = 11,
    ALPHA_LRED = 12,  ALPHA_LMAGENTA = 13, ALPHA_YELLOW = 14, ALPHA_WHITE = 15,
};

#endif
