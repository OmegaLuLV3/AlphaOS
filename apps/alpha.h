/* Convenience header for AlphaOS applications. */
#ifndef APPS_ALPHA_H
#define APPS_ALPHA_H

#include "../include/alpha_api.h"

int app_main(const alpha_api_t *os);

/* tiny printf supporting %s %c %d %u %x — enough for sample apps */
static void __attribute__((unused)) aprintf(const alpha_api_t *os, const char *fmt, ...)
{
    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    for (; *fmt; fmt++) {
        if (*fmt != '%') {
            os->putchar(*fmt);
            continue;
        }
        fmt++;
        if (*fmt == 's') {
            const char *s = __builtin_va_arg(ap, const char *);
            os->print(s ? s : "(null)");
        } else if (*fmt == 'c') {
            os->putchar((char)__builtin_va_arg(ap, int));
        } else if (*fmt == 'd' || *fmt == 'u' || *fmt == 'x') {
            unsigned int v;
            if (*fmt == 'd') {
                int sv = __builtin_va_arg(ap, int);
                if (sv < 0) {
                    os->putchar('-');
                    sv = -sv;
                }
                v = (unsigned int)sv;
            } else {
                v = __builtin_va_arg(ap, unsigned int);
            }
            unsigned int base = (*fmt == 'x') ? 16 : 10;
            char buf[12];
            int i = 0;
            if (!v)
                buf[i++] = '0';
            while (v) {
                buf[i++] = "0123456789abcdef"[v % base];
                v /= base;
            }
            while (i--)
                os->putchar(buf[i]);
        } else {
            os->putchar('%');
            if (*fmt)
                os->putchar(*fmt);
            else
                break;
        }
    }
    __builtin_va_end(ap);
}

#endif
