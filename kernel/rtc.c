/* CMOS real-time clock driver — powers the taskbar clock and `date`. */
#include "kernel.h"

static u8 cmos_read(u8 reg)
{
    outb(0x70, reg);
    return inb(0x71);
}

static u8 bcd(u8 v)
{
    return (v >> 4) * 10 + (v & 0x0F);
}

void rtc_read(rtc_time_t *t)
{
    /* wait until no update is in progress so we read a consistent time */
    while (cmos_read(0x0A) & 0x80)
        ;

    u8 sec = cmos_read(0x00);
    u8 min = cmos_read(0x02);
    u8 hour = cmos_read(0x04);
    u8 day = cmos_read(0x07);
    u8 month = cmos_read(0x08);
    u8 year = cmos_read(0x09);
    u8 status_b = cmos_read(0x0B);

    if (!(status_b & 0x04)) { /* BCD mode */
        sec = bcd(sec);
        min = bcd(min);
        hour = bcd(hour & 0x7F) | (hour & 0x80);
        day = bcd(day);
        month = bcd(month);
        year = bcd(year);
    }
    if (!(status_b & 0x02) && (hour & 0x80)) /* 12h mode, PM bit */
        hour = ((hour & 0x7F) + 12) % 24;

    t->sec = sec;
    t->min = min;
    t->hour = hour;
    t->day = day;
    t->month = month;
    t->year = 2000 + year;
}
