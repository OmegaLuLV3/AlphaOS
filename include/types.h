#ifndef ALPHA_TYPES_H
#define ALPHA_TYPES_H

typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;

/* pointer-sized integer: 8 bytes under -m64. Addresses in this OS are
   always kept below 4 GiB by design (kernel, apps, and the framebuffer
   all live in low memory), but page table entries, CR3, and the PE32+
   ImageBase field are genuinely 64-bit quantities, so code that stores
   or manipulates raw addresses uses uptr rather than u32. */
typedef unsigned long uptr;
typedef unsigned long usize;

#define NULL ((void *)0)
#define true 1
#define false 0
typedef int bool;

#endif
