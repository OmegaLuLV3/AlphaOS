/*
 * noexec.exe — deliberately writes a one-byte `ret` machine-code stub
 * into a heap allocation (os->alloc(), the same tracked allocator
 * VirtualAlloc/HeapAlloc/malloc all route through — see api.c's
 * proc_alloc()) and jumps into it.
 *
 * This is here to prove the kernel heap is genuinely non-executable
 * (see SECURITY.md finding #12), the same way crash.exe proves page 0
 * is genuinely unmapped: before that fix, this would have executed the
 * `ret` and returned normally; now the instruction fetch itself must
 * page-fault (NX violation), and the kernel's fault isolation kills
 * this process while the OS and shell keep running.
 */
#include "alpha.h"

typedef void (*fn_t)(void);

int app_main(const alpha_api_t *os)
{
    os->print("about to jump into heap-allocated bytes. wish me luck!\n");

    unsigned char *code = (unsigned char *)os->alloc(16);
    code[0] = 0xC3; /* ret */

    fn_t f = (fn_t)code;
    f(); /* NX page fault -> kernel kills us, shell survives */

    os->print("if you see this, the heap was executable -- BAD\n");
    return 0;
}
