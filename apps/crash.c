/*
 * crash.exe — deliberately dereferences an unmapped address to prove
 * the kernel's fault isolation: the process is killed and its resources
 * reclaimed, but the OS and shell keep running.
 */
#include "alpha.h"

int app_main(const alpha_api_t *os)
{
    os->print("about to dereference a null pointer. wish me luck!\n");
    os->alloc(1234); /* leak on purpose so the reaper has work to do */

    volatile int *p = (volatile int *)0;
    return *p; /* page fault -> kernel kills us, shell survives */
}
