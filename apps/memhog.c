/*
 * memhog.exe — demonstrates the kernel's per-process resource tracking.
 * Allocates a pile of buffers, frees only half of them, and exits;
 * the OS reclaims the rest automatically ("[os] reclaimed ..." line).
 */
#include "alpha.h"

#define CHUNKS 16
#define CHUNK_SIZE 4096

int app_main(const alpha_api_t *os)
{
    void *ptrs[CHUNKS];
    alpha_meminfo_t before, after;

    os->meminfo(&before);
    aprintf(os, "heap used before: %u bytes\n", before.heap_used);

    for (int i = 0; i < CHUNKS; i++) {
        ptrs[i] = os->alloc(CHUNK_SIZE);
        if (!ptrs[i]) {
            os->print("allocation failed!\n");
            return 1;
        }
        /* touch the memory so it's really ours */
        for (int j = 0; j < CHUNK_SIZE; j++)
            ((unsigned char *)ptrs[i])[j] = (unsigned char)(i ^ j);
    }
    os->meminfo(&after);
    aprintf(os, "allocated %u KiB in %d chunks, heap used now: %u bytes\n",
            (CHUNKS * CHUNK_SIZE) / 1024, CHUNKS, after.heap_used);

    /* deliberately free only the even chunks */
    for (int i = 0; i < CHUNKS; i += 2)
        os->free(ptrs[i]);
    os->print("freed half of them; leaking the rest on purpose...\n");
    os->print("watch the OS clean up after me:\n");
    return 0;
}
