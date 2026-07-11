/*
 * Kernel heap: first-fit free list with block splitting and coalescing
 * over a contiguous physical region. Small, predictable, no fragmentation
 * surprises — every block header records its size so kfree() is O(1)
 * plus a merge with its neighbors.
 */
#include "kernel.h"

#define HEAP_SIZE  (16u * 1024 * 1024) /* holds GUI buffers + app heaps */
#define BLOCK_MAGIC 0xA1FA05B1

typedef struct block {
    u32 magic;
    u32 size;              /* payload bytes */
    bool free;
    struct block *next;
    struct block *prev;
} block_t;

static block_t *heap_head;
static u32 heap_used_bytes;

#define HDR sizeof(block_t)
#define MIN_SPLIT 32

void kheap_init(void)
{
    uptr base = pmm_alloc_contig(HEAP_SIZE / PAGE_SIZE);
    if (!base)
        panic("kheap: cannot allocate heap region");

    /* W^X: this heap backs every kmalloc/kfree in the kernel *and*
       every app-side allocator that routes through it (VirtualAlloc,
       HeapAlloc, malloc, AlphaOS's own alloc -- see api.c's
       proc_alloc()). None of that is ever legitimately code, so
       marking the whole region non-executable closes off the classic
       "corrupt a pointer, jump into heap-sprayed shellcode" primitive
       for every allocation in the system in one place, rather than
       needing to reason about it per call site. */
    for (uptr off = 0; off < HEAP_SIZE; off += PAGE_SIZE)
        paging_map(base + off, base + off, 1, 0);

    heap_head = (block_t *)base;
    heap_head->magic = BLOCK_MAGIC;
    heap_head->size = HEAP_SIZE - HDR;
    heap_head->free = true;
    heap_head->next = NULL;
    heap_head->prev = NULL;
}

void *kmalloc(u32 size)
{
    if (!size)
        return NULL;
    size = (size + 7) & ~7u;

    for (block_t *b = heap_head; b; b = b->next) {
        if (!b->free || b->size < size)
            continue;

        if (b->size >= size + HDR + MIN_SPLIT) {
            block_t *rest = (block_t *)((u8 *)b + HDR + size);
            rest->magic = BLOCK_MAGIC;
            rest->size = b->size - size - HDR;
            rest->free = true;
            rest->next = b->next;
            rest->prev = b;
            if (b->next)
                b->next->prev = rest;
            b->next = rest;
            b->size = size;
        }
        b->free = false;
        heap_used_bytes += b->size;
        return (u8 *)b + HDR;
    }
    return NULL;
}

void kfree(void *ptr)
{
    if (!ptr)
        return;
    block_t *b = (block_t *)((u8 *)ptr - HDR);
    if (b->magic != BLOCK_MAGIC || b->free)
        return; /* invalid or double free: ignore rather than corrupt */

    b->free = true;
    heap_used_bytes -= b->size;

    /* coalesce with next */
    if (b->next && b->next->free) {
        b->size += HDR + b->next->size;
        b->next = b->next->next;
        if (b->next)
            b->next->prev = b;
    }
    /* coalesce with prev */
    if (b->prev && b->prev->free) {
        b->prev->size += HDR + b->size;
        b->prev->next = b->next;
        if (b->next)
            b->next->prev = b->prev;
        b->magic = 0;
    }
}

void kheap_stats(u32 *used, u32 *free_bytes)
{
    if (used)
        *used = heap_used_bytes;
    if (free_bytes)
        *free_bytes = HEAP_SIZE - heap_used_bytes;
}
