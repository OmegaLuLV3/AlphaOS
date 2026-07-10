/*
 * The AlphaOS system call table handed to every application, plus
 * per-process allocation tracking so that anything a process fails to
 * free is reclaimed automatically when it exits or crashes.
 */
#include "kernel.h"

typedef struct alloc_node {
    struct alloc_node *next;
    u32 size;
    /* payload follows */
} alloc_node_t;

static void *api_alloc(unsigned int size)
{
    if (!current_process || !size)
        return NULL;
    alloc_node_t *node = kmalloc(sizeof(alloc_node_t) + size);
    if (!node)
        return NULL;
    node->size = size;
    node->next = current_process->allocs;
    current_process->allocs = (struct alloc_node *)node;
    current_process->heap_bytes += size;
    return node + 1;
}

static void api_free(void *ptr)
{
    if (!current_process || !ptr)
        return;
    alloc_node_t *node = (alloc_node_t *)ptr - 1;
    alloc_node_t **pp = (alloc_node_t **)&current_process->allocs;
    for (; *pp; pp = &(*pp)->next) {
        if (*pp == node) {
            *pp = node->next;
            current_process->heap_bytes -= node->size;
            kfree(node);
            return;
        }
    }
    /* pointer not from api_alloc: ignore */
}

void proc_release_all(process_t *p)
{
    alloc_node_t *node = (alloc_node_t *)p->allocs;
    while (node) {
        alloc_node_t *next = node->next;
        kfree(node);
        node = next;
    }
    p->allocs = NULL;
    p->heap_bytes = 0;
}

static void api_meminfo(alpha_meminfo_t *out)
{
    if (!out)
        return;
    out->total_kib = pmm_total_kib();
    out->free_kib = pmm_free_kib();
    kheap_stats(&out->heap_used, &out->heap_free);
}

static void api_exit(int code)
{
    if (current_process && current_process->running) {
        current_process->exit_code = code;
        k_longjmp(current_process->exit_jmp, 1);
    }
    panic("exit() called with no process running");
}

static int api_getch(void) { return input_getch(); }

static int api_readline(char *buf, unsigned int max)
{
    return input_readline(buf, max);
}

static const alpha_api_t table = {
    .version   = ALPHA_API_VERSION,
    .print     = kprint,
    .putchar   = kputc,
    .clear     = console_clear,
    .set_color = console_set_color,
    .getch     = api_getch,
    .readline  = api_readline,
    .alloc     = api_alloc,
    .free      = api_free,
    .meminfo   = api_meminfo,
    .sleep_ms  = sleep_ms,
    .uptime_ms = uptime_ms,
    .exit      = api_exit,
};

const alpha_api_t *api_table(void)
{
    return &table;
}
