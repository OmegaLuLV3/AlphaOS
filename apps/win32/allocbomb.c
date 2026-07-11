/*
 * allocbomb.exe — proves the proc_alloc() header-overflow fix (see
 * SECURITY.md finding #13). Requests an allocation sized just below
 * UINT32_MAX: before the fix, `sizeof(alloc_node_t) + size` silently
 * wrapped past 2^32 when narrowed to the u32 kmalloc() takes, so this
 * call would "succeed" with a real allocation of only a few bytes
 * while VirtualAlloc's own zero-fill then wrote ~4 GiB starting from
 * it, corrupting the entire kernel heap. Now it must fail cleanly
 * (return NULL) instead, and a normal allocation right after must
 * still work correctly -- proving the heap wasn't corrupted along the
 * way, the same way the earlier malformed-PE tests prove the shell
 * survives, not just that the bad call itself was rejected.
 */
#include "win32.h"

static HANDLE out;

static void print(LPCSTR s)
{
    DWORD written;
    WriteConsoleA(out, s, lstrlenA(s), &written, NULL);
}

int wmain(void)
{
    out = GetStdHandle(STD_OUTPUT_HANDLE);

    print("requesting a ~4GiB VirtualAlloc (should fail cleanly)...\r\n");
    void *huge = VirtualAlloc(NULL, 0xFFFFFFF0u, MEM_COMMIT | MEM_RESERVE,
                              PAGE_READWRITE);
    print(huge == NULL ? "VirtualAlloc correctly returned NULL\r\n"
                        : "BUG: VirtualAlloc should have failed!\r\n");

    print("requesting a ~4GiB HeapAlloc (should fail cleanly)...\r\n");
    void *huge2 = HeapAlloc(GetProcessHeap(), 0, 0xFFFFFFF0u);
    print(huge2 == NULL ? "HeapAlloc correctly returned NULL\r\n"
                        : "BUG: HeapAlloc should have failed!\r\n");

    /* if the heap were corrupted by either call above, this normal
       allocation would now behave incorrectly (wrong data back, or a
       crash) */
    char *buf = VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!buf) {
        print("BUG: a normal VirtualAlloc failed after the bad ones!\r\n");
        ExitProcess(1);
    }
    const char *msg = "heap is intact after the rejected allocations";
    int i = 0;
    for (; msg[i]; i++)
        buf[i] = msg[i];
    buf[i] = 0;
    print(buf);
    print("\r\n");
    VirtualFree(buf, 0, MEM_RELEASE);

    ExitProcess(0);
    return 0;
}
