/*
 * winhello.exe — a Windows-style program. No AlphaOS API anywhere:
 * everything goes through PE imports from kernel32.dll, exactly like a
 * native Win32 console application.
 */
#include "win32.h"

static HANDLE out;

static void print(LPCSTR s)
{
    DWORD written;
    WriteConsoleA(out, s, lstrlenA(s), &written, NULL);
}

static void print_num(DWORD v)
{
    char buf[12];
    int i = 11;
    buf[i] = 0;
    if (!v)
        buf[--i] = '0';
    while (v) {
        buf[--i] = '0' + v % 10;
        v /= 10;
    }
    print(&buf[i]);
}

int wmain(void)
{
    out = GetStdHandle(STD_OUTPUT_HANDLE);

    print("Hello from winhello.exe -- a Win32-style program!\r\n");
    print("My imports were resolved from the PE import table.\r\n");

    print("GetCommandLineA: \"");
    print(GetCommandLineA());
    print("\"\r\n");

    /* memory through VirtualAlloc, like a native app would */
    char *buf = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE,
                             PAGE_READWRITE);
    if (!buf) {
        print("VirtualAlloc failed!\r\n");
        return 1;
    }
    const char *msg = "VirtualAlloc gave me a page and it works.";
    for (int i = 0; msg[i]; i++)
        buf[i] = msg[i];
    print(buf);
    print("\r\n");
    VirtualFree(buf, 0, MEM_RELEASE);

    /* HeapAlloc path too */
    DWORD *nums = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                            16 * sizeof(DWORD));
    for (int i = 1; i < 16; i++)
        nums[i] = nums[i - 1] + i; /* triangular numbers */
    print("HeapAlloc: 15th triangular number is ");
    print_num(nums[15]);
    print("\r\n");
    HeapFree(GetProcessHeap(), 0, nums);

    /* dynamic linking, the Windows way */
    HMODULE k32 = LoadLibraryA("kernel32.dll");
    DWORD(WINAPI * pGetTickCount)(void) =
        GetProcAddress(k32, "GetTickCount");
    if (pGetTickCount) {
        print("GetProcAddress(kernel32, GetTickCount) -> uptime ");
        print_num(pGetTickCount());
        print(" ms\r\n");
    }

    Sleep(30);
    print("winhello: done, calling ExitProcess(0)\r\n");
    ExitProcess(0);
    return 42; /* never reached */
}
