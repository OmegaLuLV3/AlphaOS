/*
 * compat/mingw_readfile.c — compiled by a REAL, unmodified mingw-w64
 * toolchain, exercising real Win32 file I/O (CreateFileA/ReadFile/
 * GetFileSize/CloseHandle) against AlphaOS's ramdisk-backed
 * kernel32.dll implementation. Uses the raw Win32 calls directly
 * rather than mingw's <stdio.h> fopen/fread, deliberately: those go
 * through a much larger piece of the real Windows CRT (ultimately a
 * different syscall path) that AlphaOS doesn't implement, whereas
 * CreateFileA/ReadFile are exactly the two kernel32 exports this is
 * meant to prove.
 */
#include <windows.h>

int main(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;

    HANDLE f = CreateFileA("data.txt", GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        const char *msg = "mingw_readfile: CreateFileA failed\r\n";
        WriteConsoleA(out, msg, lstrlenA(msg), &written, NULL);
        ExitProcess(1);
    }

    char buf[128];
    DWORD size = GetFileSize(f, NULL);
    DWORD read = 0;
    ReadFile(f, buf, size < sizeof(buf) ? size : sizeof(buf) - 1, &read,
             NULL);
    buf[read] = 0;
    CloseHandle(f);

    const char *prefix = "mingw_readfile: real Win32 file I/O read: ";
    WriteConsoleA(out, prefix, lstrlenA(prefix), &written, NULL);
    WriteConsoleA(out, buf, lstrlenA(buf), &written, NULL);

    ExitProcess(0);
    return 0;
}
