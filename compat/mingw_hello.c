/*
 * compat/mingw_hello.c — compiled by a REAL, unmodified mingw-w64
 * toolchain (x86_64-w64-mingw32-gcc, default flags, full CRT), not by
 * AlphaOS's own apps/ pipeline. This is here to prove Win32
 * compatibility empirically rather than just assert it: if this file
 * still runs on AlphaOS after some future change, the kernel32/msvcrt
 * surface in kernel/win32.c (CRT startup, TLS/TEB setup, critical
 * sections, argc/argv, atexit) is still intact.
 *
 * Deliberately ordinary — no special entry point, no -nostdlib, no
 * hand-picked minimal imports. Just `int main(void)`.
 */
#include <windows.h>

int main(void)
{
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const char *msg = "hello from a REAL mingw-w64 compiled Windows binary\r\n";
    DWORD written;
    WriteConsoleA(out, msg, lstrlenA(msg), &written, NULL);
    ExitProcess(0);
    return 0;
}
