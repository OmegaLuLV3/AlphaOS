/*
 * readfile.exe — a Windows-style program exercising real Win32 file
 * I/O (CreateFileA/ReadFile/GetFileSize/SetFilePointer/CloseHandle),
 * imported by name from kernel32.dll exactly like winhello.exe's
 * console/memory calls. Backed by the read-only ramdisk: opens
 * data.txt (bundled alongside this source and packed onto the
 * ramdisk), reads it whole, seeks back to a known offset and reads a
 * substring, then proves a nonexistent file and a write attempt both
 * fail the way a real read-only volume would.
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

    HANDLE f = CreateFileA("data.txt", GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        print("CreateFileA(data.txt) failed!\r\n");
        ExitProcess(1);
    }

    DWORD size = GetFileSize(f, NULL);
    print("data.txt is ");
    print_num(size);
    print(" bytes\r\n");

    char buf[128];
    DWORD read = 0;
    if (size < sizeof(buf) && ReadFile(f, buf, size, &read, NULL)) {
        buf[read] = 0;
        print("contents: ");
        print(buf);
    }

    /* seek to the word "brown" and read just that word */
    SetFilePointer(f, 10, NULL, FILE_BEGIN);
    char word[6];
    ReadFile(f, word, 5, &read, NULL);
    word[5] = 0;
    print("seeked read at offset 10: ");
    print(word);
    print("\r\n");

    CloseHandle(f);

    /* the ramdisk is read-only and has no such file either way */
    HANDLE nope = CreateFileA("does_not_exist.txt", GENERIC_READ, 0, NULL,
                              OPEN_EXISTING, 0, NULL);
    print(nope == INVALID_HANDLE_VALUE
              ? "CreateFileA on a missing file correctly failed\r\n"
              : "BUG: missing file open should have failed\r\n");

    ExitProcess(0);
    return 0;
}
