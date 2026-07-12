/*
 * diskfile.exe — exercises real Win32 file I/O against the *writable*
 * FAT disk (kernel/ata.c + kernel/fat.c), as opposed to readfile.exe
 * which only ever touches the strictly-read-only ramdisk. Creates a
 * file with CREATE_ALWAYS + GENERIC_WRITE, writes known bytes, closes
 * it (committing to the FAT disk), then reopens with OPEN_EXISTING +
 * GENERIC_READ and reads the bytes back to prove a genuine round trip
 * through the disk, not just an in-memory echo.
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

    const char *msg = "written by diskfile.exe via CreateFileA/WriteFile";
    HANDLE f = CreateFileA("DFTEST.TXT", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        print("CreateFileA(CREATE_ALWAYS) on the disk failed!\r\n");
        ExitProcess(1);
    }

    DWORD written = 0;
    BOOL wok = WriteFile(f, msg, lstrlenA(msg), &written, NULL);
    CloseHandle(f);
    if (!wok || written != (DWORD)lstrlenA(msg)) {
        print("WriteFile to the disk failed!\r\n");
        ExitProcess(1);
    }
    print("wrote DFTEST.TXT to the disk\r\n");

    HANDLE g = CreateFileA("DFTEST.TXT", GENERIC_READ, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (g == INVALID_HANDLE_VALUE) {
        print("re-opening DFTEST.TXT (OPEN_EXISTING) failed!\r\n");
        ExitProcess(1);
    }

    char buf[128];
    DWORD read = 0;
    BOOL rok = ReadFile(g, buf, sizeof(buf) - 1, &read, NULL);
    CloseHandle(g);
    buf[read] = 0;

    BOOL match = rok && read == written;
    for (DWORD i = 0; match && i < read; i++)
        if (buf[i] != msg[i])
            match = FALSE;

    if (match)
        print("disk round trip OK: read back exactly what was written\r\n");
    else
        print("BUG: disk round trip mismatch\r\n");

    ExitProcess(0);
    return 0;
}
