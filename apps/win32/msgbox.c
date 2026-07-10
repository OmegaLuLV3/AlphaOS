/*
 * msgbox.exe — Windows-style GUI call: user32.dll!MessageBoxA.
 * The kernel draws a real modal message box window with an OK button.
 */
#include "win32.h"

int wmain(void)
{
    int r = MessageBoxA(NULL,
                        "Hello from msgbox.exe!\n"
                        "This dialog came from user32.dll!MessageBoxA,\n"
                        "resolved through a real PE import table.",
                        "AlphaOS says", MB_OK);

    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    const char *what = r == IDOK ? "msgbox: you clicked OK\r\n"
                                 : "msgbox: dialog was closed\r\n";
    WriteConsoleA(out, what, lstrlenA(what), &written, NULL);
    return 0;
}
