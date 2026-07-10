/*
 * Win32 API subset implemented by AlphaOS. Signatures and constants
 * match the real windows.h (stdcall, same argument layout), so code
 * written against this header also compiles with a Windows toolchain.
 */
#ifndef ALPHA_WIN32_H
#define ALPHA_WIN32_H

#define WINAPI __attribute__((stdcall))

typedef unsigned int   DWORD;
typedef int            BOOL;
typedef unsigned int   UINT;
typedef void          *HANDLE;
typedef void          *HMODULE;
typedef void          *HWND;
typedef void          *LPVOID;
typedef const void    *LPCVOID;
typedef char          *LPSTR;
typedef const char    *LPCSTR;
typedef DWORD         *LPDWORD;

#define NULL ((void *)0)
#define TRUE 1
#define FALSE 0

#define STD_INPUT_HANDLE  ((DWORD)-10)
#define STD_OUTPUT_HANDLE ((DWORD)-11)
#define STD_ERROR_HANDLE  ((DWORD)-12)

#define MEM_COMMIT  0x1000
#define MEM_RESERVE 0x2000
#define MEM_RELEASE 0x8000
#define PAGE_READWRITE 0x04
#define HEAP_ZERO_MEMORY 0x08

#define MB_OK 0x0
#define IDOK     1
#define IDCANCEL 2

/* kernel32.dll */
void    WINAPI ExitProcess(DWORD code);
HANDLE  WINAPI GetStdHandle(DWORD which);
BOOL    WINAPI WriteConsoleA(HANDLE h, LPCVOID buf, DWORD len,
                             LPDWORD written, LPVOID reserved);
BOOL    WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len,
                         LPDWORD written, LPVOID overlapped);
BOOL    WINAPI ReadConsoleA(HANDLE h, LPVOID buf, DWORD max,
                            LPDWORD read, LPVOID reserved);
void    WINAPI Sleep(DWORD ms);
DWORD   WINAPI GetTickCount(void);
LPVOID  WINAPI VirtualAlloc(LPVOID addr, DWORD size, DWORD type,
                            DWORD protect);
BOOL    WINAPI VirtualFree(LPVOID addr, DWORD size, DWORD type);
HANDLE  WINAPI GetProcessHeap(void);
LPVOID  WINAPI HeapAlloc(HANDLE heap, DWORD flags, DWORD size);
BOOL    WINAPI HeapFree(HANDLE heap, DWORD flags, LPVOID ptr);
LPSTR   WINAPI GetCommandLineA(void);
DWORD   WINAPI GetLastError(void);
void    WINAPI SetLastError(DWORD err);
HMODULE WINAPI LoadLibraryA(LPCSTR name);
LPVOID  WINAPI GetProcAddress(HMODULE module, LPCSTR name);
int     WINAPI lstrlenA(LPCSTR s);

/* user32.dll */
int     WINAPI MessageBoxA(HWND hwnd, LPCSTR text, LPCSTR caption,
                           UINT type);

/* the program's entry, called by wincrt0 */
int wmain(void);

#endif
