/*
 * Win32 API subset implemented by AlphaOS. Signatures and constants
 * match the real windows.h, using the real Microsoft x64 calling
 * convention (ms_abi), so code written against this header also
 * compiles with a Windows toolchain (MinGW, -nostdlib) unmodified.
 */
#ifndef ALPHA_WIN32_H
#define ALPHA_WIN32_H

#define WINAPI __attribute__((ms_abi))

typedef unsigned int   DWORD;
typedef unsigned long  SIZE_T;   /* 8 bytes on x64, matches real Windows */
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
LPVOID  WINAPI VirtualAlloc(LPVOID addr, SIZE_T size, DWORD type,
                            DWORD protect);
BOOL    WINAPI VirtualFree(LPVOID addr, SIZE_T size, DWORD type);
HANDLE  WINAPI GetProcessHeap(void);
LPVOID  WINAPI HeapAlloc(HANDLE heap, DWORD flags, SIZE_T size);
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
