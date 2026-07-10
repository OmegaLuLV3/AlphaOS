# AlphaOS

A lightweight 32-bit x86 operating system, written from scratch in C and
assembly, that **loads and runs `.exe` (PE32) files the way Windows
does** — resolving their DLL import tables against a built-in Win32 API
subset — with a Windows-7-inspired graphical desktop and a real driver
layer, while staying tiny and careful about resources.

```
  AlphaOS 0.3 -- a lightweight OS that runs .exe files
  130944 KiB RAM managed | 17672 KiB in use | 8 file(s) on ramdisk
  display: 1024x768x32 desktop | 6 PCI device(s)

alpha> run winhello.exe with args
Hello from winhello.exe -- a Win32-style program!
My imports were resolved from the PE import table.
GetCommandLineA: "winhello.exe with args"
VirtualAlloc gave me a page and it works.
HeapAlloc: 15th triangular number is 120
GetProcAddress(kernel32, GetTickCount) -> uptime 9080 ms
winhello: done, calling ExitProcess(0)
[os] winhello.exe exited with code 0 (60 ms)
```

![start menu](docs/screenshot-startmenu.png)
*The desktop: terminal window running the shell, start menu, taskbar
with live RTC clock.*

![paint.exe](docs/screenshot-paint.png)
*`paint.exe` — a PE32 executable that opens its own window through the
AlphaOS windowing API.*

![msgbox.exe](docs/screenshot-msgbox.png)
*`msgbox.exe` — a Windows-style program calling
`user32.dll!MessageBoxA` through its PE import table.*

## Highlights

- **Real PE32 loader** — validates the full header chain (DOS `MZ` → PE
  signature → COFF → optional header → section table), maps the image at
  its preferred `ImageBase` via paging, copies sections, zero-fills the
  `.bss` tail, and applies base relocations. The `.exe` files it runs are
  structurally valid PE files — `file` reports them as
  `PE32 executable (console) Intel 80386`, and `objdump -p` parses their
  import tables.
- **Native-Windows-style API** — programs import OS functions by name
  from `kernel32.dll` / `user32.dll` through a genuine PE **import
  table**; the loader patches their IAT exactly like Windows' loader
  does. The implemented subset (all `stdcall`, real signatures):
  `ExitProcess`, `GetStdHandle`, `WriteConsoleA`, `WriteFile`,
  `ReadConsoleA`, `Sleep`, `GetTickCount`, `VirtualAlloc`/`VirtualFree`,
  `GetProcessHeap`, `HeapAlloc`/`HeapFree`, `GetCommandLineA`,
  `GetLastError`/`SetLastError`, `LoadLibraryA`, `GetProcAddress`,
  `lstrlenA`, and `user32.dll!MessageBoxA` — which draws a real modal
  dialog with an OK button. Unresolved imports fail the load with the
  missing `dll!symbol` named. Legacy AlphaOS-API programs (no imports)
  still run; the loader picks the convention per binary.
- **GUI desktop (Windows-7 style)** — gradient wallpaper, overlapping
  draggable windows with alpha-blended "glass" title bars and drop
  shadows, a taskbar with a start orb, per-window buttons and a live RTC
  clock, and a start menu listing every `.exe` on the ramdisk. The shell
  runs inside a Terminal window; `.exe` apps can open windows of their
  own through the API (see `paint.exe`). Event-driven compositing: the
  CPU still idles in `hlt`, nothing redraws unless something changed.
- **Driver layer** —
  | driver | hardware | notes |
  |---|---|---|
  | `pci.c` | PCI bus (ports 0xCF8/0xCFC) | enumeration, `lspci`, drivers bind by ID |
  | `bga.c` | Bochs/QEMU VBE display | binds to PCI 1234:1111, 1024×768×32 LFB |
  | `mouse.c` | PS/2 mouse (IRQ 12) | 3-byte packets, ring buffer |
  | `keyboard.c` | PS/2 keyboard (IRQ 1) | scan set 1, shift/caps |
  | `rtc.c` | CMOS real-time clock | taskbar clock, `date` |
  | `pit.c` | 8254 timer (IRQ 0) | 100 Hz tick, sleep, uptime |
  | `serial.c` | 16550 UART | full headless console + logs |
  | `font.c` | VGA | captures the BIOS 8×16 font for the GUI |

  Balanced by design: if the display adapter is missing (e.g. unusual
  real hardware), the OS degrades gracefully to the VGA text-mode shell —
  every feature except windows still works.
- **Lightweight** — kernel ~3.5k lines of C/asm; the whole system boots
  to a composited desktop in well under a second with a 44 KiB kernel.
- **Resource management**
  - Bitmap physical-memory manager + kernel heap with coalescing.
  - Every process allocation is tracked and reclaimed on exit **or
    crash** — including windows an app leaves open (`memhog.exe`,
    `paint.exe`).
  - `mem`, `sysinfo.exe`, and the `meminfo` API expose live statistics.
- **Fault isolation** — CPU exceptions inside an app kill the process,
  not the OS (`crash.exe` demos a null dereference; page 0 is unmapped
  so null pointers actually fault).

## Building and running

Requirements: `gcc` (with 32-bit support), `binutils`, `make`,
`python3`, `qemu-system-i386`. No cross-compiler needed.

```sh
make          # build kernel, .exe apps, and the ramdisk image
make run-vga  # boot the desktop in a QEMU window  <-- the fun one
make run      # headless: serial console in your terminal (Ctrl-A X quits)
make test     # scripted end-to-end boot test (34 assertions)
```

In the GUI: click the orb for the start menu, launch `paint.exe`, drag
windows by their title bars, close them with the ✕. The Terminal window
is the same shell as the serial console — both are live at once.

## Shell commands

| command | description |
|---|---|
| `ls` | list files on the ramdisk |
| `run <file.exe>` | load and execute a PE executable (bare `name.exe` works too) |
| `peinfo <file>` | dump PE headers of an executable |
| `mem` | physical memory and heap statistics |
| `lspci` | list devices found by the PCI driver |
| `date` | read the real-time clock |
| `uptime`, `echo`, `clear`, `help`, `halt` | the usual |

## Bundled programs

| app | demonstrates |
|---|---|
| `hello.exe` | basic output, API versioning |
| `sysinfo.exe` | memory/uptime introspection |
| `primes.exe` | CPU work + heap allocation (sieve of Eratosthenes) |
| `memhog.exe` | leak reclamation: frees half its buffers, OS reclaims the rest |
| `crash.exe` | fault isolation: null deref kills the app, not the OS |
| `paint.exe` | **GUI app**: opens its own window, mouse drawing, palette |
| `winhello.exe` | **Windows-style**: kernel32 imports only — console I/O, VirtualAlloc/HeapAlloc, GetProcAddress, ExitProcess |
| `msgbox.exe` | **Windows-style**: `user32.dll!MessageBoxA` modal dialog |

## How a `.exe` is born and executed

```
apps/foo.c ──gcc -m32──▶ foo.o ──ld (base 0x40001000)──▶ foo.elf
   ──objcopy -O binary──▶ foo.bin ──tools/mkpe.py──▶ foo.exe   (real PE32)
   ──tools/mkinitrd.py──▶ initrd.img ──multiboot module──▶ ramdisk
```

Windows-style apps additionally link IAT slots + trampolines generated
by `tools/mkimports.py` from `apps/win32/imports.list`, and `mkpe.py`
emits the matching PE import directory (descriptors, lookup tables,
hint/name entries).

At `run foo.exe [args]` time the kernel:

1. parses and validates the PE headers and section table,
2. allocates physical frames and maps them at the PE's `ImageBase`
   (0x40000000 — far above kernel identity-mapped RAM, so the preferred
   base is always honored),
3. copies each section to its `VirtualAddress`, zero-fills `.bss`,
   applies `.reloc` fixups if the base ever had to change,
4. **resolves the import table**: every `dll!name` the image imports is
   looked up in the kernel's kernel32/user32 export tables and written
   into the image's IAT — the same job Windows' loader performs,
5. calls the entry point. Binaries with imports get the Windows
   convention (no arguments — the OS is reached purely through
   imports); import-free binaries get the legacy AlphaOS convention
   (`int app_main(const alpha_api_t *os)`, which also carries the
   windowing API used by `paint.exe`),
6. on exit or crash: frees tracked heap allocations (`VirtualAlloc`,
   `HeapAlloc`, and AlphaOS `alloc` all feed the same per-process
   tracker), closes leftover windows, unmaps and frees the image pages,
   and reports anything it had to reclaim.

Apps run in ring 0 in a dedicated address range — a deliberate
lightweight design (no TSS/ring-3 machinery); protection comes from
paging, validation, and exception recovery rather than privilege levels.

Scope note: AlphaOS implements the Win32 *mechanism* (PE imports,
stdcall, IAT patching) and a useful API subset. A program written
against this subset — even built with a real Windows toolchain
(MinGW `-nostdlib`, no CRT) — runs unmodified. Arbitrary off-the-shelf
Windows software still won't: that needs the full Win32 surface and a
CRT (a Wine-sized project). Unsupported imports are reported by name at
load time.

## Layout

```
kernel/   boot.S, GDT/IDT, PIC/PIT, drivers (pci, bga, mouse, kbd, rtc,
          serial, font), pmm, paging, kheap, ramdisk, PE loader + import
          resolver, Win32 API (win32.c), AlphaOS API, gfx, window
          manager/compositor, terminal, shell
          gfx primitives, window manager/compositor, terminal, shell
apps/     crt0.S, app.ld, alpha.h, sample programs; win32/ has the
          Windows-style runtime (win32.h, wincrt0.S, imports.list)
tools/    mkpe.py (flat binary → PE32 w/ import tables), mkimports.py,
          mkinitrd.py, run_tests.sh
include/  alpha_api.h — the kernel↔app ABI, shared by both sides
```
