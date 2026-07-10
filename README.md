# AlphaOS

A lightweight 32-bit x86 operating system, written from scratch in C and
assembly, that **loads and runs `.exe` (PE32) files** — now with a
Windows-7-inspired graphical desktop and a real driver layer, while
staying tiny and careful about resources.

```
  AlphaOS 0.2 -- a lightweight OS that runs .exe files
  130944 KiB RAM managed | 17608 KiB in use | 6 file(s) on ramdisk
  display: 1024x768x32 desktop | 6 PCI device(s)

alpha> run hello.exe
Hello from hello.exe!
I am a PE32 executable loaded by AlphaOS (API v2).
[os] hello.exe exited with code 0 (0 ms)
```

## Highlights

- **Real PE32 loader** — validates the full header chain (DOS `MZ` → PE
  signature → COFF → optional header → section table), maps the image at
  its preferred `ImageBase` via paging, copies sections, zero-fills the
  `.bss` tail, and applies base relocations. The `.exe` files it runs are
  structurally valid PE files — `file` reports them as
  `PE32 executable (console) Intel 80386`.
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
make test     # scripted end-to-end boot test (25 assertions)
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

## How a `.exe` is born and executed

```
apps/foo.c ──gcc -m32──▶ foo.o ──ld (base 0x40001000)──▶ foo.elf
   ──objcopy -O binary──▶ foo.bin ──tools/mkpe.py──▶ foo.exe   (real PE32)
   ──tools/mkinitrd.py──▶ initrd.img ──multiboot module──▶ ramdisk
```

At `run foo.exe` time the kernel:

1. parses and validates the PE headers and section table,
2. allocates physical frames and maps them at the PE's `ImageBase`
   (0x40000000 — far above kernel identity-mapped RAM, so the preferred
   base is always honored),
3. copies each section to its `VirtualAddress`, zero-fills `.bss`,
   applies `.reloc` fixups if the base ever had to change,
4. calls the entry point with the AlphaOS API table
   (`int app_main(const alpha_api_t *os)`) — console I/O, alloc/free,
   sleep, meminfo, exit, and in API v2: `win_create` / `win_canvas` /
   `win_present` / `win_poll` / `win_destroy` for windowed apps,
5. on exit or crash: frees tracked heap allocations, closes leftover
   windows, unmaps and frees the image pages, reports anything it had
   to reclaim.

Apps run in ring 0 in a dedicated address range — a deliberate
lightweight design (no TSS/ring-3 machinery); protection comes from
paging, validation, and exception recovery rather than privilege levels.

Note: AlphaOS runs PE executables built against its own API — Windows
programs won't run, since AlphaOS implements its own syscall table, not
the Win32 API (that would be a Wine-sized project).

## Layout

```
kernel/   boot.S, GDT/IDT, PIC/PIT, drivers (pci, bga, mouse, kbd, rtc,
          serial, font), pmm, paging, kheap, ramdisk, PE loader, API,
          gfx primitives, window manager/compositor, terminal, shell
apps/     crt0.S, app.ld, alpha.h and the sample programs
tools/    mkpe.py (flat binary → PE32), mkinitrd.py, run_tests.sh
include/  alpha_api.h — the kernel↔app ABI, shared by both sides
```
