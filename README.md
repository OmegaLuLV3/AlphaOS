# AlphaOS

A lightweight 32-bit x86 operating system, written from scratch in C and
assembly, that **loads and runs `.exe` (PE32) files** — with careful
resource management as a core design goal.

```
  AlphaOS 0.1 -- a lightweight OS that runs .exe files
  130944 KiB RAM managed | 9432 KiB in use | 5 file(s) on ramdisk
  type 'help' for commands

alpha> run hello.exe
Hello from hello.exe!
I am a PE32 executable loaded by AlphaOS (API v1).
[os] hello.exe exited with code 0 (0 ms)
```

## Highlights

- **Real PE32 loader** — validates the full header chain (DOS `MZ` → PE
  signature → COFF → optional header → section table), maps the image at
  its preferred `ImageBase` via paging, copies sections, zero-fills the
  `.bss` tail (`VirtualSize` > `SizeOfRawData`), and applies base
  relocations when present. The `.exe` files it runs are structurally
  valid PE files — `file` reports them as
  `PE32 executable (console) Intel 80386`.
- **Lightweight** — the kernel is ~2,000 lines of C/asm; a full system
  (kernel + 5 apps + ramdisk) is under 100 KiB and boots in QEMU with
  128 MiB of RAM in a fraction of a second. Apps are 1–2 KiB each.
- **Resource management**
  - Bitmap physical-memory manager (4 KiB frames; 512 MiB costs 16 KiB
    of bitmap).
  - Kernel heap with block splitting and coalescing on free.
  - Every allocation a process makes is tracked; when it exits — or
    crashes — the kernel reclaims anything it leaked, plus its image
    pages. `memhog.exe` demos this on purpose.
  - `mem`, `sysinfo.exe`, and the `meminfo` API expose live statistics.
- **Fault isolation** — CPU exceptions inside an app (e.g. the null
  dereference in `crash.exe`) kill the process and return to the shell;
  the OS keeps running. Virtual page 0 is left unmapped so null-pointer
  bugs fault instead of silently reading memory.
- **Dual console** — VGA text mode and COM1 serial simultaneously, so it
  is fully usable headless (`make run`) or with a display (`make run-vga`).

## Building and running

Requirements: `gcc` (with 32-bit support), `binutils`, `make`,
`python3`, `qemu-system-i386`. No cross-compiler needed.

```sh
make          # build kernel, .exe apps, and the ramdisk image
make run      # boot in QEMU, serial console in your terminal (Ctrl-A X to quit)
make run-vga  # boot with a VGA window
make test     # scripted end-to-end boot test (17 assertions)
```

## Shell commands

| command | description |
|---|---|
| `ls` | list files on the ramdisk |
| `run <file.exe>` | load and execute a PE executable (bare `name.exe` works too) |
| `peinfo <file>` | dump PE headers of an executable |
| `mem` | physical memory and heap statistics |
| `uptime` | time since boot |
| `echo`, `clear`, `help`, `halt` | the usual |

## Bundled programs

| app | demonstrates |
|---|---|
| `hello.exe` | basic output, API versioning |
| `sysinfo.exe` | memory/uptime introspection |
| `primes.exe` | CPU work + heap allocation (sieve of Eratosthenes) |
| `memhog.exe` | leak reclamation: frees half its buffers, OS reclaims the rest |
| `crash.exe` | fault isolation: null deref kills the app, not the OS |

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
   (`int app_main(const alpha_api_t *os)`) — print, readline, alloc,
   free, sleep, meminfo, exit…,
5. on exit or crash: frees tracked heap allocations, unmaps and frees
   the image pages, reports anything it had to reclaim.

Apps run in ring 0 in a dedicated address range — a deliberate
lightweight design (no TSS/ring-3 machinery); protection comes from
paging, validation, and exception recovery rather than privilege levels.

Note: AlphaOS runs PE executables built against its own API — Windows
programs won't run, since AlphaOS implements its own syscall table, not
the Win32 API (that would be a Wine-sized project).

## Layout

```
kernel/   boot.S, GDT/IDT, PIC/PIT, keyboard, console+serial,
          pmm, paging, kheap, ramdisk, PE loader, API, shell
apps/     crt0.S, app.ld, alpha.h and the sample programs
tools/    mkpe.py (flat binary → PE32), mkinitrd.py, run_tests.sh
include/  alpha_api.h — the kernel↔app ABI, shared by both sides
```
