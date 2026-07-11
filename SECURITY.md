# AlphaOS security assessment

This is a from-scratch, un-audited hobby kernel — treat it as a research/
learning OS, not a hardened production system. This document records a
real audit pass (not a checklist exercise): findings are things that were
actually read, understood, exploited-in-analysis, fixed, and then
re-verified against the running kernel, including with deliberately
malicious input files. Every fix below is reflected in the current code
and covered by `make test`.

## Findings fixed in this pass

### 1. Kernel panic via malformed `.exe` (CWE-248 / DoS) — **critical**

**Where:** `kernel/pe.c`, `pe_run()`.

`current_process->running` was only set to `true` immediately before
calling the entry point. But header/section copying, base-relocation
processing, and import-table walking — all of which dereference
file-supplied offsets — ran *before* that point. `kernel/idt.c`'s fault
handler only kills the current process (`k_longjmp`) when
`current_process && current_process->running`; otherwise it calls
`panic()`, halting the entire machine.

**Impact:** a single malformed (or maliciously crafted) `.exe` placed on
the ramdisk, or reached through any future loader path, could take down
the whole OS on `run`/`peinfo` — turning "one bad file" into "reboot the
machine," which defeats the entire point of the process/fault-isolation
model this OS is built around.

**Fix:** `pe_run()` now constructs the `process_t`, sets
`current_process`, and calls `k_setjmp()` *before* any file-controlled
memory operation. `proc.running = true` covers the full load sequence —
header copy, section copies, relocations, import resolution, and entry
execution — as a single fault-isolated region. A fault anywhere in that
span now correctly kills just that one load attempt.

**Verified:** three crafted malicious PE files (see "Verification"
below) that previously would have faulted during import resolution or
section copying with `current_process->running == false` are now
rejected cleanly, and the shell — and a subsequent normal `run
hello.exe` — remain fully functional afterward.

### 2. Integer-overflow bounds-check bypasses (CWE-190) — **critical**

**Where:** `kernel/pe.c` (`pe_parse`, `resolve_imports`), `kernel/ramdisk.c`
(`ramdisk_init`).

Several bounds checks added two attacker-controlled `u32` values and
compared the *32-bit* sum against a limit, e.g.:

```c
if (dos->e_lfanew + 4 + sizeof(coff_header_t) > f->size)   /* BEFORE */
```

If `e_lfanew` is near `0xFFFFFFFF`, the sum wraps to a small number, the
check passes when it should fail, and the wrapped value is then used
directly in pointer arithmetic (`f->data + dos->e_lfanew`) — a wild,
attacker-steered pointer, dozens of GiB away from any valid buffer. The
same pattern existed in: section `raw_ptr`/`raw_size` bounds, the PE32+
optional-header bound, the import-directory bound, the import
hint/name-offset bound, and the ramdisk archive's per-entry
`offset`/`size` bound.

**Fix:** every such check now widens at least one operand to `uptr`
(64-bit) before adding, so the comparison happens in an arithmetic
domain large enough that a legitimate `u32` field can never wrap it.

### 3. Unvalidated `ilt_rva` in import resolution — **high**

**Where:** `kernel/pe.c`, `resolve_imports()`.

The loader validated `iat_rva` but used `ilt_rva` (when nonzero) to
build the *lookup* table pointer without validating it at all —
`ilt_rva` is fully attacker-controlled and was dereferenced immediately.

**Fix:** whichever of `ilt_rva`/`iat_rva` is actually used is now bounds-
checked before any pointer built from it is dereferenced.

### 4. Read-before-bounds-check loop ordering (CWE-125) — **high**

**Where:** `kernel/pe.c`, `resolve_imports()`.

Both the import-descriptor loop and the thunk loop were written as
`for (...; d->name_rva; d++) { if (out_of_bounds) return err; ... }` —
the *loop condition* dereferences the next entry before the *body's*
bounds check ever runs for it. The first iteration is protected by a
pre-loop check; every iteration after that reads one entry ahead of
what's been validated.

**Fix:** both loops now check bounds as the *first* statement of every
iteration, before touching the entry at all, then read/act on it, then
advance — no dereference is ever unconditioned on a bounds check for
that specific access.

### 5. Missing IAT write-target bound (CWE-787, OOB write) — **high**

**Where:** `kernel/pe.c`, `resolve_imports()`.

The per-thunk loop bounds-checked the *lookup table* (read side) but
never separately validated `iat_rva + i*8` (write side) as `i` grows.
`ilt_rva` and `iat_rva` can point at different regions with different
valid extents in a crafted file, so a long lookup table paired with a
short IAT array could write past the IAT's actual bounds.

**Fix:** the write target is now bounds-checked on every iteration,
independently of the read side.

### 6. `size_of_headers` never checked against `size_of_image` (OOB write)
— **high**

**Where:** `kernel/pe.c`, `pe_run()`.

The initial header copy is `memcpy(base, f->data, min(size_of_headers,
f->size))`. `f->size` bounds the *source*, but nothing bounded
`size_of_headers` against `size_of_image` (which determines how many
pages are actually mapped at `base`) — a file with a small `size_of_image`
but a deliberately huge `size_of_headers`, backed by a large enough file,
could write past the mapped destination region.

**Fix:** `pe_parse()` now rejects `size_of_headers > size_of_image`.

### 7. Allocation-size truncation in the Win32 allocator shims (CWE-197)
— **medium**

**Where:** `kernel/win32.c` — `VirtualAlloc`, `HeapAlloc`, `malloc`,
`calloc`.

Windows `SIZE_T` is 64-bit; these all cast straight to `(u32)size` before
calling `proc_alloc()`. A caller requesting e.g. `0x100000001` (4 GiB + 1)
bytes would silently get a 1-byte allocation while believing it holds
4 GiB — the classic truncation-then-overflow pattern. `calloc(n, size)`
additionally multiplied `n * size` in `u64` with no overflow check at
all (the classic `calloc`-overflow class, real CVEs in real libc
implementations).

**Fix:** a shared `checked_alloc()` rejects (returns `NULL`, matching
real allocator failure semantics) anything that wouldn't survive the
32-bit narrowing intact; `calloc` additionally checks the multiplication
for overflow before computing the total.

### 8. Unbounded ramdisk archive entry count (OOB read) — **low**
(build-time-trusted today; fixed as defense in depth)

**Where:** `kernel/ramdisk.c`, `ramdisk_init()`.

The archive's entry `count` field was clamped to `MAX_FILES` but never
validated against the module's actual mapped size before the entry
table was read — a `count` near the max with a tiny actual module would
read entry-table bytes past the real allocation.

**Fix:** `count` is now also clamped by how many entries could possibly
fit in `mod_size` before anything is read.

### 9. `apply_relocs()` had no bounds checking at all

**Where:** `kernel/pe.c`.

`rva`/`size` from the relocation data directory, and `page_rva` read
from *inside* each relocation block, were used to compute write
addresses with zero validation against `size_of_image`. **This is
currently unreachable**: the loader always maps the image at its
preferred `ImageBase` (no relocation is ever actually needed, so
`delta` is always `0` and the function returns immediately) — but it's
written as if it handles the nonzero case, and leaving that path
unguarded is a loaded gun for whenever address-conflict handling is
added later.

**Fix:** bounds-checked the same way as everything else in this file,
now, before it's ever load-bearing.

### 10. `WM_CLOSE` destroyed the window without dispatching `WM_DESTROY`
— **correctness, not exploitable, but a real hang**

**Where:** `kernel/win32.c`, the new `USER32.dll` window/message
subsystem added to run real GUI binaries (see the top-level README for
what this subsystem is).

The default `WM_CLOSE` handling tore down the underlying window
directly instead of calling through `DestroyWindow`, which real
Windows uses specifically because it synchronously dispatches
`WM_DESTROY` to the window's own `WndProc` *before* anything is torn
down — that's the app's only chance to call `PostQuitMessage` and end
its own message loop. Skipping that step meant closing a real Win32
GUI app's window via its X button permanently hung the process: its
`GetMessageA` loop kept polling a window that would never produce
another event or a paint request again, and `quit_posted` was never
set. Not a memory-safety bug (nothing was corrupted, no OOB access),
but a real correctness bug that would have made every real GUI app
un-closeable.

**Fix:** `WM_CLOSE`'s default handler now calls the same
`DestroyWindow` path a real app would, which dispatches `WM_DESTROY`
to the registered `WndProc` first. Verified interactively: a real
mingw-w64-compiled GUI binary (`compat/mingw_winapp.c`) now exits with
code 0 after its window is closed via a scripted click on its close
button, with the usual per-process resource reclamation still firing.

### 11. SSE was never enabled at the CPU level — **compatibility gap,
not a vulnerability, documented for completeness**

**Where:** `kernel/kernel.c`.

Not a security finding, but adjacent to this pass in spirit: every
kernel C file is compiled with `-mgeneral-regs-only` (see finding
history in earlier commits) so *our own* code never emits SSE
instructions — but that flag only controls our compiler's codegen, not
the CPU. `CR4.OSFXSR` defaulted to 0, so any SSE instruction anywhere,
including in an externally-compiled `.exe`, was simply unrecognized by
the CPU (`#UD`, invalid opcode) the instant it executed — and SSE2 is
mandatory baseline on real x86-64, so normal compiler codegen (e.g. a
struct zero-init becoming `pxor %xmm0,%xmm0`) hits this immediately in
practically any real-world binary. Fixed by actually enabling SSE
(`CR0.EM=0`, `CR0.MP=1`, `CR4.OSFXSR=1`, `CR4.OSXMMEXCPT=1`) once during
boot. No FPU/SSE context save-restore was added alongside this, and
that omission is intentional, not an oversight: AlphaOS never runs two
processes concurrently and the kernel's own code never touches
XMM/x87 state, so there is no second execution context whose SSE
state could ever collide with an app's.

## Verification

Beyond `make test` (38 assertions, including the malicious-file checks
below), three PE files were hand-crafted by binary-patching legitimate
AlphaOS-built executables to trigger the specific bugs above:

| file | corruption | pre-fix behavior (by analysis) | post-fix behavior (observed) |
|---|---|---|---|
| `evil_a.exe` | `e_lfanew = 0xFFFFFFF0` | wild read via wrapped bounds check | `peinfo`/`run`: "PE header out of bounds" |
| `evil_b.exe` | `section[0].raw_ptr = 0xFFFFFFF0` | wild read during section copy | `peinfo`/`run`: "section raw data out of bounds" |
| `evil_c.exe` | import directory `rva = 0xFFFFFFF0` | wild read during import resolution | `run`: "import descriptor out of bounds" |

All three are rejected with a specific, correct error message. Critically,
the shell remains fully responsive afterward, and a normal `run hello.exe`
immediately after all three malicious attempts still succeeds — proving
containment, not just rejection.

## Design-level mitigations already in place

- **No ASLR, but a real containment boundary.** Every process — however
  it crashes — is caught by `idt.c`'s fault handler and killed
  individually; the kernel keeps running (this is the property finding
  #1 above was specifically defeating and is now restored end-to-end).
- **Page 0 is deliberately left unmapped** (`paging.c`), so null-pointer
  dereferences fault immediately instead of silently reading the
  identity-mapped low-memory region.
- **The ramdisk is read-only at runtime.** There is no write/delete/
  format path anywhere in the kernel. A compromised or buggy process —
  or the AI assistant, see below — cannot introduce new code or persist
  anything; every reboot starts from the exact image that was built.
- **Per-process resource tracking.** Every `alloc`/`VirtualAlloc`/
  `HeapAlloc`/`malloc`/`calloc` call is tracked per-process and reclaimed
  on exit or crash — a crashing or malicious process cannot leak kernel
  heap memory across runs.
- **The USER32/GDI32 window subsystem (`kernel/win32.c`) reuses the
  fault-isolation boundary rather than adding a new one.** Window
  classes and HWNDs live in small fixed-size tables
  (`MAX_WIN_CLASSES`/`MAX_HWNDS` = 16), reset at the start of every
  win-style process (`win32_reset_gui_state()`, called from
  `win32_reset_process_state()`) so a previous process's registrations
  or dangling window pointers can never leak into the next one.
  Calling into an app's registered `WndProc` (from `DispatchMessageA`
  or `DestroyWindow`'s `WM_DESTROY` dispatch) is exactly the same kind
  of "call an attacker-supplied function pointer" as calling the PE
  entry point itself — already covered by the same `k_setjmp`/
  `proc.running=true` region finding #1 hardened, not a new exposure.
- **`-mno-red-zone -mgeneral-regs-only`** on every C compilation unit —
  not a security feature per se, but their *absence* would be a
  correctness bug that manifests as stack corruption under interrupts;
  documented here because it's exactly the kind of freestanding-kernel
  detail that's easy to get wrong silently.
- **The AI assistant channel (`kernel/ai.c` + `tools/ai_bridge.py`) is
  allowlisted by construction, not by prompt.** The guest-side protocol
  handler is a five-way `switch` with no write/delete/shutdown opcode —
  those code paths don't exist, so no prompt injection, host-bridge bug,
  or malicious model response can reach them. `run_exe` (the one tool
  with a real effect) is off by default on the bridge, and even when
  enabled requires an interactive human confirmation before the request
  is forwarded to the guest at all. See `kernel/ai.c`'s header comment
  and `tools/ai_bridge.py`'s docstring for the full threat model.

## Known limitations (honestly disclosed, not fixed)

These are real gaps. Fixing them is out of scope for this pass — they'd
each be a substantial project on their own — but pretending they don't
exist would be worse than naming them:

- **No W^X / no execute-disable enforcement.** Every mapped page (app
  image, kernel heap) is Read+Write, and there's no NX bit usage. An app
  with a memory-corruption bug in its own logic has no additional
  barrier stopping it from turning that into code execution within its
  own process (which is then still contained by fault isolation for
  anything that actually faults — but a successful code-execution
  primitive that doesn't fault isn't caught by that net).
- **No ASLR.** Every app loads at a fixed, predictable `ImageBase`
  unless it specifies otherwise. Combined with no W^X, this means a
  hypothetical exploit chain within a single process has an easier time
  than it would on a hardened OS.
- **Ring 0 for everything.** Apps run at the same privilege level as the
  kernel (documented as a deliberate lightweight-design tradeoff since
  the very first version of this OS). Containment currently comes
  entirely from paging + fault handling + the loader's own validation,
  not from a hardware privilege boundary. A bug that achieves arbitrary
  code execution *without* faulting has full kernel privileges.
- **`__C_specific_handler` (SEH) is a hard stop, not real exception
  handling.** A real Windows exception (not a raw CPU fault, a
  language-level `try`/`except`) reaching this function calls `panic()`.
  Programs that depend on catching their own exceptions will crash where
  real Windows would recover. This is a correctness/compatibility gap
  more than a security one, but it's adjacent to #1 above in spirit —
  documented so it isn't mistaken for "handled."
- **Ordinal imports are rejected outright**, not resolved. A real DLL
  that imports by ordinal simply fails to load — a compatibility gap,
  listed here because it's the direct sibling of several fixes above
  (both are "how do we handle a form of import we don't fully support,"
  and this one is handled by outright refusal rather than partial
  trust).
- **This audit is not exhaustive.** It covered the highest-risk, most
  attacker-reachable code (the PE/import loader, the ramdisk archive
  parser, the Win32 allocator shims, the shell's buffer handling, and
  the new AI channel) with real analysis and working exploit-style test
  files, not a mechanical sweep of every function in the kernel. Treat
  "audited" as "this specific surface was looked at carefully," not
  "this OS is safe against a motivated attacker."
