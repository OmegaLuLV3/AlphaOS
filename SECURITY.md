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

### 12. W^X / NX enforcement added — **hardening, closes the "known
limitation" named below in this same file for real .exe images and the
kernel heap**

**Where:** `kernel/boot.S`, `kernel/paging.c`, `kernel/pe.c`,
`kernel/kheap.c`, `kernel/bga.c`.

Previously every mapped page — app image, kernel heap, framebuffer —
was Read+Write and implicitly executable, with no NX bit usage
anywhere (named explicitly as a known limitation below). A bug
anywhere that let an attacker control a jump/call target and place
bytes of their choosing in memory (a classic buffer-overflow-to-
shellcode primitive) had no additional barrier stopping code execution
in that memory, on top of whatever the bug itself already allowed.

Fixed in three parts:

- **EFER.NXE** is now set at the same time as EFER.LME in `boot.S`
  (previously never set at all, so the CPU ignored the NX bit in any
  PTE unconditionally). `paging_map()` now takes independent
  `writable`/`executable` flags backed by the PTE's NX bit (bit 63)
  instead of always mapping pages executable.
- **`CR0.WP` is now set** in `paging_init()`. This matters specifically
  *because* AlphaOS runs every app in ring 0 (see "Known limitations"
  below): without `CR0.WP`, supervisor-mode writes ignore a PTE's R/W
  bit entirely, so marking a page "read-only" would be a no-op for any
  code running at the kernel's own privilege level — which is all of
  it. With `CR0.WP` set, a read-only mapping is actually enforced
  regardless of ring.
- **The kernel heap is now mapped non-executable in one place**
  (`kheap_init()`, right after the region is carved out of physical
  RAM) — this covers every `kmalloc`/`VirtualAlloc`/`HeapAlloc`/
  `malloc`/AlphaOS-`alloc` allocation in the system at once, since they
  all route through the same heap (see `api.c`'s `proc_alloc()`),
  closing off "corrupt a pointer, jump into heap-sprayed shellcode" for
  the entire system rather than needing per-call-site reasoning. The
  framebuffer (`bga.c`) is likewise mapped non-executable — it's pixel
  data, never code.
- **Loaded `.exe` images get real per-section W^X**
  (`pe.c:harden_sections()`). Every page is mapped writable+non-executable
  while the loader is still writing into the image (section copy,
  relocations, IAT patching); once that's done, pages belonging to a
  section that declares `IMAGE_SCN_MEM_EXECUTE` get execute permission,
  and — if that section does *not* also declare `IMAGE_SCN_MEM_WRITE` —
  lose write permission too. A genuine toolchain's `.text` (mingw-w64
  included) declares execute-without-write, so this is real W^X for
  real binaries: `compat/mingw_hello.c` and `compat/mingw_winapp.c`
  (see finding #10) both still run correctly with their actual code
  pages read-only+executable, verified interactively for the GUI binary
  (it reaches its blocking `GetMessageA` loop with no fault, meaning
  `WinMain`, `RegisterClassA`, `CreateWindowExA`, and its GDI paint path
  all executed correctly from a read-only+exec page) and via `make test`
  for the console binary.

  AlphaOS's own toolchain (`tools/mkpe.py`) emits a single section
  flagged *both* execute and write for every app it builds (see that
  file's header comment) — `harden_sections()` deliberately leaves
  those alone (grants execute, but doesn't remove write, since the
  section's own declared characteristics say it's meant to be written,
  and that's also where its own IAT patching happens). So AlphaOS's own
  apps (`hello.exe`, `paint.exe`, `winhello.exe`, ...) are unaffected —
  still RWX, exactly as before this change — while genuine third-party
  binaries now get real enforcement. Splitting AlphaOS's own build
  pipeline into separate RX-code / RW-data sections is real future work
  (see "Known limitations" below), not done here.

This was caught mid-implementation, not shipped broken: the first
version of `harden_sections()` skipped execute+write sections entirely
instead of granting them execute, which mapped every AlphaOS-native
`.exe` non-executable and made `hello.exe`/`winhello.exe`/etc. fault at
their very first instruction (`page fault ... err=11`, the instruction-
fetch bit set) — caught immediately by `make test` going from 38/0 to
27/11, fixed, and reverified before this was considered done.

### 13. Integer-overflow-to-heap-corruption in `proc_alloc()` — a second,
deeper truncation `checked_alloc()` didn't cover — **critical**

**Where:** `kernel/api.c`, function `proc_alloc()`.

Found by a dedicated adversarial review pass over the newest code
(the file I/O and W^X additions above) that also re-examined the
allocator path underneath them. `proc_alloc(u32 size)` computed its
real allocation as:

```c
alloc_node_t *node = kmalloc(sizeof(alloc_node_t) + size);
```

`sizeof(alloc_node_t)` is a 64-bit `usize`, so the addition itself
happens in 64-bit arithmetic — but `kmalloc()` takes a plain `u32`, so
the 64-bit sum is silently truncated back to 32 bits *at the call
site*. For any `size` within `sizeof(alloc_node_t)` (16 bytes) of
`UINT32_MAX`, `16 + size` wraps past 2^32 and the truncated value
passed to `kmalloc()` collapses to a tiny number (as low as 1).
`kmalloc()` then succeeds with a real allocation of only a few bytes,
and `proc_alloc()` proceeds as if it got the real, huge allocation it
asked for:

- `node->size = size` writes the caller's original (huge) size at
  offset 8 of that tiny real block — a guaranteed out-of-bounds write
  into the *next* block's header in `kheap.c`'s free list, corrupting
  kernel heap metadata directly.
- `return node + 1` hands back a pointer 16 bytes past `node` — which
  doesn't even land inside the tiny real allocation.

This is the same overflow-truncation bug *class* finding #7 fixed
(`checked_alloc()`, `win32.c`), but a distinct, previously-unpatched
instance one layer deeper: `checked_alloc()` only guards the size
*argument* against exceeding `UINT32_MAX` before calling `proc_alloc()`
— it has no way to know `proc_alloc()` does its own narrowing
arithmetic internally, so a size like `0xFFFFFFF0` sails through
`checked_alloc()` clean and hits this bug one function later.

**Exploit path:** `VirtualAlloc(NULL, 0xFFFFFFF0, MEM_COMMIT, PAGE_READWRITE)`
(or the `HeapAlloc`/`calloc` equivalents, or the native AlphaOS
`os->alloc()` syscall directly) triggers the truncation. Worse,
`w_VirtualAlloc`/`w_HeapAlloc` then unconditionally `memset()` the
*original* (huge) size into the handful of real bytes actually
allocated — a single call cascades into wiping out most or all of the
16 MiB kernel heap before eventually walking off mapped memory.

**Fix:** `proc_alloc()` now rejects any `size > UINT32_MAX -
sizeof(alloc_node_t)` up front, before the addition that used to wrap
is ever computed — the same "reject the oversized request instead of
silently truncating it" approach `checked_alloc()` already used one
layer up, just applied at the layer where the truncation actually
happens.

**Verification:** `apps/win32/allocbomb.c` requests a ~4 GiB
`VirtualAlloc` and `HeapAlloc`, confirms both now return `NULL`
instead of "succeeding," then performs a normal small `VirtualAlloc`
immediately after and writes/reads through it — proving the heap
wasn't left corrupted by the rejected calls, not just that the calls
themselves were rejected. `make test`: 51/51 passing.

### 14. A real network stack — the first genuine remote attack surface
AlphaOS has ever had, threat-modeled from day one

**Where:** `kernel/net.c` (new file): an RTL8139 PCI NIC driver plus
Ethernet/ARP/IPv4/ICMP parsing, exposed as a `ping` shell command.

Every prior finding in this document was reachable only by a
*locally-loaded* malicious `.exe` or ramdisk file — there was no code
path anywhere in the kernel that parsed bytes that arrived over a
wire. This changes that categorically: `net.c`'s Ethernet/ARP/IPv4/
ICMP parsers run inside a hardware interrupt handler (`nic_irq()`)
against whatever bytes QEMU's virtual NIC DMAs into the RX ring —
structurally the same trust level as a loaded `.exe` file (attacker-
controlled, must be defended against directly), except now reachable
by anything that can put a frame on the wire, not just something that
can get a file onto the ramdisk at build time.

**What's already defended, by construction:**
- Every parser (`eth_handle_frame`, `arp_handle`, `ip_handle`,
  `icmp_handle`) checks the received length against its header size
  *before* reading any field, the same discipline `pe.c`'s PE parser
  uses against a malicious `.exe`.
- The RX ring loop (`nic_irq()`) treats the NIC-reported packet length
  itself as untrusted: a `rx_len` outside `[4, RX_BUF_LEN]` resets the
  ring pointer and stops, rather than being used to compute a buffer
  offset; `offset + rx_len <= sizeof(rx_buffer)` is checked before the
  frame is ever handed to `eth_handle_frame()`.
- `ip_handle()` validates the IPv4 header length (`ihl`) against the
  real received byte count (not the packet's own self-reported
  `total_length`) before ever dereferencing anything past the fixed
  20-byte header.

**Found and fixed before this was considered done, not shipped
broken:** an early version of `ip_handle()` checked `total_len > len`
(reject a header that claims more bytes than actually arrived) but not
`total_len < ihl` (a header claiming to be *shorter* than its own
declared header length). That asymmetry meant `total_len - ihl`
— passed as the payload length into `icmp_handle()` — could underflow
(`u16`/`u32` arithmetic wrapping to a huge value) on a deliberately
malformed packet. The pointer arithmetic itself stayed safely inside
the RX buffer (a separate, already-correct bounds check saw to that),
but the wrapped length would have let `icmp_handle()` read past this
packet's real data into whatever a *previous* packet left behind in
the ring buffer — and, if triggered on the echo-request path, echo up
to 32 of those stale bytes back to the attacker in a reply. That's a
narrow but real information-disclosure primitive (leaking fragments of
a prior packet to whoever sends the next malformed one), caught by
manual adversarial review of the receive path (the send/happy path was
already proven correct empirically — see Verification below — but a
successful ping doesn't exercise malformed-input handling at all).
Fixed by additionally requiring `total_len >= ihl`.

**Deliberately not yet defended — known, accepted scope for this
first slice:** no TCP (nothing here parses variable-length TCP
options or reassembles segments — the highest-complexity, highest-risk
parsing surface in any network stack — because there is no TCP yet),
no IP fragmentation reassembly (fragmented packets are simply not
matched to anything and drop silently — reassembly bugs are a classic
CVE source and this sidesteps the entire class by not attempting it),
no promiscuous/multicast reception (`RCR_APM|RCR_AB` only — the NIC
itself drops anything not addressed to our MAC or broadcast, before
software ever sees it). Each of these is real future work, not an
oversight to paper over.

**Verification:** an actual round trip over emulated hardware, not a
loopback shortcut — `make test`'s `ping` command sends a real ARP
request, receives a real ARP reply from QEMU's SLIRP gateway, sends a
real ICMP echo request, and receives a real ICMP echo reply, end to
end through the RTL8139 TX ring, the IRQ-driven RX ring, and every
parser above. `make test`: 54/54 passing.

### 15. UDP + a minimal DNS client — same threat model as #14, extended
to a new parser with its own classic bug class

**Where:** `kernel/net.c`: `udp_handle()`, and the DNS resolver
(`net_dns_resolve()`, `dns_skip_name()`, `dns_encode_name()`).

Continues finding #14's threat model directly: `udp_handle()` and the
DNS response parser run against bytes that arrived over the wire (via
QEMU SLIRP's DNS proxy in normal use), so they're held to the same
standard as everything above — bounds-checked against the real
received length before any field is read, not against a length the
packet itself claims.

DNS specifically has its own well-known historical bug class beyond
plain bounds-checking: **compressed name pointers that loop**, letting
a malicious response spin a naive parser forever (or walk it endlessly
around the packet re-reading the same bytes). `dns_skip_name()`
sidesteps this class entirely rather than defending against it with a
jump-count budget: it never actually *follows* a compression pointer's
target at all. A pointer is always exactly 2 bytes at the location
being skipped over (in the question section, or between answer
records) — skipping past it needs to know it's a pointer and its
fixed 2-byte width, never where it points. Since the resolver only
ever needs the first A-record's 4-byte RDATA (not the record's own
NAME field, which it never reads), there was no need to write a
pointer-following name decoder — and therefore no pointer-loop
surface to defend against, by construction rather than by a guard that
could itself have an off-by-one.

Every remaining length in the parser (`dns_skip_name`'s own bound,
`qdcount`/`ancount` loop bounds against `reply_len`, `rdlength` against
the remaining bytes before trusting an A record's RDATA) is checked
the same defensive way as finding #14's IP/ICMP/UDP parsers — reject
and stop rather than trust a self-reported length.

**`udp_handle()`'s reply-matching is intentionally not a real socket
table.** AlphaOS only ever runs one blocking network call at a time
(`net_ping()`, `net_dns_resolve()` — never concurrently, by the same
single-process-at-a-time design the rest of this codebase relies on),
so a single `udp_expect_local_port`/`udp_reply_seen` pair does the job
a socket table would. This is a scope note, not a vulnerability: there
is currently no code path that could have two outstanding requests to
confuse.

**Verification:** `nslookup example.com` in this development
environment resolved to a genuine external IP address end to end —
`net_dns_resolve()`'s UDP query really left the RTL8139, QEMU SLIRP's
DNS proxy really forwarded it to a real upstream resolver, and the
real response (including whatever name compression a real-world
resolver uses) was parsed correctly. `make test`'s automated check
accepts either a real resolution *or* the resolver's own clean timeout
message — deliberately, since (unlike `ping`, which only ever talks to
QEMU's own virtual gateway) DNS resolution depends on the *test
runner's* actual internet access, which this suite can't assume every
environment has; a hang or a crash either way would still fail the
suite. `make test`: 55/55 passing.

### 16. TCP + a minimal HTTP/1.1 client — two real bugs, both caught by
testing against a genuine external server rather than a synthetic one

**Where:** `kernel/net.c`: the TCP state machine (`tcp_handle()`,
`net_tcp_connect/send/recv/close()`), and `net_http_get()`.

Client-only, single connection, stop-and-wait (see the file's own
header comment above `tcp_handle()` for the full list of what this
deliberately doesn't do yet — no congestion control, no SACK, no
out-of-order reassembly, no real TIME_WAIT). Built the same way as
every other protocol in this file: bounds-checked against the real
received length before any field is read, one static connection
struct rather than a socket table (AlphaOS only makes one blocking
network call at a time, the same design `net_ping()`/
`net_dns_resolve()` already rely on).

**Two real bugs surfaced by testing against an actual external HTTP
server (`pypi.org`), not a mock — exactly the scenario `ping`'s and
`nslookup`'s targets never exercised:**

1. **No IP routing — `ip_send()` always ARP-resolved the final
   destination directly, never the gateway.** `ping` targets the
   gateway itself; `nslookup` targets the DNS proxy — both happen to
   already sit on the local SLIRP subnet, so ARP-resolving them
   directly was indistinguishable from correct routing. The first real
   `http pypi.org /` request exposed this immediately: a real internet
   host is *not* on the local subnet, an ARP request for it can never
   get a reply (nothing on the virtual Ethernet segment owns that
   address), and the connection just timed out. Fixed by adding
   `ip_is_local()` (checks whether an address shares our /24) and
   resolving the *gateway's* MAC as the next hop for anything that
   isn't local, while the IP header's destination address correctly
   stays the real, remote target. This is basic, textbook IP routing
   — its absence wasn't a subtle bug, it was untested code path, found
   the moment a real remote host was actually the target.
2. **Acking data that was silently dropped.** The receive path
   capped how much of an incoming segment it would copy into
   `tcp.rx_buf` (correctly, to avoid an overflow) but then acked the
   *entire* segment regardless — including the part it just threw
   away. A well-behaved TCP sender, having been told "got it, don't
   resend," never sends those bytes again: permanent, silent data
   loss, not just reduced throughput. Combined with a second bug —
   `tcp_send_segment()` advertised a constant window
   (`sizeof(rx_buf)`) instead of the real current free space — a
   large response (`pypi.org`'s actual headers, in practice) filled
   the buffer, silently lost its tail, and the connection reported a
   truncated response with no error. Both fixed together: the window
   now reports live free space, and `rcv_nxt` (and therefore every
   ACK) only ever advances by the number of bytes *actually kept*, so
   a sender that overruns our window gets nothing acked for the
   overrun and correctly retransmits once `net_tcp_recv()` drains the
   buffer and sends a window-update ACK announcing the room again (added
   specifically to avoid the alternative failure mode — a sender that
   correctly stops at a zero window and then has no signal telling it
   the window reopened, i.e. a self-inflicted stall). Caught by manual
   review immediately after the *first* bug's fix let real data start
   flowing far enough to hit it — the initial `pypi.org` response came
   back truncated mid-header at exactly `sizeof(rx_buf)` bytes, which
   is what led to finding this.

**Known limitations, disclosed rather than fixed in this pass:**
incoming segments (IP/ICMP/UDP/TCP alike) aren't checksum-verified —
only ever computed when *sending*. This is a data-integrity gap, not
really a security one: an adversary capable of injecting packets on
the path can trivially compute a correct checksum too, since it's not
a cryptographic MAC. More relevant from a security angle: `tcp_handle()`
accepts a `RST` from anything matching the connection's IP/port tuple
without validating its sequence number falls in the current receive
window — real TCP stacks require this specifically to raise the bar
against off-path RST injection. The initial sequence number
(`net_tcp_connect()`'s `snd_nxt`) is derived from `uptime_ms()`, not a
real random source — adequate against the trusted, directly-connected
SLIRP backend this targets, not against a hostile network path. None
of these matter yet because nothing this codebase does today puts
AlphaOS on an untrusted network path (see the Roadmap in README.md) —
but "not yet exposed to that threat model" is a fact about deployment,
not a property of the code, so they're listed here rather than assumed
away.

**Verification:** `http pypi.org /` — real DNS resolution, a real TCP
three-way handshake, a real HTTP/1.1 request, and a complete, correct,
un-truncated real response (`HTTP/1.1 301 Moved Permanently` plus the
full header block, ending exactly where the real response ends) from
PyPI's actual production server, cross-checked byte-for-byte against a
raw Python socket making the identical request from the host. `make
test`'s automated check accepts either a real response or the client's
own clean failure message, same reasoning as `nslookup`'s check above.
`make test`: 56/56 passing.

### 17. TLS 1.2 — a from-scratch cryptographic stack, deliberately narrow in
protocol scope, verified against real certificates and a real handshake
partner where this environment's own network policy allowed it

**Where:** `kernel/crypto.c` (SHA-256, HMAC-SHA256, the TLS 1.2 PRF,
AES-128-GCM, bignum arithmetic, P-256 ECDHE, RSA PKCS#1 v1.5
verification, RDRAND-backed entropy), `kernel/x509.c` (a bounds-checked
ASN.1 DER parser and X.509 field extractor), `kernel/roots.c` (five
embedded RSA trusted-root CAs), `kernel/tls.c` (the handshake state
machine, record layer, and certificate chain validation), exposed via
the `https` shell command.

**Scope, by design, not by omission:** exactly one cipher suite
(`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`), one curve (P-256), one
signature scheme (RSA/SHA-256), client-only, single connection, no
renegotiation, no session resumption, no client certificates, chain
depth capped at 4 certificates, RSA-only chains (a leaf, intermediate,
or root signed with ECDSA cannot be verified — the connection fails
closed, it does not silently skip that check). Every one of those is a
scope decision made once, up front, rather than a corner cut under
time pressure: verifying a wide protocol surface against from-scratch
primitives is a fundamentally bigger undertaking than a lightweight
OS's HTTPS needs justify, and a narrow, fully-verified implementation
is safer than a broad, partially-verified one.

**Every primitive was implemented against its specification and
independently verified before being trusted by anything else** — see
`crypto.c`'s own header comment for the full methodology (every known-
answer vector is either a published standard or generated by a second,
independent implementation — Python's hashlib/hmac, OpenSSL, or
PyCryptodome — never hand-copied hex) and `crypto_selftest()`/
`x509_selftest()`/`x509_roots_selftest()`/`tls_selftest()`, which
re-run all of it on the actual compiled kernel at every single boot,
gated by `crypto_ok`: nothing in `tls.c` is permitted to run if any of
those self-tests failed.

**Two real bugs this process caught, neither of them hypothetical:**

1. **`bn_mod_wide`'s binary-long-division step silently discarded an
   overflow bit whenever the modulus used close to the full 4096-bit
   bignum width** — every RSA-2048 and P-256 (256-bit) vector this
   codebase had tested against up to that point stayed comfortably
   under that width and never triggered it. It surfaced the moment a
   genuine RSA-4096 root CA (ISRG Root X1) was added to the trusted
   set and its self-signature verification silently produced a
   wrong-but-plausible-looking result instead of failing loudly.
   Fixed by forcing the subtraction whenever the shift-out carry bit
   is set (`bn_sub`'s existing mod-2^4096 wraparound arithmetic then
   produces the bit-for-bit correct result without needing a wider
   intermediate representation) and locked in with a permanent
   full-width regression vector in `crypto_selftest()`. This is the
   second time in this codebase's crypto work that a fixed-width
   bignum operation was silently wrong at exactly the boundary its
   fixed width was supposed to handle — see the earlier `bn_modexp`
   performance bug in the git history for the first.
2. **A one-line reassembly-buffer overflow guard in `tls.c`'s
   handshake-message reader compared the wrong quantities** —
   `tls.hs_len + TLS_RECORD_MAX > TLS_HS_BUF_MAX` was checked *before*
   a record was ever read, using the maximum possible record size
   (16640 bytes) rather than the record actually received, which is
   larger than the reassembly buffer itself (12288 bytes) and so was
   always true — every handshake failed at the very first `ServerHello`
   read, before a single byte had actually overflowed anything. Fixed
   by moving the check to after the real record length is known.
   Caught immediately by the first live handshake attempt, not by
   code review — exactly the value of testing against a real
   connection rather than only unit tests.

**Live testing, and this environment's own limits on it:** this sandbox's
outbound network path intercepts *all* TLS — not just tooling
invoked from the agent shell, but traffic from AlphaOS's own guest NIC
inside QEMU too — via the sandbox's own TLS-terminating egress proxy,
presenting a locally-issued certificate chain rather than the target
site's real one. That is not a gap in AlphaOS; it means a fully
"real-internet" end-to-end run could not be performed *from inside
this particular build environment*, and the honest thing to do is say
so rather than paper over it. What the live attempt *did* prove,
against `example.com` through that proxy: a real `ServerHello`
parsed correctly; a real 3-certificate chain (leaf, intermediate,
self-signed root) parsed correctly; both cross-signature verifications
in that chain (leaf verified by intermediate, intermediate verified by
root) succeeded using this codebase's own RSA/SHA-256 implementation
against real, independently-issued certificates; hostname and validity-
period checks against the RTC passed; and chain validation then
**correctly and safely refused to trust it**, because that proxy's
root is not (and must not be) in this codebase's embedded trusted-root
set. A TLS client that trusts an unrecognized interception CA to get a
test to pass would be a much worse outcome than a test that can't run
to completion in this particular sandbox — this is fail-closed
behavior working exactly as designed, not a bug to route around, and
no bypass of it was committed (one was drafted for local diagnostic
purposes only, during development, and was never part of any commit).

**Everything downstream of certificate validation** — `ServerKeyExchange`
parsing and its RSA/SHA-256 signature verification, ECDHE key
derivation (`master_secret` and the key block), the client/server
`Finished` computation, and the AEAD record framing (the 8-byte
explicit-nonce layout and AAD construction from RFC 5288) — is
cross-checked in `tls_selftest()` against independent from-scratch
Python implementations (a hand-written TLS 1.2 PRF built on
`hmac`/`hashlib`, and PyCryptodome for the RSA test signature), plus
negative cases (a corrupted `ServerKeyExchange` signature, a tampered
AEAD ciphertext) confirming each is correctly rejected. During
development, this same coverage additionally ran under AddressSanitizer
and UndefinedBehaviorSanitizer with no findings.

**Known limitations, disclosed rather than fixed in this pass:** no
TLS 1.3 (older, simpler to implement correctly, and the only version a
minimal from-scratch stack can realistically verify well); no
certificate revocation checking (no OCSP, no CRLs) — a compromised or
expired-then-revoked certificate that's still within its stated
validity window is accepted; no protection against a downgrade attack
in the sense a multi-suite client would need, though offering exactly
one cipher suite and one protocol version means there is nothing *to*
downgrade to; timing side channels are addressed only where `crypto.c`
already addresses them (constant-time-ish GCM tag comparison) — RSA/
bignum operations are not constant-time and could in principle leak
timing information to a very well-positioned local attacker, not a
concern for this project's actual threat model (see below) but a real
gap in an implementation aiming for general-purpose use. The
`RDRAND`-only entropy source (`crypto_random_bytes()`) fails closed
with no fallback if unavailable — deliberately, since a TLS connection
whose ephemeral key came from a predictable source is worse than no
TLS at all, but it does mean ECDHE (and therefore `https`) simply
cannot work on hardware/hypervisors without `RDRAND`.

**Verification:** `crypto_selftest()`, `x509_selftest()`,
`x509_roots_selftest()`, and `tls_selftest()` all pass on every boot
(`make test`). A real `example.com` handshake through this
environment's egress proxy exercised `ServerHello` parsing, 3-certificate
chain parsing, two independent RSA/SHA-256 chain-signature
verifications, hostname/validity checks, and the correct, fail-closed
rejection of an untrusted root. `ServerKeyExchange` parsing/
verification, ECDHE key derivation, `Finished` computation, and AEAD
record framing are covered by `tls_selftest()`'s known-answer vectors,
independently cross-checked against Python during development
(21/21 passing, including 5 negative cases, run under ASan/UBSan with
no findings before being ported into the kernel self-test).

## Verification

Beyond `make test` (56 assertions, including the malicious-file checks
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
  The kernel32 file API added for real Win32 file I/O
  (`CreateFileA`/`ReadFile`/`GetFileSize`/`SetFilePointer`/
  `CloseHandle`, `win32.c`) is deliberately built on top of this
  guarantee rather than around it: `CreateFileA` only ever succeeds for
  `OPEN_EXISTING` + `GENERIC_READ` against a name `ramdisk_find()`
  actually has — no `CREATE_ALWAYS`/`OPEN_ALWAYS`, no `GENERIC_WRITE`,
  and `WriteFile` on an open file handle fails outright (see
  `w_WriteFile`) — so this new surface cannot become the write/persist
  path this bullet says doesn't exist. Handles live in a small
  fixed-size table reset per process, the same pattern as the window
  subsystem below.
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

- **W^X is now real but partial (see finding #12 above).** The kernel
  heap and framebuffer are fully non-executable, and a genuine
  third-party `.exe`'s real code sections (execute-without-write, as a
  real toolchain emits) are read-only+executable. What's *not* covered:
  AlphaOS's own toolchain (`tools/mkpe.py`) still emits one RWX section
  per app, so AlphaOS-native binaries get no W^X benefit at all —
  fixing that needs `mkpe.py`/`apps/app.ld` to emit separate code/data
  sections, which is a real toolchain change, not a loader change, and
  wasn't done here. A stack region also isn't separately tracked or
  marked non-executable (apps don't have one distinct from the shared
  kernel stack in this ring-0-for-everything design — see below).
- **No ASLR.** Every app loads at a fixed, predictable `ImageBase`
  unless it specifies otherwise. Combined with partial W^X, this means
  a hypothetical exploit chain within a single process (especially one
  targeting an AlphaOS-native binary, or the shared kernel stack) has
  an easier time than it would on a hardened OS.
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
- **The network stack (findings #14/#15/#16) is intentionally minimal,
  not hardened.** TCP now exists (client-only, single connection, no
  congestion control/SACK/out-of-order reassembly), a minimal HTTP/1.1
  GET client on top of it, and now TLS 1.2 on top of *that* (finding
  #17) — but plain `http` traffic is still exactly as exposed as
  before: nothing it reaches is confidential or tamper-evident in
  transit, and an on-path attacker can read or rewrite every byte it
  sends or receives. No incoming checksum verification anywhere in the
  stack (IP/ICMP/UDP/TCP), no TCP RST sequence-number validation (so
  RST injection from anything that can reach the connection's IP/port
  tuple isn't defended against), and TCP's initial sequence number is
  derived from `uptime_ms()`, not a real random source — see finding
  #16 for the full reasoning on why none of this matters *yet*
  (nothing here is exposed to an untrusted network path today) without
  it being an excuse to skip fixing before it would matter. DNS
  answers aren't validated against the question beyond the transaction
  ID matching and the QR bit being set — no 0x20 encoding, no strict
  source-port randomization beyond the fixed `DNS_LOCAL_PORT`, which is
  fine against a directly-connected, trusted SLIRP proxy but would not
  be fine against an untrusted network path once this talks to a real
  DNS server over a real link. The IP configuration is a single
  hardcoded static address matching QEMU's SLIRP defaults — there's no
  DHCP client, so this driver only makes sense against the exact
  backend the Makefile configures. An auto-updater pulling from GitHub
  now has TLS available (finding #17) but still needs a disk driver
  and writable filesystem (see README's roadmap) before it's possible
  at all; see finding #17 for TLS's own scope and known limitations
  in detail (RSA-only chains, no revocation checking, no TLS 1.3,
  among others) — those apply on top of everything in this bullet,
  not instead of it.
