#!/bin/bash
# Boot AlphaOS in QEMU headless, drive the shell over the serial console,
# and assert on the output. Used by `make test` and CI.
set -u

BUILD=${BUILD:-build}
LOG=$BUILD/test.log

# mingw_hello.exe only exists if a mingw-w64 cross compiler was present
# at build time (see Makefile's COMPAT_EXES) — assert on it when it is,
# skip cleanly when it isn't, so this suite passes on either setup.
HAVE_MINGW=0
[ -f "$BUILD/apps/mingw_hello.exe" ] && HAVE_MINGW=1

feed() {
    # GRUB (SeaBIOS -> GRUB2 -> our kernel) adds a few seconds versus a
    # direct -kernel boot, so give it more time before the first command
    sleep 5
    for cmd in "help" "ls" "peinfo hello.exe" "run hello.exe" \
               "sysinfo.exe" "run primes.exe" "run memhog.exe" \
               "peinfo winhello.exe" "run winhello.exe with args" \
               "run crash.exe" "run noexec.exe" "run readfile.exe" \
               "run allocbomb.exe" \
               "run nope.exe" \
               "echo still alive" \
               "lspci" "date" "mem" "uptime"; do
        printf '%s\n' "$cmd"
        sleep 1
    done
    printf 'ping\n'
    sleep 3
    # nslookup needs the *test runner's* real internet access (SLIRP
    # forwards the DNS query to the host's actual resolver) -- unlike
    # `ping`, which only ever talks to QEMU's own virtual gateway.
    # Exercised here either way so a hang/crash would still be caught,
    # but the check below accepts either a real answer or the clean
    # "no answer" failure path, since this suite can't assume the
    # environment running it has outbound DNS.
    printf 'nslookup example.com\n'
    sleep 3
    # same "test runner's real internet access" caveat as nslookup
    # above, plus TCP specifically -- pypi.org is used here (rather
    # than example.com) only because it's a stable, well-known plain-
    # HTTP-reachable host; nothing pypi-specific is asserted below.
    printf 'http pypi.org /\n'
    sleep 6
    if [ "$HAVE_MINGW" = 1 ]; then
        printf 'run mingw_hello.exe\n'
        sleep 1.5
        printf 'run mingw_readfile.exe\n'
        sleep 1.5
        # mingw_winapp.exe is a real GUI app with a GetMessageA message
        # loop that only ends on a mouse click on its close button —
        # this non-interactive harness can't provide that, so just
        # confirm the loader parses its PE headers/imports correctly
        # (peinfo) rather than actually running it into a hang.
        printf 'peinfo mingw_winapp.exe\n'
        sleep 1.5
    fi
    printf 'halt\n'
}

# QEMU's own multiboot loader (-kernel) only accepts 32-bit ELF kernels;
# AlphaOS is now x86-64, so it boots through the GRUB2 rescue ISO instead.
# -netdev user,id=net0 -device rtl8139,netdev=net0: same reasoning as the
# Makefile's $(QEMU) — explicit, not relying on QEMU's own default NIC.
feed | timeout 120 qemu-system-x86_64 -m 128 -vga std \
    -cdrom "$BUILD/alphaos.iso" \
    -netdev user,id=net0 -device rtl8139,netdev=net0 \
    -nographic -no-reboot | tee "$LOG"

echo
echo "==== checking output ===="
pass=0
fail=0
check() {
    if grep -q "$1" "$LOG"; then
        echo "PASS: $1"
        pass=$((pass + 1))
    else
        echo "FAIL: $1"
        fail=$((fail + 1))
    fi
}

check "AlphaOS 0.11"
check "pci: .* device(s.*bus\|s)"                  # pci scan ran
check "font: captured 8x16 VGA font"
check "mouse: PS/2 mouse on IRQ 12"
# SHA-256/HMAC-SHA256/TLS-PRF/AES-128-GCM known-answer vectors, checked
# on the actual compiled kernel at boot -- see kernel/crypto.c
check "crypto: self-test passed"
check "net: RTL8139 at io=.* irq=.* mac=.* ip=10.0.2.15"
check "bga: 1024x768x32 framebuffer"
check "gui: desktop ready"
check "1024x768x32 desktop"
check "QEMU/Bochs VGA display adapter"             # lspci output
check "/20[0-9][0-9] "                             # date shows a sane year
check "hello.exe"                                  # ls output
check "PE32+ executable"                           # peinfo
check "image base     0x40000000"                  # peinfo
check "Hello from hello.exe!"                      # app ran
check "hello.exe exited with code 0"
check "AlphaOS system information"                 # sysinfo via bare name
check "primes below 10000: 1229"                   # correct computation
check "leaking the rest on purpose"                # memhog ran
check "reclaimed"                                  # kernel reclaimed leaks
# Windows-style API (PE import table)
check "win32: .* kernel32, .* user32, .* msvcrt, .* gdi32 exports"
check "imports        kernel32.dll: ExitProcess"   # peinfo import dump
check "Hello from winhello.exe"
check "resolved from the PE import table"
check 'GetCommandLineA: "winhello.exe with args"'
check "VirtualAlloc gave me a page and it works"
check "HeapAlloc: 15th triangular number is 120"
check "GetProcAddress(kernel32, GetTickCount) -> uptime"
check "winhello.exe exited with code 0"
check "\[fault\]"                                  # crash.exe page fault
check "killing process 'crash.exe'"                # fault isolation kicked in
check "crash.exe exited with code -1"
check "about to jump into heap-allocated bytes"    # noexec.exe started
check "killing process 'noexec.exe'"               # heap is really NX: the
check "noexec.exe exited with code -1"             # ret stub faulted, didn't run
# real Win32 file I/O (CreateFileA/ReadFile/GetFileSize/SetFilePointer),
# backed by the read-only ramdisk
check "data.txt is 49 bytes"
check "contents: The quick brown fox jumps over the lazy ramdisk."
check "seeked read at offset 10: brown"
check "CreateFileA on a missing file correctly failed"
# proc_alloc() header-overflow fix (SECURITY.md #13): a ~4GiB request
# must fail cleanly, not wrap to a tiny real allocation and corrupt
# the heap
check "VirtualAlloc correctly returned NULL"
check "HeapAlloc correctly returned NULL"
check "heap is intact after the rejected allocations"
check "allocbomb.exe exited with code 0"
check "not found"                                  # run nope.exe error path
check "still alive"                                # shell survived the crash
check "physical:"                                  # mem command
# real network stack: RTL8139 TX/RX, ARP resolution, ICMP echo against
# QEMU SLIRP's gateway -- a genuine round trip over emulated hardware,
# not a loopback shortcut
check "pinging gateway 10.0.2.2"
check "reply from 10.0.2.2: time="
# nslookup: accept either a real resolution or the clean failure
# message -- see the feed() comment above on why this can't require
# an actual answer unconditionally
check "example.com -> [0-9]\|nslookup: example.com: no answer"
# http: real TCP handshake + HTTP/1.1 request/response, or the clean
# failure path -- same reasoning as nslookup above. A hang or crash
# either way would still fail the suite (the shell must reach the next
# prompt for later checks -- "not found"/"still alive" below -- to run
# at all).
check "bytes ---\|http: request failed"
if [ "$HAVE_MINGW" = 1 ]; then
    check "hello from a REAL mingw-w64 compiled Windows binary"
    check "mingw_hello.exe exited with code 0"         # genuine 3rd-party .exe ran
    check "mingw_readfile: real Win32 file I/O read: The quick brown fox"
    check "mingw_readfile.exe exited with code 0"      # real .exe read a real file
    check "imports        USER32.dll: BeginPaint"      # real GUI app's import table parses
    check "imports        GDI32.dll: TextOutA"
else
    echo "SKIP: mingw-w64 compat checks (no cross compiler at build time)"
fi
check "powering off"

echo
echo "$pass passed, $fail failed"
exit $((fail > 0))
