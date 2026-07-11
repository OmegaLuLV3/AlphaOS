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
               "run crash.exe" "run nope.exe" "echo still alive" \
               "lspci" "date" "mem" "uptime"; do
        printf '%s\n' "$cmd"
        sleep 1
    done
    if [ "$HAVE_MINGW" = 1 ]; then
        printf 'run mingw_hello.exe\n'
        sleep 1.5
    fi
    printf 'halt\n'
}

# QEMU's own multiboot loader (-kernel) only accepts 32-bit ELF kernels;
# AlphaOS is now x86-64, so it boots through the GRUB2 rescue ISO instead.
feed | timeout 120 qemu-system-x86_64 -m 128 -vga std \
    -cdrom "$BUILD/alphaos.iso" \
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

check "AlphaOS 0.5"
check "pci: .* device(s.*bus\|s)"                  # pci scan ran
check "font: captured 8x16 VGA font"
check "mouse: PS/2 mouse on IRQ 12"
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
check "win32: .* exports in kernel32.dll"
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
check "not found"                                  # run nope.exe error path
check "still alive"                                # shell survived the crash
check "physical:"                                  # mem command
if [ "$HAVE_MINGW" = 1 ]; then
    check "msvcrt.dll"                                 # win32_init log line
    check "hello from a REAL mingw-w64 compiled Windows binary"
    check "mingw_hello.exe exited with code 0"         # genuine 3rd-party .exe ran
else
    echo "SKIP: mingw-w64 compat checks (no cross compiler at build time)"
fi
check "powering off"

echo
echo "$pass passed, $fail failed"
exit $((fail > 0))
