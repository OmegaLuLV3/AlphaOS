#!/bin/bash
# Boot AlphaOS in QEMU headless, drive the shell over the serial console,
# and assert on the output. Used by `make test` and CI.
set -u

BUILD=${BUILD:-build}
LOG=$BUILD/test.log

feed() {
    # give the OS time to boot / finish the previous command
    sleep 2
    for cmd in "help" "ls" "peinfo hello.exe" "run hello.exe" \
               "sysinfo.exe" "run primes.exe" "run memhog.exe" \
               "run crash.exe" "run nope.exe" "echo still alive" \
               "mem" "uptime" "halt"; do
        printf '%s\n' "$cmd"
        sleep 1
    done
}

feed | timeout 60 qemu-system-i386 -m 128 \
    -kernel "$BUILD/kernel.elf" -initrd "$BUILD/initrd.img" \
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

check "AlphaOS 0.1"
check "hello.exe"                                  # ls output
check "PE32 executable"                            # peinfo
check "image base     0x40000000"                  # peinfo
check "Hello from hello.exe!"                      # app ran
check "hello.exe exited with code 0"
check "AlphaOS system information"                 # sysinfo via bare name
check "primes below 10000: 1229"                   # correct computation
check "leaking the rest on purpose"                # memhog ran
check "reclaimed"                                  # kernel reclaimed leaks
check "\[fault\]"                                  # crash.exe page fault
check "killing process 'crash.exe'"                # fault isolation kicked in
check "crash.exe exited with code -1"
check "not found"                                  # run nope.exe error path
check "still alive"                                # shell survived the crash
check "physical:"                                  # mem command
check "powering off"

echo
echo "$pass passed, $fail failed"
exit $((fail > 0))
