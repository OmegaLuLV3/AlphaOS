#!/data/data/com.termux/files/usr/bin/bash
# Boots AlphaOS's already-built ISO + disk image under QEMU inside
# Termux on Android -- headless (serial console right in your Termux
# terminal), same shell you get from `make run` on a desktop. No GUI/
# VNC setup needed: it's the exact same -nographic boot this repo's
# CI/dev workflow already relies on, just running on a phone's CPU
# via QEMU's software (TCG) x86-64 emulation instead of a desktop's --
# there's no KVM acceleration for x86-on-ARM, so boot and everything
# else will feel slower than on a real machine, but it works the same.
#
# Usage: copy alphaos.iso and disk.img (both under build/ after a
# desktop `make`) onto the phone -- e.g. via `termux-setup-storage`
# and moving them into ~/storage/downloads, or `adb push`, or a cloud
# drive -- then run this script from the directory that has them:
#
#   pkg install qemu-system-x86-64
#   ./termux_run.sh /path/to/alphaos.iso /path/to/disk.img
#
# disk.img is optional (a fresh 32MB one is created if you don't have
# it yet or don't pass one), matching the Makefile's own
# $(BUILD)/disk.img rule -- but if you *do* pass one, whatever
# AlphaOS's writable disk commands (write/rm, or diskfile.exe) save to
# it persists on your phone across runs, exactly like a real disk.

set -euo pipefail

ISO=${1:-}
DISK=${2:-}

if [ -z "$ISO" ] || [ ! -f "$ISO" ]; then
    echo "usage: $0 <path-to-alphaos.iso> [path-to-disk.img]" >&2
    echo "  (build these on a desktop with 'make', they're under build/)" >&2
    exit 1
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 not found -- install it first:" >&2
    echo "  pkg install qemu-system-x86-64" >&2
    exit 1
fi

if [ -z "$DISK" ]; then
    DISK="$(dirname "$ISO")/disk.img"
    if [ ! -f "$DISK" ]; then
        echo "no disk.img given/found -- creating a fresh 32MB one at $DISK"
        if ! command -v mformat >/dev/null 2>&1; then
            echo "mtools not found -- install it: pkg install mtools" >&2
            exit 1
        fi
        dd if=/dev/zero of="$DISK" bs=1M count=32 status=none
        mformat -i "$DISK" -v ALPHAOS ::
    fi
fi

echo "booting $ISO (disk: $DISK) -- Ctrl-A X to quit QEMU"
# +rdrand matters here, not just for parity with the desktop build:
# kernel/crypto.c's entropy source is RDRAND-only and fails closed
# with no fallback (see SECURITY.md), so `https` silently can't work
# without it. TCG emulates RDRAND in software regardless of whether
# the phone's own ARM CPU has anything equivalent, so this works the
# same on Android as it does on a desktop host.
qemu-system-x86_64 -m 128 -vga std -cdrom "$ISO" \
    -cpu qemu64,+rdrand -boot order=d \
    -drive file="$DISK",format=raw,if=ide \
    -netdev user,id=net0 -device rtl8139,netdev=net0 \
    -nographic
