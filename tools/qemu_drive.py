#!/usr/bin/env python3
"""
Drives the AlphaOS shell over a QEMU pty, waiting for each real
"alpha> " prompt before sending the next command instead of a fixed
sleep. Real ATA disk operations (kernel/ata.c) can take anywhere from
milliseconds to several seconds depending on host I/O contention (a
FLUSH CACHE can drive a genuine fsync() of build/disk.img) -- no fixed
delay is both fast and reliable, so this synchronizes on the shell's
actual prompt instead. See tools/run_tests.sh.

Usage: qemu_drive.py <log_path> <commands_file> -- <qemu_argv...>
"""
import os
import pty
import select
import subprocess
import sys
import time
import tty

PROMPT = b"alpha> "
BOOT_TIMEOUT = 90
CMD_TIMEOUT = 60
DRAIN_TIMEOUT = 10


def read_until(fd, marker, timeout, log):
    """Read from fd until `marker` appears, EOF, or timeout. Always
    logs everything read either way -- a timeout or early EOF still
    needs its partial output captured for the caller's checks."""
    buf = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return False, buf
        r, _, _ = select.select([fd], [], [], remaining)
        if fd not in r:
            continue
        try:
            chunk = os.read(fd, 4096)
        except OSError:
            return False, buf
        if not chunk:
            return False, buf
        buf += chunk
        log.write(chunk)
        log.flush()
        if marker in buf:
            return True, buf


def main():
    sep = sys.argv.index("--")
    log_path, commands_file = sys.argv[1:sep]
    qemu_argv = sys.argv[sep + 1:]

    with open(commands_file) as f:
        commands = [line.rstrip("\n") for line in f if line.strip()]

    master_fd, slave_fd = pty.openpty()
    # A pty's slave side defaults to a real terminal (canonical mode,
    # local echo, CR/LF translation) -- none of which QEMU's byte-
    # transparent stdio serial backend expects. Raw mode makes this
    # behave like the plain pipe the previous shell-only harness used,
    # so nothing here echoes or rewrites bytes on top of what the
    # guest itself already echoes.
    tty.setraw(slave_fd)
    proc = subprocess.Popen(qemu_argv, stdin=slave_fd, stdout=slave_fd,
                             stderr=slave_fd, close_fds=True)
    os.close(slave_fd)

    with open(log_path, "wb") as log:
        read_until(master_fd, PROMPT, BOOT_TIMEOUT, log)
        for i, cmd in enumerate(commands):
            os.write(master_fd, (cmd + "\n").encode())
            last = i == len(commands) - 1
            if last:
                # 'halt' powers the machine off rather than returning to
                # a prompt -- just drain whatever final output follows
                # (e.g. "powering off...") for a short, bounded time.
                read_until(master_fd, b"\x00", DRAIN_TIMEOUT, log)
            else:
                ok, _ = read_until(master_fd, PROMPT, CMD_TIMEOUT, log)
                if not ok and proc.poll() is not None:
                    break  # qemu exited unexpectedly (crash, etc.)

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
