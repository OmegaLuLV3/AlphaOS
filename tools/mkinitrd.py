#!/usr/bin/env python3
"""
mkinitrd.py — pack files into an ARFS archive for the AlphaOS ramdisk.

layout:  "ARFS" | u32 count | count x { char name[32], u32 off, u32 size }
         | file data...

usage: mkinitrd.py <out.img> <file1> [file2 ...]
"""
import os
import struct
import sys


def main():
    if len(sys.argv) < 3:
        sys.exit(f"usage: {sys.argv[0]} <out.img> <files...>")

    out, files = sys.argv[1], sys.argv[2:]
    header_size = 8 + 40 * len(files)

    entries = b""
    data = b""
    offset = header_size
    for path in files:
        name = os.path.basename(path).encode()
        if len(name) > 31:
            sys.exit(f"filename too long (max 31): {path}")
        with open(path, "rb") as fp:
            blob = fp.read()
        entries += struct.pack("<32sII", name, offset, len(blob))
        data += blob
        offset += len(blob)

    with open(out, "wb") as fp:
        fp.write(b"ARFS" + struct.pack("<I", len(files)) + entries + data)
    print(f"{out}: {len(files)} file(s), {offset} bytes")


if __name__ == "__main__":
    main()
