#!/usr/bin/env python3
"""
mkpe.py — wrap a flat code+data blob into a valid PE32 (.exe) image.

Apps are compiled with GCC, linked at ImageBase+0x1000 (see apps/app.ld),
flattened with objcopy, and packaged here with a proper DOS header,
COFF header, PE32 optional header, and a single RWX section. The result
is a structurally valid PE file: the AlphaOS loader (and any PE tool,
e.g. `file` or pefile) can parse it.

usage: mkpe.py <flat.bin> <out.exe> [--bss N] [--base 0x40000000]
"""
import argparse
import struct
import time

SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def build(blob: bytes, bss: int, image_base: int) -> bytes:
    text_rva = SECTION_ALIGN
    vsize = len(blob) + bss
    raw_size = align(len(blob), FILE_ALIGN)
    size_of_image = align(text_rva + vsize, SECTION_ALIGN)
    size_of_headers = FILE_ALIGN

    # --- DOS header: 'MZ', e_lfanew -> PE header directly at 0x40
    dos = struct.pack("<2s", b"MZ") + b"\0" * 58 + struct.pack("<I", 0x40)
    assert len(dos) == 0x40

    # --- COFF file header
    IMAGE_FILE_MACHINE_I386 = 0x014C
    characteristics = 0x0103  # RELOCS_STRIPPED | EXECUTABLE_IMAGE | 32BIT
    coff = struct.pack(
        "<HHIIIHH",
        IMAGE_FILE_MACHINE_I386,
        1,                    # NumberOfSections
        int(time.time()),
        0, 0,                 # no symbol table
        0xE0,                 # SizeOfOptionalHeader (standard PE32)
        characteristics,
    )

    # --- PE32 optional header (0xE0 bytes: 0x60 fixed + 16 data dirs)
    opt = struct.pack(
        "<HBBIIIIII"          # magic..BaseOfData
        "IIIHHHHHHIIIIHH"     # ImageBase..DllCharacteristics
        "IIIIII",             # stack/heap/loaderflags/numdirs
        0x10B,                # PE32
        1, 0,                 # linker version
        raw_size,             # SizeOfCode
        0, bss,               # init/uninit data sizes
        text_rva,             # AddressOfEntryPoint (crt0 is first)
        text_rva,             # BaseOfCode
        text_rva,             # BaseOfData
        image_base,
        SECTION_ALIGN, FILE_ALIGN,
        1, 0,                 # OS version
        0, 0,                 # image version
        3, 10,                # subsystem version
        0,                    # Win32VersionValue
        size_of_image,
        size_of_headers,
        0,                    # checksum
        3,                    # Subsystem: CUI
        0,                    # DllCharacteristics
        0x100000, 0x1000,     # stack reserve/commit
        0x100000, 0x1000,     # heap reserve/commit
        0,                    # LoaderFlags
        16,                   # NumberOfRvaAndSizes
    )
    opt += b"\0" * (16 * 8)   # empty data directories
    assert len(opt) == 0xE0

    # --- section table: one RWX ".text" holding code+data, bss as tail
    IMAGE_SCN = 0xE0000060    # CODE|INIT_DATA|EXECUTE|READ|WRITE
    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\0\0\0",
        vsize,                # VirtualSize (includes .bss)
        text_rva,             # VirtualAddress
        raw_size,             # SizeOfRawData
        size_of_headers,      # PointerToRawData
        0, 0, 0, 0,
        IMAGE_SCN,
    )

    headers = dos + b"PE\0\0" + coff + opt + section
    assert len(headers) <= size_of_headers, "headers overflow one sector"
    headers += b"\0" * (size_of_headers - len(headers))

    return headers + blob + b"\0" * (raw_size - len(blob))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("blob")
    ap.add_argument("out")
    ap.add_argument("--bss", type=lambda v: int(v, 0), default=0)
    ap.add_argument("--base", type=lambda v: int(v, 0), default=0x40000000)
    args = ap.parse_args()

    with open(args.blob, "rb") as fp:
        blob = fp.read()
    exe = build(blob, args.bss, args.base)
    with open(args.out, "wb") as fp:
        fp.write(exe)
    print(f"{args.out}: {len(exe)} bytes "
          f"(code+data {len(blob)}, bss {args.bss}, base {args.base:#x})")


if __name__ == "__main__":
    main()
