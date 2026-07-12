# AlphaOS build
#
#   make          build kernel, apps (.exe), and initrd
#   make run      boot in QEMU (serial console in your terminal)
#   make run-vga  boot in QEMU with a VGA window
#   make test     scripted boot: pipes shell commands in, checks output

CC      := gcc
LD      := ld
OBJCOPY := objcopy
PYTHON  := python3

BUILD := build

# -mno-red-zone is mandatory: interrupts run on the SAME stack as
# whatever they preempted (no IST/TSS stack switch), so any C code
# that might be interrupted with hardware IRQs enabled — which is
# everything, kernel and apps alike, once kmain calls sti() — must not
# rely on the System V red zone, or an ISR's own stack pushes would
# corrupt it out from under the interrupted function.
#
# -mgeneral-regs-only is also mandatory: without it GCC will happily
# use SSE registers/instructions for ordinary struct zeroing or copies
# (e.g. `pxor %xmm0,%xmm0`), but we never set CR0/CR4 to enable SSE and
# never save/restore FPU/SSE state across process switches — so any
# such instruction raises #UD (invalid opcode). Restricting codegen to
# general-purpose registers sidesteps needing any of that machinery.
CFLAGS := -m64 -mno-red-zone -mgeneral-regs-only -ffreestanding -fno-pic \
          -fno-stack-protector -fno-asynchronous-unwind-tables -nostdlib \
          -O2 -Wall -Wextra -fno-strict-aliasing
ASFLAGS := -m64
KLDFLAGS := -m elf_x86_64 -T kernel/linker.ld -nostdlib

# ---- kernel ---------------------------------------------------------

KOBJS := boot.o setjmp.o isr.o kernel.o console.o serial.o string.o \
         gdt.o idt.o pic.o pit.o keyboard.o pmm.o paging.o kheap.o \
         ramdisk.o pe.o api.o shell.o \
         pci.o rtc.o mouse.o font.o bga.o gfx.o terminal.o wm.o win32.o \
         ai.o net.o crypto.o x509.o roots.o
KOBJS := $(addprefix $(BUILD)/kernel/,$(KOBJS))

# ---- apps -----------------------------------------------------------

APPS     := hello sysinfo memhog primes crash paint noexec
APP_EXES := $(addprefix $(BUILD)/apps/,$(addsuffix .exe,$(APPS)))

# Windows-style apps: call the OS via PE imports (kernel32/user32)
WINAPPS  := winhello msgbox readfile allocbomb
WIN_EXES := $(addprefix $(BUILD)/apps/,$(addsuffix .exe,$(WINAPPS)))
IMPORTS  := apps/win32/imports.list

# data files packed onto the ramdisk as-is (not .exe's) -- readfile.exe
# reads this one back via CreateFileA/ReadFile to prove real Win32 file
# I/O against the (read-only) ramdisk
DATA_FILES := apps/win32/data.txt

# ---- compat: real third-party-toolchain binaries, built only if a
# mingw-w64 cross compiler is present, to regression-test Win32
# compatibility against something AlphaOS's own toolchain didn't
# produce. Silently skipped otherwise — never required for `make`.
MINGW_CC := $(shell command -v x86_64-w64-mingw32-gcc 2>/dev/null)
ifneq ($(MINGW_CC),)
COMPAT_EXES := $(BUILD)/apps/mingw_hello.exe $(BUILD)/apps/mingw_winapp.exe \
               $(BUILD)/apps/mingw_readfile.exe
endif

.PHONY: all run run-vga test clean

all: $(BUILD)/kernel.elf $(BUILD)/initrd.img $(BUILD)/alphaos.iso

$(BUILD)/kernel $(BUILD)/apps:
	mkdir -p $@

$(BUILD)/kernel/%.o: kernel/%.c kernel/kernel.h include/alpha_api.h | $(BUILD)/kernel
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/kernel/%.o: kernel/%.S | $(BUILD)/kernel
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD)/kernel.elf: $(KOBJS) kernel/linker.ld
	$(LD) $(KLDFLAGS) -o $@ $(KOBJS)

# ---- application pipeline: C -> ELF -> flat blob -> PE32 .exe -------

$(BUILD)/apps/crt0.o: apps/crt0.S | $(BUILD)/apps
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD)/apps/%.o: apps/%.c apps/alpha.h include/alpha_api.h | $(BUILD)/apps
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/apps/%.elf: $(BUILD)/apps/%.o $(BUILD)/apps/crt0.o apps/app.ld
	$(LD) -m elf_x86_64 -T apps/app.ld -nostdlib -o $@ \
	    $(BUILD)/apps/crt0.o $<

$(BUILD)/apps/%.exe: $(BUILD)/apps/%.elf tools/mkpe.py
	$(OBJCOPY) -O binary $< $(BUILD)/apps/$*.bin
	$(PYTHON) tools/mkpe.py $(BUILD)/apps/$*.bin $@ \
	    --bss 0x$$(nm $< | awk '$$3=="__bss_size"{print $$1}')

# ---- Windows-style pipeline: imports manifest -> IAT stubs -> PE ----

$(BUILD)/apps/imports.S: $(IMPORTS) tools/mkimports.py | $(BUILD)/apps
	$(PYTHON) tools/mkimports.py $(IMPORTS) $@

$(BUILD)/apps/imports.o: $(BUILD)/apps/imports.S
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD)/apps/wincrt0.o: apps/win32/wincrt0.S | $(BUILD)/apps
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD)/apps/%.wo: apps/win32/%.c apps/win32/win32.h | $(BUILD)/apps
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/apps/%.winelf: $(BUILD)/apps/%.wo $(BUILD)/apps/wincrt0.o \
                        $(BUILD)/apps/imports.o apps/win32/winapp.ld
	$(LD) -m elf_x86_64 -T apps/win32/winapp.ld -nostdlib -o $@ \
	    $(BUILD)/apps/wincrt0.o $(BUILD)/apps/imports.o $<

$(WIN_EXES): $(BUILD)/apps/%.exe: $(BUILD)/apps/%.winelf tools/mkpe.py \
             $(IMPORTS)
	$(OBJCOPY) -O binary $< $(BUILD)/apps/$*.bin
	$(PYTHON) tools/mkpe.py $(BUILD)/apps/$*.bin $@ \
	    --entry 0x1100 --imports $(IMPORTS) \
	    --bss 0x$$(nm $< | awk '$$3=="__bss_size"{print $$1}')

$(BUILD)/apps/mingw_hello.exe: compat/mingw_hello.c | $(BUILD)/apps
	$(MINGW_CC) -O2 -o $@ $<

$(BUILD)/apps/mingw_winapp.exe: compat/mingw_winapp.c | $(BUILD)/apps
	$(MINGW_CC) -O2 -mwindows -o $@ $<

$(BUILD)/apps/mingw_readfile.exe: compat/mingw_readfile.c | $(BUILD)/apps
	$(MINGW_CC) -O2 -o $@ $<

$(BUILD)/initrd.img: $(APP_EXES) $(WIN_EXES) $(COMPAT_EXES) $(DATA_FILES) \
                      tools/mkinitrd.py
	$(PYTHON) tools/mkinitrd.py $@ $(APP_EXES) $(WIN_EXES) $(COMPAT_EXES) \
	    $(DATA_FILES)

# ---- bootable ISO -----------------------------------------------------
#
# QEMU's own built-in multiboot loader (-kernel) only accepts 32-bit
# ELF kernels; an ELF64 kernel needs a real bootloader. GRUB2's
# multiboot loader is more capable — it loads a 64-bit ELF via a plain
# Multiboot 1 header just fine — so we boot through a GRUB2 rescue ISO
# instead of -kernel directly.

$(BUILD)/alphaos.iso: $(BUILD)/kernel.elf $(BUILD)/initrd.img boot/grub.cfg
	mkdir -p $(BUILD)/iso/boot/grub
	cp $(BUILD)/kernel.elf $(BUILD)/iso/boot/kernel.elf
	cp $(BUILD)/initrd.img $(BUILD)/iso/boot/initrd.img
	cp boot/grub.cfg $(BUILD)/iso/boot/grub/grub.cfg
	grub-mkrescue -o $@ $(BUILD)/iso

# ---- run / test -----------------------------------------------------
#
# -netdev user,id=net0 -device rtl8139,netdev=net0: explicit rather than
# relying on QEMU's own default NIC (which varies by version/build) —
# kernel/net.c's driver specifically targets the RTL8139 model and the
# SLIRP "user" backend's default addressing (guest 10.0.2.15/24,
# gateway 10.0.2.2). `ping` at the shell exercises the whole stack.

QEMU := qemu-system-x86_64 -m 128 -vga std -cdrom $(BUILD)/alphaos.iso \
        -cpu qemu64,+rdrand \
        -netdev user,id=net0 -device rtl8139,netdev=net0

run: all
	$(QEMU) -nographic

run-vga: all
	$(QEMU) -serial stdio

# run-ai: boots with a second serial port (COM2) exposed as a Unix
# socket for tools/ai_bridge.py to attach to. The AI channel does
# nothing on its own — nothing listens on that socket, and the `ai`
# shell command just times out — until you separately run the bridge
# with your own ANTHROPIC_API_KEY. That's deliberate: the feature is
# opt-in on both the guest (typing `ai ...`) and the host (starting the
# bridge process) sides.
#
# -serial mon:stdio (not plain -nographic) is deliberate: adding a
# second -serial flag for the AI channel suppresses -nographic's own
# implicit serial-to-stdio wiring, so without this your keystrokes go
# to the QEMU monitor instead of the AlphaOS shell.
run-ai: all
	$(QEMU) -display none -serial mon:stdio \
	    -serial unix:$(BUILD)/aichan.sock,server=on,wait=off

test: all
	./tools/run_tests.sh

clean:
	rm -rf $(BUILD)
