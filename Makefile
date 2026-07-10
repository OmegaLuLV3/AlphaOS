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

CFLAGS := -m32 -ffreestanding -fno-pic -fno-stack-protector \
          -fno-asynchronous-unwind-tables -nostdlib -O2 -Wall -Wextra \
          -fno-strict-aliasing
ASFLAGS := -m32
KLDFLAGS := -m elf_i386 -T kernel/linker.ld -nostdlib

# ---- kernel ---------------------------------------------------------

KOBJS := boot.o setjmp.o isr.o kernel.o console.o serial.o string.o \
         gdt.o idt.o pic.o pit.o keyboard.o pmm.o paging.o kheap.o \
         ramdisk.o pe.o api.o shell.o
KOBJS := $(addprefix $(BUILD)/kernel/,$(KOBJS))

# ---- apps -----------------------------------------------------------

APPS     := hello sysinfo memhog primes crash
APP_EXES := $(addprefix $(BUILD)/apps/,$(addsuffix .exe,$(APPS)))

.PHONY: all run run-vga test clean

all: $(BUILD)/kernel.elf $(BUILD)/initrd.img

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
	$(LD) -m elf_i386 -T apps/app.ld -nostdlib -o $@ \
	    $(BUILD)/apps/crt0.o $<

$(BUILD)/apps/%.exe: $(BUILD)/apps/%.elf tools/mkpe.py
	$(OBJCOPY) -O binary $< $(BUILD)/apps/$*.bin
	$(PYTHON) tools/mkpe.py $(BUILD)/apps/$*.bin $@ \
	    --bss 0x$$(nm $< | awk '$$3=="__bss_size"{print $$1}')

$(BUILD)/initrd.img: $(APP_EXES) tools/mkinitrd.py
	$(PYTHON) tools/mkinitrd.py $@ $(APP_EXES)

# ---- run / test -----------------------------------------------------

QEMU := qemu-system-i386 -m 128 -kernel $(BUILD)/kernel.elf \
        -initrd $(BUILD)/initrd.img

run: all
	$(QEMU) -nographic

run-vga: all
	$(QEMU) -serial stdio

test: all
	./tools/run_tests.sh

clean:
	rm -rf $(BUILD)
