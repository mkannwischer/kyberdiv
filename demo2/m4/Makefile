PREFIX	?= arm-none-eabi
CC		= $(PREFIX)-gcc
LD		= $(PREFIX)-gcc
OBJCOPY	= $(PREFIX)-objcopy
OBJDUMP	= $(PREFIX)-objdump
GDB		= $(PREFIX)-gdb
OPENCM3_DIR =libopencm3


DEVICE=stm32f407vg
LIBNAME= opencm3_stm32f4
ARCH_FLAGS = -mthumb -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16


NUMREPS ?= 1

DEFINES=-DSTM32F4 -DSTM32F407VG -DNUMREPS=$(NUMREPS)

CFLAGS		+= -Os\
		   -Wall -Wextra -Wimplicit-function-declaration \
		   -Wredundant-decls -Wmissing-prototypes -Wstrict-prototypes \
		   -Wundef -Wshadow \
		   -I$(OPENCM3_DIR)/include \
		   -Ikyber \
		   -I. \
		   -fno-common $(ARCH_FLAGS) -MD $(DEFINES)

LDSCRIPT = $(DEVICE).ld

LDLIBS += -l$(LIBNAME)
LIBDEPS += $(OPENCM3_DIR)/lib/lib$(LIBNAME).a

LDFLAGS += -L$(OPENCM3_DIR)/lib
LDFLAGS += \
	--specs=nosys.specs \
	-Wl,--wrap=_sbrk \
	-nostartfiles \
	-ffreestanding \
	-T$(LDSCRIPT) \
	$(ARCH_FLAGS)



KYBER_SRCS=$(wildcard kyber/*.c) $(wildcard kyber/*.S)
SRC=hal-opencm3.c fips202.c randombytes.c keccakf1600.S

all: bench.bin

%.bin: %.elf
	$(OBJCOPY) -Obinary $(*).elf $(*).bin

%.elf: test/%.c $(SRC) $(LDSCRIPT) $(KYBER_SRCS)
	$(CC) $(CFLAGS) -o $(*).elf test/$(*).c  $(SRC) $(KYBER_SRCS) $(LDFLAGS) -l$(LIBNAME)

clean:
	find . -name \*.o -type f -exec rm -f {} \;
	find . -name \*.d -type f -exec rm -f {} \;
	rm -f *.elf
	rm -f *.bin
	rm -rf obj/
