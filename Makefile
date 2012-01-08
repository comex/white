DATA = $(word 1,$(wildcard ./data ../data))
CFLAGS += -fno-builtin -Wno-missing-field-initializers -DCIRCULAR -DWATCHPOINTS -I$(DATA)
#CFLAGS += -DTRACER
CFLAGS += -DSPARTAN
include $(DATA)/Makefile.common

all: .data $(OUTDIR) $(OUTDIR)/white_loader kcode.dylib serialplease.dylib stuff

$(OUTDIR):
	mkdir $(OUTDIR)

$(OUTDIR)/white_loader: $(OUTDIR)/white_loader.o $(DATA)/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $(OUTDIR)/white_loader.o $(DATA)/$(OUTDIR)/libdata.a
ifneq "$(LDID)" ""
	$(LDID) -Sent.plist $@
endif

%.o: %.c kinc.h kcode.h black.h
	$(GCC_armv7) $(CFLAGS) -c -o $@ $<
%.o: %.S
	$(GCC_armv7) $(CFLAGS) -c -o $@ $<
stuff: stuff.c
	$(GCC_armv7) $(CFLAGS) -o stuff stuff.c

GCC_DYLIB = LD_NO_COMPACT_LINKEDIT=1 $(GCC_armv7) $(CFLAGS) -dynamiclib -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress -segprot __TEXT rwx rwx -fblocks

kcode.dylib: kcode.o black.o creep.o creepasm.o protoss.o protossasm.o failsafe.o
	$(GCC_DYLIB) -o $@ $^

serialplease.dylib: serialplease.o
	$(GCC_DYLIB) -o $@ $^

milk.dylib: milk.o
	$(GCC_DYLIB) -o $@ $^
	
mem.dylib: mem.c
	LD_NO_COMPACT_LINKEDIT=1 $(GCC_armv7) $(CFLAGS) -dynamiclib -o mem.dylib mem.c -fwhole-program -combine -nostdinc -nodefaultlibs -lgcc -Wimplicit -Ixnu -Ixnu/bsd -Ixnu/libkern -Ixnu/osfmk -Ixnu/bsd/i386 -Ixnu/bsd/sys -Ixnu/EXTERNAL_HEADERS -Ixnu/osfmk/libsa -D__i386__ -DKERNEL -DKERNEL_PRIVATE -DBSD_KERNEL_PRIVATE -D__APPLE_API_PRIVATE -DXNU_KERNEL_PRIVATE -flat_namespace -undefined dynamic_lookup

clean: .clean
	make -C $(DATA) clean
	rm -rf stuff *.o kcode.dylib mem.dylib milk.dylib serialplease.dylib
