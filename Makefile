CFLAGS += -fno-builtin -DWATCHPOINTS -I.
include data/Makefile.common

all: .data $(OUTDIR) $(OUTDIR)/white_loader kcode.dylib mem.dylib serialplease.dylib
.data:
	make -C data BUILD=$(BUILD)

$(OUTDIR):
	mkdir $(OUTDIR)

$(OUTDIR)/white_loader: $(OUTDIR)/white_loader.o data/$(OUTDIR)/libdata.a
	$(GCC) -o $@ $(OUTDIR)/white_loader.o data/$(OUTDIR)/libdata.a
ifneq "$(LDID)" ""
	$(LDID) -Sent.plist $@
endif

%.o: %.c kinc.h
	$(GCC_armv7) $(CFLAGS) -c -o $@ $<
%.o: %.S
	$(GCC_armv7) $(CFLAGS) -c -o $@ $<
stuff: stuff.c
	$(GCC_armv7) $(CFLAGS) -o stuff stuff.c

GCC_DYLIB = $(GCC_armv7) $(CFLAGS) -dynamiclib -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read-only-relocs suppress -segprot __TEXT rwx rwx -fblocks

kcode.dylib: kcode.o black.o creep.o creepasm.o protoss.o protossasm.o failsafe.o
	$(GCC_DYLIB) -o $@ $^

serialplease.dylib: serialplease.o
	$(GCC_DYLIB) -o $@ $^

milk.dylib: milk.o
	$(GCC_DYLIB) -o $@ $^
	
mem.dylib: mem.c
	$(GCC) $(CFLAGS) -dynamiclib -o mem.dylib mem.c -fwhole-program -combine -nostdinc -nodefaultlibs -lgcc -Wimplicit -Ixnu -Ixnu/bsd -Ixnu/libkern -Ixnu/osfmk -Ixnu/bsd/i386 -Ixnu/bsd/sys -Ixnu/EXTERNAL_HEADERS -Ixnu/osfmk/libsa -D__i386__ -DKERNEL -DKERNEL_PRIVATE -DBSD_KERNEL_PRIVATE -D__APPLE_API_PRIVATE -DXNU_KERNEL_PRIVATE -flat_namespace -undefined dynamic_lookup

clean: .clean
	make -C data clean
	rm -rf stuff *.o kcode.dylib mem.dylib 
