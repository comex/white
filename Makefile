GCC := /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -gstabs -std=gnu99 -Os -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.1.sdk/ -mapcs-frame -fomit-frame-pointer
all: loader stuff kcode.dylib mem.dylib
%.o: %.c
	$(GCC) -c -o $@ $<
loader_: data/binary.o data/common.o data/find.o data/white_loader.o 
	$(GCC) -o loader_ $^
loader: loader_
	cp loader_ loader
	ldid -Sent.plist loader
stuff: stuff.c
	$(GCC) -o stuff stuff.c
kcode.dylib: kcode.c black.c creep.c creepasm.S
	$(GCC) -dynamiclib -o kcode.dylib kcode.c black.c creep.c creepasm.S -fwhole-program -combine -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress
mem.dylib: mem.c
	$(GCC) -dynamiclib -o mem.dylib mem.c -fwhole-program -combine -nostdinc -nodefaultlibs -lgcc -Wimplicit -Ixnu -Ixnu/bsd -Ixnu/libkern -Ixnu/osfmk -Ixnu/bsd/i386 -Ixnu/bsd/sys -Ixnu/EXTERNAL_HEADERS -Ixnu/osfmk/libsa -D__i386__ -DKERNEL -DKERNEL_PRIVATE -DBSD_KERNEL_PRIVATE -D__APPLE_API_PRIVATE -DXNU_KERNEL_PRIVATE -flat_namespace -undefined dynamic_lookup -fno-builtin-printf
clean:
	rm -f loader loader_ data/*.o stuff kcode.dylib mem.dylib
