GCC := /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -g3 -std=gnu99 -Os -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.1.sdk/ -mapcs-frame -fomit-frame-pointer -mthumb -fno-builtin-printf
all: loader stuff kcode.dylib mem.dylib
%.o: %.c kinc.h
	$(GCC) -c -o $@ $< -DIMG3_SUPPORT
%.o: %.S
	$(GCC) -c -o $@ $< -DIMG3_SUPPORT
loader_: data/binary.o data/common.o data/find.o data/white_loader.o data/cc.o data/lzss.o
	$(GCC) -o loader_ $^
loader: loader_
	cp loader_ loader
	ldid -Sent.plist loader
stuff: stuff.c
	$(GCC) -o stuff stuff.c
KCODE_OBJS = kcode.o black.o creep.o creepasm.o protoss.o protossasm.o
kcode.dylib: $(KCODE_OBJS)
	$(GCC) -dynamiclib -o kcode.dylib $(KCODE_OBJS) -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress -segprot __TEXT rwx rwx 
mem.dylib: mem.c
	$(GCC) -dynamiclib -o mem.dylib mem.c -fwhole-program -combine -nostdinc -nodefaultlibs -lgcc -Wimplicit -Ixnu -Ixnu/bsd -Ixnu/libkern -Ixnu/osfmk -Ixnu/bsd/i386 -Ixnu/bsd/sys -Ixnu/EXTERNAL_HEADERS -Ixnu/osfmk/libsa -D__i386__ -DKERNEL -DKERNEL_PRIVATE -DBSD_KERNEL_PRIVATE -D__APPLE_API_PRIVATE -DXNU_KERNEL_PRIVATE -flat_namespace -undefined dynamic_lookup

chain: chain-kern.dylib chain-user
chain-kern.dylib: chain-kern.c kinc.h
	$(GCC) -dynamiclib -g -o chain-kern.dylib chain-kern.c -fwhole-program -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress -fno-builtin
chain-user: chain-user.c
	$(GCC) -o chain-user chain-user.c
clean:
	rm -f loader loader_ data/*.o stuff kcode.dylib mem.dylib chain-user chain-kern.dylib
