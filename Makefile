GCC ?= /Developer/Platforms/iPhoneOS.platform/Developer/usr/bin/gcc-4.2 -arch armv7 -isysroot /Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.2.sdk/ -mapcs-frame -fomit-frame-pointer -mthumb -fno-builtin-printf -fno-builtin-memset -fno-builtin-memcpy
CFLAGS += -g3 -std=gnu99 -Os -I.
all: stuff white_loader kcode.dylib mem.dylib
%.o: %.c kinc.h
	$(GCC) $(CFLAGS) -c -o $@ $< -DIMG3_SUPPORT -Wreturn-type
%.o: %.S
	$(GCC) $(CFLAGS) -c -o $@ $< -DIMG3_SUPPORT
stuff: stuff.c
	$(GCC) $(CFLAGS) -o stuff stuff.c
KCODE_OBJS = kcode.o black.o creep.o creepasm.o protoss.o protossasm.o
kcode.dylib: $(KCODE_OBJS)
	$(GCC) $(CFLAGS) -dynamiclib -o kcode.dylib $(KCODE_OBJS) -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress -segprot __TEXT rwx rwx 
mem.dylib: mem.c
	$(GCC) $(CFLAGS) -dynamiclib -o mem.dylib mem.c -fwhole-program -combine -nostdinc -nodefaultlibs -lgcc -Wimplicit -Ixnu -Ixnu/bsd -Ixnu/libkern -Ixnu/osfmk -Ixnu/bsd/i386 -Ixnu/bsd/sys -Ixnu/EXTERNAL_HEADERS -Ixnu/osfmk/libsa -D__i386__ -DKERNEL -DKERNEL_PRIVATE -DBSD_KERNEL_PRIVATE -D__APPLE_API_PRIVATE -DXNU_KERNEL_PRIVATE -flat_namespace -undefined dynamic_lookup

chain: chain-kern.dylib chain-user
chain-kern.dylib: chain-kern.c kinc.h
	$(GCC) $(CFLAGS) -dynamiclib -g -o chain-kern.dylib chain-kern.c -fwhole-program -nostdlib -nodefaultlibs -lgcc -undefined dynamic_lookup -read_only_relocs suppress -fno-builtin
chain-user: chain-user.c
	$(GCC) $(CFLAGS) -o chain-user chain-user.c

white_loader: data/libdata.a white_loader.o
	$(GCC) $(CFLAGS) -o $@ white_loader.o -Ldata -ldata
ifneq ($(shell which lipo),)
	bash -c 'if [ -n "`lipo -info $@ | grep arm`" ]; then ldid -Sent.plist $@; fi'
endif


clean:
	rm -rf white_loader stuff *.o kcode.dylib mem.dylib chain-user chain-kern.dylib *.dSYM
