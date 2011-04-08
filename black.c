#include "kinc.h"
#define cast(a, b) ((a) (b))

void *hook(void *addr, void *replacement, int mode, void *tag) {
    bool thumb = cast(uint32_t, addr) & 1;
    uint32_t *storeto = cast(void *, cast(uint32_t, addr) & ~1);
    uint32_t value = storeto[0];
    uint32_t value2 = 0;
    uint32_t *p;
    uint32_t alloc;
    uint32_t insn;

    // Verify that it's safe to hook.
    // We expect PUSH {regs, LR}; ADD R7, SP, #x
    if(thumb) {
        if((value & 0xff00ff00) != 0xaf00b500) {
            IOLog("I couldn't hook %p because its prolog is weird (%08x)\n", addr, value);
            if(mode) {
                IOLog("...but I'll do it anyway\n");
            } else {
                return NULL;
            }
        }
        // PSA: MOV PC, #x just does nothing.
        int i = 1;
        uint32_t number;
        uint32_t *pcrel = cast(void *, cast(uint32_t, addr) & ~3);
        do {
            do {
                number = pcrel[++i];
                if(i == 1024) {
                    IOLog("hook: no suitable address found\n");
                    return NULL;
                }
            } while((number & 3) == 2);
            alloc = number & 0xfffff000;
        } while(vm_allocate(kernel_map, (vm_offset_t *) &alloc, 0x2000, 0));


        insn = 0xf000f8df | ((i - 1) << 18);
        IOLog("hook: I got insn=%08x storeto=%p number=%08x\n", insn, storeto, number);

        if(number & 1) {
            *cast(uint16_t *, number & ~1) = 0x4778; // bx pc
        }
        p = cast(void *, (number + 3) & ~3);
    } else {
        value2 = storeto[1];

        if((value & 0xffd04000) != 0xe9004000 || (value2 & 0xffeff000) != 0xe28d7000) {
            IOLog("I couldn't hook %p because its prolog is weird (%08x, %08x)\n", addr, value, value2);
            if(mode) {
                IOLog("...but I'll do it anyway\n");
            } else {
                return NULL;
            }
        }

        if(vm_allocate(kernel_map, (vm_offset_t *) &alloc, 0x1000, 1)) {
            IOLog("couldn't allocate\n");
            return NULL;
        }
        p = cast(void *, alloc);
        insn = 0xe51ff004;
    }

    if(mode == 2) {
        // push {r0-r12, lr}; mov r0, sp; ldr r1, addr; mov lr, pc; ldr pc, a; pop {r0-r12, lr}; adr pc, b+1; addr: .long 0; a: .long 0; b: .long 0
        *p++ = 0xe92d5fff;
        *p++ = 0xe1a0000d;
        *p++ = 0xe59f100c;
        *p++ = 0xe1a0e00f;
        *p++ = 0xe59ff008;
        *p++ = 0xe8bd5fff;
        *p++ = thumb ? 0xe28ff005 : 0xe28ff004;
        *p++ = cast(uint32_t, addr); // dumb
    } else {
        // push {r0-r3, r7, lr}; add r1, sp, #24; add r7, sp, #16; push {r1}; adr r0, b+1; mov r1, sp; ldr r12, a; blx r12; add sp, #20; pop {r7, pc}; a: .long 0; b: .long 0'
        *p++ = 0xe92d408f;
        *p++ = 0xe28d1018;
        *p++ = 0xe28d7010;
        *p++ = 0xe92d0002;
        *p++ = thumb ? 0xe28f0015 : 0xe28f0014;
        *p++ = 0xe1a0100d;
        *p++ = 0xe59fc008;
        *p++ = 0xe12fff3c;
        *p++ = 0xe28dd014;
        *p++ = 0xe8bd8080;
    }

    *p++ = cast(uint32_t, replacement);

    // The return stub
    *p++ = value;
    if(!thumb) {
        *p++ = value2;
    }
    *p++ = thumb ? 0xf000f8df : 0xe51ff004; // ldr pc, [pc]
    *p++ = cast(uint32_t, addr) + (thumb ? 4 : 8);
    
    // bookkeeping
    uint32_t *ret = p;
    *p++ = cast(uint32_t, tag);
    *p++ = alloc;
    *p++ = cast(uint32_t, addr);
    *p++ = value;
    *p++ = value2;
    
    vm_protect(kernel_map, cast(vm_address_t, alloc), thumb ? 0x2000 : 0x1000, 1, 5);
    vm_protect(kernel_map, cast(vm_address_t, alloc), thumb ? 0x2000 : 0x1000, 0, 5);

    storeto[0] = insn;
    if(!thumb) {
        // unsafe!
        storeto[1] = alloc;
    }
    flush_cache(storeto, 8);
    return ret;
}

void *unhook(uint32_t *stuff) {
    void *tag = cast(void *, stuff[0]);
    bool thumb = stuff[2] & 1;
    uint32_t *storeto = cast(void *, stuff[2] & ~1);
    storeto[0] = stuff[3];
    if(!thumb) {
        storeto[1] = stuff[4];
    }
    flush_cache(storeto, 8);

    if(vm_deallocate(kernel_map, cast(vm_address_t, stuff[1]), thumb ? 0x2000 : 0x1000)) {
        IOLog("vm_deallocate failed!\n");
    }
    IOLog("unhooked %p\n", storeto);
    return tag;
}
