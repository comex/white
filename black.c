#include "kinc.h"
#define cast(a, b) ((a) (b))

void *hook(void *addr, void *replacement, bool force, void *tag) {
    if(0 == (cast(uint32_t, addr) & 1)) {
        IOLog("Hooking ARM functions is not supported\n");
        return NULL;
    }
    uint32_t *storeto = cast(void *, cast(char *, addr) - 1);
    uint32_t value = *storeto;

    // Verify that it's safe to hook.
    // We expect PUSH {regs, LR}; ADD Rn, SP, #x
    if(!( ((value & 0xff00) == 0xb500) && ((value & 0xf8000000) == 0xa8000000) )) {
        IOLog("I couldn't hook %p because its prolog is weird (%08x)\n", addr, value);
        if(force) {
            IOLog("...but I'll do it anyway\n");
        } else {
            return NULL;
        }
    }
    
    // PSA: MOV PC, #x just does nothing.
    int i = 0;
    uint32_t number, alloc;
    do {
        do {
            number = storeto[++i];
            if(i == 1025) {
                IOLog("hook: no suitable address found\n");
                return NULL;
            }
        } while((number & 3) == 2);
        alloc = number & 0xfffff000;
    } while(vm_allocate(kernel_map, (vm_offset_t *) &alloc, 0x2000, 0));


    uint32_t insn = 0xf000f8df | ((i - 1) << 18);
    IOLog("hook: I got insn=%08x storeto=%p number=%08x\n", insn, storeto, number);

    if(number & 1) {
        *cast(uint16_t *, number & ~1) = 0x4778; // bx pc
    }
    uint32_t *p = cast(void *, (number + 3) & ~3);
    // push {r0-r3, r7, lr}; add r1, sp, #24; add r7, sp, #16; push {r1}; adr r0, b+1; mov r1, sp; ldr r12, a; blx r12; add sp, #20; pop {r7, pc}; a: .long 0; b: .long 0'
    *p++ = 0xe92d408f;
    *p++ = 0xe28d1018;
    *p++ = 0xe28d7010;
    *p++ = 0xe92d0002;
    *p++ = 0xe28f0015;
    *p++ = 0xe1a0100d;
    *p++ = 0xe59fc008;
    *p++ = 0xe12fff3c;
    *p++ = 0xe28dd014;
    *p++ = 0xe8bd8080;

    *p++ = cast(uint32_t, replacement);

    // The return stub
    *p++ = value;
    *p++ = 0xf000f8df; // ldr pc, [pc]
    *p++ = cast(uint32_t, addr) + 4;
    
    // bookkeeping
    uint32_t *ret = p;
    *p++ = cast(uint32_t, tag);
    *p++ = alloc;
    *p++ = cast(uint32_t, storeto);
    *p++ = value;
    
    vm_protect(kernel_map, cast(vm_address_t, alloc), 0x2000, 1, 5);
    vm_protect(kernel_map, cast(vm_address_t, alloc), 0x2000, 0, 5);

    *storeto = insn;
    flush_cache(storeto, 4);
    return ret;
}

void *unhook(uint32_t *stuff) {
    void *tag = cast(void *, stuff[0]);
    uint32_t *storeto = cast(void *, stuff[2]);
    *storeto = stuff[3];
    flush_cache(storeto, 4);

    if(vm_deallocate(kernel_map, cast(vm_address_t, stuff[1]), 0x2000)) {
        IOLog("vm_deallocate failed!\n");
    }
    IOLog("unhooked %p\n", storeto);
    return tag;
}
