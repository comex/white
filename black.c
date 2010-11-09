#include "kinc.h"
#define cast(a, b) ((a) (b))

void *hook(void *addr, void *replacement, bool force) {
    if(0 == cast(uint32_t, addr) & 1) {
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
    uint32_t number, alloc, ret;
    do {
        x:
        number = storeto[++i];
        if(number & 2) {
            if(number & 1)
                number += 2;
            else
                goto x;
        }
        alloc = number & 0xfffff000;
    } while(ret = vm_allocate(kernel_map, (vm_offset_t *) &alloc, 0x1000, 0));


    uint32_t insn = 0xf000f8df | ((i - 1) << 18);
    IOLog("hook: I got %08x insn=%08x storeto=%p number=%08x\n", number, insn, storeto, number);

    uint32_t *p = cast(uint32_t *, number & ~1);
    *p++ = (number & 1) ? 0xf000f8df : 0xe51ff004; // ldr pc, [pc]
    *p++ = cast(uint32_t, replacement);

    // A stub
    uint32_t stub = cast(uint32_t, p) | 1;
    *p++ = value;
    *p++ = 0xf000f8df; // ldr pc, [pc]
    *p++ = cast(uint32_t, addr) + 4;
    
    vm_protect(kernel_map, cast(vm_address_t, alloc), 0x1000, 1, 5);
    vm_protect(kernel_map, cast(vm_address_t, alloc), 0x1000, 0, 5);

    *storeto = insn;
    invalidate_icache(cast(vm_offset_t, storeto), 4, false);
    return (void *) stub;
}

void unhook(void *stub) {
    if(!stub) return;
    stub = cast(char *, stub) - 1;
    uint32_t *stub_ = stub;
    *((uint32_t *) ((stub_[2] - 4) & ~1)) = stub_[0];
    invalidate_icache(cast(vm_offset_t, stub), 4, false);

    vm_deallocate(kernel_map, cast(vm_address_t, cast(uint32_t, stub) & 0xfffff000), 0x1000);
    IOLog("unhooked %p\n", stub);
}
