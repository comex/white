#include "black.h"
#define cast(a, b) ((a) (b))
#define par(addr, op) cast(typeof(addr), cast(uintptr_t, addr) op)

/*

static thread_call_t stw_thread_call;
static volatile int stw_flag;
//static lck_grp_t *stw_lck_grp;
static lck_mtx_t *stw_lck;

static void thread2(thread_call_param_t _1, thread_call_param_t _2) {

void hook_init() {

}

void hook_fini() {

}

static void stop_the_world() {
}

static void start_the_world() {

}

*/

// PSA: MOV PC, #x just does nothing.

void *hook(void *addr, void *replfunc, int flags, void *tag) {
    bool thumb = par(addr, & 1);
#ifdef NO_THUMB
    thumb = false;
#endif
    uint32_t *storeto = par(addr, & ~1);
    uint32_t jumpto;
    uint32_t returnto;

    uint32_t value = storeto[0];
    uint32_t value2 = thumb ? 0x46c046c0 : 0xe1a00000;

    vm_address_t alloc;
    vm_size_t alloc_size;
    uint32_t insn;

    // Verify that it's safe to hook.
    // We expect PUSH {regs, LR}; ADD R7, SP, #x
    if(!(flags & HOOK_ANYWHERE)) {
        bool okay;
        if(thumb) {
            okay = (storeto[0] & 0xff00ff00) == 0xaf00b500;
        } else {
            okay = (storeto[0] & 0xffd04000) == 0xe9004000 && (storeto[1] & 0xffeff000) == 0xe28d7000;
        }
        if(!okay) {
            IOLog("I couldn't hook %p because its prolog is weird (%08x)\n", addr, storeto[0]);
            if(flags & HOOK_FORCE) {
                IOLog("...but I'll do it anyway\n");
            } else {
                return NULL;
            }
        }
    }

    if(flags & HOOK_POLITE) {
        value2 = storeto[1];
        returnto = cast(uint32_t, addr) + 8;
        if(vm_allocate(kernel_map, &alloc, 0x1000, 1)) {
            IOLog("hook: couldn't allocate\n");
            return NULL;
        }
        jumpto = alloc;
        alloc_size = 0x1000;
        insn = thumb ? 0xf000f8df : 0xe51ff004; // ldr pc, [pc]
    } else {
        returnto = cast(uint32_t, addr) + 4;
        int i = -1;
        uint32_t *pcrel = thumb ? par(addr + 4, & ~3) : addr + 8;
        do {
            do {
                if(++i == 1024) {
                    IOLog("hook (impolite): no suitable address found\n");
                    return NULL;
                }
                jumpto = pcrel[i];
            } while((jumpto & 3) == 2); // implausible address
            alloc = jumpto & 0xfffff000;
        } while(vm_allocate(kernel_map, &alloc, 0x2000, 0));
        alloc_size = 0x2000;


        insn = thumb ? (0xf000f8df | (i << 18)) : (0xe59ff000 | i);
    }
    IOLog("hook: I got insn=%08x storeto=%p jumpto=%08x\n", insn, storeto, jumpto);

    char *to_flush = cast(void *, jumpto & ~1);
    if(jumpto & 1) {
        *cast(uint16_t *, jumpto & ~1) = 0x4778; // bx pc
    }
    uint32_t *p = cast(void *, (jumpto + 3) & ~3); 

    if(flags & HOOK_ANYWHERE) {
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
        *p++ = 0xe1a0e00f;
        *p++ = 0xe59ff004;
        *p++ = 0xe28dd014;
        *p++ = 0xe8bd8080;
    }

    *p++ = cast(uint32_t, replfunc);

    // Return stub
    struct hook_info *hi = cast(void *, p);
    hi->value = value;
    hi->value2 = value2;
    hi->jump = thumb ? 0xf000f8df : 0xe51ff004; // ldr pc, [pc]
    hi->returnto = returnto;
    hi->flags = flags;
    hi->tag = tag;
    hi->alloc = alloc;
    hi->alloc_size = alloc_size;
    hi->storeto = storeto;

    flush_cache(to_flush, (char *) &p[1] - to_flush);
    
    vm_protect(kernel_map, alloc, alloc_size, 1, 5);
    vm_protect(kernel_map, alloc, alloc_size, 0, 5);

    //stop_the_world();
    storeto[0] = insn;
    if(flags & HOOK_POLITE) {
        storeto[1] = jumpto;
    }
    //start_the_world();
    flush_cache(storeto, 8);

    return hi;
}

void *unhook(void *stuff) {
    struct hook_info *hi = stuff;
    void *tag = hi->tag;
    //stop_the_world();
    hi->storeto[0] = hi->value;
    if(hi->flags & HOOK_POLITE) {
        hi->storeto[1] = hi->value2;
    }
    //start_the_world();
    flush_cache(hi->storeto, 8);
    IOLog("unhooked %p\n", hi->storeto);

    if(vm_deallocate(kernel_map, hi->alloc, hi->alloc_size)) {
        IOLog("vm_deallocate failed!\n");
    }
    return tag;
}

void *old_to_pc(void *old) {
    uintptr_t val = ((uint32_t *) ((uintptr_t) old & ~1))[3];
    return (void *) (val - ((val & 1) ? 5 : 8));
}
