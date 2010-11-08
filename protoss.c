#include <stdint.h>
#include "kinc.h"
__attribute__((constructor))
static void why_cant_i_downvote_people_on_stack_overflow() {
    union {
        struct {
            unsigned a:16;
            unsigned b:16;
        };
        unsigned int c;
    } u;
    u.a = 0xbeef;
    u.b = 0xdead;

    if(u.c != 0xdeadbeef) { 
        IOLog("u fail it\n");
    }
}

union dbgbcr {
    uint32_t val;
    struct {
        unsigned breakpoint_enable:1;
        unsigned privileged_mode_control:2;
        unsigned z4:2;
        unsigned byte_address_select:4;
        unsigned z3:5;
        unsigned security_state_control:2;
        unsigned linked_brp_num:4;
        unsigned dbgbvr_unlinked_or_linked:1;
        unsigned dbgbvr_iva_or_context_id:1;
        unsigned dbgbvr_match_or_mismatch:1;
        unsigned z2:1;
        unsigned address_range_mask:5;
        unsigned z1:3;
    } __attribute__((packed));
};

static uint32_t *trace_start;
extern uint32_t *trace_ptr;

__attribute__((const))
static inline void **vector_base() {
    return (void **) 0xffff0000;
}

void prefetch_handler();
extern void *prefetch_saved;

static const int num_ints = 0x4000;

__attribute__((constructor))
static void init_debug() {
    uint32_t dbgdrar, dbgdsar;
    asm("mrc p14, 0, %0, c1, c0, 0" :"=r"(dbgdrar) :);
    asm("mrc p14, 0, %0, c2, c0, 0" :"=r"(dbgdsar) :);
    //dbgdrar + dbgdsar
}

__attribute__((destructor))
static void fini_debug() {

}

static inline uint32_t read_debug(int num) {
     
}

static inline void write_debug(int num, uint32_t val) {

}

int protoss_go() {
    if(prefetch_saved) {
        IOLog("protoss_go: already enabled (%p)\n", prefetch_saved);
        return -1;
    }

    if(vector_base()[3] != (void *) 0xe59ff018) {
        return -1;
    }

    if(!trace_start) trace_start = IOMalloc(num_ints * sizeof(uint32_t));
    trace_start[num_ints - 1] = 0xffffffff;
    for(int i = 0; i < num_ints - 1; i++) trace_start[i] = 0;

    // We can't ever branch to 80xxxxxx, so overwrite it here
    prefetch_saved = vector_base()[3+8];
    vector_base()[3+8] = (void *) prefetch_handler;

    union dbgbcr dbgbcr0, dbgbcr1;
    uint32_t dbgbvr0, dbgbvr1;

    dbgbcr0.z1 = 0;
    dbgbcr0.address_range_mask = 28; // f0000000 (inc ffff0000) = pass; everything else = fail!
    dbgbcr0.z2 = 0;
    dbgbcr0.dbgbvr_match_or_mismatch = 1; // mismatch
    dbgbcr0.dbgbvr_iva_or_context_id = 0; // IVA
    dbgbcr0.dbgbvr_unlinked_or_linked = 1; // linked
    dbgbcr0.linked_brp_num = 1;
    dbgbcr0.security_state_control = 0; // match in either security state
    dbgbcr0.byte_address_select = 0xf; // I don't understand why this exists.
    dbgbcr0.z4 = 0;
    dbgbcr0.breakpoint_enable = 1; // woo
    
    dbgbvr0 = 0xf0000000;
    
    dbgbcr1.z1 = 0;
    dbgbcr1.address_range_mask = 0; // exact (but it's step-two for thumb :()
    dbgbcr1.z2 = 0;
    dbgbcr1.dbgbvr_match_or_mismatch = 1; // mismatch
    dbgbcr1.dbgbvr_iva_or_context_id = 0; // IVA
    dbgbcr1.dbgbvr_unlinked_or_linked = 0;
    dbgbcr1.linked_brp_num = 0;
    dbgbcr1.security_state_control = 0; // match in either security state
    dbgbcr1.byte_address_select = 0xf;
    dbgbcr1.z4 = 0;
    dbgbcr1.breakpoint_enable = 1;

    dbgbvr1 = 0xdeadbeec; // asm will fill this in for single stepping

    //9-7->Crn 6-4->op2 3-0->Crm
    write_debug(80, dbgbcr0.val);
    write_debug(81, dbgbcr1.val);
    write_debug(64, dbgbvr0);
    write_debug(65, dbgbvr1);
    
    uint32_t dbgdscr;
    asm("mrc p14, 0, %0, c0, c2, 2" : "=r"(dbgdscr));
    IOLog("dbgdscr: %08x\n", dbgdscr);
    dbgdscr = (dbgdscr & ~0xc000) | 0x8000; // turn on monitor debug mode
    asm volatile("mcr p14, 0, %0, c0, c2, 2" :: "r"(dbgdscr));
}

void protoss_stop() {
    if(!prefetch_saved) return;
    uint32_t dbgdscr;
    asm("mrc p14, 0, %0, c0, c2, 2" : "=r"(dbgdscr));
    IOLog("dbgdscr: %08x\n", dbgdscr);
    dbgdscr = (dbgdscr & ~0xc000); // turn off debug mode
    asm volatile("mcr p14, 0, %0, c0, c2, 2" :: "r"(dbgdscr));
    uint32_t dbgbcr = 0;
    asm volatile("mcr p14, 0, %0, c0, c0, 5" :: "r"(dbgbcr));
    asm volatile("mcr p14, 0, %0, c0, c1, 5" :: "r"(dbgbcr));
}

void protoss_unload() {
    protoss_stop();
    if(trace_start) {
        IOFree(trace_start);
        trace_start = NULL;
    }
}

int protoss_get_records(user_addr_t buf, uint32_t bufsize) {
    if(!trace_start) return -1;
    uint32_t size = num_ints * sizeof(uint32_t);
    if(size > bufsize) size = bufsize;
    copyout(trace_start, buf, size);
    return 0;
}
