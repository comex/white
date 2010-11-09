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
static uint32_t dbgdscr_saved;
static bool going;

static const int num_ints = 0x4000;

extern uint32_t volatile *dbg_map;

static inline uint32_t read_debug(int num) {
    return dbg_map[num];     
}

static inline void write_debug(int num, uint32_t val) {
    dbg_map[num] = val;
}

static void begin_debug() {
    asm volatile("cpsid if");
    write_debug(192, 0xc5acce55);
    write_debug(1004, 0xc5acce55);
    read_debug(197); // This is necessary!  I don't know why.
    asm volatile("dsb");
}

static void end_debug() {
    asm volatile("dsb");
    asm volatile("cpsie if");
}

__attribute__((constructor))
static void init_debug() {
    void *reg_entry = IORegistryEntry_fromPath("IOService:/AppleARMPE/arm-io/AppleS5L8930XIO/cpu-debug-interface", NULL, NULL, NULL, NULL);
    if(!reg_entry) return;
    void *map = IOService_mapDeviceMemoryWithIndex(reg_entry, 0, 0);
    if(!map) return;
    dbg_map = IOMemoryMap_getAddress(map);
    begin_debug(); // interrupts disabled
    uint32_t val = read_debug(34);
    end_debug();
    IOLog("%x\n", val);
}

int protoss_go() {
    if(going) {
        IOLog("protoss_go: already enabled\n");
        return -1;
    }
    
    going = true;

    if(vector_base()[3] != (void *) 0xe59ff018) {
        return -1;
    }

    if(!trace_start) trace_start = IOMalloc(num_ints * sizeof(uint32_t));
    trace_start[num_ints - 1] = 0xffffffff;
    for(int i = 0; i < num_ints - 1; i++) trace_start[i] = 0;

    // We can't ever branch to 80xxxxxx, so overwrite it here
    prefetch_saved = vector_base()[3+8];
    vector_base()[3+8] = (void *) prefetch_handler;

    union dbgbcr dbgbcr0, dbgbcr4;
    uint32_t dbgbvr0, dbgbvr4;

    dbgbcr0.z1 = 0;
    dbgbcr0.address_range_mask = 0;
    dbgbcr0.z2 = 0;
    dbgbcr0.dbgbvr_match_or_mismatch = 1; // mismatch
    dbgbcr0.dbgbvr_iva_or_context_id = 0; // IVA
    dbgbcr0.dbgbvr_unlinked_or_linked = 1; // linked
    dbgbcr0.linked_brp_num = 4;
    dbgbcr0.security_state_control = 0; // match in either security state
    dbgbcr0.byte_address_select = 0xf; // I don't understand why this exists.
    dbgbcr0.z4 = 0;
    dbgbcr0.privileged_mode_control = 0; // user, system, svc *but not* exception
    dbgbcr0.breakpoint_enable = 1; // woo
    
    dbgbcr4.z1 = 0;
    dbgbcr4.address_range_mask = 0; // exact (but it's step-two for thumb :()
    dbgbcr4.z2 = 0;
    dbgbcr4.dbgbvr_match_or_mismatch = 0; // match
    dbgbcr4.dbgbvr_iva_or_context_id = 1; // Context ID
    dbgbcr4.dbgbvr_unlinked_or_linked = 1;
    dbgbcr4.linked_brp_num = 0;
    dbgbcr4.security_state_control = 0;
    dbgbcr4.byte_address_select = 0xf;
    dbgbcr4.z4 = 0;
    dbgbcr4.privileged_mode_control = 0;
    dbgbcr4.breakpoint_enable = 1;

    IOLog("%08x %08x\n", dbgbcr0.val, dbgbcr4.val);

    dbgbvr0 = 0xdeadbeec; // asm will fill this in for single stepping
    // get current context ID
    asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(dbgbvr4) :);
    
    begin_debug(); // interrupts disabled
    uint32_t dbgdscr = read_debug(34);
    dbgdscr_saved = dbgdscr;
    dbgdscr &= ~0xc000; // turn off debug
    write_debug(34, dbgdscr);

    //9-7->Crn 6-4->op2 3-0->Crm
    write_debug(64+0, dbgbvr0);
    write_debug(64+4, dbgbvr4);
    write_debug(80, dbgbcr0.val);
    write_debug(80+4, dbgbcr4.val);

    goto end;

    dbgdscr |= 0x8000; // turn on monitor debug mode
    //write_debug(34, dbgdscr);
end:
    end_debug();
    IOLog("dbgdscr_saved: %08x\n", dbgdscr_saved);
    return 0;
}

void protoss_stop() {
    if(prefetch_saved) {
        vector_base()[3+8] = prefetch_saved;
        prefetch_saved = NULL;
    }
    if(!going) return;
    begin_debug(); // interrupts disabled
    if(dbgdscr_saved) write_debug(34, dbgdscr_saved);
    write_debug(80, 0);
    write_debug(81, 0);
    write_debug(64, 0);
    write_debug(65, 0);
    going = false;
    end_debug();
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
