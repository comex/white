// NOTE:
// The behavior of the debug register interface is really weird.
// The only way I can get it to not crash is to toe the line exactly to what the kernel is doing, even when it doesn't seem to make sense -- for example, reading register 197 right after writing c5acce55 is required to make a subsequent read of 34 not crash.

#include <stdint.h>
#include "kinc.h"
/*
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
*/

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

struct trace_entry {
    uint32_t r[13];
    uint32_t lr;
} __attribute__((packed));

static struct trace_entry *trace_start;
extern struct trace_entry *trace_ptr;

__attribute__((const))
static inline void **vector_base() {
    return (void **) 0xffff0000;
}

void prefetch_handler();
extern void *prefetch_saved;
static bool going;

static const int num_trace_entries = 0x4000;

extern uint32_t volatile *dbg_map;

static inline uint32_t read_debug(int num) {
    uint32_t result = dbg_map[num];
    return result;
}

static inline void write_debug(int num, uint32_t val) {
    dbg_map[num] = val;
}

int old_ie;

static void begin_debug() {
    old_ie = ml_set_interrupts_enabled(0);
    //write_debug(192, 0xc5acce55);
    write_debug(1004, 0xc5acce55);
    //read_debug(197); // This is necessary!  I don't know why.
}

static void end_debug() {
    ml_set_interrupts_enabled(old_ie);
}

__attribute__((constructor))
static void init_debug() {
    void *reg_entry = IORegistryEntry_fromPath("IOService:/AppleARMPE/arm-io/AppleS5L8930XIO/cpu-debug-interface", NULL, NULL, NULL, NULL);
    if(!reg_entry) return;
    void *map = IOService_mapDeviceMemoryWithIndex(reg_entry, 0, 0);
    if(!map) return;
    dbg_map = IOMemoryMap_getAddress(map);
    /*begin_debug(); // interrupts disabled
    read_debug(197);
    uint32_t val = read_debug(34);
    end_debug();
    IOLog("%p %x\n", dbg_map, val);*/
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

    if(!trace_start) trace_start = IOMalloc(num_trace_entries * sizeof(struct trace_entry));
    memset(trace_start, 0, (num_trace_entries - 1) * sizeof(struct trace_entry));
    memset(&trace_start[num_trace_entries - 1], 0xff, sizeof(struct trace_entry));
    trace_ptr = &trace_start[1];

    // We can't ever branch to 80xxxxxx, so overwrite it here
    prefetch_saved = vector_base()[3+8];
    vector_base()[3+8] = (void *) prefetch_handler;

    union dbgbcr dbgbcr5, dbgbcr4;
    dbgbcr5.val = dbgbcr4.val = 0;
    uint32_t dbgbvr5, dbgbvr4;

    dbgbcr5.z1 = 0;
    dbgbcr5.address_range_mask = 0;
    dbgbcr5.z2 = 0;
    dbgbcr5.dbgbvr_match_or_mismatch = 1; // mismatch
    dbgbcr5.dbgbvr_iva_or_context_id = 0; // IVA
    dbgbcr5.dbgbvr_unlinked_or_linked = 1; // linked
    dbgbcr5.linked_brp_num = 4;
    dbgbcr5.security_state_control = 0; // match in either security state
    dbgbcr5.byte_address_select = 0xf; // I don't understand why this exists.
    dbgbcr5.z4 = 0;
    dbgbcr5.privileged_mode_control = 0; // user, system, svc *but not* exception
    dbgbcr5.breakpoint_enable = 1; // woo
    
    dbgbvr5 = 0xdeadbeec; // asm will fill this in for single stepping
    
    dbgbcr4.z1 = 0;
    dbgbcr4.address_range_mask = 0; // exact (but it's step-two for thumb :()
    dbgbcr4.z2 = 0;
    dbgbcr4.dbgbvr_match_or_mismatch = 0; // match
    dbgbcr4.dbgbvr_iva_or_context_id = 1; // Context ID
    dbgbcr4.dbgbvr_unlinked_or_linked = 1;
    dbgbcr4.linked_brp_num = 5;
    dbgbcr4.security_state_control = 0;
    dbgbcr4.byte_address_select = 0xf;
    dbgbcr4.z4 = 0;
    dbgbcr4.privileged_mode_control = 0;
    dbgbcr4.breakpoint_enable = 1;

    IOLog("%08x %08x\n", dbgbcr5.val, dbgbcr4.val);

    // get current context ID
    asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(dbgbvr4) :);
    
    begin_debug(); // interrupts disabled
    read_debug(197);
    uint32_t dbgdscr = read_debug(34);
    dbgdscr |= 0x8000; // turn on debug
    write_debug(34, dbgdscr);
    // watchpoint
    for(int i = 0; i < 16; i++) {
        write_debug(80 + i, 0);
        write_debug(112 + i, 0);
    }
    for(int i = 0; i < 16; i++) {
        uint32_t bvr = 0, bcr = 0;
        if(i == 4) {
            bvr = dbgbvr4;
            bcr = dbgbcr4.val;
        } else if(i == 5) {
            bvr = dbgbvr5;
            bcr = dbgbcr5.val;
        }
        write_debug(64 + i, bvr);
        write_debug(80 + i, bcr);
        write_debug(112 + i, read_debug(112 + i));
    }
    end_debug();
    
    return 0;
}

void protoss_stop() {
    if(going) {
        begin_debug(); // interrupts disabled
        read_debug(197);
        uint32_t dbgdscr = read_debug(34);
        dbgdscr |= 0x8000; // turn on debug
        write_debug(34, dbgdscr);
        // watchpoint
        for(int i = 0; i < 16; i++) {
            write_debug(80 + i, 0);
            write_debug(112 + i, 0);
        }

        dbgdscr = read_debug(34);
        dbgdscr &= ~0x8000;
        write_debug(34, dbgdscr);
        end_debug();
    }
    if(prefetch_saved) {
        vector_base()[3+8] = prefetch_saved;
        prefetch_saved = NULL;
    }
}

void protoss_unload() {
    protoss_stop();
    if(trace_start) {
        IOFree(trace_start);
        trace_start = NULL;
        trace_ptr = NULL;
    }
}

int protoss_get_records(user_addr_t buf, uint32_t bufsize) {
    if(!trace_start) return -1;
    size_t size = num_trace_entries * sizeof(struct trace_entry);
    if(size > bufsize) size = bufsize;
    copyout(trace_start, buf, size);
    return 0;
}
