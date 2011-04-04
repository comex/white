// NOTE:
// The behavior of the debug register interface is really weird.
// The only way I can get it to not crash is to toe the line exactly to what the kernel is doing, even when it doesn't seem to make sense -- for example, reading register 197 right after writing c5acce55 is required to make a subsequent read of 34 not crash.

#include <stdint.h>
#include "kinc.h"

union dbgwcr {
    uint32_t val;
    struct {
        unsigned watchpoint_enable:1;
        unsigned privileged_mode_control:2;
        unsigned loadstore_access_control:2;
        unsigned byte_address_select:8;
        unsigned z3:1;
        unsigned security_state_control:2;
        unsigned linked_brp_num:4;
        unsigned enable_linking:1;
        unsigned z2:3;
        unsigned address_range_mask:5;
        unsigned z1:3;
    } __attribute__((packed));
};

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
    uint32_t sp;
    uint32_t lr;
    uint32_t r[13];
    uint32_t pc;
} __attribute__((packed));

static struct trace_entry *trace_start;
extern struct trace_entry *trace_ptr;
static const int num_trace_entries = 0x8000;

#ifdef WATCHPOINTS
struct watch_entry {
    uint32_t r[13];
    uint32_t lr;
    uint32_t pc;
    uint32_t accessed_address;
    uint32_t accessed_value;
    uint32_t was_store;
} __attribute__((packed));

static struct watch_entry *watch_start;
extern struct watch_entry *watch_ptr;
static const int num_watch_entries = 0x8000;

static uint32_t debug_stuff[64];
#endif

__attribute__((const))
static inline void **vector_base() {
    return (void **) 0xffff0000;
}

// :(
#ifdef WATCHPOINTS
extern uint32_t ter_patch_loc[]
asm("$_44_03_99_e5_f8_60_98_e5_06_00_50_e1_01_00_00_0a");
static uint32_t ter_orig[4];
static bool ter_patched;

void watch_prefetch_handler();
void watch_data_handler();
extern void *data_saved;
#endif
static bool watch_going;

void trace_prefetch_handler();
extern void *prefetch_saved;
static bool trace_going;

extern uint32_t volatile *dbg_map;

static inline uint32_t read_debug(int num) {
    return dbg_map[num];
}

static inline void write_debug(int num, uint32_t val) {
    dbg_map[num] = val;
}

int old_ie;

static void begin_debug() {
    //IOLog("begin_debug\n");
    old_ie = ml_set_interrupts_enabled(0);
    //write_debug(192, 0);
    write_debug(1004, 0xc5acce55);
}

static void end_debug() {
    write_debug(1004, 0);
    //write_debug(192, 0xc5acce55);
    ml_set_interrupts_enabled(old_ie);
}

__attribute__((constructor))
static void init_debug() {
    void *reg_entry = IORegistryEntry_fromPath("IOService:/AppleARMPE/arm-io/AppleS5L8930XIO/cpu-debug-interface", NULL, NULL, NULL, NULL);
    if(!reg_entry) return;
    void *map = IOService_mapDeviceMemoryWithIndex(reg_entry, 0, 0);
    if(!map) return;
    dbg_map = IOMemoryMap_getAddress(map);
}

uint32_t protoss_dump_debug_reg(uint32_t reg) {
    //IOLog("dbg_map = %p\n", dbg_map);
    uint32_t result;
    begin_debug();
    read_debug(197);
    result = read_debug(reg);
    end_debug();
    return result;
}

int protoss_write_debug_reg(uint32_t reg, uint32_t val) {
    //IOLog("%d %d\n", reg, val);
    begin_debug();
    read_debug(197);
    write_debug(reg, val);
    end_debug();
    return 0;
}

int protoss_go_watch(uint32_t address, uint32_t mask) {
#ifdef WATCHPOINTS
    if((mask & (mask + 1)) || mask == 0xffffffff) {
        IOLog("protoss_go_watch: invalid mask value %x\n", mask);
        return -1;
    }

    if(address & mask) {
        IOLog("protoss_go_watch: address (%08x) & mask (%x) is nonzero\n", address, mask);
        return -1;
    }

    if(address & 3) {
        IOLog("protoss_go_watch: address (%08x) & 3 is nonzero\n", address);
        return -1;
    }

    uint32_t mask_bits = 0;
    while(mask) {
        mask_bits++;
        mask >>= 1;
    }

    if(mask_bits == 1 || mask_bits == 2) mask_bits = 0;

    if(trace_going || watch_going) {
        IOLog("protoss_go_watch: already enabled\n");
        return -1;
    }

    if(vector_base()[4] != (void *) 0xe59ff018 || vector_base()[3] != (void *) 0xe59ff018) {
        return -1;
    }

    watch_going = true;
    
    if(!watch_start) watch_start = IOMalloc(num_watch_entries * sizeof(struct watch_entry));
    memset(watch_start, 0, (num_watch_entries - 1) * sizeof(struct watch_entry));
    memset(&watch_start[num_watch_entries - 1], 0xff, sizeof(struct watch_entry));
    watch_ptr = &watch_start[1];

    data_saved = vector_base()[4+8];
    vector_base()[4+8] = (void *) watch_data_handler;
    prefetch_saved = vector_base()[3+8];
    vector_base()[3+8] = (void *) watch_prefetch_handler;
    
    union dbgwcr dbgwcrN;
    dbgwcrN.val = 0;
    uint32_t dbgwvrN;

    dbgwcrN.z1 = 0;
    dbgwcrN.address_range_mask = mask_bits;
    dbgwcrN.z2 = 0;
    dbgwcrN.enable_linking = 0;
    dbgwcrN.linked_brp_num = 0;
    dbgwcrN.security_state_control = 0;
    dbgwcrN.z3 = 0;
    dbgwcrN.byte_address_select = 0xff;
    dbgwcrN.loadstore_access_control = 3; // load or store
    dbgwcrN.privileged_mode_control = 1; // privileged only
    dbgwcrN.watchpoint_enable = 1;
    
    union dbgbcr dbgbcrN;
    dbgbcrN.val = 0;
    uint32_t dbgbvrN;

    dbgbcrN.z1 = 0;
    dbgbcrN.address_range_mask = 0;
    dbgbcrN.z2 = 0;
    dbgbcrN.dbgbvr_match_or_mismatch = 1; // mismatch
    dbgbcrN.dbgbvr_iva_or_context_id = 0; // IVA
    dbgbcrN.dbgbvr_unlinked_or_linked = 0; // unlinked
    dbgbcrN.linked_brp_num = 0;
    dbgbcrN.security_state_control = 0; 
    dbgbcrN.byte_address_select = 0xf;
    dbgbcrN.z4 = 0;
    dbgbcrN.privileged_mode_control = 0; // user, system, svc *but not* exception
    dbgbcrN.breakpoint_enable = 0;
    
    dbgbvrN = 0xdeadbeec;

    dbgwvrN = address;

    memset(debug_stuff, 0, sizeof(debug_stuff));
    debug_stuff[-64 + 64 + 0] = dbgbvrN;
    debug_stuff[-64 + 80 + 0] = dbgbcrN.val;
    debug_stuff[-64 + 96 + 0] = dbgwvrN;
    debug_stuff[-64 + 112 + 0] = dbgwcrN.val;

    IOLog("writing to %p\n", ter_patch_loc);

    old_ie = ml_set_interrupts_enabled(0);

    for(int i = 0; i < 4; i++) ter_orig[i] = ter_patch_loc[i];

    ter_patch_loc[0] = 0xe59f0000;
    ter_patch_loc[1] = 0xea000000;
    ter_patch_loc[2] = (uint32_t) debug_stuff;
    ter_patch_loc[3] = 0xe1a00000; // nop
    
    flush_cache(ter_patch_loc, sizeof(ter_orig));
    
    ter_patched = true;

    ml_set_interrupts_enabled(old_ie);

    IOSleep(1);

    IOLog("%08x %08x %08x %08x\n", ter_orig[0], ter_orig[1], ter_orig[2], ter_orig[3]);
    
    return 0;
#else
    IOLog("no watchpoints\n");
    return -1;
#endif
}

int protoss_go() {
    if(trace_going || watch_going) {
        IOLog("protoss_go: already enabled\n");
        return -1;
    }
    
    if(vector_base()[3] != (void *) 0xe59ff018) {
        return -1;
    }
    
    trace_going = true;

    if(!trace_start) trace_start = IOMalloc(num_trace_entries * sizeof(struct trace_entry));
    memset(trace_start, 0, (num_trace_entries - 1) * sizeof(struct trace_entry));
    memset(&trace_start[num_trace_entries - 1], 0xff, sizeof(struct trace_entry));
    trace_ptr = &trace_start[1];

    // We can't ever branch to 80xxxxxx, so overwrite it here
    prefetch_saved = vector_base()[3+8];
    vector_base()[3+8] = (void *) trace_prefetch_handler;

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
    dbgbcr5.byte_address_select = 0xf;
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
    if(trace_going || watch_going) {
        begin_debug(); // interrupts disabled
        read_debug(197);
        uint32_t dbgdscr = read_debug(34);
        dbgdscr |= 0x8000; // turn on debug
        write_debug(34, dbgdscr);
        for(int i = 0; i < 16; i++) {
            // bcr and wcr
            write_debug(80 + i, 0);
            write_debug(112 + i, 0);
        }

        dbgdscr = read_debug(34);
        dbgdscr &= ~0x8000;
        write_debug(34, dbgdscr);
        end_debug();
    }

    if(trace_going) {
        trace_going = false;
    }
    
    watch_going = false;

#ifdef WATCH{OINTS
    if(ter_patched) {
        memset(debug_stuff, 0, sizeof(debug_stuff));
        old_ie = ml_set_interrupts_enabled(0);

        for(int i = 0; i < 4; i++) ter_patch_loc[i] = ter_orig[i];
    
        flush_cache(ter_patch_loc, sizeof(ter_orig));

        ter_patched = false;

        ml_set_interrupts_enabled(old_ie);
    }
#endif

    if(prefetch_saved) {
        vector_base()[3+8] = prefetch_saved;
        prefetch_saved = NULL;
    }

#ifdef WATCH{OINTS
    if(data_saved) {
        vector_base()[4+8] = data_saved;
        data_saved = NULL;
    }
#endif
}

void protoss_unload() {
    protoss_stop();
    if(trace_start) {
        IOLog("trace_ptr was %d\n", trace_ptr - trace_start);
        IOFree(trace_start);
        trace_start = NULL;
        trace_ptr = NULL;
    }
#ifdef WATCHPOINTS
    if(watch_start) {
        IOLog("watch_ptr was %d\n", watch_ptr - watch_start);
        IOFree(watch_start);
        watch_start = NULL;
        watch_ptr = NULL;
    }
#endif
}

int protoss_get_records(int type, user_addr_t buf, uint32_t bufsize) {
    size_t size;
    const void *ptr;
    switch(type) {
    case 0:
        ptr = trace_start;
        size = num_trace_entries * sizeof(struct trace_entry);
        break;
#ifdef WATCHPOINTS
    case 1:
        ptr = watch_start;
        size = num_watch_entries * sizeof(struct watch_entry);
        break;
#endif
    default:
        return -1;
    }
    if(!ptr) return -1;
    if(size > bufsize) size = bufsize;
    return copyout(ptr, buf, size);
}
