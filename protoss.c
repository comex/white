// NOTE:
// The behavior of the debug register interface is really weird.
// The only way I can get it to not crash is to toe the line exactly to what the kernel is doing, even when it doesn't seem to make sense -- for example, reading register 197 right after writing c5acce55 is required to make a subsequent read of 34 not crash.

#include <stdint.h>
#include "kinc.h"

#define NUM_TRACE_ENTRIES 0x8000
#define NUM_WATCH_ENTRIES 0x8000

static int old_ie;
static inline void disable_interrupts() {
    old_ie = ml_set_interrupts_enabled(0);
}
static inline void enable_interrupts() {
    ml_set_interrupts_enabled(old_ie);
}

struct dbgwcr {
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

struct dbgbcr {
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

extern volatile struct {
    uint32_t z1[34]; 
    uint32_t dbgdscr;
    uint32_t z2[64 - 35];
    struct dbg_state {
        uint32_t bvr[16];
        struct dbgbcr bcr[16];
        uint32_t wvr[16];
        struct dbgwcr wcr[16];
    } state;
    uint32_t z3[197 - 128];
    uint32_t prsr;
    uint32_t z4[1004 - 198];
    uint32_t lar;
} *dbg_regs;
static void *dbg_map;
static struct dbg_state dbg_state;

void **const vector_base = (void **) 0xffff0000;

struct trace_entry {
    uint32_t sp;
    uint32_t lr;
    uint32_t r[13];
    uint32_t pc;
} __attribute__((packed));

extern struct trace_entry *trace_start, *trace_end;
extern struct trace_entry *volatile trace_ptr;
static struct trace_entry *old_trace_ptr;

#ifdef WATCHPOINTS
struct watch_entry {
    uint32_t sp;
    uint32_t lr;
    uint32_t r[13];
    uint32_t pc;
    uint32_t accessed_address;
    uint32_t accessed_value;
    uint32_t was_store;
} __attribute__((packed));

static struct watch_entry *watch_start;
extern volatile struct watch_entry *watch_ptr;

extern uint32_t thread_exception_return[]
asm("$_A_80_00_0c_f1_90_9f_1d_ee_XX_83_99_e5_XX_50_98_e5_00_00_55_e3");
static uint32_t ter_orig[4];

void watch_prefetch_handler();
void watch_data_handler();
extern void *data_saved;
#endif

void trace_prefetch_handler();
extern void *prefetch_saved;

static bool watch_going;
static bool trace_going;

static void init_debug() {
    if(!dbg_map) {
        void *reg_entry = IORegistryEntry_fromPath("IOService:/AppleARMPE/arm-io/AppleS5L8930XIO/cpu-debug-interface", NULL, NULL, NULL, NULL);
        if(!reg_entry) panic("couldn't find cpu-debug-interface");
        dbg_map = IOService_mapDeviceMemoryWithIndex(reg_entry, 0, 0);
        if(!dbg_map) panic("couldn't map cpu-debug-interface memory");
        dbg_regs = IOMemoryMap_getAddress(dbg_map);
    }
}

static void begin_debug() {
    init_debug();
    disable_interrupts();
    dbg_regs->lar = 0xc5acce55;
    (void) dbg_regs->prsr;
}

static void end_debug() {
    dbg_regs->lar = 0;
    enable_interrupts();
}

uint32_t protoss_dump_debug_reg(uint32_t reg) {
    uint32_t result;
    begin_debug();
    result = dbg_regs->z1[reg];
    end_debug();
    return result;
}

int protoss_write_debug_reg(uint32_t reg, uint32_t val) {
    begin_debug();
    dbg_regs->z1[reg] = val;
    end_debug();
    return 0;
}

static void twiddle_dbg(bool on) {
    begin_debug();

    for(int i = 0; i < 16; i++) {
        dbg_regs->state.bcr[i] = (struct dbgbcr) {0};
        dbg_regs->state.wcr[i] = (struct dbgwcr) {0};
    }

    if(on) {
        for(int i = 0; i < 16; i++) {
            dbg_regs->state.bvr[i] = dbg_state.bvr[i];
            dbg_regs->state.bcr[i] = dbg_state.bcr[i];
            dbg_regs->state.wvr[i] = dbg_state.wvr[i];
            dbg_regs->state.wcr[i] = dbg_state.wcr[i];
        }
        dbg_regs->dbgdscr |= 0x8000; // turn on debug
    } else {
        dbg_regs->dbgdscr &= ~0x8000;
    }
    end_debug();
}

int protoss_go_watch(uint32_t address, uint32_t mask) {
    (void) address; (void) mask;
#ifdef WATCHPOINTS
    if(trace_going || watch_going) {
        IOLog("protoss_go_watch: already enabled\n");
        return -1;
    }

    init_debug();

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

    if(vector_base[4] != (void *) 0xe59ff018 || vector_base[3] != (void *) 0xe59ff018) {
        return -1;
    }

    if(!watch_start) watch_start = IOMalloc(NUM_WATCH_ENTRIES * sizeof(struct watch_entry));
    memset(watch_start, 0, (NUM_WATCH_ENTRIES - 1) * sizeof(struct watch_entry));
    memset(&watch_start[NUM_WATCH_ENTRIES - 1], 0xff, sizeof(struct watch_entry));
    watch_ptr = &watch_start[1];
    
    memset(&dbg_state, 0, sizeof(dbg_state));
    
    dbg_state.wcr[0].z1 = 0;
    dbg_state.wcr[0].address_range_mask = mask_bits;
    dbg_state.wcr[0].z2 = 0;
    dbg_state.wcr[0].enable_linking = 0;
    dbg_state.wcr[0].linked_brp_num = 0;
    dbg_state.wcr[0].security_state_control = 0;
    dbg_state.wcr[0].z3 = 0;
    dbg_state.wcr[0].byte_address_select = 0xff;
    dbg_state.wcr[0].loadstore_access_control = 3; // load or store
    dbg_state.wcr[0].privileged_mode_control = 3; // (not) privileged only
    dbg_state.wcr[0].watchpoint_enable = 1;

    dbg_state.wvr[0] = address;
    
    dbg_state.bcr[5].z1 = 0;
    dbg_state.bcr[5].address_range_mask = 0;
    dbg_state.bcr[5].z2 = 0;
    dbg_state.bcr[5].dbgbvr_match_or_mismatch = 1; // mismatch
    dbg_state.bcr[5].dbgbvr_iva_or_context_id = 0; // IVA
    dbg_state.bcr[5].dbgbvr_unlinked_or_linked = 1; // linked
    dbg_state.bcr[5].linked_brp_num = 4;
    dbg_state.bcr[5].security_state_control = 0; 
    dbg_state.bcr[5].byte_address_select = 0xf;
    dbg_state.bcr[5].z4 = 0;
    dbg_state.bcr[5].privileged_mode_control = 0; // user, system, svc *but not* exception
    dbg_state.bcr[5].breakpoint_enable = 0;
    
    dbg_state.bcr[4].z1 = 0;
    dbg_state.bcr[4].address_range_mask = 0; // exact (but it's step-two for thumb :()
    dbg_state.bcr[4].z2 = 0;
    dbg_state.bcr[4].dbgbvr_match_or_mismatch = 0; // match
    dbg_state.bcr[4].dbgbvr_iva_or_context_id = 1; // Context ID
    dbg_state.bcr[4].dbgbvr_unlinked_or_linked = 1;
    dbg_state.bcr[4].linked_brp_num = 5;
    dbg_state.bcr[4].security_state_control = 0;
    dbg_state.bcr[4].byte_address_select = 0xf;
    dbg_state.bcr[4].z4 = 0;
    dbg_state.bcr[4].privileged_mode_control = 0;
    dbg_state.bcr[4].breakpoint_enable = 0;
    
    prefetch_saved = vector_base[3+8];
    vector_base[3+8] = (void *) watch_prefetch_handler;
    data_saved = vector_base[4+8];
    vector_base[4+8] = (void *) watch_data_handler;

    memcpy(ter_orig, thread_exception_return + 11, 16);
    thread_exception_return[11] = 0xe59f0000; // ldr r0, [pc]
    thread_exception_return[12] = 0xea000000; // b 8
    thread_exception_return[13] = (uint32_t) &dbg_state;
    thread_exception_return[14] = 0xe1a00000; // nop
    flush_cache(thread_exception_return + 11, 16);

    watch_going = true;

    twiddle_dbg(true);
    
    return 0;
#else
    IOLog("watchpoints disabled\n");
    return -1;
#endif
}

int protoss_go() {
    if(trace_going || watch_going) {
        IOLog("protoss_go: already enabled\n");
        return -1;
    }
    
    if(vector_base[3] != (void *) 0xe59ff018) {
        return -1;
    }
    
    if(!trace_start) {
        trace_start = IOMalloc(NUM_TRACE_ENTRIES * sizeof(struct trace_entry));
        trace_end = trace_start + NUM_TRACE_ENTRIES;
    }
    memset(trace_start, 0, NUM_TRACE_ENTRIES * sizeof(struct trace_entry));

    memset(&dbg_state, 0, sizeof(dbg_state));

    dbg_state.bcr[5].z1 = 0;
    dbg_state.bcr[5].address_range_mask = 0;
    dbg_state.bcr[5].z2 = 0;
    dbg_state.bcr[5].dbgbvr_match_or_mismatch = 1; // mismatch
    dbg_state.bcr[5].dbgbvr_iva_or_context_id = 0; // IVA
    dbg_state.bcr[5].dbgbvr_unlinked_or_linked = 1; // linked
    dbg_state.bcr[5].linked_brp_num = 4;
    dbg_state.bcr[5].security_state_control = 0; // match in either security state
    dbg_state.bcr[5].byte_address_select = 0xf;
    dbg_state.bcr[5].z4 = 0;
    dbg_state.bcr[5].privileged_mode_control = 0; // user, system, svc *but not* exception
    dbg_state.bcr[5].breakpoint_enable = 1; // woo
    
    dbg_state.bcr[4].z1 = 0;
    dbg_state.bcr[4].address_range_mask = 0; // exact
    dbg_state.bcr[4].z2 = 0;
    dbg_state.bcr[4].dbgbvr_match_or_mismatch = 0; // match
    dbg_state.bcr[4].dbgbvr_iva_or_context_id = 1; // Context ID
    dbg_state.bcr[4].dbgbvr_unlinked_or_linked = 1;
    dbg_state.bcr[4].linked_brp_num = 5;
    dbg_state.bcr[4].security_state_control = 0;
    dbg_state.bcr[4].byte_address_select = 0xf;
    dbg_state.bcr[4].z4 = 0;
    dbg_state.bcr[4].privileged_mode_control = 0;
    dbg_state.bcr[4].breakpoint_enable = 1;
    
    // BVR <- current context ID
    asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(dbg_state.bvr[4]));

    // We can't ever branch to 80xxxxxx, so overwrite the data
    prefetch_saved = vector_base[3+8];
    vector_base[3+8] = (void *) trace_prefetch_handler;
    
    trace_going = true;
    
    twiddle_dbg(true);
    
    trace_ptr = &trace_start[1];
    
    return 0;
}

void protoss_stop() {
    old_trace_ptr = trace_ptr;
    trace_ptr = NULL;

    disable_interrupts();

    if(trace_going || watch_going) {
        twiddle_dbg(false);
    }

#ifdef WATCHPOINTS
    if(watch_going) {
        memcpy(thread_exception_return + 11, ter_orig, 16);
        flush_cache(thread_exception_return + 11, 16);
    }
#endif
    
    if(prefetch_saved) {
        vector_base[3+8] = prefetch_saved;
        prefetch_saved = NULL;
    }

#ifdef WATCHPOINTS
    if(data_saved) {
        vector_base[4+8] = data_saved;
        data_saved = NULL;
    }
#endif

    trace_going = false;
    watch_going = false;

    enable_interrupts();
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
    if(dbg_map) {
        OSObject_release(dbg_map);
        dbg_map = NULL;
    }
}

int protoss_get_records(int type, user_addr_t buf, uint32_t bufsize) {
    size_t size;
    const void *ptr;
    int cur_count;
    switch(type) {
    case 0:
        ptr = trace_start;
        cur_count = old_trace_ptr - trace_start;
        size = NUM_TRACE_ENTRIES * sizeof(struct trace_entry);
        break;
#ifdef WATCHPOINTS
    case 1:
        ptr = watch_start;
        cur_count = watch_ptr - watch_start;
        size = NUM_WATCH_ENTRIES * sizeof(struct watch_entry);
        break;
#endif
    default:
        return -1;
    }
    if(!ptr) return -1;
    if(size > bufsize) size = bufsize;
    if(copyout(ptr, buf, size)) return -1;
    return cur_count;
}
