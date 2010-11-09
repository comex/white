#include "kinc.h"
// black.c
void *hook(void *addr, void *replacement);
void unhook(void *stub);
// creep.c
int creep_go(void *start, int size);
void creep_get_records(user_addr_t buf, uint32_t bufsize);
void creep_stop();
// protoss.c
int protoss_go();
int protoss_get_records(user_addr_t buf, uint32_t bufsize);
void protoss_stop();
void protoss_unload();

struct mysyscall_args {
    uint32_t mode;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
};

void *(*logger_old)(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7);
static void *logger_hook(void *a1, void *a2, void *a3, void *a4, void *a5, void *a6, void *a7) {
    void *result = logger_old(a1, a2, a3, a4, a5, a6, a7);
    IOLog("logger_hook: from:%p,%p,%p r0=%p r1=%p r2=%p r3=%p a5=%p a6=%p a7=%p result=%p\n", __builtin_return_address(0), __builtin_return_address(1), __builtin_return_address(2), a1, a2, a3, a4, a5, a6, a7, result);
    return result;
}

int (*vm_fault_enter_old)(void *m, void *pmap, uint32_t vaddr, vm_prot_t prot, boolean_t wired, boolean_t change_wiring, boolean_t no_cache, int *type_of_fault);
int vm_fault_enter_hook(void *m, void *pmap, uint32_t vaddr, vm_prot_t prot, boolean_t wired, boolean_t change_wiring, boolean_t no_cache, int *type_of_fault) {
    if((vaddr & 0xf0000000) == 0x10000000) {
        if(!(vaddr & 0xfffff)) { // xxx
            IOLog("vm_map_enter: vaddr=%08x pmap=%p prot=%x wired=%d change_wiring=%d no_cache=%d\n", vaddr, pmap, prot, wired, change_wiring, no_cache);
        }
    }
    return vm_fault_enter_old(m, pmap, vaddr, prot, wired, change_wiring, no_cache, type_of_fault);
}

int (*weird_old)(char *buf, int size);
int weird_hook(char *buf, int size) {
    int ret = weird_old(buf, size);
    IOLog("weird_old: [%x] ", size);
    while(size--) {
        IOLog("%02x ", (int) *buf++);
    }
    IOLog("=> %x\n", ret);
    return ret;
}

static int list_iosurfaces() {
    void *reg_entry = IORegistryEntry_fromPath("IOService:/IOResources/IOCoreSurfaceRoot", NULL, NULL, NULL, NULL);
    if(!reg_entry) {
        IOLog("No reg_entry...\n");
        return 1;
    }
    int highest_number = prop(reg_entry, 0x84, int);
    void **root = prop(reg_entry, 0x80, void **);
    IOLog("highest_number: %d\n", highest_number);
    //IOLog("root: %p\n", root);
    for(int i = 0; i < highest_number; i++) {
        void *surface = root[i];
        if(!surface) continue;
        int its_id = prop(surface, 8, int);
        char global = prop(surface, 0x15, char);
        int owner = prop(surface, 0x44, int);
        int width = prop(surface, 0x58, int);
        int height = prop(surface, 0x5c, int);
        int allocsize = prop(surface, 0x74, int);
        void *vt = prop(surface, 0, void *);
        
        void *md = prop(surface, 0x24, void *);
        void *phys = (md && prop(md, 0, unsigned int) == 0x802340e4) ? IOMemoryDescriptor_getPhysicalAddress(md) : NULL;
        unsigned int vram = phys ? ((unsigned int) phys - 0x4fd00000) : (unsigned int) -1;

        IOLog("%d: %p vt=%p id=%d global=%d owner=%x %dx%d allocsize=%d @vram=%u\n", i, surface, vt, its_id, (int) global, owner, width, height, allocsize, vram);
    }
    return 0;
}

static int do_something_usb_related() {
    char *base = (void *) 0xd3edc000;
    for(int i = 0; i < 8; i++) {
        volatile uint32_t *control = (void *) (base + i*0x20 + 0x900);
        uint32_t c = *control;
        IOLog("%x\n", c);
    }
    *((volatile uint32_t *) (base + 3*0x20 + 0x914)) = 0x40001000;
    *((volatile uint32_t *) (base + 3*0x20 + 0x910)) = (1 << 19) | 63;
    *((volatile uint32_t *) (base + 3*0x20 + 0x900)) |= 0x84000000;
    IOLog("%08x\n", *((volatile uint32_t *) (base + 3*0x20 + 0x900)));
    IOSleep(100);
    IOLog("%08x\n", *((volatile uint32_t *) (base + 3*0x20 + 0x900)));

    return 0;
}

static int ioreg(user_addr_t path) {
    char buf[128];
    size_t done;
    copyinstr(path, buf, sizeof(buf), &done);
    void *regentry = IORegistryEntry_fromPath(buf, NULL, NULL, NULL, NULL);
    return (int) regentry;
}

static uint32_t *the_arm_debug_info;
static uint32_t saved[2];

static void disable_kernel_debug(uint32_t *adi) {
    if(the_arm_debug_info) return;
    the_arm_debug_info = adi;
    saved[0] = the_arm_debug_info[0];
    saved[1] = the_arm_debug_info[1];
    the_arm_debug_info[0] = the_arm_debug_info[1] = 0;
}
static void enable_kernel_debug() {
    if(!the_arm_debug_info) return;
    the_arm_debug_info[0] = saved[0];
    the_arm_debug_info[1] = saved[1];
    the_arm_debug_info = NULL;
}

// from the loader
extern struct sysent sysent[];
struct sysent saved_sysent;

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval);
__attribute__((constructor))
void init() {
    IOLog("init %p\n", mysyscall);
    saved_sysent = sysent[8];
    sysent[8] = (struct sysent){ 1, 0, 0, (void *) mysyscall, NULL, NULL, _SYSCALL_RET_INT_T, 5 * sizeof(uint32_t) };
    
}

void fini_() {
    IOLog("unhook\n");
    creep_stop();
    protoss_unload();
    unhook(logger_old); logger_old = NULL;
    unhook(vm_fault_enter_old); vm_fault_enter_old = NULL;
    unhook(weird_old); weird_old = NULL;
}

__attribute__((destructor))
void fini() {
    fini_();
    sysent[8] = saved_sysent;
}

// keep in sync with stuff.c
struct regs {
    uint32_t ttbr0;
    uint32_t ttbr1;
    uint32_t ttbcr;
    uint32_t contextidr;
    uint32_t sctlr;
    uint32_t scr;
    uint32_t dbgdidr;
    uint32_t dbgdrar;
    uint32_t dbgdsar;
    uint32_t id_dfr0;
    uint32_t dbgdscr;
};

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval)
{
    //IOLog("Hi mode=%d\n", uap->mode);
    //IOLog("kernel_pmap = %p nx_enabled = %d\n", kernel_pmap, kernel_pmap[0x420/4]);
    // Turn off nx_enabled so we can make pages executable in kernel land.
    kernel_pmap[0x420/4] = 0;
    switch(uap->mode) {
    case 0: { // get regs
        struct regs regs;
        asm("mrc p15, 0, %0, c2, c0, 0" :"=r"(regs.ttbr0) :);
        asm("mrc p15, 0, %0, c2, c0, 1" :"=r"(regs.ttbr1) :);
        asm("mrc p15, 0, %0, c2, c0, 2" :"=r"(regs.ttbcr) :);
        asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(regs.contextidr) :);
        asm("mrc p15, 0, %0, c1, c0, 0" :"=r"(regs.sctlr) :);
        //asm("mcr p15, 0, %0, c1, c1, 0" :: "r"(1 << 6));
        asm("mrc p15, 0, %0, c1, c1, 0" :"=r"(regs.scr) :);
        asm("mrc p14, 0, %0, c0, c0, 0" :"=r"(regs.dbgdidr) :);
        asm("mrc p14, 0, %0, c1, c0, 0" :"=r"(regs.dbgdrar) :);
        asm("mrc p14, 0, %0, c2, c0, 0" :"=r"(regs.dbgdsar) :);
        asm("mrc p15, 0, %0, c0, c1, 2" :"=r"(regs.id_dfr0) :);
        asm("mrc p14, 0, %0, c0, c1, 0" : "=r"(regs.dbgdscr));
        int error;
        if(error = copyout(&regs, (user_addr_t) uap->b, sizeof(regs))) return error;
        *retval = 0;
        break;
    }
    case 1: { // copy physical data
        void *descriptor = IOMemoryDescriptor_withPhysicalAddress(uap->b, uap->c, kIODirectionIn);
        void *map = IOMemoryDescriptor_map(descriptor, 0);
        unsigned int *data = IOMemoryMap_getAddress(map);
        //IOLog("data = %x\n", data); break;
        
        *retval = copyout(data, (user_addr_t) uap->d, uap->c);
        
        delete_object(map);
        delete_object(descriptor);
        break;
    }
    case 2: // more realistic read
        *retval = copyout((void *) uap->b, (user_addr_t) uap->d, uap->c);
        break;
    case 3: // read32 just in case
        *retval = *((int32_t *) uap->b);
        break;
    case 4: // crash
        ((void (*)()) 0xdeadbeef)();
        *retval = 0;
        break;
    case 5: // list IOSurfaces
        *retval = list_iosurfaces();
        break;
    case 6: // unhook
        fini_();
        break;
    case 7: // hook a function, log args
        *retval = 0;
        if(!(logger_old = hook((void *) uap->b, logger_hook))) {
            *retval = -1;
        }
        break;
    case 8: // hook vm_fault_enter
        *retval = 0;
        if(!(vm_fault_enter_old = hook((void *) uap->b, vm_fault_enter_hook))) {
            *retval = -1;
        }
        break;
    case 9: // hook weird
        *retval = 0;
        if(!(weird_old = hook((void *) uap->b, weird_hook))) {
            *retval = -1;
        }
        break;
    case 10:
        *retval = creep_go((void *) uap->b, (int) uap->c);
        break;
    case 11:
        creep_get_records((user_addr_t) uap->b, uap->c);
        *retval = 0;
        break;
    case 12:
        *retval = do_something_usb_related();
        break;
    case 13:
        *retval = ioreg((user_addr_t) uap->b);
        break;
    case 14:
        *retval = protoss_get_records((user_addr_t) uap->b, uap->c);
        break;
    case 15:
        if(!(*retval = protoss_go())) {
            //IOLog("Hi\n");
            protoss_stop();
        }
        break;
    case 16: {// physical read32 (if the 32-bitness actually matters)
        void *descriptor = IOMemoryDescriptor_withPhysicalAddress(uap->b, 4, kIODirectionIn);
        void *map = IOMemoryDescriptor_map(descriptor, 0);
        volatile uint32_t *data = IOMemoryMap_getAddress(map);
        
        *retval = *data;
        
        delete_object(map);
        delete_object(descriptor);
        break;
    }
    case 17:
        disable_kernel_debug((void *) uap->b);
        break;
    case 18:
        enable_kernel_debug();
        break;
    default:
        IOLog("Unknown mode %d\n", uap->mode);
        *retval = -1;
        break;
    }

    return 0;
}
