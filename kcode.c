#include "kinc.h"
#include "kcode.h"

static void *hook_tag;

static int tracer_ticks;
static lck_grp_t *lck_grp;
static lck_mtx_t *tracer_lck;

struct apply_args {
    void **sp;
    void *r0, *r1, *r2, *r3;
    void *r7; // not actually part of the __builtin_apply_args() struct
};

struct apply_result {
    void *r0, *r1, *r2, *r3;
};

struct frame {
    struct frame *r7;
    void *lr;
};

static void get_return_addresses(struct frame *frame, void **returns, int n) {
    while(n--) {
        if(!frame || frame == (void *) 0xffffffff) {
            *returns++ = (void *) 0xeeeeeeee;
        } else {
            *returns++ = frame->lr;
            frame = frame->r7;
        }
    }
}

static void *generic_hook(bool should_trace, void *old, struct apply_args *args) {
    if(should_trace) {
        protoss_go();
    }
    struct apply_result *result = __builtin_apply(old, args, 60);
    if(should_trace) {
        protoss_stop();
    }
    void *returns[6];
    get_return_addresses(args->r7, returns, 6);
    IOLog("hook%s: from:%p <- %p <- %p <- %p <- %p <- %p r0=%p r1=%p r2=%p r3=%p a5=%p a6=%p a7=%p result=%p pid=%d\n",
        should_trace ? " (traced)" : "",
        returns[0], returns[1], returns[2], returns[3], returns[4], returns[5],
        args->r0, args->r1, args->r2, args->r3, args->sp[0], args->sp[1], args->sp[2],
        result->r0,
        proc_pid(current_proc()));
    return result;
}

static void noreturn_hook(uint32_t regs[14], uint32_t pc) {
#if 0
    // meant for hooking syscall
    static uint32_t skipped, count[0x1000];
    if(++count[regs[12] & 0xfff] > 10) {
        skipped++; // we get it already!
        return;
    } else if(skipped) {
        IOLog("(skipped %u entries)\n", skipped);
        memset(count, 0, sizeof(count));
        skipped = 0;
    }
#endif
    IOLog("[%d] @%x hook: r0=0x%x r1=0x%x r2=0x%x r3=0x%x r4=0x%x r5=0x%x r6=0x%x r7=0x%x r8=0x%x r9=0x%x r10=0x%x r11=0x%x r12=0x%x sp=%p lr=0x%x\n", proc_pid(current_proc()), pc, regs[0], regs[1], regs[2], regs[3], regs[4], regs[5], regs[6], regs[7], regs[8], regs[9], regs[10], regs[11], regs[12], regs + 14, regs[13]);
}

static void *logger_hook(void *old, struct apply_args *args) {
    __builtin_return(generic_hook(false, old, args));
}

static void *tracer_hook(void *old, struct apply_args *args) {
    lck_mtx_lock(tracer_lck);
    bool should_trace = !tracer_ticks--;
    void *result = generic_hook(should_trace, old, args);
    lck_mtx_unlock(tracer_lck);
    __builtin_return(result);
}

static void *weird_hook(void *old, struct apply_args *args) {
    //IOLog("weird_hook: %d: %p, %p, %p, %p\n", args->sp[12], args->sp[0], args->sp[1], args->sp[2], args->sp[3]); 
    __builtin_return(__builtin_apply(old, args, 60));
}

static int ioreg(uint32_t type, user_addr_t path) {
    char buf[128];
    size_t done;
    copyinstr(path, buf, sizeof(buf), &done);
    void *regentry;
    if(type == 128) {
        regentry = IORegistryEntry_fromPath(buf, NULL, NULL, NULL, NULL);
    } else {
        void *matching;
        switch(type) {
        case 134:
            matching = IOService_serviceMatching(buf, NULL);
            break;
        case 135:
            matching = IOService_nameMatching(buf, NULL);
            break;
        default:
            IOLog("?\n");
            return -1;
        }
        void *iterator = IOService_getMatchingServices(matching);
        if(!iterator) {
            IOLog("null iterator\n");
            return -1;
        }
        void *object;
        regentry = NULL;
        while(object = OSIterator_getNextObject(iterator)) {
            if(!regentry) regentry = object;
            IOLog("- %p\n", object);
        }
        IOLog("\n");
        OSObject_release(iterator);
        OSObject_release(matching);
    }
    return (int) regentry;
}

static uint32_t lookup_metaclass(user_addr_t name) {
    char buf[128];
    size_t done;
    copyinstr(name, buf, sizeof(buf), &done);
    void *symbol = OSSymbol_withCString(buf);
    uint32_t result = (uint32_t) OSMetaClass_getMetaClassWithName(symbol);
    OSObject_release(symbol);
    return result;
}

uint32_t get_proc_map(int pid) {
    struct proc *p = proc_find(pid);
    if(!p) return 0;
    return p->task->map->pmap->phys;
}

static int poke_mem(void *kaddr, uint32_t uaddr, uint32_t size, bool write, bool phys) {
    void *descriptor = 0, *map = 0;
    int retval;
    if(phys) {
        descriptor = IOMemoryDescriptor_withPhysicalAddress((uint32_t) kaddr, size, write ? kIODirectionOut : kIODirectionIn);
        if(!descriptor) {
            IOLog("couldn't create descriptor\n");
            return -1;
        }
        map = IOMemoryDescriptor_map(descriptor, 0);
        if(!map) {
            IOLog("couldn't map descriptor\n");
            OSObject_release(descriptor);
            return -1;
        }
        kaddr = IOMemoryMap_getAddress(map);
    }

    if(write) {
        retval = copyin(uaddr, kaddr, size);
    } else {
        retval = copyout(kaddr, uaddr, size);
    }

    if(phys) {
        OSObject_release(map);
        OSObject_release(descriptor);
    }
    return retval;
}

static int add_hook(void *addr, void *replacement, int mode) {
    void *tag = hook(addr, replacement, mode, hook_tag);
    if(tag) {
        IOLog("tag: %p\n", tag);
        hook_tag = tag;
        return 0;
    } else {
        return -1;
    }
}


int do_something() {
    uint32_t time, microtime;
    clock_get_system_microtime(&time, &microtime);
    IOLog("sec=%u usec=%u\n", time, microtime);
    return 0;
}

// from the loader
extern struct sysent sysent[];
struct sysent saved_sysent;

struct mysyscall_args {
    uint32_t mode;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
};

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval);
__attribute__((constructor))
void init() {
    IOLog("init %p\n", mysyscall);
    saved_sysent = sysent[8];
    sysent[8] = (struct sysent){ 1, 0, 0, (void *) mysyscall, NULL, NULL, _SYSCALL_RET_INT_T, sizeof(struct mysyscall_args) };
    lck_grp = lck_grp_alloc_init("kcode", NULL);
    tracer_lck = lck_mtx_alloc_init(lck_grp, NULL);
}

void fini_() {
    IOLog("unhook\n");
    creep_stop();
    protoss_unload();
    while(hook_tag) {
        hook_tag = unhook(hook_tag);
    }
}

__attribute__((destructor))
void fini() {
    fini_();
    lck_mtx_free(tracer_lck, lck_grp);
    lck_grp_free(lck_grp);
    sysent[8] = saved_sysent;
}

// keep in sync with stuff.c
struct regs {
    uint32_t cpsr;
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
    uint32_t tpidrprw;
    uint32_t dacr;
};

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval)
{
    switch(uap->mode) {
    case 0: { // get regs
        struct regs regs;
        asm("mrs %0, cpsr" :"=r"(regs.cpsr));
        asm("mrc p15, 0, %0, c2, c0, 0" :"=r"(regs.ttbr0));
        asm("mrc p15, 0, %0, c2, c0, 1" :"=r"(regs.ttbr1));
        asm("mrc p15, 0, %0, c2, c0, 2" :"=r"(regs.ttbcr));
        asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(regs.contextidr));
        asm("mrc p15, 0, %0, c1, c0, 0" :"=r"(regs.sctlr));
        //asm("mcr p15, 0, %0, c1, c1, 0" :: "r"(1 << 6));
        asm("mrc p15, 0, %0, c1, c1, 0" :"=r"(regs.scr));
        asm("mrc p14, 0, %0, c0, c0, 0" :"=r"(regs.dbgdidr));
        asm("mrc p14, 0, %0, c1, c0, 0" :"=r"(regs.dbgdrar));
        asm("mrc p14, 0, %0, c2, c0, 0" :"=r"(regs.dbgdsar));
        asm("mrc p15, 0, %0, c0, c1, 2" :"=r"(regs.id_dfr0));
        asm("mrc p14, 0, %0, c0, c1, 0" : "=r"(regs.dbgdscr));
        asm("mrc p15, 0, %0, c13, c0, 4" : "=r"(regs.tpidrprw));
        asm("mrc p15, 0, %0, c3, c0, 0" : "=r"(regs.dacr));
        *((volatile int *) 0x80001000);
        *((volatile int *) 0x80001000);
        *((volatile int *) 0x80001000);
        int error;
        if(error = copyout(&regs, (user_addr_t) uap->b, sizeof(regs))) return error;
        *retval = 0;
        break;
    }
    case 1: // copy data
        *retval = poke_mem((void *) uap->b, uap->c, uap->d, uap->e, uap->f);
        break;
    case 4: // crash
        ((void (*)()) 0xdeadbeef)();
        *retval = 0;
        break;
    case 6: // unhook
        fini_();
        break;
    case 7: // hook a function, log args
        *retval = add_hook((void *) uap->b, logger_hook, uap->c);
        break;
    case 8: // noreturn
        *retval = add_hook((void *) uap->b, noreturn_hook, 2);
        break;
    case 9: // hook weird
        *retval = add_hook((void *) uap->b, weird_hook, uap->c);
        break;
    case 10:
        *retval = creep_go((void *) uap->b, (int) uap->c);
        break;
    case 11:
        creep_get_records((user_addr_t) uap->b, uap->c);
        *retval = 0;
        break;
    case 13:
        *retval = ioreg(uap->b, (user_addr_t) uap->c);
        break;
    case 14:
        *retval = protoss_get_records(uap->b, (user_addr_t) uap->c, uap->d);
        break;
    case 15:
        if(!(*retval = protoss_go())) {
            IOLog("Hi\n");
            protoss_stop();
        }
        break;
    case 17:
        Debugger("Debugger() from kcode");
        break;
    case 20: // tracer
        tracer_ticks = uap->d;
        *retval = add_hook((void *) uap->b, tracer_hook, uap->c);
        break;
    case 21:
        *retval = lookup_metaclass(uap->b);
        break;
    case 22:
        *retval = protoss_go_watch(uap->b, uap->c);
        break;
    case 23:
        *retval = protoss_dump_debug_reg(uap->b);
        break;
    case 24:
        *retval = protoss_write_debug_reg(uap->b, uap->c);
        break;
    case 25: {
        void *metaclass;
        if(run_failsafe(&metaclass, &OSObject_getMetaClass, uap->b, 0)) {
            *retval = 5;
        } else {
            const char *name = OSMetaClass_getClassName(metaclass);
            size_t done;
            *retval = copyoutstr(name, uap->c, uap->d, &done);
        }
        break;
    }
    case 26:
        *retval = OSObject_getRetainCount((void *) uap->b);
        break;
    case 27:
        *retval = do_something();
        break;
    case 28:
        *retval = (int32_t) get_proc_map((int) uap->b);
        break;
    default:
        IOLog("Unknown mode %d\n", uap->mode);
        *retval = -1;
        break;
    }

    return 0;
}
