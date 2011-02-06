#include <stdint.h>
#include <stdbool.h>
#define LC __attribute__((long_call))

typedef uint32_t user_addr_t;
typedef uint32_t vm_size_t, vm_address_t, boolean_t, size_t, vm_offset_t, vm_prot_t, vm_map_size_t;
typedef int32_t pid_t, kern_return_t;

typedef struct ipc_port *mach_port_t;

struct timespec;

typedef struct pmap {
    void *virt;
    uint32_t phys;
    // ...
} *pmap_t;

typedef struct _vm_map {
    char whatever[0x24];
    pmap_t pmap;
    vm_map_size_t size;
    vm_map_size_t user_wire_limit;
    vm_map_size_t user_wire_size;
    int ref_count;
    int res_count;
} *vm_map_t;

typedef struct proc {
    void *prev;
    void *next;
    pid_t p_pid;
    struct task *task;
} *proc_t;

typedef uint32_t lck_mtx_t[3];

typedef struct _lck_grp_ lck_grp_t;

struct task {
    // lock
    lck_mtx_t lock;
    uint32_t ref_count;
    boolean_t active;
    boolean_t halting;
    vm_map_t map;
};

extern vm_map_t kernel_map;
extern uint32_t *kernel_pmap;

LC void *memset(void *b, int c, size_t len);

LC void *memcpy(void *restrict s1, const void *restrict s2, size_t len);

LC void invalidate_icache(vm_offset_t addr, unsigned cnt, bool phys);

LC void flush_dcache(vm_offset_t addr, unsigned cnt, bool phys);

LC void *IOMalloc(size_t size);
LC void IOFree(void *p);

LC int vm_allocate(vm_map_t map, vm_offset_t *addr, vm_size_t size, int flags);

LC int vm_deallocate(register vm_map_t map, vm_offset_t start, vm_size_t size);

LC int vm_protect(vm_map_t map, vm_offset_t start, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

LC int copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes);

LC int copyin(const user_addr_t uaddr, void *kaddr, size_t len);

LC int copyinstr(const user_addr_t uaddr, void *kaddr, size_t len, size_t *done);

LC int copyoutstr(const void *kaddr, user_addr_t uaddr, size_t len, size_t *done);

LC vm_map_t vm_map_switch(vm_map_t map)
asm("$t_f0_b5_03_af_05_46_1d_ee_90_4f_d4_f8");

LC void vm_map_deallocate(vm_map_t map);

// locks

LC lck_grp_t *lck_grp_alloc_init(const char *grp_name, void *attr);

LC void lck_grp_free(lck_grp_t *grp);

LC lck_mtx_t *lck_mtx_alloc_init(lck_grp_t *grp, void *attr);

LC void lck_mtx_lock(lck_mtx_t *lck);

LC void lck_mtx_unlock(lck_mtx_t *lck);

LC void lck_mtx_free(lck_mtx_t *lck, lck_grp_t *grp);

LC int sleep(void *chan, int pri);

LC int msleep(void *chan, lck_mtx_t *mtx, int pri, const char *wmsg, struct timespec *ts);

LC void wakeup(void *chan);

//

LC void IOLog(const char *msg, ...) __attribute__((format (printf, 1, 2)));

LC void IOSleep(unsigned int milliseconds);

LC int ml_set_interrupts_enabled(int enabled);

LC struct proc *proc_find(int pid);

LC int proc_pid(struct proc *proc);

LC struct proc *current_proc();

LC void panic(const char *string, ...);

static inline void flush_cache(void *addr, unsigned cnt) {
    flush_dcache((vm_offset_t) addr, cnt, false);
    invalidate_icache((vm_offset_t) addr, cnt, false);
}

typedef	void (*thread_continue_t)(void *param, int wait_result);

LC kern_return_t kernel_thread_start(thread_continue_t continuation, void *parameter, mach_port_t *new_thread);

typedef enum IODirection { 
    kIODirectionNone = 0, 
    kIODirectionIn = 1, // User land 'read' 
    kIODirectionOut = 2, // User land 'write' 
    kIODirectionOutIn = 3 
} IODirection; 

LC void *IOMemoryDescriptor_withPhysicalAddress(unsigned long address, unsigned long withLength, IODirection withDirection)
asm("__ZN18IOMemoryDescriptor19withPhysicalAddressEmm11IODirection");

LC void *IOMemoryDescriptor_map(void *descriptor, unsigned int options)
asm("__ZN18IOMemoryDescriptor3mapEm");

LC void *IOMemoryDescriptor_getPhysicalAddress(void *descriptor)
asm("__ZN18IOMemoryDescriptor18getPhysicalAddressEv");

LC void *IOMemoryMap_getAddress(void *map)
asm("__ZN11IOMemoryMap10getAddressEv");

LC void *IOService_serviceMatching(const char *buf, void *table)
asm("__ZN9IOService15serviceMatchingEPKcP12OSDictionary");

LC void *IOService_nameMatching(const char *buf, void *table)
asm("__ZN9IOService12nameMatchingEPKcP12OSDictionary");

LC void *IOService_getMatchingServices(void *matching)
asm("__ZN9IOService19getMatchingServicesEP12OSDictionary");

static inline void *OSIterator_getNextObject(void *iterator) {
    return ((void *(***)(void *)) iterator)[0][21](iterator);
}

LC void *IORegistryEntry_fromPath(const char *name, void *plane, char *residualPath, int *residualLength, void *fromEntry)
asm("__ZN15IORegistryEntry8fromPathEPKcPK15IORegistryPlanePcPiPS_");

LC void *IOService_mapDeviceMemoryWithIndex(void *service, unsigned int index, unsigned int options)
asm("__ZN9IOService24mapDeviceMemoryWithIndexEjm");

LC void *OSSymbol_withCString(const char *string)
asm("__ZN8OSSymbol11withCStringEPKc");

LC void *OSMetaClass_getMetaClassWithName(void *symbol)
asm("__ZN11OSMetaClass20getMetaClassWithNameEPK8OSSymbol");

LC void *OSMetaClass_getClassName(void *metaclass)
asm("__ZNK11OSMetaClass12getClassNameEv");

static inline void *get_metaclass(void *object) {
    void *(*ptr)(void *) = ((void ***) object)[0][0x1c/4];
    *((volatile uint32_t *) ptr);
    return ptr(object);
}

LC int OSObject_getRetainCount(void *object)
asm("__ZNK8OSObject14getRetainCountEv");

static inline void delete_object(void *object) {
    ((void (***)(void *)) object)[0][1](object);
}

static inline void release_object(void *object) {
    ((void (***)(void *)) object)[0][2](object);
}

static inline void *retain_object(void *object) {
    ((void (***)(void *)) object)[0][4](object);
    return object;
}

// copied from xnu

typedef int32_t sy_call_t(struct proc *, void *, int *);
typedef void    sy_munge_t(const void *, void *);

struct sysent {     /* system call table */
    int16_t     sy_narg;    /* number of args */
    int8_t      sy_resv;    /* reserved  */
    int8_t      sy_flags;   /* flags */
    sy_call_t   *sy_call;   /* implementing function */
    sy_munge_t  *sy_arg_munge32; /* system call arguments munger for 32-bit process */
    sy_munge_t  *sy_arg_munge64; /* system call arguments munger for 64-bit process */
    int32_t     sy_return_type; /* system call return types */
    uint16_t    sy_arg_bytes;   /* Total size of arguments in bytes for
                     * 32-bit system calls
                     */
};
#define _SYSCALL_RET_INT_T      1   

// end copied

#define prop(a, off, typ) *((typ *)(((char *) (a))+(off)))

#define NULL ((void *) 0)
