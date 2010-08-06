#include <stdint.h>
#include <stdbool.h>
// This is stupid and generates wasteful code, but is necessary.  The BL instruction generated otherwise treats it as ARM and ignores the least-significant bit.
// A proper solution is apparently making the generated symbol have the right attribute, but I can't do that without... manually generating an ELF file?
#define LC __attribute__((long_call))

typedef uint32_t user_addr_t, vm_size_t, vm_address_t, boolean_t, size_t, vm_offset_t, vm_prot_t;
typedef void *vm_map_t;

extern vm_map_t kernel_map;
extern uint32_t *kernel_pmap;

LC void invalidate_icache(vm_offset_t addr, unsigned cnt, bool phys);

LC void *IOMalloc(size_t size);

LC int vm_allocate(vm_map_t map, vm_offset_t *addr, vm_size_t size, int flags);

LC int vm_deallocate(register vm_map_t map, vm_offset_t start, vm_size_t size);


LC int vm_protect(vm_map_t map, vm_offset_t start, vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

LC int copyout(const void *kernel_addr, user_addr_t user_addr, vm_size_t nbytes);

LC void IOLog(const char *msg, ...) __attribute__((format (printf, 1, 2)));

typedef enum IODirection { 
    kIODirectionNone = 0, 
    kIODirectionIn = 1, // User land 'read' 
    kIODirectionOut = 2, // User land 'write' 
    kIODirectionOutIn = 3 
} IODirection; 

LC void *IOMemoryDescriptor_withPhysicalAddress(unsigned long address, unsigned long withLength, IODirection withDirection)
asm("_ZN18IOMemoryDescriptor19withPhysicalAddressEmm11IODirection");

LC void *IOMemoryDescriptor_map(void *descriptor, unsigned int options)
asm("_ZN18IOMemoryDescriptor3mapEm");

LC void *IOMemoryDescriptor_getPhysicalAddress(void *descriptor)
asm("_ZN18IOMemoryDescriptor18getPhysicalAddressEv");

LC void *IOMemoryMap_getAddress(void *map)
asm("_ZN11IOMemoryMap10getAddressEv");

LC void *IORegistryEntry_fromPath(const char *name, void *plane, char *residualPath, int *residualLength, void *fromEntry)
asm("_ZN15IORegistryEntry8fromPathEPKcPK15IORegistryPlanePcPiPS_");

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

#define prop(a, off, typ) *((typ *)(((char *) (a))+(off)))

#define NULL ((void *) 0)
