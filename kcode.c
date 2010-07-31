#include "kinc.h"

struct mysyscall_args {
    uint32_t mode;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
};

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

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval)
{
    //IOLog("Hi mode=%d\n", uap->mode);
    switch(uap->mode) {
    case 0: { // get regs
        unsigned int ttbr0, ttbr1, ttbcr, contextidr;
        asm("mrc p15, 0, %0, c2, c0, 0" :"=r"(ttbr0) :);
        asm("mrc p15, 0, %0, c2, c0, 1" :"=r"(ttbr1) :);
        asm("mrc p15, 0, %0, c2, c0, 2" :"=r"(ttbcr) :);
        asm("mrc p15, 0, %0, c13, c0, 1" :"=r"(contextidr) :);
        int error;
        if(error = copyout(&ttbr0, (user_addr_t) uap->b, sizeof(ttbr0))) return error;
        if(error = copyout(&ttbr1, (user_addr_t) uap->c, sizeof(ttbr1))) return error;
        if(error = copyout(&ttbcr, (user_addr_t) uap->d, sizeof(ttbcr))) return error;
        if(error = copyout(&contextidr, (user_addr_t) uap->e, sizeof(contextidr))) return error;
        //IOLog("ttbr0=%x ttbr1=%x, ttbcr=%x\n", ttbr0, ttbr1, ttbcr);
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
    case 2: { // more realistic read
        *retval = copyout((void *) uap->b, (user_addr_t) uap->d, uap->c);
        break;
    }
    case 3: { // read32 just in case
        *retval = *((int32_t *) uap->b);
        break;
    }
    case 4: { // crash
        asm("sub sp, #2; mov r0, #0; ldr r0, [r0]");
        break;
    }
    case 5: { // list IOSurfaces
        *retval = list_iosurfaces();
        break;
    }
    default:
        IOLog("Unknown mode %d\n", uap->mode);
        break;
    }
    
    return 0;
}
