#include "kinc.h"

struct mysyscall_args {
    uint32_t mode;
    uint32_t b;
    uint32_t c;
    uint32_t d;
};

static void dump_ttbr(unsigned int ttbr0) {
    void *descriptor = IOMemoryDescriptor_withPhysicalAddress(ttbr0 & ~0x3f, 4096, kIODirectionIn);
    void *map = IOMemoryDescriptor_map(descriptor, 0);
    unsigned int *data = IOMemoryMap_getAddress(map);


    delete_object(map);
    delete_object(descriptor);
}

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval)
{
    IOLog("Hi mode=%d\n", uap->mode);
    switch(uap->mode) {
    case 0: { // get regs
        unsigned int ttbr0, ttbr1, ttbcr;
        asm("mrc p15, 0, %0, c2, c0, 0" :"=r"(ttbr0) :);
        asm("mrc p15, 0, %0, c2, c0, 1" :"=r"(ttbr1) :);
        asm("mrc p15, 0, %0, c2, c0, 2" :"=r"(ttbcr) :);
        int error;
        if(error = copyout(&ttbr0, (user_addr_t) uap->b, sizeof(ttbr0))) return error;
        if(error = copyout(&ttbr1, (user_addr_t) uap->c, sizeof(ttbr1))) return error;
        if(error = copyout(&ttbcr, (user_addr_t) uap->d, sizeof(ttbcr))) return error;
        IOLog("ttbr0=%x ttbr1=%x, ttbcr=%x\n", ttbr0, ttbr1, ttbcr);
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
    default:
        IOLog("Unknown mode %d\n", uap->mode);
        break;
    }
    
    return 0;
}
