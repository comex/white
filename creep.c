#include "kinc.h"

struct record {
    uint32_t address; // 0
    uint32_t value; // 4
    uint16_t actual_instruction; // 8
    uint16_t pad; 
    struct record *next; // c
} __attribute__((packed));

void undef_handler();
extern struct record *record_start;
extern void *undef_saved;

__attribute__((const))
static inline void **vector_base() {
    //void *result;
    //asm("mrc p15, 0, %0, c12, c0, 0" :"=r"(result));
    //return result;
    return (void **) 0xffff0000;
}

int creep_go(void *start, int size) {
    if(undef_saved) {
        IOLog("creep_go: already going (%p)\n", undef_saved);
        return -1;
    }
    // ldr pc, [pc, #0x18] (-> +0x20)
    if(vector_base()[1] != (void *) 0xe59ff018) {
        return -1;
    }

    uint16_t *p = start;
    record_start = NULL;
    while(size > 0) {
        uint16_t val = *p;
        if((val & 0xff87) == 0x4780) {
            struct record *record = IOMalloc(sizeof(struct record));
            record->address = (uint32_t)p; // |1
            record->actual_instruction = val;
            record->value = 0;
            record->next = record_start;
            record_start = record;
            //IOLog("%08x\n", record->address);
            // 0xde* are permanently undefined
            *p = 0xdeca;
            flush_cache(p, 2);
        }
        size -= 2;
        p++;
    }

    void **v = &vector_base()[1+8];
    undef_saved = *v;
    //IOLog("actually setting undefined instruction handler to %p (from %p)\n", (void *) undef_handler, undef_saved);
    *v = (void *) undef_handler;
    return 0;
}

void creep_get_records(user_addr_t buf, uint32_t bufsize) {
    for(struct record *record = record_start; record; record = record->next) {
        size_t sz = 2 * sizeof(uint32_t);
        if(bufsize < sz) return;
        copyout(record, buf, sz);
        buf += sz;
        bufsize -= sz;
    }
}

void creep_stop() {
    if(!undef_saved) return;    

    IOLog("restoring undefined instruction handler to %p\n", undef_saved);
    vector_base()[1+8] = undef_saved;    
    undef_saved = 0;
    struct record *r;
    while(r = record_start) {
        record_start = r->next;
        if(!r->value) {
            *((uint16_t *) (r->address)) = r->actual_instruction;
            flush_cache((void *) r->address, 2);
        }
        IOFree(r);
    }
}
