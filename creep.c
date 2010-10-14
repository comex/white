#include "kinc.h"

void undefined_handler();

struct record {
    uint32_t address;
    uint32_t actual_instruction;
    uint32_t value;
    struct record *next;
} __attribute__((packed));
struct record *record_start;

static void *saved;

__attribute__((const))
static inline void **vector_base() {
    //void *result;
    //asm("mrc p15, 0, %0, c12, c0, 0" :"=r"(result));
    //return result;
    return (void **) 0xffff0000;
}

int creep_go(void *start, int size) {
    // ldr pc, [pc, #0x18] (-> +0x20)
    if(vector_base()[1] != (void *) 0xe59ff018) {
        return -1;
    }

    uint16_t *p = start;
    record_start = NULL;
    while(size > 0) {
        uint16_t val = *p;
        if((val & 0x7fc7) == 0x23c0) {
            struct record *record = IOMalloc(sizeof(struct record));
            record->address = (uint32_t)p + 1; // |1
            record->actual_instruction = val;
            record->value = 0;
            record->next = record_start;
            record_start = record;
            IOLog("%08x\n", record->address);
            // 0xde* are permanently undefined
            *p = 0xdeca;
            invalidate_icache((vm_offset_t) p, 2, false);
        }
        size -= 2;
        p++;
    }

    void **v = &vector_base()[1+8];
    saved = *v;
    IOLog("setting undefined instruction handler to %p (from %p)\n", (void *) undefined_handler, saved);
    //*v = (void *) undefined_handler;
    return 0;
}

void creep_stop() {
    IOLog("restoring undefined instruction handler to %p\n", saved);
    vector_base()[1+8] = saved;    
    struct record *r;
    while(r = record_start) {
        record_start = r->next;
        if(!r->value) {
            *((uint16_t *) (r->address - 1)) = r->actual_instruction;
            invalidate_icache((vm_offset_t) (r->address - 1), 2, false);
        }
        IOFree(r);
    }
}
