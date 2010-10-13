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

static inline void **vector_base() {
    void *result;
    asm("mrc p15, 0, %0, c12, c0, 0" :"=r"(result));
    return result;
}

void creep_go(void *start, int size) {
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
            
        }
        size -= 2;
        p++;
    }

    void **v = &vector_base()[1];
    saved = *v;
    IOLog("setting undefined instruction handler to %p\n", (void *) undefined_handler);
    *v = (void *) undefined_handler;
}

void creep_stop() {
    IOLog("restoring undefined instruction handler to %p\n", saved);
    vector_base()[1] = saved;    
    struct record *r;
    while(r = record_start) {
        record_start = r->next;
        IOFree(r);
    }
}
