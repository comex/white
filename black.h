#pragma once
#include "kinc.h"

struct frame {
    struct frame *r7;
    void *lr;
};

struct apply_args {
    void **sp;
    void *r0, *r1, *r2, *r3;
    struct frame frame; // not actually part of the __builtin_apply_args() struct
};

struct apply_result {
    void *r0, *r1, *r2, *r3;
};

#define HOOK_FORCE 1
#define HOOK_ANYWHERE 2
#define HOOK_POLITE 4

struct hook_info {
    uint32_t value;
    uint32_t value2;
    uint32_t jump;
    uint32_t returnto;
    uint32_t flags;
    void *tag;
    vm_address_t alloc;
    vm_size_t alloc_size;
    uint32_t *storeto;
};

void *hook(void *addr, void *replacement, int flags, void *tag);
void *unhook(void *stuff);
/*void hook_init();
void hook_fini();*/
