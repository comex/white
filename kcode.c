#include "kinc.h"

struct mysyscall_args {
    uint32_t a;
    uint32_t b;
    uint32_t c;
};

int mysyscall(void *p, struct mysyscall_args *uap, int32_t *retval)
{
    IOLog("mysyscall: a=%u b=%u c=%u\n", uap->a, uap->b, uap->c);
    *retval = 42;
    return 0;
}
