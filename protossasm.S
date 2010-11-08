.arm
.globl _prefetch_handler
_prefetch_handler:
    ;# is this actually a breakpoint?
    mrc p15, 0, sp, c5, c0, 1
    tst sp, #(1 << 10)
    ldrne pc, _prefetch_saved
    cmp sp, #2
    and sp, #0xf
    cmp sp, #2
    ldrne pc, _prefetch_saved
    ;# is this in the kernel?
    mrs sp, spsr
    and sp, #0x1f ;# M
    cmp sp, #0x10
    ldreq pc, _prefetch_saved

    ;# ok, this is us
    str lr, saved_lr

    ldr sp, _trace_ptr
    ldr lr, [sp]
    cmp lr, #0
    bne fin ;# out of space
    ldr sp, _trace_ptr
    mrc p15, 0, lr, c6, c0, 2
    str lr, [sp], #4
    str sp, _trace_ptr

fin:
    ldr lr, saved_lr
    ;# don't get caught at exactly the same location
    sub lr, #4
    and sp, lr, #0xfffffffc
    mcr p14, 0, sp, c0, c2, 4 ;# dbgbvr1
    movs pc, lr

saved_lr: .long 0
.globl _trace_ptr, _prefetch_saved
_trace_ptr: .long 0
_prefetch_saved: .long 0
