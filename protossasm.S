.arm
.globl _prefetch_handler
_prefetch_handler:
    ;# is this actually a breakpoint?
    mrc p15, 0, sp, c5, c0, 1
    tst sp, #(1 << 10)
    ldrne pc, _prefetch_saved
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
    cmp sp, #0
    beq fin
    ldr lr, [sp]
    cmp lr, #0
    bne fin ;# out of space

    ldr lr, [sp, #-4]
    mrc p15, 0, sp, c6, c0, 2
    cmp lr, sp
    beq fin ;# duplicate

    ldr sp, _trace_ptr
    mrc p15, 0, lr, c6, c0, 2
    stmia sp!, {r0-r12, lr}
    str sp, _trace_ptr

fin:
    ldr sp, _dbg_map
    ldr lr, c5acce55
    str lr, [sp, #0xfb0]
    ldr lr, [sp, #0x314] ;# do not remove
    #ldr lr, [sp, #0x88]
    #bic lr, #0x8000
    #str lr, [sp, #0x88]

    ldr lr, saved_lr
    sub lr, #4
    and lr, #0xfffffffc
    ;# don't get caught at exactly the same location
    str lr, [sp, #0x114]

    ldr lr, saved_lr
    subs pc, lr, #4

saved_lr: .long 0
c5acce55: .long 0xc5acce55
.globl _trace_ptr, _prefetch_saved, _dbg_map
_trace_ptr: .long 0
_prefetch_saved: .long 0
_dbg_map: .long 0
