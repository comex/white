.arm
.globl _trace_prefetch_handler
_trace_prefetch_handler:
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
    strd r0, r1, saved_r0
    sub lr, #4

    ldr sp, _trace_ptr
    cmp sp, #0
    beq fin1
    ldr r1, [sp]
    cmp r1, #0
    bne fin1 ;# out of space

    ldr r1, [sp, #-4]
    cmp r1, lr
    beq fin1 ;# duplicate

    and r1, lr, #0xf0000000
    cmp r1, #0xf0000000
    beq fin1 ;# (probably) in kcode; not interesting

    ldr r0, _dbg_map
    ldr r1, c5acce55
    str r1, [r0, #0xfb0]
    ldr r1, [r0, #0x314] ;# do not remove

    ldr r1, [r0, #0x154]
    bic r1, #1
    str r1, [r0, #0x154]
    ;# go spelunking
    cpsid aif, #0x13
    mov r0, sp
    mov r1, lr
    cpsid aif, #0x17

    stmia sp!, {r0-r1}
    ldrd r0, r1, saved_r0
    stmia sp!, {r0-r12, lr}

    str sp, _trace_ptr

fin1:
    ldr r0, _dbg_map
    ldr r1, c5acce55
    str r1, [r0, #0xfb0]
    ldr r1, [r0, #0x314] ;# do not remove

    ;# don't get caught at exactly the same location
    bic r1, lr, #3
    str r1, [r0, #0x114]

    ;# and the BCR
    mrs r1, spsr
    tst r1, #(1 << 5)
    mov sp, #(15 << 5) ;# ARM -> 0b1111
    moveq sp, #(15 << 5) ;# ARM -> 0b1111
    andne r1, lr, #2 ;# Thumb -> 0b1100 or 0b0011
    movne sp, #(3 << 5)
    movne sp, sp, lsl r1

    ldr r1, [r0, #0x154]
    bic r1, #(15 << 5)
    orr r1, sp ;# byte address select
    orr r1, #1
    str r1, [r0, #0x154]

    ldrd r0, r1, saved_r0
    movs pc, lr

saved_r0: .long 0
saved_r1: .long 0
c5acce55: .long 0xc5acce55

.globl _trace_ptr, _prefetch_saved, _dbg_map
_trace_ptr: .long 0
_prefetch_saved: .long 0
_dbg_map: .long 0

