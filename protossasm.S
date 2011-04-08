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
    sub lr, #4
    srsdb sp!, #0x13

    ldr sp, _dbg_regs
    ldr lr, c5acce55
    str lr, [sp, #0xfb0]
    ldr lr, [sp, #0x314] 
    ldr lr, [sp, #0x154]
    bic lr, #1
    str lr, [sp, #0x154]

    cpsid aif, #0x13

    push {r0-r2}
    ldr r0, [sp, #0xc] ;# saved LR

    ldr r2, _trace_ptr
    ldr r1, [r2]
    cmp r1, #0
    bne fin1 ;# out of space

    ldr r1, [r2, #-4]
    cmp r1, r0
    beq fin1 ;# duplicate

    and r1, r0, #0xf0000000
    cmp r1, #0xf0000000
    beq fin1 ;# (probably) in kcode; not interesting

    ldrd r0, r1, [sp]
    strd r0, r1, [r2], #8
    ldr r1, [sp, #8]
    str r1, [r2], #4
    stmia r2!, {r3-r12, sp, lr}
    ldr r0, [sp, #0xc]
    str r0, [r2], #4

    str r2, _trace_ptr

fin1:
    ldr r2, _dbg_regs
    ;# don't get caught at exactly the same location
    bic r1, r0, #3
    str r1, [r2, #0x114]

    ;# and the BCR
    ldr r1, [sp, #0x10] ;# SPSR
    tst r1, #(1 << 5)
    moveq r0, #(15 << 5) ;# ARM -> 0b1111
    andne r1, r0, #2 ;# Thumb -> 0b1100 or 0b0011
    movne r0, #(3 << 5)
    movne r0, r0, lsl r1

    ldr r1, [r2, #0x154]
    bic r1, #(15 << 5)
    orr r1, r0 ;# byte address select
    orr r1, #1
    str r1, [r2, #0x154]

    mov r0, sp
    add sp, #0x14
    cpsid aif, #0x17
    ldm r0, {r0-r2, pc}^


#ifdef WATCHPOINTS
.globl _watch_prefetch_handler
_watch_prefetch_handler:
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

    str lr, saved_lr

    ldr sp, _dbg_regs
    ldr lr, c5acce55
    str lr, [sp, #0xfb0]
    ldr lr, [sp, #0x314] ;# do not remove

    ;# disable the breakpoint
    ldr lr, [sp, #0x140]
    and lr, #0xfffffffe 
    str lr, [sp, #0x140]

    ;# enable the watchpoint
    ldr lr, [sp, #0x1c0]
    orr lr, #1
    str lr, [sp, #0x1c0]
    
    ldr lr, saved_lr
    subs pc, lr, #4

.globl _watch_data_handler
_watch_data_handler:

    ;# is this actually a watchpoint?
    mrc p15, 0, sp, c5, c0, 0
    tst sp, #(1 << 10)
    ldrne pc, _data_saved
    and sp, #0xf
    cmp sp, #2
    ldrne pc, _data_saved
    ;# is this in the kernel?
    mrs sp, spsr
    and sp, #0x1f ;# M
    cmp sp, #0x10
    ldreq pc, _data_saved

    #movs pc, lr
    #mov r0, #0
    #ldr pc, [r0]

    str lr, saved_lr

bpstuff:
    ldr sp, _dbg_regs
    ldr lr, c5acce55
    str lr, [sp, #0xfb0]
    ldr lr, [sp, #0x314] ;# do not remove

    ;# disable the watchpoint
    ldr lr, [sp, #0x1c0]
    and lr, #0xfffffffe
    str lr, [sp, #0x1c0]
    
    ;# enable the breakpoint
    ldr lr, saved_lr
    sub lr, #8
    and lr, #0xfffffffc
    str lr, [sp, #0x100]

    ldr lr, [sp, #0x140]
    orr lr, #1
    str lr, [sp, #0x140]
# done

    ldr sp, _watch_ptr
    cmp sp, #0
    beq fin2
    ldr lr, [sp]
    cmp lr, #0
    bne fin2 ;# out of space
    
    # r[0-12], pc
    ldr sp, _watch_ptr
    ldr lr, saved_lr
    sub lr, #8
    stmia sp!, {r0-r12, lr}

    # accessed_address
    # this is technically undefined
    mrc p15, 0, lr, c6, c0, 0
    stmia sp!, {lr}

    # accessed_value 
    ldr lr, [lr]
    stmia sp!, {lr}

    # was_store
    mrc p15, 0, lr, c5, c0, 0
    ands lr, #(1 << 11)
    movne lr, #1
    stmia sp!, {lr}
    
    str sp, _watch_ptr

fin2:
    ldr lr, saved_lr

    subs pc, lr, #8
#endif

.globl _trace_ptr, _prefetch_saved, _data_saved, _dbg_regs
_trace_ptr: .long 0
_prefetch_saved: .long 0
_data_saved: .long 0
_dbg_regs: .long 0

c5acce55: .long 0xc5acce55

