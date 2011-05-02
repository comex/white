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

    strd r0, r1, saved_regs 

    ldr r0, _dbg_regs
    ldr r1, c5acce55
    str r1, [r0, #0xfb0]
    ldr r1, [r0, #0x314] 

    ldr r1, [r0, #0x154]
    bic r1, #1
    str r1, [r0, #0x154]

    ldr sp, _trace_ptr
    ldr r0, _trace_end
    cmp sp, r0
#ifdef CIRCULAR
    ldreq sp, _trace_start
#else
    beq fin1 ;# out of space
#endif

    ldr r1, [sp, #-4]
    cmp r1, lr
    beq fin1 ;# duplicate

    and r1, lr, #0xf0000000
    cmp r1, #0xf0000000
    beq fin1 ;# (probably) in kcode; not interesting

    ;# go spelunking
    cpsid aif, #0x13
    mov r0, sp
    mov r1, lr
    cpsid aif, #0x17

    stmia sp!, {r0-r1}
    ldrd r0, r1, saved_regs
    stmia sp!, {r0-r12, lr}

    str sp, _trace_ptr

fin1:
    ldr r0, _dbg_regs
    ;# don't get caught at exactly the same location
    bic r1, lr, #3
    str r1, [r0, #0x114]

    ;# and the BCR
    mrs r1, spsr
    tst r1, #(1 << 5)
    moveq sp, #(15 << 5) ;# ARM -> 0b1111
    andne r1, lr, #2 ;# Thumb -> 0b1100 or 0b0011
    movne sp, #(3 << 5)
    movne sp, sp, lsl r1

    ldr r1, [r0, #0x154]
    bic r1, #(15 << 5)
    orr r1, sp ;# byte address select
    orr r1, #1
    str r1, [r0, #0x154]

    ldrd r0, r1, saved_regs
    movs pc, lr

c5acce55: .long 0xc5acce55
saved_regs: .long 0, 0

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

loque_loop:
    adr sp, loque
    ldrex sp, [sp]
    cmp sp, #0
    bne loque_loop
    adr sp, loque
    .long 0xe18ddf9d ;# strex sp, sp, [sp]
    cmp sp, #0
    bne loque_loop

    strd r0, r1, saved_regs

    ldr r0, _dbg_regs
    ldr r1, c5acce55
    str r1, [r0, #0xfb0]
    ldr r1, [r0, #0x314] ;# do not remove
    
    ;# enable the watchpoint
    ldr r1, [r0, #0x1c0]
    orr r1, #1
    str r1, [r0, #0x1c0]
    
    ;# disable the breakpoint
    ldr r1, [r0, #0x154]
    bic r1, #1
    str r1, [r0, #0x154]
    
    ldr r1, [r0, #0x150]
    bic r1, #1
    str r1, [r0, #0x150]

    ldrd r0, r1, saved_regs
    
    mov sp, #0
    str sp, loque

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

loque_loop_1:
    adr sp, loque
    ldrex sp, [sp]
    cmp sp, #0
    bne loque_loop
    adr sp, loque
    .long 0xe18ddf9d ;# strex sp, sp, [sp]
    cmp sp, #0
    bne loque_loop_1

    sub lr, #8

    strd r0, r1, saved_regs

bpstuff:
    ldr r0, _dbg_regs
    ldr r1, c5acce55
    str r1, [r0, #0xfb0]
    ldr r1, [r0, #0x314] ;# do not remove

    ;# disable the watchpoint
    ldr r1, [r0, #0x1c0]
    bic r1, #1
    str r1, [r0, #0x1c0]
    
    ldr sp, _watch_ptr
    ldr r1, [sp]
    cmp r1, #0
    bne fin2 ;# out of space
    
    ;# go spelunking
    cpsid aif, #0x13
    mov r0, sp
    mov r1, lr
    cpsid aif, #0x17

    stmia sp!, {r0-r1}
    adr r0, saved_regs
    ldrd r0, r1, [r0]
    stmia sp!, {r0-r12, lr}

    # accessed_address
    # this is technically undefined
    mrc p15, 0, r0, c6, c0, 0
    stmia sp!, {r0}

    # accessed_value 
    ldr r0, [r0]

    # was_store
    mrc p15, 0, r1, c5, c0, 0
    ands r1, #(1 << 11)
    movne r1, #1

    stmia sp!, {r0, r1}
    
    str sp, _watch_ptr
    
    ldr r0, _dbg_regs
    ;# enable the breakpoint
    bic r1, lr, #3
    str r1, [r0, #0x114]
    
    ;# and the BCR
    mrs r1, spsr
    tst r1, #(1 << 5)
    moveq sp, #(15 << 5) ;# ARM -> 0b1111
    andne r1, lr, #2 ;# Thumb -> 0b1100 or 0b0011
    movne sp, #(3 << 5)
    movne sp, sp, lsl r1

    ldr r1, [r0, #0x154]
    bic r1, #(15 << 5)
    orr r1, sp
    orr r1, #1
    str r1, [r0, #0x154]
    
    mrc p15, 0, r1, c13, c0, 1
    str r1, [r0, #0x110]

    ldr r1, [r0, #0x150]
    orr r1, #1
    str r1, [r0, #0x150]
# done
    
fin2:
    adr r0, saved_regs
    ldrd r0, r1, [r0]

    mov sp, #0
    str sp, loque

    movs pc, lr
#endif


.globl _trace_ptr, _trace_start, _trace_end
_trace_start: .long 0
_trace_ptr: .long 0
_trace_end: .long 0

.globl _watch_ptr, _prefetch_saved, _data_saved, _dbg_regs
_watch_ptr: .long 0
_prefetch_saved: .long 0
_data_saved: .long 0
_dbg_regs: .long 0

loque: .long 0
