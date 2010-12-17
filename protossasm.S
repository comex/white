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
    str lr, saved_lr

    ldr sp, _trace_ptr
    cmp sp, #0
    beq fin1
    ldr lr, [sp]
    cmp lr, #0
    bne fin1 ;# out of space

    ldr lr, [sp, #-4]
    mrc p15, 0, sp, c6, c0, 2
    cmp lr, sp
    beq fin1 ;# duplicate

    ldr sp, _trace_ptr
    mrc p15, 0, lr, c6, c0, 2
    stmia sp!, {r0-r12, lr}
    str sp, _trace_ptr

fin1:
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

    ldr sp, _dbg_map
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
    ldr sp, _dbg_map
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


saved_lr: .long 0
c5acce55: .long 0xc5acce55
.globl _trace_ptr, _prefetch_saved
.globl _watch_ptr, _data_saved
.globl _dbg_map
_trace_ptr: .long 0
_prefetch_saved: .long 0
_watch_ptr: .long 0
_data_saved: .long 0
_dbg_map: .long 0
